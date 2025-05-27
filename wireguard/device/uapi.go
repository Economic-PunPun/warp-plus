/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bepass-org/warp-plus/wireguard/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)

	writeBuf := func(format string, args ...any) error {
		buf.WriteString(fmt.Sprintf(format, args...))
		buf.WriteString("\n")
		return nil
	}

	writeHex := func(name string, val []byte) {
		writeBuf(name+"=%x", val)
	}

	writeBool := func(name string, val bool) {
		if val {
			writeBuf(name+"=true")
		} else {
			writeBuf(name+"=false")
		}
	}

	writeNum := func(name string, val int64) {
		writeBuf(name+"=%d", val)
	}

	writeStrings := func(name string, val []string) {
		for _, s := range val {
			writeBuf(name+"=%s", s)
		}
	}

	writeBuf("last_handshake_time_nanos=%d", device.lastHandshakeNano.Load())
	writeBuf("device_state=%s", device.state.String())

	writeHex("public_key", device.staticIdentity.publicKey)
	writeHex("listen_port", []byte(strconv.Itoa(int(device.net.bind.Port()))))
	if device.fwmark.Load() != 0 {
		writeNum("fwmark", int64(device.fwmark.Load()))
	}

	device.peers.RLock()
	defer device.peers.RUnlock()

	for _, peer := range device.peers.keyMap {
		writeBuf("peer")
		writeHex("public_key", peer.handshake.remoteStatic)
		if peer.endpoint.Load() != nil {
			writeBuf("endpoint=%s", peer.endpoint.Load().String())
		}
		if peer.handshake.presharedKey != nil {
			writeHex("preshared_key", peer.handshake.presharedKey[:])
		}
		if peer.persistentKeepaliveInterval.Load() != 0 {
			writeNum("persistent_keepalive_interval", int64(peer.persistentKeepaliveInterval.Load().Seconds()))
		}
		writeNum("rx_bytes", int64(peer.rxBytes.Load()))
		writeNum("tx_bytes", int64(peer.txBytes.Load()))
		if peer.handshake.lastHandshakeNano.Load() != 0 {
			writeNum("last_handshake_time_nanos", peer.handshake.lastHandshakeNano.Load())
		}
		if peer.handshake.remoteIndex.Load() != 0 {
			writeNum("protocol_version", 1) // Hardcoded for now as there's only one active protocol version
		}

		// Amnezia VPN obfuscation parameters
		writeBool("use_protocol_extension", peer.UseProtocolExtension)
		if peer.Jc != 0 {
			writeNum("jc", int64(peer.Jc))
		}
		if peer.Jmin != 0 {
			writeNum("jmin", int64(peer.Jmin))
		}
		if peer.Jmax != 0 {
			writeNum("jmax", int64(peer.Jmax))
		}
		if peer.S1 != nil {
			writeNum("s1", int64(*peer.S1))
		}
		if peer.S2 != nil {
			writeNum("s2", int64(*peer.S2))
		}
		if peer.H1 != nil {
			writeNum("h1", int64(*peer.H1))
		}
		if peer.H2 != nil {
			writeNum("h2", int64(*peer.H2))
		}
		if peer.H3 != nil {
			writeNum("h3", int64(*peer.H3))
		}
		if peer.H4 != nil {
			writeNum("h4", int64(*peer.H4))
		}

		for _, allowedIP := range peer.allowedIPs.Enumerate() {
			writeBuf("allowed_ip=%s", allowedIP.String())
		}
	}

	_, err := w.Write(buf.Bytes())
	return err
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) error {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	type ipcSetPeer struct {
		*Peer
		replaceAllowedIPs bool
		remove            bool
		endpoint          conn.Endpoint // Only present if `endpoint` was actually parsed, rather than nil
	}

	peersToSet := make(map[NoisePublicKey]*ipcSetPeer)
	var currentPeer *ipcSetPeer
	var err error

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, found := strings.Cut(line, "=")
		if !found {
			return ipcErrorf(ipc.IpcErrorInvalid, "line contains no = sign")
		}

		if key == "public_key" {
			currentPeer = &ipcSetPeer{}
			key, err := hexDecode(value)
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "public_key is not valid hex: %w", err)
			}
			if len(key) != NoisePublicKeySize {
				return ipcErrorf(ipc.IpcErrorInvalid, "public_key has wrong length")
			}
			var noisePublicKey NoisePublicKey
			copy(noisePublicKey[:], key)

			device.peers.RLock()
			currentPeer.Peer = device.peers.keyMap[noisePublicKey]
			device.peers.RUnlock()

			if currentPeer.Peer == nil {
				currentPeer.Peer = device.NewPeer(noisePublicKey)
			}
			peersToSet[noisePublicKey] = currentPeer
			continue
		}

		if currentPeer == nil {
			switch key {
			case "private_key":
				key, err := hexDecode(value)
				if err != nil {
					return ipcErrorf(ipc.IpcErrorInvalid, "private_key is not valid hex: %w", err)
				}
				if len(key) != NoisePrivateKeySize {
					return ipcErrorf(ipc.IpcErrorInvalid, "private_key has wrong length")
				}
				var noisePrivateKey NoisePrivateKey
				copy(noisePrivateKey[:], key)
				device.SetPrivateKey(noisePrivateKey)
				continue
			case "listen_port":
				port, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return ipcErrorf(ipc.IpcErrorInvalid, "listen_port is not valid integer: %w", err)
				}
				err = device.SetListeningPort(uint16(port))
				if err != nil {
					return ipcErrorf(ipc.IpcErrorInvalid, "listen_port could not be set: %w", err)
				}
				continue
			case "fwmark":
				fwmark, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return ipcErrorf(ipc.IpcErrorInvalid, "fwmark is not valid integer: %w", err)
				}
				device.SetFwmark(uint32(fwmark))
				continue
			}
			return ipcErrorf(ipc.IpcErrorInvalid, "config file must start with public_key, private_key, listen_port, or fwmark")
		}

		// handle peer lines
		err = handlePeerLine(currentPeer, key, value)
		if err != nil {
			return err
		}
	}

	for _, p := range peersToSet {
		if p.remove {
			device.RemovePeer(p.Peer)
			continue
		}

		device.AddPeer(p.Peer) // will no-op if already added

		// Endpoint only configured if `endpoint` key explicitly present
		if p.endpoint != nil {
			p.Peer.SetEndpoint(p.endpoint)
		}

		// replace allowed ips
		if p.replaceAllowedIPs {
			p.Peer.allowedIPs.Clear()
		}

		// Amnezia VPN obfuscation parameters handling
		if p.UseProtocolExtension { // Only set if explicitly enabled
			if p.Jc != 0 {
				p.Peer.Jc = p.Jc
			}
			if p.Jmin != 0 {
				p.Peer.Jmin = p.Jmin
			}
			if p.Jmax != 0 {
				p.Peer.Jmax = p.Jmax
			}
			if p.S1 != nil {
				s1Val := *p.S1
				p.Peer.S1 = &s1Val
			}
			if p.S2 != nil {
				s2Val := *p.S2
				p.Peer.S2 = &s2Val
			}
			if p.H1 != nil {
				h1Val := *p.H1
				p.Peer.H1 = &h1Val
			}
			if p.H2 != nil {
				h2Val := *p.H2
				p.Peer.H2 = &h2Val
			}
			if p.H3 != nil {
				h3Val := *p.H3
				p.Peer.H3 = &h3Val
			}
			if p.H4 != nil {
				h4Val := *p.H4
				p.Peer.H4 = &h4Val
			}
		} else { // If explicitly disabled, unset all.
			p.Peer.Jc = 0
			p.Peer.Jmin = 0
			p.Peer.Jmax = 0
			p.Peer.S1 = nil
			p.Peer.S2 = nil
			p.Peer.H1 = nil
			p.Peer.H2 = nil
			p.Peer.H3 = nil
			p.Peer.H4 = nil
		}
	}

	return nil
}

func handlePeerLine(peer *ipcSetPeer, key string, value string) error {
	var err error
	switch key {
	case "preshared_key":
		key, err := hexDecode(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "preshared_key is not valid hex: %w", err)
		}
		if len(key) != NoisePresharedKeySize {
			return ipcErrorf(ipc.IpcErrorInvalid, "preshared_key has wrong length")
		}
		var psKey NoisePresharedKey
		copy(psKey[:], key)
		peer.SetPresharedKey(&psKey)
	case "endpoint":
		peer.endpoint, err = conn.EndpointFromString(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "endpoint is not valid: %w", err)
		}
	case "persistent_keepalive_interval":
		seconds, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "persistent_keepalive_interval is not valid integer: %w", err)
		}
		peer.SetPersistentKeepalive(time.Duration(seconds) * time.Second)
	case "allowed_ip":
		ip, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "allowed_ip is not valid: %w", err)
		}
		peer.allowedIPs.Add(ip)
	case "replace_allowed_ips":
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "replace_allowed_ips is not true")
		}
		peer.replaceAllowedIPs = true
	case "remove":
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "remove is not true")
		}
		peer.remove = true

	// Amnezia VPN obfuscation parameters
	case "use_protocol_extension":
		if value == "true" {
			peer.UseProtocolExtension = true
		} else if value == "false" {
			peer.UseProtocolExtension = false
		} else {
			return ipcErrorf(ipc.IpcErrorInvalid, "use_protocol_extension must be true or false")
		}
	case "jc":
		jc, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "jc is not a valid integer: %w", err)
		}
		peer.Jc = int(jc)
	case "jmin":
		jmin, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "jmin is not a valid integer: %w", err)
		}
		peer.Jmin = int(jmin)
	case "jmax":
		jmax, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "jmax is not a valid integer: %w", err)
		}
		peer.Jmax = int(jmax)
	case "s1":
		s1, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "s1 is not a valid integer: %w", err)
		}
		s1Int := int(s1)
		peer.S1 = &s1Int
	case "s2":
		s2, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "s2 is not a valid integer: %w", err)
		}
		s2Int := int(s2)
		peer.S2 = &s2Int
	case "h1":
		h1, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "h1 is not a valid 8-bit integer: %w", err)
		}
		h1Byte := byte(h1)
		peer.H1 = &h1Byte
	case "h2":
		h2, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "h2 is not a valid 8-bit integer: %w", err)
		}
		h2Byte := byte(h2)
		peer.H2 = &h2Byte
	case "h3":
		h3, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "h3 is not a valid 8-bit integer: %w", err)
		}
		h3Byte := byte(h3)
		peer.H3 = &h3Byte
	case "h4":
		h4, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "h4 is not a valid 8-bit integer: %w", err)
		}
		h4Byte := byte(h4)
		peer.H4 = &h4Byte

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "unknown key %q", key)
	}
	return nil
}

func hexDecode(s string) ([]byte, error) {
	return ipc.HexDecode(s)
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(ipc.IpcErrorInvalid, "trailing character in UAPI get: %q", nextByte)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			err = ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI operation")
		}

		if err != nil {
			ipcErr, ok := err.(*IPCError)
			if ok {
				_, err = buffered.WriteString(fmt.Sprintf("errno=%d\n", ipcErr.ErrorCode()))
			} else {
				_, err = buffered.WriteString("errno=1\n") // EPERM
			}
			if err != nil {
				return
			}
		}

		_, err = buffered.WriteString("\n")
		if err != nil {
			return
		}
		err = buffered.Flush()
		if err != nil {
			return
		}
	}
}
