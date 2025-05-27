/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/bepass-org/warp-plus/wireguard/conn"
	"github.com/bepass-org/warp-plus/wireguard/tun"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (device *Device) RoutineSequentialSender() {
	device.log.Verbosef("Routine: sequential sender started")
	defer device.log.Verbosef("Routine: sequential sender stopped")

	var (
		currentPacket          []byte
		currentElement         *QueueOutboundElement
		next                   uint64
		skipNextNonce          bool
		handshakeAttempts      int
		handshakeAttemptExpiry time.Time
	)

	keepaliveBuffer := device.GetMessageBuffer()
	copy(keepaliveBuffer.bytes[0:], []byte{MessageKeepalive})

	for {
		elemsContainer := <-device.queue.outbound.c
		if elemsContainer == nil {
			return
		}

		initiatingElem := elemsContainer.elems[0]

		device.peers.RLock()
		peer, ok := device.peers.keyMap[initiatingElem.peerID]
		device.peers.RUnlock()

		if !ok || peer == nil {
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			elemsContainer.Unlock()
			device.PutOutboundElementsContainer(elemsContainer)
			continue
		}

		if !peer.isRunning.Load() {
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			elemsContainer.Unlock()
			device.PutOutboundElementsContainer(elemsContainer)
			continue
		}

		dataSent := false
		elemsContainer.Lock()
		bufs := make([][]byte, 0, len(elemsContainer.elems))
		for _, elem := range elemsContainer.elems {
			if len(elem.packet) != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, elem.packet)
		}
		elemsContainer.Unlock()

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err := peer.SendBuffers(bufs, false)
		if dataSent {
			peer.timersDataSent()
		}
		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		elemsContainer.Unlock()
		device.PutOutboundElementsContainer(elemsContainer)

		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				device.log.Verbosef(err.Error())
			} else {
				device.log.Errorf("Failed to send data: %v", err)
				peer.endpoint.Lock()
				peer.endpoint.clearSrcOnTx = true
				peer.endpoint.Unlock()
			}
		}
	}
}

func (device *Device) encrypt(
	peer *Peer,
	currentKeypair *Keypair,
	payload []byte,
) (
	[]byte,
	*Keypair,
	error,
) {
	if currentKeypair == nil {
		handshake := &peer.handshake
		handshake.mutex.Lock()
		defer handshake.mutex.Unlock()

		if handshake.created.Load() && handshake.lastSentHandshake.Add(RekeyTimeout).After(time.Now()) {
			currentKeypair = handshake.handshakeNonce.Load()
			if currentKeypair != nil {
				return nil, currentKeypair, ErrHandshakeAlreadyInProgress
			}
		}

		handshake.Clear()
		handshake.created.Store(true)

		handshake.localEphemeral.GenerateKey()
		handshake.precomputedStaticStatic = MixKey(handshake.localEphemeral.privateKey, handshake.remoteStatic)
		handshake.precomputedEphemeralStatic = MixKey(handshake.localEphemeral.privateKey, handshake.remoteEphemeral.publicKey)

		handshake.chainingKey, handshake.hash = KDF1(handshake.precomputedStaticStatic[:], handshake.hash[:])
		handshake.chainingKey, handshake.hash = KDF2(handshake.localEphemeral.publicKey[:], handshake.hash[:])
		handshake.chainingKey, handshake.hash = KDF2(peer.handshake.remoteStatic[:], handshake.hash[:])

		handshake.hash = Hash(handshake.hash[:], []byte("Noise_IK_WireGuard_0"))
		handshake.hash = Hash(handshake.hash[:], peer.staticIdentity.publicKey[:])

		mac1 := HMAC(handshake.hash[:], handshake.localEphemeral.publicKey[:])
		mac2 := HMAC(mac1[:], peer.handshake.remoteStatic[:])

		msg := NewMessageInitiation()
		msg.localEphemeral = handshake.localEphemeral.publicKey
		msg.localIndex = device.indexTable.NewIndex(peer)
		msg.mac1 = mac1
		msg.mac2 = mac2

		handshake.chainingKey, handshake.hash, msg.encryptedEphemeral = KDF3(handshake.precomputedStaticStatic[:], handshake.hash[:], peer.staticIdentity.publicKey[:])
		handshake.chainingKey, handshake.hash, msg.encryptedStatic = KDF3(handshake.precomputedEphemeralStatic[:], handshake.hash[:], peer.staticIdentity.publicKey[:])

		currentKeypair = new(Keypair)
		currentKeypair.sendNonce.Store(0)
		currentKeypair.receiveNonce.Store(0)
		currentKeypair.created = time.Now()
		currentKeypair.replayFilter.Init()
		handshake.handshakeNonce.Store(currentKeypair)

		return msg.Marshal(), currentKeypair, nil
	}

	msg := NewMessageTransport()
	msg.receiverIndex = currentKeypair.remoteIndex.Load()
	msg.nonce = currentKeypair.sendNonce.Load()
	msg.encryptedPacket = payload
	msg.mac1 = HMAC(currentKeypair.hash[:], payload)

	currentKeypair.sendNonce.Add(1)
	return msg.Marshal(), currentKeypair, nil
}

func (device *Device) RoutineEncryptionWorker() {
	device.log.Verbosef("Routine: encryption worker started")
	defer device.log.Verbosef("Routine: encryption worker stopped")

	for message := range device.queue.encryption.c {
		var (
			keypair      *Keypair
			currentNonce uint64
			err          error
		)

		if message.keypair != nil {
			keypair = message.keypair
			currentNonce = keypair.sendNonce.Load()
		}

		message.packet, keypair, err = device.encrypt(
			message.peer,
			keypair,
			message.buffer.bytes[message.offset:message.length],
		)

		if err == nil {
			nonceBytes := make([]byte, chacha20poly1305.NonceSize)
			binary.LittleEndian.PutUint64(nonceBytes, currentNonce)
			
			message.packet, err = chacha20poly1305.New(keypair.sendKey[:]).Seal(
				message.packet[:0],
				nonceBytes, 
				message.packet,
				nil,
			)
			if err != nil {
				device.log.Errorf("Failed to encrypt packet: %v", err)
			}
		}

		device.queue.encryption.wg.Done()

		if err != nil {
			device.PutMessageBuffer(message.buffer)
			message.buffer = nil
			message.packet = nil
			continue
		}

		message.peer.SendQueue(message.buffer)
	}
}

func (device *Device) RoutineDecryptionWorker() {
	device.log.Verbosef("Routine: decryption worker started")
	defer device.log.Verbosef("Routine: decryption worker stopped")

	for message := range device.queue.decryption.c {
		var err error
		var currentNonce uint64

		if message.keypair != nil {
			currentNonce = message.keypair.receiveNonce.Load()
		}

		nonceBytes := make([]byte, chacha20poly1305.NonceSize)
		binary.LittleEndian.PutUint64(nonceBytes, currentNonce)

		message.packet, err = chacha20poly1305.New(message.keypair.receiveKey[:]).Open(
			message.packet[:0],
			nonceBytes, 
			message.packet,
			nil,
		)

		if err != nil {
			device.PutMessageBuffer(message.buffer)
			message.buffer = nil
			message.packet = nil
			continue
		}

		message.peer.ReceiveQueue(message.buffer)
	}
}

type RoutinesPool struct {
	sync.WaitGroup
	c chan *Message
}

func (device *Device) StartRoutinesPool(name string, count int, worker func()) {
	device.log.Verbosef("Routine: %s routines started (%d)", name, count)
	for i := 0; i < count; i++ {
		device.queue.encryption.wg.Add(1)
		go worker()
	}
}

func (device *Device) StopRoutinesPool(name string, count int) {
	device.log.Verbosef("Routine: %s routines stopping (%d)", name, count)
	for i := 0; i < count; i++ {
		device.queue.encryption.c <- nil
	}
	device.queue.encryption.wg.Wait()
	device.log.Verbosef("Routine: %s routines stopped (%d)", name, count)
}

func (device *Device) StartSender() {
	device.log.Verbosef("Sender: starting")
	device.StartRoutinesPool("sequential sender", 1, device.RoutineSequentialSender)
	device.StartRoutinesPool("encryption worker", runtime.NumCPU(), device.RoutineEncryptionWorker)
}

func (device *Device) StopSender() {
	device.log.Verbosef("Sender: stopping")
	device.StopRoutinesPool("encryption worker", runtime.NumCPU())
	device.StopRoutinesPool("sequential sender", 1)
}
