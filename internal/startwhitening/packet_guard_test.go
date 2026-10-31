package startwhitening

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type packetGuardCipher struct {
	net.PacketConn
	read  func([]byte) (int, net.Addr, error)
	write func([]byte, net.Addr) (int, error)
	close func() error
}

func (c *packetGuardCipher) ReadFrom(p []byte) (int, net.Addr, error) { return c.read(p) }
func (c *packetGuardCipher) WriteTo(p []byte, address net.Addr) (int, error) {
	return c.write(p, address)
}
func (c *packetGuardCipher) Close() error { return c.close() }

func TestPacketGuardAuthenticatesWholeDatagramBeforePlaintextTruncation(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	address := &net.UDPAddr{IP: net.ParseIP("192.0.2.99"), Port: 9999}
	good := bytes.Repeat([]byte{73}, 65535)
	var next func([]byte) (int, net.Addr, error)
	cipher := &packetGuardCipher{read: func(p []byte) (int, net.Addr, error) {
		if len(p) != 65535 {
			t.Errorf("ciphertext was truncated before authentication: %d", len(p))
			return 0, nil, io.ErrShortBuffer
		}
		return next(p)
	}, close: func() error { return nil }}
	guard := GuardAuthenticatedPacket(raw, func(net.Conn) net.PacketConn { return cipher })
	defer guard.Close()
	for _, size := range []int{0, 1, 47, 65535, 70000} {
		next = func(p []byte) (int, net.Addr, error) { return copy(p, good), address, nil }
		output := make([]byte, size)
		n, found, err := guard.ReadFrom(output)
		if err != nil || n != min(size, len(good)) || found != address || !bytes.Equal(output[:n], good[:n]) {
			t.Fatal("valid complete datagram lost bounded plaintext semantics", size, n, found, err)
		}
	}
	authFailure := errors.New("actual cipher rejected authentication")
	for _, bad := range []struct {
		n    int
		err  error
		want error
	}{{12, authFailure, authFailure}, {-1, nil, io.ErrShortBuffer}, {65536, nil, io.ErrShortBuffer}} {
		next = func(p []byte) (int, net.Addr, error) { copy(p, "untrusted"); return bad.n, address, bad.err }
		output := bytes.Repeat([]byte{9}, 32)
		n, _, err := guard.ReadFrom(output)
		if n != 0 || !errors.Is(err, bad.want) || !bytes.Equal(output, bytes.Repeat([]byte{9}, 32)) {
			t.Fatal("failed cipher exposed unauthenticated or out-of-bounds plaintext", n, err)
		}
	}
}

func TestPacketGuardCancellationJoinsDuplexCipherAndEveryClose(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	readEntered, writeEntered := make(chan struct{}), make(chan struct{})
	closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
	var reading, writing atomic.Bool
	var closed atomic.Int32
	cipher := &packetGuardCipher{
		read: func(p []byte) (int, net.Addr, error) {
			reading.Store(true)
			defer reading.Store(false)
			close(readEntered)
			n, err := raw.Read(p)
			return n, nil, err
		},
		write: func(p []byte, _ net.Addr) (int, error) {
			writing.Store(true)
			defer writing.Store(false)
			close(writeEntered)
			return raw.Write(p)
		},
		close: func() error {
			if reading.Load() || writing.Load() {
				t.Error("cipher close overlapped its still-running packet I/O")
			}
			closed.Add(1)
			close(closeEntered)
			<-closeRelease
			return nil
		},
	}
	guard := GuardAuthenticatedPacket(raw, func(net.Conn) net.PacketConn { return cipher })
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() { _, _, err := guard.ReadFrom(make([]byte, 1)); readDone <- err }()
	go func() { _, err := guard.WriteTo([]byte("packet"), nil); writeDone <- err }()
	<-readEntered
	<-writeEntered
	ctx, cancel := context.WithCancel(context.Background())
	first, second := make(chan error, 1), make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { first <- guard.Close() })
	defer stop()
	cancel()
	select {
	case <-closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt and join both exact socket directions")
	}
	go func() { second <- guard.Close() }()
	select {
	case <-first:
		t.Error("cancel owner returned before the cipher close joined")
	default:
	}
	select {
	case <-second:
		t.Error("another Close returned before the captured cipher close joined")
	default:
	}
	close(closeRelease)
	if <-first != nil || <-second != nil || <-readDone == nil || <-writeDone == nil || closed.Load() != 1 {
		t.Fatal("packet teardown lost idempotence, interruption, or joined ownership")
	}
	if n, _, err := guard.ReadFrom(make([]byte, 8)); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatal("retired packet owner accepted another read", n, err)
	}
	if n, err := guard.WriteTo([]byte("late"), nil); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatal("retired packet owner accepted another write", n, err)
	}
	if guard.scratch != nil {
		t.Fatal("joined packet owner retained plaintext storage")
	}
}

type packetGuardCloseSocket struct {
	net.Conn
	calls atomic.Int32
	err   error
}

func (c *packetGuardCloseSocket) Close() error { c.calls.Add(1); return c.err }

func TestPacketGuardCipherSharesOnePhysicalCloseWithoutLosingErrors(t *testing.T) {
	rawFailure, cipherFailure := errors.New("physical close failed"), errors.New("cipher release failed")
	raw := &packetGuardCloseSocket{err: rawFailure}
	var cipherCloses atomic.Int32
	guard := GuardAuthenticatedPacket(raw, func(owned net.Conn) net.PacketConn {
		if owned == raw {
			t.Fatal("cipher bypassed the retained idempotent socket")
		}
		return &packetGuardCipher{close: func() error { cipherCloses.Add(1); return errors.Join(owned.Close(), cipherFailure) }}
	})
	for range 2 {
		if err := guard.Close(); !errors.Is(err, rawFailure) || !errors.Is(err, cipherFailure) {
			t.Fatal("packet cleanup discarded an owned close failure", err)
		}
	}
	if raw.calls.Load() != 1 || cipherCloses.Load() != 1 {
		t.Fatal("packet owner repeated physical or cipher teardown")
	}
}
