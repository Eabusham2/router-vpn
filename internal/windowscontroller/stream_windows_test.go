//go:build windows

package windowscontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

func actualBinaryPipes(t *testing.T) (*Pipe, *Pipe) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	server, err := NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(ctx) }()
	client, err := DialPipe(ctx, server.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	self, err := OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	image, err := PinImage(fixtureExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	peer, err := client.VerifyPeer(self, image)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Process.Close(); err != nil {
		t.Fatal(err)
	}
	hello := []byte("RouterVPN-UI-Bridge-v1\n")
	written := make(chan error, 1)
	go func() { written <- client.WriteFrame(ctx, hello) }()
	actual, err := server.ReadFrame(ctx)
	if err != nil || !bytes.Equal(actual, hello) {
		t.Fatal("binary channel lost its bounded public hello", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	peer, err = server.VerifyPeer(self, image)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Identity.Primary {
		t.Error("binary channel writer escaped identification-only proof")
	}
	if err := peer.Process.Close(); err != nil {
		t.Fatal(err)
	}
	return server, client
}

func TestWindowsControllerStreamActualBinaryChunks(t *testing.T) {
	server, client := actualBinaryPipes(t)
	body := bytes.Repeat([]byte{0, '\n', '\r', '\\', 0xff, 0xc3, 0xa9, '"'}, 32768)
	want := sha256.Sum256(body)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	written := make(chan error, 1)
	go func() {
		remaining := body
		for len(remaining) > 0 {
			count := len(remaining)
			if count > 4096 {
				count = 4096
			}
			n, err := client.WriteContext(ctx, remaining[:count])
			if err != nil {
				written <- err
				return
			}
			remaining = remaining[n:]
		}
		written <- nil
	}()
	result := make([]byte, len(body))
	remaining := result
	for len(remaining) > 0 {
		count := len(remaining)
		if count > 4096 {
			count = 4096
		}
		n, err := server.ReadContext(ctx, remaining[:count])
		if err != nil {
			t.Fatal("actual binary pipe read failed", err)
		}
		remaining = remaining[n:]
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(result) != want {
		t.Fatal("actual binary pipe altered newlines, NULs or UTF-8 bytes")
	}
	// No binary read may consume a future protocol byte beyond its exact slice.
	go func() { _, err := client.WriteContext(ctx, []byte{'a', 'b'}); written <- err }()
	var next [1]byte
	if n, err := server.ReadContext(ctx, next[:]); err != nil || n != 1 || next[0] != 'a' {
		t.Fatal("binary chunk overread its captured slice", err)
	}
	if n, err := server.ReadContext(ctx, next[:]); err != nil || n != 1 || next[0] != 'b' {
		t.Fatal("binary chunk consumed the next frame byte", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestWindowsControllerStreamBoundsAndCancellation(t *testing.T) {
	server, client := actualBinaryPipes(t)
	for _, body := range [][]byte{nil, make([]byte, 4097)} {
		if _, err := server.ReadContext(context.Background(), body); err == nil {
			t.Fatal("unbounded native binary read was admitted")
		}
		if _, err := client.WriteContext(context.Background(), body); err == nil {
			t.Fatal("unbounded native binary write was admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.ReadContext(ctx, make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled binary read entered another owner", err)
	}
	if _, err := client.WriteContext(ctx, []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled binary write entered another owner", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if _, err := server.ReadContext(bounded, make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("binary channel did not observe exact peer closure", err)
	}
}

func TestWindowsControllerStreamCloseJoinsBorrowedWriter(t *testing.T) {
	server, _ := actualBinaryPipes(t)
	// Hold a real entered ownership borrow independently of OS scheduling; the
	// same Close must retain its actual native handle until it joins this owner.
	handle, release, err := server.borrow(true)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	t.Cleanup(func() { once.Do(release) })
	done := make(chan error, 1)
	go func() { done <- server.Close() }()
	select {
	case err := <-done:
		t.Fatal("binary channel closed its native handle before the captured borrow joined", err)
	case <-time.After(50 * time.Millisecond):
	}
	if handle == 0 {
		t.Fatal("captured binary writer lost its native handle")
	}
	once.Do(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := server.WriteContext(context.Background(), []byte{1}); !errors.Is(err, ErrClosed) {
		t.Fatal("retired binary channel admitted another write", err)
	}
}
