package applexray

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestStreamEnforcesReadWriteDeadlinesAndOwnerCancellation(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}
	stream := NewStreamConn(ctx, upstream, addr)
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline not enforced", err)
	}
	_ = stream.SetReadDeadline(time.Time{})
	go func() { _, _ = peer.Write([]byte("okay")) }()
	data := make([]byte, 4)
	if _, err := io.ReadFull(stream, data); err != nil || string(data) != "okay" {
		t.Fatal("read reset broken", err)
	}
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if n, err := stream.Write(make([]byte, 256*1024)); !errors.Is(err, os.ErrDeadlineExceeded) || n >= 256*1024 {
		t.Fatal("write deadline not enforced", n, err)
	}
	cancel()
	wait(t, stream.done)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("unconsumed data survived owner cancellation")
	}
	if stream.RemoteAddr().String() != addr.String() {
		t.Fatal("payload destination identity lost")
	}
}
func TestStreamBidirectionalPayloadAndConcurrentClose(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()
	stream := NewStreamConn(context.Background(), upstream, peer.RemoteAddr())
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	data := bytes.Repeat([]byte("native"), 20000)
	done := make(chan error, 1)
	go func() {
		received := make([]byte, len(data))
		_, err := io.ReadFull(peer, received)
		if err == nil && !bytes.Equal(data, received) {
			err = errors.New("payload changed")
		}
		if err == nil {
			_, err = peer.Write(received)
		}
		done <- err
	}()
	if _, err := stream.Write(data); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(data))
	if _, err := io.ReadFull(stream, received); err != nil || !bytes.Equal(data, received) {
		t.Fatal("returned payload changed", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for n := 0; n < 20; n++ {
		group.Add(1)
		go func() { defer group.Done(); _ = stream.Close() }()
	}
	group.Wait()
	if _, err := stream.Write([]byte("late")); err == nil {
		t.Fatal("closed write accepted")
	}
}
