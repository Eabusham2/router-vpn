package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestProtectedTCPTransfersDialContextToEstablishedSocket(t *testing.T) {
	type valueKey struct{}
	caller, cancelCaller := context.WithTimeout(context.WithValue(context.Background(), valueKey{}, "captured-route"), time.Hour)
	defer cancelCaller()
	client, peer := net.Pipe()
	defer peer.Close()
	var captured context.Context
	network, err := NewNetwork(context.Background(), func(ctx context.Context, _, _ string) (net.Conn, error) {
		captured = ctx
		if value := ctx.Value(valueKey{}); value != "captured-route" {
			t.Fatal("native transport lost caller routing values", value)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("pending native dial lost its caller deadline")
		}
		return client, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close(context.Background())
	connection, err := network.DialContext(caller, "tcp", "bridge.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if captured.Err() != nil {
		t.Fatal("successful native dial canceled its established stream context", captured.Err())
	}
	cancelCaller()
	if captured.Err() != nil {
		t.Fatal("retired dial caller canceled an established native stream", captured.Err())
	}
	if _, ok := captured.Deadline(); ok {
		t.Fatal("established stream retained a retired dial deadline")
	}
	done := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("owned")); done <- err }()
	data := make([]byte, 5)
	if _, err := io.ReadFull(connection, data); err != nil || string(data) != "owned" {
		t.Fatal("established transport could not carry data", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(captured.Err(), context.Canceled) {
		t.Fatal("socket close left native transport context alive", captured.Err())
	}
}

func TestProtectedPacketsRetainContextUntilSessionDrain(t *testing.T) {
	caller, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()
	packet := &packetFixture{closed: make(chan struct{})}
	var captured context.Context
	network, err := NewNetwork(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("TCP is outside this packet lifetime fixture")
	}, func(ctx context.Context, _, _ string) (net.PacketConn, error) {
		captured = ctx
		return packet, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close(context.Background())
	if _, err = network.ListenPacket(caller, "udp", "0.0.0.0:0"); err != nil {
		t.Fatal(err)
	}
	if captured.Err() != nil {
		t.Fatal("successful packet dial canceled its native transport context", captured.Err())
	}
	cancelCaller()
	if captured.Err() != nil {
		t.Fatal("retired packet caller canceled an established native transport", captured.Err())
	}
	if err = network.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(captured.Err(), context.Canceled) {
		t.Fatal("session drain left native packet context alive", captured.Err())
	}
	select {
	case <-packet.closed:
	default:
		t.Fatal("session drain left native packet socket alive")
	}
}
