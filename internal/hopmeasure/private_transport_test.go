package hopmeasure

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

type privateLateDialEngine struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (e privateLateDialEngine) Identity() string { return "owned-private-native-generation" }
func (e privateLateDialEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	return e.dial(ctx, tag, address)
}

func TestPrivateCancellationDrainsIgnoredNativeDialAndActualClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	closeStarted, closeRelease := make(chan struct{}), make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	engine := privateLateDialEngine{dial: func(_ context.Context, tag, address string) (net.Conn, error) {
		if tag != "external-entry" || address != "10.77.0.1:8787" {
			t.Error("private probe escaped captured route")
		}
		close(entered)
		<-release
		return &publicGateConn{Conn: left, closeStarted: closeStarted, closeRelease: closeRelease}, nil
	}}
	s, err := New(engine, []Hop{{ID: "captured-entry", Role: "entry", Tag: "external-entry", Kind: "private-node", API: "http://10.77.0.1:8787", Token: "private-token", Proof: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := strings.Repeat("d", 32)
	if err = s.Start(id, 65536); err != nil {
		t.Fatal(err)
	}
	<-entered
	s.Cancel(id)
	drained := make(chan error, 1)
	go func() { drained <- s.Drain(id) }()
	select {
	case err := <-drained:
		t.Fatal("private native dial escaped drain", err)
	case <-time.After(15 * time.Millisecond):
	}
	close(release)
	<-closeStarted
	select {
	case err := <-drained:
		t.Fatal("private native close escaped drain", err)
	case <-time.After(15 * time.Millisecond):
	}
	close(closeRelease)
	if err = <-drained; err != nil {
		t.Fatal(err)
	}
	var status Status
	if json.Unmarshal([]byte(s.StatusJSON()), &status) != nil || !status.Drained || len(status.Results) != 0 {
		t.Fatal("cancelled private metrics survived drain", status)
	}
}
