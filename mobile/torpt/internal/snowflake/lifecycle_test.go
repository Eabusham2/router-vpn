package snowflake_client

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v4"
)

type unopenedNetwork struct {
	transport.Net
	queries atomic.Int32
	closes  atomic.Int32
	entered chan struct{}
}

func (n *unopenedNetwork) ResolveUDPAddr(string, string) (*net.UDPAddr, error) {
	if n.queries.Add(1) == 1 {
		close(n.entered)
	}
	return nil, errors.New("unused client performed DNS")
}
func (n *unopenedNetwork) Close(context.Context) error { n.closes.Add(1); return nil }

func TestUnusedSnowflakeClientDoesNotStartNAT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	network := &unopenedNetwork{entered: make(chan struct{})}
	client, err := NewSnowflakeClient(ctx, ClientConfig{
		BrokerURL: "https://broker.example/", FrontDomains: []string{"front.example"},
		ICEAddresses:      []string{"stun:stun.example:3478"},
		BridgeFingerprint: "1111111111111111111111111111111111111111",
	}, network, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unused client dialed")
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-network.entered:
		t.Fatal("an unused Snowflake constructor started an unowned NAT lookup")
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	done := make(chan error, 1)
	go func() { _, err := client.Dial(); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled-before-Dial cleanup waited for an unstarted NAT worker")
	}
	if network.queries.Load() != 0 || network.closes.Load() != 1 {
		t.Fatal("unused canceled client touched its network or did not release it")
	}
}
