package torpt

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/transport/v4"
	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func TestSnowflakeSOCKSOwnerRetainsActualPendingDNS(t *testing.T) {
	plan, err := mobiletor.NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{
		"snowflake 192.0.2.8:443 0123456789ABCDEF0123456789ABCDEF01234567 fingerprint=0123456789ABCDEF0123456789ABCDEF01234567 url=https://broker.example/ front=front.example ice=stun:stun.example:3478",
	}})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	var active, physicalDials atomic.Int32
	free := func() { releaseOnce.Do(func() { close(release) }) }
	defer free()
	owner, err := StartWithNetwork(context.Background(), plan,
		func(context.Context, string, string) (net.Conn, error) {
			physicalDials.Add(1)
			return nil, errors.New("fixture forbids an uncanceled broker dial")
		}, func(ctx context.Context, kind, address string) (net.PacketConn, error) {
			return (&net.ListenConfig{}).ListenPacket(ctx, kind, address)
		}, NetworkOptions{Interfaces: []*transport.Interface{}, Resolve: func(context.Context, string, string) ([]netip.Addr, error) {
			active.Add(1)
			defer active.Add(-1)
			once.Do(func() { close(entered) })
			<-release // Model a real native resolver that is slow to honor cancellation.
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { free(); closeBridges(t, owner) }()
	client, response := openPT(t, owner.Listeners()["snowflake"], plan.Bridges[0])
	defer client.Close()
	if response != 0 {
		t.Fatal("the captured Snowflake PT factory did not accept its exact frozen bridge")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the real Snowflake owner did not use the supplied resolver")
	}
	bounded, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := owner.Close(bounded); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unfinished actual DNS was not retained by bridge close: %v", err)
	}
	select {
	case <-owner.Done():
		t.Fatal("bridge owner released a still-running Snowflake DNS worker")
	default:
	}
	if active.Load() == 0 {
		t.Fatal("fixture no longer holds actual DNS work")
	}
	free()
	closeBridges(t, owner)
	if active.Load() != 0 || physicalDials.Load() != 0 {
		t.Fatal("late DNS escaped into a new broker dial or did not drain")
	}
}
