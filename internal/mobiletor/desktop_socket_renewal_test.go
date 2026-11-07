package mobiletor

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only native PF/credential work is modeled. The shipping broker, FIFO,
// original TCP descriptors, receipt deadlines, cancellation and joined drain
// execute unchanged. Each modeled native operation costs less than the real
// two-second guardian bound; no fixture wait renews or extends a receipt.
type desktopRenewalFixture struct {
	*desktopSocketPolicyFixture
	control desktopSocketControlMutex
	groups  atomic.Int32
	maximum atomic.Int32
	cost    time.Duration
	sizes   chan int
}

func (p *desktopRenewalFixture) enter(ctx context.Context) (context.Context, func(), error) {
	if err := p.control.lockContext(ctx); err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, desktopSocketControlWait)
	return bounded, func() { cancel(); p.control.Unlock() }, nil
}

func desktopRenewalFixtureWait(ctx context.Context, cost time.Duration) error {
	timer := time.NewTimer(cost)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *desktopRenewalFixture) grantSocketAdmitted(ctx context.Context, grant DesktopSocketGrant) (DesktopSocketReceipt, error) {
	ctx, release, err := p.enter(ctx)
	if err != nil {
		return DesktopSocketReceipt{}, desktopSocketUnsubmittedGrant(grant, err)
	}
	defer release()
	started := time.Now()
	if grant.Sequence > 1 {
		if err := desktopRenewalFixtureWait(ctx, p.cost); err != nil {
			return DesktopSocketReceipt{}, err
		}
	}
	receipt, err := p.desktopSocketPolicyFixture.Grant(ctx, grant)
	receipt.ExpiresAt = started.Add(7 * time.Second).UnixMilli()
	return receipt, err
}

func (p *desktopRenewalFixture) revokeSocketAdmitted(ctx context.Context, grant DesktopSocketGrant) error {
	ctx, release, err := p.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	return p.desktopSocketPolicyFixture.Revoke(ctx, grant)
}

func (p *desktopRenewalFixture) renewSocketsAdmitted(ctx context.Context, members []desktopSocketRenewal) []desktopSocketRenewalResult {
	return desktopSocketControlRenewals(ctx, members, p.enter, func(ctx context.Context, requests []DesktopSocketGrant) ([]DesktopSocketReceipt, error) {
		p.groups.Add(1)
		if p.sizes != nil {
			p.sizes <- len(requests)
		}
		for old := p.maximum.Load(); int32(len(requests)) > old; old = p.maximum.Load() {
			if p.maximum.CompareAndSwap(old, int32(len(requests))) {
				break
			}
		}
		started := time.Now()
		if err := desktopRenewalFixtureWait(ctx, p.cost); err != nil {
			return nil, err
		}
		receipts := make([]DesktopSocketReceipt, len(requests))
		for index, request := range requests {
			receipt, err := p.desktopSocketPolicyFixture.Grant(ctx, request)
			if err != nil {
				return nil, err
			}
			receipt.ExpiresAt = started.Add(7 * time.Second).UnixMilli()
			receipts[index] = receipt
		}
		return receipts, nil
	})
}

func TestDesktopSocketRenewalGroupRetainsQueuedOriginalStreams(t *testing.T) {
	for _, count := range []int{8, desktopSocketRenewalLimit + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { desktopSocketRenewalStreams(t, count, 0) })
	}
	t.Run("staggered", func(t *testing.T) { desktopSocketRenewalStreams(t, 4, 100*time.Millisecond) })
}

func desktopSocketRenewalStreams(t *testing.T, count int, stagger time.Duration) {
	t.Helper()
	p := &desktopRenewalFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), cost: 650 * time.Millisecond, sizes: make(chan int, 32)}
	b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error("queued renewal did not join original owners", err)
		}
	})
	listener := desktopSocketListener(t)
	var peers sync.WaitGroup
	t.Cleanup(peers.Wait)
	connections := make([]net.Conn, 0, count)
	var first DesktopSocketReceipt
	var last DesktopSocketReceipt
	for index := range count {
		accepted := make(chan *net.TCPConn, 1)
		go func() { connection, _ := listener.AcceptTCP(); accepted <- connection }()
		connection, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		peer := desktopSocketAwait(t, accepted)
		if peer == nil {
			t.Fatal("original retained stream was never accepted")
		}
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer peer.Close()
			_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.Copy(peer, peer)
		}()
		socket := connection.(*desktopSocketConn).socket
		socket.mu.Lock()
		member := socket.peers[socket.remote]
		socket.mu.Unlock()
		receipt, valid := member.snapshot()
		if !valid {
			t.Fatal("fixture did not capture an original grant")
		}
		if first == (DesktopSocketReceipt{}) {
			first = receipt
		}
		last = receipt
		if stagger != 0 && index+1 < count {
			_ = desktopRenewalFixtureWait(context.Background(), stagger)
		}
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	// Establish two foreground FIFO owners before the unchanged monitor's
	// renewal point. Their actual queue ownership, not a sleep in Grant, proves
	// that the renewal may not jump another already queued request.
	if err := desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(first.ObservedAt).Add(1700*time.Millisecond))); err != nil {
		t.Fatal(err)
	}
	p.control.Lock()
	var releaseOnce sync.Once
	releaseControl := func() { releaseOnce.Do(p.control.Unlock) }
	defer releaseControl()
	foreground := make(chan int, 2)
	for index := range 2 {
		go func() {
			ctx, release, err := p.enter(context.Background())
			if err == nil {
				err = desktopRenewalFixtureWait(ctx, 300*time.Millisecond)
				release()
			}
			if err != nil {
				foreground <- -1
				return
			}
			foreground <- index
		}()
		desktopSocketAwaitControlQueue(t, &p.control, index+1)
	}
	queuedUntil := time.Now().Add(time.Second)
	for {
		p.control.mu.Lock()
		queued := len(p.control.waiters)
		p.control.mu.Unlock()
		if queued >= 3 {
			break
		}
		if time.Now().After(queuedUntil) {
			t.Fatal("renewal never entered the captured foreground queue")
		}
		time.Sleep(time.Millisecond)
	}
	// Later receipts become due while the first original group is still
	// queued. They must remain unsubmitted until it joins, then coalesce into
	// the next captured group instead of filling this FIFO with singleton jobs.
	_ = desktopRenewalFixtureWait(context.Background(), 450*time.Millisecond)
	p.control.mu.Lock()
	queued := len(p.control.waiters)
	p.control.mu.Unlock()
	if queued != 3 {
		t.Fatal("staggered renewal accumulated independent queued groups", queued)
	}
	releaseControl()
	for expected := range 2 {
		if actual := desktopSocketAwait(t, foreground); actual != expected {
			t.Fatal("renewal changed original foreground FIFO ownership", actual, expected)
		}
	}
	// Exercise real bytes after the original five-second readback has ended.
	// The old per-peer path expires later queued owners even though every
	// admitted native operation is itself comfortably within two seconds.
	_ = desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(last.ObservedAt).Add(5250*time.Millisecond)))
	for index, connection := range connections {
		socket := connection.(*desktopSocketConn).socket
		if !socket.allowed(socket.remote) {
			t.Fatalf("queued original stream lost its acknowledged readback at member %d: %v", index, socket.admission.first.Load())
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write([]byte{byte(index + 1)}); err != nil {
			t.Fatal("renewed original descriptor could not write", err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(connection, reply[:]); err != nil || reply[0] != byte(index+1) {
			t.Fatal("renewal changed the retained byte path", index, reply, err)
		}
	}
	minimumGroup := int32(4)
	if stagger != 0 {
		minimumGroup = 2
		firstSize, nextSize := desktopSocketAwait(t, p.sizes), desktopSocketAwait(t, p.sizes)
		if firstSize >= count || nextSize < 2 || firstSize+nextSize != count {
			t.Fatal("later original receipts did not coalesce after their preceding group joined", firstSize, nextSize)
		}
	}
	if p.groups.Load() == 0 || p.maximum.Load() < minimumGroup {
		t.Fatal("queued proof did not execute a bounded group of original peers")
	}
	if count > desktopSocketRenewalLimit && p.groups.Load() < 2 {
		t.Fatal("renewal did not execute its separate capacity rollover group")
	}
	if p.maximum.Load() > desktopSocketRenewalLimit {
		t.Fatal("renewal exceeded its captured native frame bound")
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil || p.count() != 0 {
		t.Fatal("grouped native renewal failed joined exact retirement", err, p.count())
	}
}

var _ desktopSocketRenewalPolicy = (*desktopRenewalFixture)(nil)
var _ desktopSocketAdmittedPolicy = (*desktopRenewalFixture)(nil)
