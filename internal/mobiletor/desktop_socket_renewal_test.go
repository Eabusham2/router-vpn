package mobiletor

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
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
	batches chan []DesktopSocketGrant
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
		if p.batches != nil {
			p.batches <- slices.Clone(requests)
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
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			desktopSocketRenewalStreams(t, count, 0, 650*time.Millisecond, 300*time.Millisecond)
		})
	}
	t.Run("staggered", func(t *testing.T) {
		desktopSocketRenewalStreams(t, 4, 100*time.Millisecond, 650*time.Millisecond, 300*time.Millisecond)
	})
	t.Run("staggered-slow-native", func(t *testing.T) {
		desktopSocketRenewalStreams(t, 4, 100*time.Millisecond, 1200*time.Millisecond, 300*time.Millisecond)
	})
	t.Run("native-fifo-work", func(t *testing.T) {
		desktopSocketRenewalStreams(t, 4, 100*time.Millisecond, 1200*time.Millisecond, 900*time.Millisecond)
	})
}

func desktopSocketRenewalStreams(t *testing.T, count int, stagger, cost, foregroundCost time.Duration) {
	t.Helper()
	if cost >= desktopSocketNativeWork || foregroundCost >= desktopSocketNativeWork {
		t.Fatal("fixture service work must fit the actual guardian operation bound")
	}
	p := &desktopRenewalFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), cost: cost, sizes: make(chan int, 32)}
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
	if err := desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(first.ObservedAt).Add(DesktopSocketReadbackAge-desktopSocketRenewalLead-300*time.Millisecond))); err != nil {
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
				err = desktopRenewalFixtureWait(ctx, foregroundCost)
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
	queuedUntil := time.UnixMilli(first.ObservedAt).Add(3 * time.Second)
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
	// queued. Already acknowledged members must share its captured native
	// transaction instead of filling this FIFO with singleton jobs or waiting
	// for a second transaction that can outlive their original five-second age.
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
		firstSize := desktopSocketAwait(t, p.sizes)
		if firstSize != count {
			t.Fatal("already acknowledged siblings did not share the original captured renewal", firstSize, count)
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

func TestDesktopSocketRenewalSchedulingFitsOriginalReadback(t *testing.T) {
	if desktopSocketRenewalLead >= DesktopSocketReadbackAge || desktopSocketNativeWork >= desktopSocketControlWait {
		t.Fatal("native work and polling no longer fit the original receipt/control bounds")
	}
}

func TestDesktopSocketRenewalQueuedWorkCannotExtendReceipt(t *testing.T) {
	p := &desktopRenewalFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), cost: 1200 * time.Millisecond}
	b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil || p.count() != 0 {
			t.Error("over-capacity renewal lost exact joined retirement", err, p.count())
		}
	})
	listener := desktopSocketListener(t)
	connection := desktopSOCKSPrivateControl(t, b, listener)
	defer connection.Close()
	socket := connection.(*desktopSocketConn).socket
	socket.mu.Lock()
	peer := socket.peers[socket.remote]
	socket.mu.Unlock()
	original, valid := peer.snapshot()
	if !valid {
		t.Fatal("pressure fixture lost its initial acknowledged socket")
	}
	// Each foreground operation fits the unchanged native work limit. Their
	// combined queue plus renewal exceeds the original five-second receipt.
	// Earlier scheduling cannot turn this excess service work into authority.
	p.control.Lock()
	var once sync.Once
	release := func() { once.Do(p.control.Unlock) }
	defer release()
	foreground := make(chan int, 2)
	for index := range 2 {
		go func() {
			ctx, done, err := p.enter(context.Background())
			if err == nil {
				err = desktopRenewalFixtureWait(ctx, desktopSocketNativeWork-100*time.Millisecond)
				done()
			}
			if err != nil {
				foreground <- -1
			} else {
				foreground <- index
			}
		}()
		desktopSocketAwaitControlQueue(t, &p.control, index+1)
	}
	desktopSocketAwaitControlQueue(t, &p.control, 3)
	_ = desktopRenewalFixtureWait(context.Background(), 450*time.Millisecond)
	release()
	for index := range 2 {
		if actual := desktopSocketAwait(t, foreground); actual != index {
			t.Fatal("renewal displaced an earlier original FIFO owner", actual, index)
		}
	}
	_ = desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(original.ObservedAt).Add(5250*time.Millisecond)))
	if socket.allowed(socket.remote) {
		t.Fatal("excess queued work extended an acknowledged receipt")
	}
	if _, err := connection.Write([]byte("expired-original")); err == nil {
		t.Fatal("queued renewal retained successful original data I/O after expiry")
	}
	receipt, _ := peer.snapshot()
	if receipt != original {
		t.Fatal("a queued transaction fabricated a fresh receipt")
	}
}

func TestDesktopSocketRenewalDoesNotAddAcknowledgementWhileQueued(t *testing.T) {
	p := &desktopRenewalFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), cost: 250 * time.Millisecond, sizes: make(chan int, 16)}
	b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	listener := desktopSocketListener(t)
	var workers sync.WaitGroup
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Close(ctx); err != nil {
			t.Error("late acknowledgement lost original joined retirement", err)
		}
		_ = listener.Close()
		workers.Wait()
	})
	accept := func() <-chan *net.TCPConn {
		accepted := make(chan *net.TCPConn, 1)
		go func() { connection, _ := listener.AcceptTCP(); accepted <- connection }()
		return accepted
	}
	echo := func(accepted <-chan *net.TCPConn) {
		peer := desktopSocketAwait(t, accepted)
		if peer == nil {
			t.Fatal("original TCP stream was not accepted")
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer peer.Close()
			_ = peer.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.Copy(peer, peer)
		}()
	}
	accepted := accept()
	first, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	echo(accepted)
	socket := first.(*desktopSocketConn).socket
	socket.mu.Lock()
	peer := socket.peers[socket.remote]
	socket.mu.Unlock()
	original, _ := peer.snapshot()
	_ = desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(original.ObservedAt).Add(DesktopSocketReadbackAge-desktopSocketRenewalLead-300*time.Millisecond)))
	p.control.Lock()
	var once sync.Once
	release := func() { once.Do(p.control.Unlock) }
	defer release()
	type dialResult struct {
		connection net.Conn
		err        error
	}
	accepted = accept()
	connected := make(chan dialResult, 1)
	go func() {
		connection, err := b.DialContext(context.Background(), "tcp", listener.Addr().String())
		connected <- dialResult{connection, err}
	}()
	// Its first grant is ahead of renewal in the actual FIFO, but is still
	// unacknowledged when the monitor captures the existing original peer.
	desktopSocketAwaitControlQueue(t, &p.control, 1)
	desktopSocketAwaitControlQueue(t, &p.control, 2)
	release()
	second := desktopSocketAwait(t, connected)
	if second.err != nil || second.connection == nil {
		t.Fatal("queued original initial grant did not join", second.err)
	}
	defer second.connection.Close()
	echo(accepted)
	if size := desktopSocketAwait(t, p.sizes); size != 1 {
		t.Fatal("queued native renewal adopted a later acknowledgement", size)
	}
	_ = desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(original.ObservedAt).Add(5250*time.Millisecond)))
	for index, connection := range []net.Conn{first, second.connection} {
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write([]byte{byte(index + 1)}); err != nil {
			t.Fatal("separately captured original stream could not write", err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(connection, reply[:]); err != nil || reply[0] != byte(index+1) {
			t.Fatal("late member changed an original stream", index, reply, err)
		}
	}
	if p.groups.Load() < 2 {
		t.Fatal("later acknowledgement never entered a separate captured renewal")
	}
}

func TestDesktopSocketRenewalDueAssociationPrecedesFreshRoots(t *testing.T) {
	for _, parentDue := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent-due-%t", parentDue), func(t *testing.T) {
			listener := desktopSocketListener(t)
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = packet.Close() })
			p := &desktopRenewalFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy(), batches: make(chan []DesktopSocketGrant, 16)}
			b, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), p, func() bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := b.Close(ctx); err != nil || p.count() != 0 {
					t.Error("capacity proof lost joined exact ownership", err, p.count())
				}
			})
			// Hold only the broker's single renewal slot during setup. Its real
			// monitor still inspects every receipt under the original age bound.
			b.mu.Lock()
			b.renewing = true
			b.mu.Unlock()
			var once sync.Once
			release := func() {
				once.Do(func() {
					b.mu.Lock()
					b.renewing = false
					b.mu.Unlock()
				})
			}
			defer release()
			control := desktopSOCKSPrivateControl(t, b, listener)
			defer control.Close()
			relay, err := b.DialContext(context.Background(), "udp", packet.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			parent := control.(*desktopSocketConn).socket
			child := relay.(*desktopConnectedPacket).packet.socket
			// Model only the association's already-established native ownership.
			// Its initial private-address attachment is covered by the separate
			// SOCKS tests; this capacity case uses actual loopback descriptors so
			// the renewal and byte-path regression needs no physical interface.
			// The held broker slot excludes every renewal read of this link.
			b.mu.Lock()
			parent.mu.Lock()
			parent.socksClaimed = true
			parent.children = map[*desktopSocket]struct{}{child: {}}
			child.parent = parent
			parent.mu.Unlock()
			b.mu.Unlock()
			desktopSOCKSPrivateExchange(t, relay, packet)
			child.mu.Lock()
			childPeer := child.peers[child.remote]
			child.mu.Unlock()
			original, valid := childPeer.snapshot()
			if !valid {
				t.Fatal("actual UDP member lost its original acknowledgement")
			}
			// A genuine later parent readback makes the child's deadline earlier.
			// Cover both a still-due parent and a fresh parent at group capture.
			parentAt := 2200 * time.Millisecond
			if parentDue {
				parentAt = 100 * time.Millisecond
			}
			_ = desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(original.ObservedAt).Add(parentAt)))
			parent.mu.Lock()
			parentPeer := parent.peers[parent.remote]
			parent.mu.Unlock()
			parentPeer.op.Lock()
			err = parent.apply(context.Background(), parentPeer)
			parentPeer.op.Unlock()
			if err != nil {
				t.Fatal("original parent renewal failed", err)
			}
			_ = desktopRenewalFixtureWait(context.Background(), time.Until(time.UnixMilli(original.ObservedAt).Add(2200*time.Millisecond)))
			for range desktopSocketRenewalLimit {
				fresh := desktopSOCKSPrivateControl(t, b, listener)
				defer fresh.Close()
			}
			release()
			batch := desktopSocketAwait(t, p.batches)
			childIndex, parentIndex := -1, -1
			for index, request := range batch {
				if request.SocketID == child.id {
					childIndex = index
				}
				if request.SocketID == parent.id {
					parentIndex = index
				}
			}
			if childIndex < 0 {
				t.Fatal("due derived UDP peer was omitted behind fresh roots", len(batch))
			}
			if len(batch) > desktopSocketRenewalLimit || parentDue && parentIndex < 0 || parentIndex >= childIndex {
				t.Fatal("bounded renewal lost parent-before-child native ownership", len(batch), parentIndex, childIndex)
			}
			until := time.Now().Add(time.Second)
			for {
				receipt, valid := childPeer.snapshot()
				if valid && receipt.Grant.Sequence > original.Grant.Sequence {
					break
				}
				if time.Now().After(until) {
					t.Fatal("selected derived peer never acknowledged its exact renewal", child.admission.first.Load())
				}
				time.Sleep(time.Millisecond)
			}
			desktopSOCKSPrivateExchange(t, relay, packet)
		})
	}
}

var _ desktopSocketRenewalPolicy = (*desktopRenewalFixture)(nil)
var _ desktopSocketAdmittedPolicy = (*desktopRenewalFixture)(nil)
