package mobiletor

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type desktopSocketObservationHostileError struct{}

func (desktopSocketObservationHostileError) Error() string {
	panic("diagnostics invoked foreign error text")
}

func TestDesktopSocketAdmissionObservationRetainsOriginal(t *testing.T) {
	capture := desktopSocketFixtureCapture()
	owner := DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: strings.Repeat("a", 64), Generation: 9, ProcessID: 41}
	broker := &DesktopSocketBroker{capture: capture, sockets: make(map[*desktopSocket]struct{})}
	remote := netip.MustParseAddrPort("192.0.2.11:443")
	parentPeer := &desktopSocketPeer{request: DesktopSocketGrant{Sequence: 5}, receipt: DesktopSocketReceipt{Grant: DesktopSocketGrant{Sequence: 5}, ObservedAt: 1234, ExpiresAt: 4321}, valid: true}
	parent := &desktopSocket{broker: broker, id: "original-control", binding: DesktopSocketBinding{Owner: owner}, remote: remote, peers: map[netip.AddrPort]*desktopSocketPeer{remote: parentPeer}}
	peer := &desktopSocketPeer{request: DesktopSocketGrant{Sequence: 4}, receipt: DesktopSocketReceipt{Grant: DesktopSocketGrant{Sequence: 3}, ObservedAt: 2345, ExpiresAt: 5432}, valid: true, applying: true}
	original := &desktopSocket{broker: broker, id: "original-relay", binding: DesktopSocketBinding{Owner: owner}, remote: remote, peers: map[netip.AddrPort]*desktopSocketPeer{remote: peer}, parent: parent}
	broker.sockets[original] = struct{}{}
	original.recordAdmissionLoss("grant-readback", peer, syscall.EACCES)
	loss := original.admission.first.Load()
	if loss == nil || loss.request != 4 || loss.receipt != 3 || loss.observed != 2345 || loss.expires != 5432 || !loss.valid || !loss.applying ||
		loss.parentReceipt != 5 || loss.parentObserved != 1234 || loss.parentExpires != 4321 || !loss.parentValid || loss.failure.errno != uint64(syscall.EACCES) {
		t.Fatal("original admission observation lost its captured peer or parent")
	}
	want := *loss
	delete(broker.sockets, original)
	replacementOwner := owner
	replacementOwner.Generation++
	replacement := &desktopSocket{broker: broker, id: original.id, binding: DesktopSocketBinding{Owner: replacementOwner}, remote: remote, peers: map[netip.AddrPort]*desktopSocketPeer{}}
	broker.sockets[replacement] = struct{}{}
	peer.mu.Lock()
	peer.valid, peer.applying, peer.request.Sequence, peer.receipt.ObservedAt = false, false, 99, 9999
	peer.mu.Unlock()
	parentPeer.mu.Lock()
	parentPeer.valid, parentPeer.receipt.ObservedAt = false, 9999
	parentPeer.mu.Unlock()
	var joined sync.WaitGroup
	for range 16 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			original.recordAdmissionLoss("exchange", nil, desktopSocketObservationHostileError{})
		}()
	}
	joined.Wait()
	if got := original.admission.first.Load(); got == nil || *got != want || replacement.admission.first.Load() != nil {
		t.Fatal("stale original observation changed its first loss or the replacement owner")
	}
	if loss.owner == desktopSocketObservationOwner(broker.capture, replacementOwner, original.id) || loss.owner == loss.parent {
		t.Fatal("diagnostic identity conflated replacement, parent and original relay")
	}
	text := loss.String()
	for _, secret := range []string{capture.SessionID, capture.SourceSHA256, capture.NetworkID, owner.IdentitySHA256, original.id, parent.id, remote.String()} {
		if strings.Contains(text, secret) {
			t.Fatal("diagnostic exposed captured raw identity or address")
		}
	}
}

func TestDesktopSocketAdmissionObservationActualRetirement(t *testing.T) {
	for _, phase := range []string{"grant-readback", "receipt-expired"} {
		t.Run(phase, func(t *testing.T) {
			endpoint, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer endpoint.Close()
			policy := desktopSocketFixturePolicy()
			policy.grant = func(_ context.Context, request DesktopSocketGrant, receipt DesktopSocketReceipt) (DesktopSocketReceipt, error) {
				if request.Sequence > 1 && phase == "grant-readback" {
					return DesktopSocketReceipt{}, syscall.EACCES
				}
				return receipt, nil
			}
			broker, err := NewDesktopSocketBroker(context.Background(), desktopSocketFixtureCapture(), policy, func() bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := broker.Close(ctx); err != nil {
					t.Error("diagnostic fixture retained its actual original socket", err)
				}
			}()
			connection, err := broker.DialContext(context.Background(), "udp4", endpoint.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			socket := connection.(*desktopConnectedPacket).packet.socket
			socket.mu.Lock()
			peer := socket.peers[socket.remote]
			socket.mu.Unlock()
			if phase == "grant-readback" {
				peer.op.Lock()
				failure := socket.apply(context.Background(), peer)
				peer.op.Unlock()
				if failure == nil {
					t.Fatal("actual failed renewal was admitted")
				}
			} else {
				peer.mu.Lock()
				peer.receipt.ObservedAt = time.Now().Add(-2 * DesktopSocketReadbackAge).UnixMilli()
				peer.mu.Unlock()
				socket.refresh()
			}
			select {
			case <-socket.done:
			case <-time.After(time.Second):
				t.Fatal("observed original retirement did not join")
			}
			loss := socket.admission.first.Load()
			if loss == nil || loss.phase != phase || loss.receipt != 1 || !loss.valid || loss.owner != desktopSocketObservationOwner(broker.capture, socket.binding.Owner, socket.id) {
				t.Fatal("actual retirement lost its first original admission evidence")
			}
			// The controlled adapter returns a joined error. The diagnostic's
			// bounded classifier deliberately does not invoke arbitrary Unwrap.
			if phase == "grant-readback" && (loss.request != 2 || !loss.applying || loss.failure.class != 5) {
				t.Fatal("failed actual renewal lost its attempted and acknowledged sequences")
			}
			if _, err := connection.Write([]byte("retired")); err == nil {
				t.Fatal("observation reopened retired admission")
			}
			broker.mu.Lock()
			_, retained := broker.sockets[socket]
			broker.mu.Unlock()
			if retained {
				t.Fatal("joined original diagnostic retained broker authority")
			}
		})
	}
}

func TestDesktopDarwinReadbackObservationCapturesOriginalRequest(t *testing.T) {
	for _, phase := range []uint32{desktopNativeObservationQueued, desktopNativeObservationPath, desktopNativeObservationStart, desktopNativeObservationWait, desktopNativeObservationLibinfo} {
		t.Run([]string{"queued", "path", "start", "wait", "libinfo"}[phase], func(t *testing.T) {
			capture := desktopSocketFixtureCapture()
			owner := DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: strings.Repeat("a", 64), Generation: 7, ProcessID: 41}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := desktopDarwinObserveRequest(ctx, capture, owner, 12, "probe")
			received := make(chan desktopDarwinReadbackSnapshot, 1)
			observation, finish := desktopDarwinObserveReadback(original, "dscl", func(snapshot desktopDarwinReadbackSnapshot) { received <- snapshot })
			observation.enter(phase, 61)
			owner.Generation, owner.ProcessID = 8, 42
			replacement := desktopDarwinObserveRequest(ctx, capture, owner, 13, "grant")
			other, finishOther := desktopDarwinObserveReadback(replacement, "secret-command", func(desktopDarwinReadbackSnapshot) { t.Error("completed replacement emitted an expiration") })
			other.enter(desktopNativeObservationWait, 62)
			finishOther()
			cancel()
			var snapshot desktopDarwinReadbackSnapshot
			select {
			case snapshot = <-received:
			case <-time.After(time.Second):
				t.Fatal("expired original readback omitted its in-progress phase")
			}
			finish()
			if snapshot.guardian != 41 || snapshot.sequence != 12 || snapshot.operation != "probe" || snapshot.command != 1 || snapshot.kind != "dscl" || snapshot.phase != phase || snapshot.child != 61 || snapshot.elapsed < 0 ||
				snapshot.owner == desktopSocketObservationOwner(capture, owner, "") {
				t.Fatal("pending diagnostic borrowed replacement owner or progress", snapshot)
			}
			for _, secret := range []string{capture.SessionID, capture.SourceSHA256, capture.NetworkID, owner.IdentitySHA256, "secret-command"} {
				if strings.Contains(snapshot.String(), secret) {
					t.Fatal("readback diagnostic exposed raw request data")
				}
			}
		})
	}
}

func TestDesktopDarwinReadbackObservationJoinsAndCannotAuthorize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = desktopDarwinObserveRequest(ctx, desktopSocketFixtureCapture(), DesktopSocketKernelOwner{ProcessID: 41}, 1, "secret-operation")
	entered, release := make(chan struct{}), make(chan struct{})
	observation, finish := desktopDarwinObserveReadback(ctx, "secret-executable", func(snapshot desktopDarwinReadbackSnapshot) {
		if snapshot.operation != "other" || snapshot.kind != "other" {
			t.Error("unrecognized diagnostic label escaped its bound")
		}
		close(entered)
		<-release
	})
	observation.enter(desktopNativeObservationWait, 51)
	cancel()
	<-entered
	joined := make(chan struct{})
	go func() { finish(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("operation returned before its own observation joined")
	default:
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("original diagnostic did not join")
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("diagnostic changed original cancellation")
	}
	if observation, done := desktopDarwinObserveReadback(context.Background(), "dscl", nil); observation != nil {
		t.Fatal("uncaptured operation acquired observation authority")
	} else {
		done()
	}
}

func TestDesktopDarwinCreatorObservationKeepsOriginalDeadline(t *testing.T) {
	for _, stage := range []struct {
		phase uint32
		name  string
	}{{desktopNativeObservationPath, "protected-path"}, {desktopNativeObservationStart, "start"},
		{desktopNativeObservationSend, "send"}, {desktopNativeObservationReceive, "receive"},
		{desktopNativeObservationAcknowledge, "acknowledge"}, {desktopNativeObservationWait, "wait"},
		{desktopNativeObservationAdopt, "adopt"}} {
		t.Run(stage.name, func(t *testing.T) {
			capture := desktopSocketFixtureCapture()
			owner := DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: strings.Repeat("b", 64), Generation: 9, ProcessID: 51}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			original := desktopDarwinObserveRequest(ctx, capture, owner, 14, "create")
			received := make(chan desktopDarwinReadbackSnapshot, 2)
			observation, finish := desktopDarwinObserveReadback(original, "creator", func(snapshot desktopDarwinReadbackSnapshot) { received <- snapshot })
			observation.enter(stage.phase, 71)
			cancel()
			// Finish immediately. Even if the timer callback has not run, the
			// original expired stage must be reported once and joined here.
			finish()
			select {
			case snapshot := <-received:
				if snapshot.operation != "create" || snapshot.kind != "creator" || snapshot.phase != stage.phase || snapshot.child != 71 || snapshot.guardian != 51 || snapshot.sequence != 14 || !strings.Contains(snapshot.String(), "phase="+stage.name+" ") {
					t.Fatal("creator diagnostic lost its original transfer stage", snapshot)
				}
				for _, secret := range []string{capture.SessionID, capture.SourceSHA256, capture.NetworkID, owner.IdentitySHA256} {
					if strings.Contains(snapshot.String(), secret) {
						t.Fatal("creator diagnostic exposed original private identity")
					}
				}
			default:
				t.Fatal("joined creator expiration omitted its original stage")
			}
			select {
			case <-received:
				t.Fatal("creator expiration was reported more than once")
			default:
			}
			if after, _ := original.Deadline(); after != deadline || original.Err() != context.Canceled {
				t.Fatal("creator diagnostic changed original deadline or cancellation")
			}
		})
	}
}
