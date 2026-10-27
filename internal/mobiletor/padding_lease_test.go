//go:build go1.25

package mobiletor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// This peer implements the wire boundary, including monotonic native expiry
// and ciphertext that can remain pending after STOP. No public network or
// fabricated native traffic is used as evidence: the C circuit tests separately
// exercise encryption and actual Tor queues. Here the real Go lease/control
// reader must own and validate those receipts under cancellation and time.
type paddingLeasePeer struct {
	mu         sync.Mutex
	control    *Control
	peer       net.Conn
	done       chan struct{}
	actions    []string
	grants     []time.Time
	high       uint64
	identity   PaddingIdentity
	rate       int
	expires    time.Time
	state      string
	channel    uint64
	initial    uint64
	advance    bool
	holdStop   bool
	pending    uint64
	delay      time.Duration
	startGate  chan struct{}
	gateAction string
	corrupt    func(string, string) string
}

func newPaddingLeasePeer(t *testing.T) *paddingLeasePeer {
	t.Helper()
	client, peer := net.Pipe()
	control, _ := NewControl(client)
	p := &paddingLeasePeer{control: control, peer: peer, done: make(chan struct{}), high: 6, advance: true, initial: 1}
	go func() {
		defer close(p.done)
		defer peer.Close()
		reader := bufio.NewReader(peer)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "SETCONF" {
				if _, err := io.WriteString(peer, "250 OK\r\n"); err != nil {
					return
				}
				continue
			}
			if len(fields) < 2 || fields[0] != "ROUTERVPN_PADDING" {
				t.Error("unexpected control family")
				return
			}
			action := fields[1]
			p.mu.Lock()
			p.actions = append(p.actions, action)
			if action == "INFO" {
				reply := paddingTestReplace(paddingTestCapability, "generation_highwater", strconv.FormatUint(p.high, 10))
				p.mu.Unlock()
				if _, err := io.WriteString(peer, paddingTestReply(reply)); err != nil {
					return
				}
				continue
			}
			if len(fields) < 5 {
				p.mu.Unlock()
				t.Error("missing captured control identity")
				return
			}
			generation, err := strconv.ParseUint(fields[4], 10, 64)
			if err != nil {
				p.mu.Unlock()
				t.Error("invalid generation on wire")
				return
			}
			identity := PaddingIdentity{SessionSHA256: fields[2], SourceSHA256: fields[3], Generation: generation}
			if action == "START" {
				if len(fields) != 9 || generation != p.high+1 || fields[7] != strings.Repeat("c", 32) || fields[8] != strings.Repeat("d", 64) {
					p.mu.Unlock()
					t.Error("start changed its captured policy or isolation")
					return
				}
				p.identity = identity
				p.high = generation
				p.rate, _ = strconv.Atoi(fields[5])
				p.state = "running"
				p.channel = p.initial
				ttl, _ := strconv.ParseInt(fields[6], 10, 64)
				p.expires = time.Now().Add(time.Duration(ttl) * time.Millisecond)
				p.grants = append(p.grants, p.expires)
			} else if identity != p.identity {
				p.mu.Unlock()
				t.Error("operation changed native generation owner")
				return
			} else if action == "RENEW" {
				ttl, _ := strconv.ParseInt(fields[5], 10, 64)
				p.expires = time.Now().Add(time.Duration(ttl) * time.Millisecond)
				p.grants = append(p.grants, p.expires)
			} else if action == "STOP" {
				p.state = "stopped"
				p.expires = time.Time{}
				if p.holdStop || p.pending != 0 {
					p.pending = 1
					p.state = "stopping"
				}
			} else if action != "STATUS" {
				p.mu.Unlock()
				t.Error("unknown padding action")
				return
			}
			if p.state == "stopping" && !p.holdStop {
				p.channel += p.pending
				p.pending = 0
				p.state = "stopped"
			}
			if p.state == "running" && p.advance && action != "START" {
				p.channel++
			}
			expires, reason := int64(0), "controller"
			if p.state == "running" {
				expires = int64((time.Until(p.expires) + time.Millisecond - 1) / time.Millisecond)
				reason = "active"
			}
			queued := p.channel + p.pending
			circuit := 0
			if queued > 0 {
				circuit = 17
			}
			reply := fmt.Sprintf("version=1 state=%s reason=%s session=%s source=%s generation=%d rate_kbps=%d expires_ms=%d queued_cells=%d queued_cell_bytes=%d channel_cells=%d channel_cell_bytes=%d dropped_cells=0 dropped_cell_bytes=0 pending_cells=%d last_circuit=%d", p.state, reason, p.identity.SessionSHA256, p.identity.SourceSHA256, p.identity.Generation, p.rate, expires, queued, queued*514, p.channel, p.channel*514, p.pending, circuit)
			gate, gateAction, delay, corrupt := p.startGate, p.gateAction, p.delay, p.corrupt
			p.mu.Unlock()
			if gate != nil && (action == gateAction || gateAction == "" && action == "START") {
				<-gate
			}
			if delay > 0 {
				time.Sleep(delay)
			}
			if corrupt != nil {
				reply = corrupt(action, reply)
			}
			if _, err := io.WriteString(peer, paddingTestReply(reply)); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		p.mu.Lock()
		gate := p.startGate
		p.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			default:
				close(gate)
			}
		}
		control.Close()
		peer.Close()
		<-p.done
	})
	return p
}

func joinPaddingLeaseTest(lease *PaddingLease) {
	if lease != nil {
		lease.Cancel()
		_ = lease.Join(context.Background())
	}
}

func paddingLeaseOptions(until time.Time, retired func(error)) PaddingLeaseOptions {
	return PaddingLeaseOptions{SessionSHA256: paddingTestIdentity.SessionSHA256, SourceSHA256: paddingTestIdentity.SourceSHA256,
		Username: strings.Repeat("c", 32), Password: strings.Repeat("d", 64), RateKbps: 192, Current: func() bool { return true }, ProofValidUntil: func() time.Time { return until }, Retire: retired}
}

func TestPaddingLeaseWaitsForChannelAndJoinsPendingCiphertext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		p.mu.Lock()
		p.initial = 0
		p.advance = false
		p.holdStop = true
		p.mu.Unlock()
		lease, err := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(30*time.Second), func(error) { t.Error("ordinary cancellation retired another owner") }))
		defer joinPaddingLeaseTest(lease)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- lease.Start(t.Context()) }()
		synctest.Wait()
		time.Sleep(250 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatal("no native channel cell nevertheless completed start", err)
		default:
		}
		if lease.Healthy() {
			t.Fatal("queued or merely running native state gained health")
		}
		p.mu.Lock()
		p.advance = true
		p.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if err := <-result; err != nil || !lease.Healthy() {
			t.Fatal("actual channel acceptance did not activate captured owner", err)
		}
		status, observed, expires, valid := lease.Receipt()
		if !valid || status.Identity != paddingTestIdentity || status.ChannelCells == 0 || observed.After(time.Now()) || expires.After(observed.Add(PaddingMaxTTL)) {
			t.Fatal("invalid bound receipt", status, valid)
		}
		lease.Cancel()
		if lease.Healthy() {
			t.Fatal("cancel retained data authority")
		}
		go func() { result <- lease.Close(t.Context()) }()
		synctest.Wait()
		status, known := lease.Status()
		if !known || status.State != "stopping" || status.PendingCells != 1 {
			t.Fatal("pending ciphertext disappeared on Stop", status)
		}
		select {
		case err := <-result:
			t.Fatal("Stop returned before native drain", err)
		default:
		}
		p.mu.Lock()
		p.holdStop = false
		p.mu.Unlock()
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		status, _ = lease.Status()
		if status.State != "stopped" || status.PendingCells != 0 {
			t.Fatal("missing actual stopped receipt", status)
		}
		if err := p.control.EnableNetwork(t.Context()); err != nil {
			t.Fatal("successful Close destroyed borrowed native controller", err)
		}
		if err := lease.Start(t.Context()); err == nil {
			t.Fatal("closed generation restarted")
		}
		if err := lease.Close(t.Context()); err != nil {
			t.Fatal("successful close not idempotent", err)
		}
	})
}

func TestPaddingLeaseCannotRenewBeyondActualProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		until := time.Now().Add(500 * time.Millisecond)
		var lease *PaddingLease
		var retired atomic.Int32
		var closeErr error
		options := paddingLeaseOptions(until, func(error) { retired.Add(1); closeErr = lease.Close(context.Background()) })
		lease, _ = NewPaddingLease(t.Context(), p.control, options)
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(600 * time.Millisecond)
		synctest.Wait()
		if lease.Healthy() || retired.Load() != 1 || lease.Error() == nil || closeErr != nil {
			t.Fatal("expired proof retained its generation or failed to join callback cleanup", retired.Load(), lease.Error(), closeErr)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.grants) < 2 {
			t.Fatal("short proof did not exercise renewal")
		}
		for _, grant := range p.grants {
			if grant.After(until) {
				t.Fatal("renewal manufactured a fresh path proof", grant, until)
			}
		}
	})
}

func TestPaddingLeaseRefreshesOnlyFromNewCapturedProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		var deadline atomic.Int64
		deadline.Store(time.Now().Add(3 * time.Second).UnixNano())
		options := paddingLeaseOptions(time.Time{}, func(error) { t.Error("fresh captured proof unexpectedly retired") })
		options.ProofValidUntil = func() time.Time { return time.Unix(0, deadline.Load()) }
		lease, _ := NewPaddingLease(t.Context(), p.control, options)
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		deadline.Store(time.Now().Add(30 * time.Second).UnixNano()) // a separately completed actual proof
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if !lease.Healthy() {
			t.Fatal("refreshed immutable proof was not adopted", lease.Error())
		}
		if err := lease.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.identity != paddingTestIdentity || len(p.grants) < 3 {
			t.Fatal("renewal changed generation or did not execute")
		}
	})
}

func TestPaddingLeaseCancelDuringStartDoesNotPublishLateReceipt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		gate := make(chan struct{})
		p.mu.Lock()
		p.startGate = gate
		p.mu.Unlock()
		lease, _ := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(30*time.Second), func(error) { t.Error("explicit cancellation called failure callback") }))
		defer joinPaddingLeaseTest(lease)
		result := make(chan error, 1)
		go func() { result <- lease.Start(t.Context()) }()
		synctest.Wait()
		lease.Cancel()
		synctest.Wait()
		close(gate)
		synctest.Wait()
		if err := <-result; err == nil || lease.Healthy() {
			t.Fatal("late initial receipt survived Cancel", err)
		}
		if err := lease.Close(t.Context()); err != nil {
			t.Fatal("valid late reply prevented exact retained cleanup", err)
		}
		if err := p.control.EnableNetwork(t.Context()); err != nil {
			t.Fatal("ordinary cancellation destroyed resident controller", err)
		}
	})
}

func TestPaddingLeaseCancelDuringStatusKeepsResidentController(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		lease, _ := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(30*time.Second), func(error) { t.Error("normal cancellation retired resident") }))
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		gate := make(chan struct{})
		p.mu.Lock()
		p.startGate, p.gateAction = gate, "STATUS"
		p.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		lease.Cancel()
		if lease.Healthy() {
			t.Fatal("pending control read retained data authority")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		if err := lease.Join(ctx); err == nil {
			t.Fatal("worker reported joined before its framed reply completed")
		}
		close(gate)
		synctest.Wait()
		if err := lease.Join(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := lease.Close(t.Context()); err != nil {
			t.Fatal("late valid status prevented native drain", err)
		}
		if err := p.control.EnableNetwork(t.Context()); err != nil {
			t.Fatal("normal cancellation destroyed process's reusable controller", err)
		}
	})
}

func TestPaddingLeaseUnresponsiveControllerStillRetiresWithinBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		gate := make(chan struct{})
		p.mu.Lock()
		p.startGate = gate
		p.mu.Unlock()
		lease, _ := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(30*time.Second), func(error) { t.Error("explicit cancellation invoked failure callback") }))
		defer joinPaddingLeaseTest(lease)
		result := make(chan error, 1)
		go func() { result <- lease.Start(t.Context()) }()
		synctest.Wait()
		lease.Cancel()
		time.Sleep(6 * time.Second)
		synctest.Wait()
		close(gate)
		synctest.Wait()
		if err := <-result; err == nil {
			t.Fatal("hung native command retained authority")
		}
		if err := lease.Join(t.Context()); err != nil {
			t.Fatal("bounded command worker did not join", err)
		}
		if err := p.control.EnableNetwork(t.Context()); err == nil {
			t.Fatal("hung stream remained reusable")
		}
		if err := lease.Close(t.Context()); err == nil {
			t.Fatal("hung stream fabricated a native stop")
		}
	})
}

func TestPaddingLeaseRetainsTimedOutStopForExactRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		p.mu.Lock()
		p.holdStop = true
		p.mu.Unlock()
		lease, _ := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(30*time.Second), func(error) { t.Error("stop timeout was not explicit cleanup") }))
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Millisecond)
		defer cancel()
		if err := lease.Close(ctx); err == nil {
			t.Fatal("pending cell acknowledged before native drain")
		}
		status, _ := lease.Status()
		if status.State != "stopping" || status.PendingCells != 1 || lease.Healthy() {
			t.Fatal("timeout lost retained stop owner", status)
		}
		p.mu.Lock()
		p.holdStop = false
		p.mu.Unlock()
		if err := lease.Close(t.Context()); err != nil {
			t.Fatal("fresh cleanup lifetime could not retry original generation", err)
		}
		status, _ = lease.Status()
		if status.Identity != paddingTestIdentity || status.State != "stopped" {
			t.Fatal("retry replaced original owner", status)
		}
	})
}

func TestPaddingLeaseConcurrentCloseCannotConsumeAnotherCleanupLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		p.mu.Lock()
		p.holdStop = true
		p.mu.Unlock()
		lease, _ := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(30*time.Second), func(error) { t.Error("explicit close retired another owner") }))
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		first := make(chan error, 1)
		go func() { first <- lease.Close(t.Context()) }()
		synctest.Wait()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		if err := lease.Close(ctx); err == nil {
			t.Fatal("second close ignored its own cancelled lifetime")
		}
		select {
		case err := <-first:
			t.Fatal("second cancellation consumed first cleanup", err)
		default:
		}
		p.mu.Lock()
		p.holdStop = false
		p.mu.Unlock()
		time.Sleep(25 * time.Millisecond)
		synctest.Wait()
		if err := <-first; err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		stops := 0
		for _, action := range p.actions {
			if action == "STOP" {
				stops++
			}
		}
		if stops != 1 {
			t.Fatal("concurrent close issued a competing native stop", stops)
		}
	})
}

func TestPaddingLeaseCloseBeforeStartDoesNotTouchNativeOwner(t *testing.T) {
	p := newPaddingLeasePeer(t)
	lease, err := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(time.Second), func(error) { t.Error("unused lease retired native owner") }))
	defer joinPaddingLeaseTest(lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := lease.Start(t.Context()); err == nil {
		t.Fatal("closed lease started a native generation")
	}
	if err := p.control.EnableNetwork(t.Context()); err != nil {
		t.Fatal("unused lease closed borrowed control", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.actions) != 0 {
		t.Fatal("unused lease touched padding controller")
	}
}

func TestPaddingLeaseParentAndPathLossRetireJoinedOwner(t *testing.T) {
	for _, cause := range []string{"parent", "path", "dns-proof"} {
		t.Run(cause, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newPaddingLeasePeer(t)
				parent, cancel := context.WithCancel(t.Context())
				defer cancel()
				var current atomic.Bool
				current.Store(true)
				var deadline atomic.Int64
				deadline.Store(time.Now().Add(30 * time.Second).UnixNano())
				var retired atomic.Int32
				var lease *PaddingLease
				var closeErr error
				options := paddingLeaseOptions(time.Time{}, func(error) { retired.Add(1); closeErr = lease.Close(context.Background()) })
				options.Current = current.Load
				options.ProofValidUntil = func() time.Time { return time.Unix(0, deadline.Load()) }
				lease, _ = NewPaddingLease(parent, p.control, options)
				defer joinPaddingLeaseTest(lease)
				if err := lease.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				switch cause {
				case "parent":
					cancel()
				case "path":
					current.Store(false)
				case "dns-proof":
					deadline.Store(time.Now().UnixNano())
				}
				if lease.Healthy() {
					t.Fatal("lost captured owner remained healthy")
				}
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				if retired.Load() != 1 || closeErr != nil {
					t.Fatal("failure callback could not clean up its already joined worker", retired.Load(), closeErr)
				}
				status, _ := lease.Status()
				if status.State != "stopped" {
					t.Fatal("native owner not retired", status)
				}
			})
		})
	}
}

func TestPaddingLeaseStalledChannelCannotKeepExtendingNativeCover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		p.mu.Lock()
		p.advance = false
		p.mu.Unlock()
		begin := time.Now()
		var retired atomic.Int32
		var lease *PaddingLease
		options := paddingLeaseOptions(begin.Add(30*time.Second), func(error) {
			retired.Add(1)
			if err := lease.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
		lease, _ = NewPaddingLease(t.Context(), p.control, options)
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if retired.Load() != 1 || lease.Healthy() {
			t.Fatal("old positive cell kept active status indefinitely")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, grant := range p.grants {
			if grant.After(begin.Add(PaddingMaxTTL)) {
				t.Fatal("stalled channel manufactured renewed progress", grant)
			}
		}
	})
}

func TestPaddingLeaseRejectsRegressedNativeCounters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		p.mu.Lock()
		p.initial = 10
		p.mu.Unlock()
		var retired atomic.Int32
		lease, _ := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(time.Now().Add(30*time.Second), func(error) { retired.Add(1) }))
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		p.mu.Lock()
		p.channel = 0
		p.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if lease.Healthy() || retired.Load() != 1 || lease.Error() == nil {
			t.Fatal("counter rollback gained authority")
		}
		if err := p.control.EnableNetwork(t.Context()); err == nil {
			t.Fatal("semantically invalid receipt retained stream")
		}
		if err := lease.Close(t.Context()); err == nil {
			t.Fatal("closed stream fabricated native teardown")
		}
	})
}

func TestPaddingLeaseReceiptDoesNotExtendByControlLatency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPaddingLeasePeer(t)
		p.mu.Lock()
		p.delay = 250 * time.Millisecond
		p.mu.Unlock()
		begin := time.Now()
		until := begin.Add(2 * time.Second)
		lease, _ := NewPaddingLease(t.Context(), p.control, paddingLeaseOptions(until, func(error) { t.Error("bounded delayed reply retired") }))
		defer joinPaddingLeaseTest(lease)
		if err := lease.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, observed, expires, valid := lease.Receipt()
		if !valid || !observed.Equal(begin) || expires.After(until) || !observed.Before(time.Now()) {
			t.Fatal("control latency was relabeled as a new native observation", observed, expires, until)
		}
		if err := lease.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPaddingLeaseInvalidConstructionAndUnprovedStartDoNoIO(t *testing.T) {
	for _, cause := range []string{"session", "source", "rate-low", "rate-high", "username", "password", "current", "proof", "retire", "parent", "control"} {
		t.Run(cause, func(t *testing.T) {
			p := newPaddingLeasePeer(t)
			options := paddingLeaseOptions(time.Now().Add(time.Second), func(error) {})
			parent := t.Context()
			control := p.control
			switch cause {
			case "session":
				options.SessionSHA256 = strings.Repeat("A", 64)
			case "source":
				options.SourceSHA256 = "node-name"
			case "rate-low":
				options.RateKbps = 31
			case "rate-high":
				options.RateKbps = 193
			case "username":
				options.Username = "unbound"
			case "password":
				options.Password = "secret"
			case "current":
				options.Current = nil
			case "proof":
				options.ProofValidUntil = nil
			case "retire":
				options.Retire = nil
			case "parent":
				parent = nil
			case "control":
				control = nil
			}
			if lease, err := NewPaddingLease(parent, control, options); err == nil || lease != nil {
				t.Fatal("invalid construction accepted")
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.actions) != 0 {
				t.Fatal("constructor performed I/O")
			}
		})
	}
	for _, cause := range []string{"path", "proof", "exhausted"} {
		t.Run(cause, func(t *testing.T) {
			p := newPaddingLeasePeer(t)
			var retired atomic.Int32
			options := paddingLeaseOptions(time.Now().Add(time.Second), func(error) { retired.Add(1) })
			switch cause {
			case "path":
				options.Current = func() bool { return false }
			case "proof":
				options.ProofValidUntil = func() time.Time { return time.Now().Add(99 * time.Millisecond) }
			case "exhausted":
				p.mu.Lock()
				p.high = math.MaxInt64
				p.mu.Unlock()
			}
			lease, err := NewPaddingLease(t.Context(), p.control, options)
			defer joinPaddingLeaseTest(lease)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Start(t.Context()); err == nil || lease.Healthy() || retired.Load() != 1 {
				t.Fatal("unproved/exhausted native generation started", err)
			}
			if err := lease.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			for _, action := range p.actions {
				if action != "INFO" || cause != "exhausted" {
					t.Fatal("unproved start performed native mutation")
				}
			}
		})
	}
}
