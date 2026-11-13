package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Only the native outbound/ingress boundary is doubled. Authenticated private
// HTTP and all fifty candidate TCP connections execute against real listeners.
// The complete saved final is deliberately unreachable and never proved.
type candidatePreparationOwnerFixture struct {
	*candidateRouteFixture
	lease            nodeChainMeasurementFixture
	mu               sync.Mutex
	capture          string
	application, dns bool
}

func (o *candidatePreparationOwnerFixture) ObservePreparationContext(ctx context.Context) (NodeChainIdentity, error) {
	o.mu.Lock()
	opened := o.application || o.dns
	o.mu.Unlock()
	if opened {
		return NodeChainIdentity{}, errors.New("temporary ingress opened")
	}
	return o.ObserveChainContext(ctx)
}
func (o *candidatePreparationOwnerFixture) BeginMeasurementContext(ctx context.Context) (func(), error) {
	return o.lease.BeginMeasurementContext(ctx)
}
func (o *candidatePreparationOwnerFixture) CandidateInventoryCurrentContext(ctx context.Context, capture string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.capture != capture {
		return nodeChainCandidatePreparationError
	}
	return ctx.Err()
}
func newCandidatePreparationRuntimeFixture(t *testing.T, mode string) (*NodeChainCandidatePreparationRuntime, *candidatePreparationOwnerFixture) {
	t.Helper()
	p, _, _ := candidatePreparationFixture(t, []string{mode, mode, "shadowsocks"}, []string{"", "", ""}, 1)
	base := newNodeChainTestEngine(t, p.original)
	base.identity.SourceSHA256, base.identity.ConfigSHA256 = p.SourceSHA256(), p.ConfigSHA256()
	base.dead = 2
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	owner := &candidatePreparationOwnerFixture{candidateRouteFixture: &candidateRouteFixture{nodeChainTestEngine: base,
		tag: p.proofs[1].Tag, address: p.candidates.targets[0].Address, peer: listener.Addr().String()}, capture: p.capture}
	runtime, err := NewNodeChainCandidatePreparationRuntime(p, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := runtime.CloseContext(ctx); err != nil {
			t.Error("prefix proof cleanup did not join", err)
		}
	})
	return runtime, owner
}
func TestNodeChainCandidatePreparationRuntimeUsesOnlyProvedPrefix(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			r, owner := newCandidatePreparationRuntimeFixture(t, mode)
			if _, err := r.NewMeasurementContext(context.Background()); err == nil {
				t.Fatal("unproved prefix acquired candidates")
			}
			if err := r.StartContext(context.Background()); err != nil {
				t.Fatal("unreachable saved final blocked prefix preparation", err)
			}
			progress := r.Progress()
			if !progress.Prepared || progress.Stage != "prefix-prepared" || progress.ApplicationOpen || progress.DNSOpen || len(progress.Prefixes) != 2 {
				t.Fatal("prefix preparation claimed connection or omitted proofs", progress)
			}
			progress.Prefixes[0].Proven = false
			if !r.Progress().Prefixes[0].Proven {
				t.Fatal("published progress changed retained proofs")
			}
			service, err := r.NewMeasurementContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			request := strings.Repeat("e", 32)
			if err := service.Start(request, r.preparation.candidates.targets[0].ID); err != nil {
				t.Fatal(err)
			}
			if err := service.Drain(request); err != nil {
				t.Fatal(err)
			}
			status := candidateStatus(t, service)
			if !status.Complete || !status.Drained || status.Failure != "" || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || owner.count.Load() != 50 {
				t.Fatal("prefix preparation lost complete actual fifty", status, owner.count.Load())
			}
			if status.Measurement != "routed-tcp-connect" || status.PrefixPosition != 1 || status.CaptureSHA256 != r.preparation.capture || status.ExpiresAt-status.MeasuredAt != 120000 {
				t.Fatal("prefix candidate receipt lost original semantics", status)
			}
			if owner.lease.active.Load() || owner.lease.released.Load() != 1 {
				t.Fatal("candidate did not retain/release native measurement hold")
			}
			base := owner.nodeChainTestEngine
			base.mu.Lock()
			calls, dns := append([]string(nil), base.calls...), base.dnsCalls
			base.mu.Unlock()
			if !reflect.DeepEqual(calls, []string{r.preparation.proofs[0].Tag, r.preparation.proofs[1].Tag}) || dns != 0 {
				t.Fatal("candidate preparation contacted unselected suffix or DNS", calls, dns)
			}
			if r.preparation.original.HealthyContext(context.Background()) == nil {
				t.Fatal("prefix preparation became complete saved connection authority")
			}
			if _, err := r.Dial(context.Background(), r.preparation.proofs[0].Tag, owner.address); err == nil {
				t.Fatal("candidate bypassed captured selected prefix")
			}
			if _, err := r.Dial(context.Background(), owner.tag, "127.0.0.1:443"); err == nil {
				t.Fatal("candidate acquired arbitrary destination")
			}
			if err := r.CloseContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			if r.HealthyContext(context.Background()) == nil || r.Progress().Prepared {
				t.Fatal("retired preparation retained candidate authority")
			}
		})
	}
}
func TestNodeChainCandidatePreparationRuntimeRejectsWrongPrivateProof(t *testing.T) {
	for _, position := range []int{0, 1} {
		r, owner := newCandidatePreparationRuntimeFixture(t, "wg")
		owner.nodeChainTestEngine.wrong = position
		if err := r.StartContext(context.Background()); err == nil {
			t.Fatal("foreign prefix identity became prepared", position)
		}
		if r.Progress().Prepared || r.Progress().Stage != "retired" || owner.count.Load() != 0 {
			t.Fatal("failed private proof retained candidate authority")
		}
		if err := r.StartContext(context.Background()); err == nil {
			t.Fatal("failed preparation was reused")
		}
	}
}
func TestNodeChainCandidatePreparationRuntimeInvalidationIsSticky(t *testing.T) {
	for _, field := range []string{"EngineID", "SessionID", "NetworkID", "SourceSHA256", "ConfigSHA256", "catalog", "application", "dns", "expiry", "lifetime"} {
		t.Run(field, func(t *testing.T) {
			r, owner := newCandidatePreparationRuntimeFixture(t, "awg2-strong")
			life, stop := context.WithCancel(context.Background())
			defer stop()
			if err := r.StartContext(life); err != nil {
				t.Fatal(err)
			}
			base := owner.nodeChainTestEngine
			base.mu.Lock()
			original := base.identity
			base.mu.Unlock()
			switch field {
			case "catalog", "application", "dns":
				owner.mu.Lock()
				if field == "catalog" {
					owner.capture = "replacement"
				} else if field == "application" {
					owner.application = true
				} else {
					owner.dns = true
				}
				owner.mu.Unlock()
			case "expiry":
				r.mu.Lock()
				r.checkedAt = time.Now().Add(-time.Minute)
				r.mu.Unlock()
			case "lifetime":
				stop()
			default:
				base.mu.Lock()
				reflect.ValueOf(&base.identity).Elem().FieldByName(field).SetString("replacement")
				base.mu.Unlock()
			}
			if _, err := r.NewMeasurementContext(context.Background()); err == nil {
				t.Fatal("changed preparation admitted candidate", field)
			}
			base.mu.Lock()
			base.identity = original
			base.mu.Unlock()
			owner.mu.Lock()
			owner.capture, owner.application, owner.dns = r.preparation.capture, false, false
			owner.mu.Unlock()
			r.mu.Lock()
			r.checkedAt = time.Now()
			r.mu.Unlock()
			if _, err := r.NewMeasurementContext(context.Background()); err == nil || r.Progress().Prepared {
				t.Fatal("change-away-and-back revived preparation", field)
			}
			if owner.count.Load() != 0 {
				t.Fatal("invalid preparation dialed candidate")
			}
		})
	}
}
func TestNodeChainCandidatePreparationRuntimeCancelledObservationRetainsJoin(t *testing.T) {
	r, owner := newCandidatePreparationRuntimeFixture(t, "wg")
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	owner.nodeChainTestEngine.beforeObserve = func(context.Context) { once.Do(func() { close(entered) }); <-release }
	go func() { finished <- r.StartContext(context.Background()) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := r.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		close(release)
		t.Fatal("unfinished native callback lost join handle", err)
	}
	select {
	case <-finished:
		close(release)
		t.Fatal("startup completed while original native callback remained held")
	default:
	}
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("late native callback revived cancelled preparation")
	}
	if err := r.CloseContext(context.Background()); err != nil {
		t.Fatal("retry did not join exact original callback", err)
	}
	if owner.count.Load() != 0 || r.Progress().Prepared {
		t.Fatal("cancelled startup acquired candidate authority")
	}
}
func TestNodeChainCandidatePreparationRuntimeCancelledCallerDoesNotRetireOwner(t *testing.T) {
	r, _ := newCandidatePreparationRuntimeFixture(t, "wg")
	if err := r.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r.HealthyContext(ctx) == nil {
		t.Fatal("cancelled observation succeeded")
	}
	if r.HealthyContext(context.Background()) != nil {
		t.Fatal("disposable caller cancellation retired original native lifetime")
	}
}

func TestNodeChainCandidatePreparationRuntimeRetainsLateCandidateAndLease(t *testing.T) {
	r, owner := newCandidatePreparationRuntimeFixture(t, "wg")
	if err := r.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := r.NewMeasurementContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	owner.closeEntered, owner.closeRelease = make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(owner.closeRelease) }) }
	defer release()
	owner.before = func(context.Context) {
		owner.mu.Lock()
		owner.capture = "changed-during-native-dial"
		owner.mu.Unlock()
	}
	request := strings.Repeat("f", 32)
	if err := service.Start(request, r.preparation.candidates.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.closeEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("late candidate socket did not reach owned close")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := service.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held candidate socket claimed drain", err)
	}
	if !owner.lease.active.Load() || owner.lease.released.Load() != 0 {
		t.Fatal("cancel released MTU hold before exact socket close")
	}
	status := candidateStatus(t, service)
	if status.Drained || len(status.Results) != 0 {
		t.Fatal("late invalidated candidate retained score or fake drain", status)
	}
	release()
	joined, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := service.CloseContext(joined); err != nil {
		t.Fatal("retry did not join original candidate socket", err)
	}
	if owner.lease.active.Load() || owner.lease.released.Load() != 1 {
		t.Fatal("joined worker failed to release exact native hold")
	}
	if err := r.CloseContext(joined); err != nil {
		t.Fatal(err)
	}
}
