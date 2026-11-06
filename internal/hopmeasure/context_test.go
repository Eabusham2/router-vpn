package hopmeasure

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observedMeasurementEngine struct {
	mu      sync.Mutex
	observe func(context.Context) (string, error)
	begin   func(context.Context) (func(), error)
	legacy  atomic.Int32
}

func (e *observedMeasurementEngine) Identity() string {
	e.legacy.Add(1)
	return "detached-reader-must-not-be-used"
}
func (e *observedMeasurementEngine) IdentityContext(ctx context.Context) (string, error) {
	e.mu.Lock()
	observe := e.observe
	e.mu.Unlock()
	if observe != nil {
		return observe(ctx)
	}
	return "captured-context-owner", ctx.Err()
}
func (e *observedMeasurementEngine) BeginMeasurement() (func(), error) {
	e.legacy.Add(1)
	return nil, errors.New("detached activity acquisition must not be used")
}
func (e *observedMeasurementEngine) BeginMeasurementContext(ctx context.Context) (func(), error) {
	e.mu.Lock()
	begin := e.begin
	e.mu.Unlock()
	if begin != nil {
		return begin(ctx)
	}
	return func() {}, ctx.Err()
}
func (*observedMeasurementEngine) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("fixture does not own a network route")
}
func (e *observedMeasurementEngine) setObserve(observe func(context.Context) (string, error)) {
	e.mu.Lock()
	e.observe = observe
	e.mu.Unlock()
}
func (e *observedMeasurementEngine) setBegin(begin func(context.Context) (func(), error)) {
	e.mu.Lock()
	e.begin = begin
	e.mu.Unlock()
}
func observedService(t *testing.T) (*Service, *observedMeasurementEngine) {
	t.Helper()
	engine := &observedMeasurementEngine{}
	service, err := New(engine, []Hop{publicHop("exit")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
		if engine.legacy.Load() != 0 {
			t.Error("context-capable owner used a detached legacy callback")
		}
	})
	return service, engine
}
func receiveMeasurement[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("original measurement operation did not join")
		var zero T
		return zero
	}
}

func TestMeasurementConstructorUsesOriginalContextAndRejectsLateIdentity(t *testing.T) {
	for _, phase := range []string{"current", "cancel-before", "cancel-during", "empty"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reads atomic.Int32
			engine := &observedMeasurementEngine{observe: func(observed context.Context) (string, error) {
				reads.Add(1)
				if observed != ctx {
					return "", errors.New("constructor replaced the caller")
				}
				if phase == "cancel-during" {
					cancel()
				}
				if phase == "empty" {
					return "", nil
				}
				return "captured-context-owner", nil
			}}
			if phase == "cancel-before" {
				cancel()
			}
			service, err := NewContext(ctx, engine, []Hop{publicHop("exit")})
			if phase == "current" {
				if err != nil || service == nil || service.identity != "captured-context-owner" {
					t.Fatal("constructor did not adopt the exact context capability", err)
				}
				cancel()
				engine.setObserve(nil)
				id := strings.Repeat("a", 32)
				if err := service.start(id, func(ctx context.Context) { <-ctx.Done() }); err != nil {
					t.Fatal("constructor deadline retired its returned service", err)
				}
				service.Cancel(id)
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || service != nil {
				t.Fatal("constructor retained an expired or missing identity")
			}
			if engine.legacy.Load() != 0 || phase == "cancel-before" && reads.Load() != 0 {
				t.Fatal("observation used a legacy or already-cancelled reader")
			}
		})
	}
}

func TestMeasurementAdmissionCancellationPreservesPreviousResult(t *testing.T) {
	for _, phase := range []string{"identity", "scope"} {
		t.Run(phase, func(t *testing.T) {
			service, engine := observedService(t)
			previous := Status{Request: strings.Repeat("a", 32), Stage: "complete", Complete: true,
				Results: []Result{{ID: "exit-node", Role: "exit", Ready: true, Kind: "public-path"}}}
			service.state = previous
			entered := make(chan struct{})
			var calls, releases atomic.Int32
			if phase == "identity" {
				engine.setObserve(func(ctx context.Context) (string, error) {
					close(entered)
					<-ctx.Done()
					return "captured-context-owner", nil // A late nil error cannot authorize admission.
				})
			} else {
				engine.setBegin(func(ctx context.Context) (func(), error) {
					close(entered)
					<-ctx.Done()
					return func() { releases.Add(1) }, nil
				})
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			id := strings.Repeat("b", 32)
			started := make(chan error, 1)
			go func() { started <- service.startContext(parent, id, func(context.Context) { calls.Add(1) }) }()
			receiveMeasurement(t, entered)
			service.Cancel(strings.Repeat("f", 32))
			if err := service.start(strings.Repeat("c", 32), func(context.Context) {}); err == nil {
				t.Fatal("replacement admission acquired the original pending request")
			}
			select {
			case err := <-started:
				t.Fatal("foreign cancellation retired the admitted owner", err)
			default:
			}
			cancelled := make(chan struct{})
			go func() { service.Cancel(id); close(cancelled) }()
			receiveMeasurement(t, cancelled)
			if err := receiveMeasurement(t, started); !errors.Is(err, context.Canceled) {
				t.Fatal("admission lost its named cancellation", err)
			}
			service.mu.Lock()
			actual, pending := service.state, service.pending
			service.mu.Unlock()
			if !reflect.DeepEqual(actual, previous) || pending != nil || calls.Load() != 0 ||
				(phase == "scope") != (releases.Load() == 1) {
				t.Fatal("rejected admission changed the previous result or leaked its scope", actual, releases.Load())
			}
		})
	}
}

func TestMeasurementRejectedAdmissionKeepsScopeUntilOriginalReleaseJoins(t *testing.T) {
	service, engine := observedService(t)
	entered, releasing, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var finishOnce sync.Once
	unblock := func() { finishOnce.Do(func() { close(finish) }) }
	defer unblock()
	var releases atomic.Int32
	engine.setBegin(func(ctx context.Context) (func(), error) {
		close(entered)
		<-ctx.Done()
		return func() { releases.Add(1); close(releasing); <-finish }, nil
	})
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	id := strings.Repeat("b", 32)
	started := make(chan error, 1)
	go func() {
		started <- service.startContext(parent, id, func(context.Context) { t.Error("cancelled admission ran") })
	}()
	receiveMeasurement(t, entered)
	service.Cancel(id)
	receiveMeasurement(t, releasing)
	if err := service.start(strings.Repeat("c", 32), func(context.Context) {}); err == nil {
		t.Fatal("replacement reused a scope before its real release")
	}
	closed := make(chan error, 1)
	go func() { closed <- service.Close() }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		service.mu.Lock()
		closing := service.closed
		service.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("close could not acquire the service during native release")
		}
	}
	select {
	case err := <-started:
		t.Fatal("failed start returned before original release", err)
	case err := <-closed:
		t.Fatal("close acknowledged an unreleased scope", err)
	default:
	}
	// Close has reached this exact admission while its real release is held.
	service.mu.Lock()
	if service.pending == nil || service.pending.id != id {
		service.mu.Unlock()
		t.Fatal("pending release lost its exact request")
	}
	service.mu.Unlock()
	unblock()
	if err := receiveMeasurement(t, started); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := receiveMeasurement(t, closed); err != nil {
		t.Fatal(err)
	}
	if releases.Load() != 1 {
		t.Fatal("original scope was released more than once")
	}
}

func TestMeasurementCallbacksRetainOneDeadlineAndNeverHoldStatusLock(t *testing.T) {
	service, engine := observedService(t)
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	deadline, _ := parent.Deadline()
	var admitted context.Context
	check := func(ctx context.Context) error {
		if !service.mu.TryLock() {
			return errors.New("native callback ran while the service status lock was held")
		}
		service.mu.Unlock()
		actual, ok := ctx.Deadline()
		if !ok || !actual.Equal(deadline) {
			return errors.New("observation replaced the original deadline")
		}
		if admitted == nil {
			admitted = ctx
		} else if admitted != ctx {
			return errors.New("native operation received a different caller")
		}
		return nil
	}
	engine.setObserve(func(ctx context.Context) (string, error) { return "captured-context-owner", check(ctx) })
	engine.setBegin(func(ctx context.Context) (func(), error) { return func() {}, check(ctx) })
	worker := make(chan error, 1)
	id := strings.Repeat("d", 32)
	if err := service.startContext(parent, id, func(ctx context.Context) {
		worker <- check(ctx)
		<-ctx.Done()
	}); err != nil {
		t.Fatal(err)
	}
	if err := receiveMeasurement(t, worker); err != nil {
		t.Fatal(err)
	}
	service.Cancel(id)
	if err := service.Drain(id); err != nil {
		t.Fatal(err)
	}
}

func TestMeasurementLateStatusCannotInvalidateReplacementOrCancellation(t *testing.T) {
	for _, phase := range []string{"replacement", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			service, engine := observedService(t)
			id := strings.Repeat("d", 32)
			if phase == "cancel" {
				if err := service.start(id, func(ctx context.Context) { <-ctx.Done() }); err != nil {
					t.Fatal(err)
				}
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			engine.setObserve(func(context.Context) (string, error) {
				if !service.mu.TryLock() {
					return "", errors.New("status held the service lock during native observation")
				}
				service.mu.Unlock()
				close(entered)
				<-release
				return "", errors.New("old status observation retired")
			})
			result := make(chan string, 1)
			go func() { result <- service.StatusJSON() }()
			receiveMeasurement(t, entered)
			engine.setObserve(nil)
			if phase == "replacement" {
				if err := service.start(id, func(ctx context.Context) { <-ctx.Done() }); err != nil {
					t.Fatal(err)
				}
			} else {
				service.Cancel(id)
			}
			unblock()
			var actual Status
			if err := json.Unmarshal([]byte(receiveMeasurement(t, result)), &actual); err != nil {
				t.Fatal(err)
			}
			if actual.Request != id || phase == "replacement" && (actual.Stage != "starting" || actual.Failure != "") ||
				phase == "cancel" && actual.Stage != "cancelled" {
				t.Fatal("old observation changed the newer request/cancellation", actual)
			}
			service.Cancel(id)
			if err := service.Drain(id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type observedLatencyEngine struct {
	*publicFixture
	service  *Service
	checks   atomic.Int32
	entered  chan struct{}
	observed atomic.Bool
}

func (e *observedLatencyEngine) VerifyMeasurement(context.Context) error {
	e.checks.Add(1)
	return nil
}
func (e *observedLatencyEngine) IdentityContext(ctx context.Context) (string, error) {
	if !e.service.mu.TryLock() {
		return "", errors.New("latency identity ran under the service status lock")
	}
	e.service.mu.Unlock()
	if e.checks.Load() >= 2 {
		if e.observed.CompareAndSwap(false, true) {
			close(e.entered)
		}
		<-ctx.Done()
		return e.publicFixture.Identity(), nil
	}
	return e.publicFixture.Identity(), ctx.Err()
}

func TestMeasurementCancelledFinalObservationCannotPublishFiftySamples(t *testing.T) {
	fixture := newPublicFixture(t)
	service := fixture.service(t, publicHop("exit"))
	engine := &observedLatencyEngine{publicFixture: fixture, service: service, entered: make(chan struct{})}
	service.engine = engine
	id := strings.Repeat("e", 32)
	if err := service.StartLatency(id, "exit-node"); err != nil {
		t.Fatal(err)
	}
	receiveMeasurement(t, engine.entered)
	if fixture.downloaded.Load() != 50 {
		t.Fatal("final observation did not follow all fifty real responses")
	}
	cancelled := make(chan struct{})
	go func() { service.Cancel(id); close(cancelled) }()
	receiveMeasurement(t, cancelled)
	if err := service.Drain(id); err != nil {
		t.Fatal(err)
	}
	actual := status(t, service)
	if actual.Stage != "cancelled" || !actual.Complete || !actual.Drained || len(actual.Results) != 0 {
		t.Fatal("late final identity published a cancelled benchmark", actual)
	}
}
