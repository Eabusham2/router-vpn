package mobilemtu

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

type externalActivityKey struct{}

type externalActivityOwner struct {
	*externalTestOwner
	activityMu sync.Mutex
	active     bool
	starts     int
	releases   int
	proofs     int
	begin      func(context.Context, State) (context.Context, context.CancelFunc, error)
}

func (o *externalActivityOwner) BeginExternalMeasurement(ctx context.Context, state State) (context.Context, context.CancelFunc, error) {
	if o.begin != nil {
		return o.begin(ctx, state)
	}
	current, err := o.Capture()
	if err != nil || current != state || ctx.Err() != nil {
		return nil, nil, errors.New("activity lost its captured TUN")
	}
	o.activityMu.Lock()
	defer o.activityMu.Unlock()
	if o.active {
		return nil, nil, errors.New("another measurement retains the TUN")
	}
	o.active = true
	o.starts++
	ctx, cancel := context.WithCancel(context.WithValue(ctx, externalActivityKey{}, o))
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			o.activityMu.Lock()
			o.active = false
			o.releases++
			o.activityMu.Unlock()
		})
	}
	return ctx, release, nil
}

func (o *externalActivityOwner) retained(ctx context.Context) bool {
	o.activityMu.Lock()
	defer o.activityMu.Unlock()
	return o.active && ctx.Value(externalActivityKey{}) == o
}

func (o *externalActivityOwner) VerifyExternal(ctx context.Context, state State) error {
	o.activityMu.Lock()
	if o.active {
		if ctx.Value(externalActivityKey{}) != o {
			o.activityMu.Unlock()
			return errors.New("proof lost its candidate activity")
		}
		o.proofs++
	}
	o.activityMu.Unlock()
	return o.externalTestOwner.VerifyExternal(ctx, state)
}

type externalActivityCache struct {
	Cache
	owner *externalActivityOwner
	saved bool
}

func (c *externalActivityCache) Save(key string, mtu int, valid func() bool) error {
	c.owner.activityMu.Lock()
	active := c.owner.active
	c.owner.activityMu.Unlock()
	if active {
		return errors.New("durable commit deadlocked behind its own measured activity")
	}
	c.saved = true
	return c.Cache.Save(key, mtu, valid)
}

func externalActivityFixture(t *testing.T) (*Controller, *externalActivityOwner, *externalActivityCache) {
	t.Helper()
	c, base, _ := publicFixtureController(t, true)
	owner := &externalActivityOwner{externalTestOwner: base}
	cache := &externalActivityCache{Cache: c.cache, owner: owner}
	c.owner, c.external.owner, c.cache = owner, owner, cache
	measure := c.external.measure
	c.external.measure = func(ctx context.Context, engine hopmeasure.Engine, hop hopmeasure.Hop, size int) (hopmeasure.Result, error) {
		if !owner.retained(ctx) || ctx.Err() != nil {
			return hopmeasure.Result{}, errors.New("candidate transfer ran outside native activity")
		}
		return measure(ctx, engine, hop, size)
	}
	return c, owner, cache
}

func TestExternalMTUCandidateActivityCoversBothProofsAndReleasesBeforeCommit(t *testing.T) {
	c, owner, cache := externalActivityFixture(t)
	if err := c.Run(strings.Repeat("a", 32), true); err != nil {
		t.Fatal("measured candidate did not retain its native activity", err, c.StatusJSON())
	}
	status := readStatus(t, c)
	owner.activityMu.Lock()
	defer owner.activityMu.Unlock()
	if !status.Measured || !cache.saved || owner.active || owner.starts != len(status.Candidates)+1 ||
		owner.releases != owner.starts || owner.proofs != 2*owner.starts {
		t.Fatal("candidate proofs, transfer, release and durable commit did not share exact ownership", status, owner.starts, owner.releases, owner.proofs)
	}
}

func TestExternalMTUCandidateActivityRemainsRetainedUntilCancelledTransferDrains(t *testing.T) {
	c, owner, cache := externalActivityFixture(t)
	entered, release := make(chan context.Context, 1), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	c.external.measure = func(ctx context.Context, _ hopmeasure.Engine, _ hopmeasure.Hop, _ int) (hopmeasure.Result, error) {
		entered <- ctx
		<-release // A real native socket worker can finish after cancellation.
		return hopmeasure.Result{}, ctx.Err()
	}
	request := strings.Repeat("b", 32)
	finished := make(chan error, 1)
	go func() { finished <- c.Run(request, true) }()
	var captured context.Context
	select {
	case captured = <-entered:
	case <-time.After(time.Second):
		t.Fatal("candidate activity never began")
	}
	c.Cancel(request)
	if captured.Err() == nil || !owner.retained(captured) || !c.Running() {
		t.Fatal("cancellation released native activity before its actual transfer drained")
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		t.Fatal("Close acknowledged an undrained candidate", err)
	case <-time.After(20 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("late canceled transfer became a winner")
		}
	case <-time.After(time.Second):
		t.Fatal("candidate did not drain after its worker returned")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close failed to join the released candidate")
	}
	owner.activityMu.Lock()
	defer owner.activityMu.Unlock()
	if owner.active || owner.starts != 1 || owner.releases != 1 || cache.saved || readStatus(t, c).Measured {
		t.Fatal("cancelled candidate retained activity or wrote a successful result")
	}
}

func TestExternalMTUCandidateActivityRejectsFailedOrIncompleteAdmission(t *testing.T) {
	for _, kind := range []string{"error", "nil-context", "nil-release", "cancelled", "replaced-state"} {
		t.Run(kind, func(t *testing.T) {
			c, owner, _ := externalActivityFixture(t)
			state, _ := owner.Capture()
			releases := 0
			owner.begin = func(ctx context.Context, _ State) (context.Context, context.CancelFunc, error) {
				release := func() { releases++ }
				switch kind {
				case "error":
					return ctx, release, errors.New("native admission rejected")
				case "nil-context":
					return nil, release, nil
				case "nil-release":
					return ctx, nil, nil
				case "cancelled":
					ctx, cancel := context.WithCancel(ctx)
					cancel()
					return ctx, release, nil
				case "replaced-state":
					owner.mu.Lock()
					owner.state.Interface = "replacement-reader"
					owner.mu.Unlock()
					return ctx, release, nil
				}
				panic("unknown fixture")
			}
			measured := false
			c.external.measure = func(context.Context, hopmeasure.Engine, hopmeasure.Hop, int) (hopmeasure.Result, error) {
				measured = true
				return hopmeasure.Result{}, nil
			}
			result := c.measureExternal(context.Background(), &probeEngine{controller: c, state: state}, state.MTU)
			if result.Working || measured || result.Failure != "captured external measurement activity is unavailable" ||
				kind == "nil-release" && releases != 0 || kind != "nil-release" && releases != 1 {
				t.Fatal("failed native activity was treated as a measured path or leaked its release", result, releases, measured)
			}
		})
	}
}

func TestExternalMTUCandidateActivityCannotDetachControllerCancellation(t *testing.T) {
	c, owner, _ := externalActivityFixture(t)
	state, _ := owner.Capture()
	fixtureContext, fixtureCancel := context.WithCancel(context.Background())
	defer fixtureCancel()
	releases := 0
	owner.begin = func(context.Context, State) (context.Context, context.CancelFunc, error) {
		return fixtureContext, func() { releases++; fixtureCancel() }, nil
	}
	entered := make(chan struct{})
	c.external.measure = func(ctx context.Context, _ hopmeasure.Engine, _ hopmeasure.Hop, _ int) (hopmeasure.Result, error) {
		close(entered)
		<-ctx.Done()
		return hopmeasure.Result{}, ctx.Err()
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Candidate, 1)
	go func() { done <- c.measureExternal(parent, &probeEngine{controller: c, state: state}, state.MTU) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		fixtureCancel()
		<-done
		t.Fatal("detached-context fixture did not reach the transfer")
	}
	cancel()
	select {
	case result := <-done:
		if result.Working || releases != 1 {
			t.Fatal("canceled detached candidate won or leaked its native activity", result, releases)
		}
	case <-time.After(time.Second):
		fixtureCancel()
		<-done
		t.Fatal("native activity detached a candidate from controller cancellation")
	}
}
