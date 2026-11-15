package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRouterNodeAutomaticMTUTerminalJoinRetainsEveryOriginalWorker(t *testing.T) {
	a, _ := newMTUTransactionFixture(t)
	tracker := sessionTrackerFor(a)
	tracker.dnsProofRunning = true // The held operation here is Auto's original callback.
	var releases [2]chan struct{}
	var releaseOnce [2]sync.Once
	for i := range releases {
		releases[i] = make(chan struct{})
	}
	t.Cleanup(func() {
		for i := range releases {
			releaseOnce[i].Do(func() { close(releases[i]) })
		}
		a.mu.Lock()
		a.closing = true
		a.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := retireRouterNodeAutomaticMTUContext(ctx, a); err != nil {
			t.Error(err)
		}
	})
	entered := make(chan int, 2)
	writes := make(chan error, 2)
	for i := range releases {
		a.mu.Lock()
		a.cmd = &exec.Cmd{Path: "original-runtime", Args: []string{string(rune('0' + i))}}
		a.mu.Unlock()
		// The second command replaces the first while its original callback is
		// held. A single waiting bool cannot account for both live workers.
		a.startRouterNodeAutomaticMTUWithRun(func(mtuRetestSnapshot) mtuAutomaticResult {
			entered <- i
			<-releases[i]
			writes <- os.WriteFile(filepath.Join(filepath.Dir(a.cfg.ProfilesFile), string(rune('a'+i))), []byte("original callback joined"), 0600)
			return mtuAutomaticResult{retry: true} // A late retry must not reopen terminal admission.
		})
		select {
		case got := <-entered:
			if got != i {
				t.Fatal("replacement callback identity changed")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("original Auto callback did not enter")
		}
	}
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := retireRouterNodeAutomaticMTUContext(ctx, a)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held original work was reported joined", err)
	}
	raw, _ := routerNodeAutomaticMTUs.Load(a)
	owner := raw.(*routerNodeAutomaticMTU)
	releaseOnce[0].Do(func() { close(releases[0]) })
	mtuWaitCondition(t, func() bool { owner.mu.Lock(); defer owner.mu.Unlock(); return owner.workers == 1 })
	select {
	case <-owner.joined:
		t.Fatal("old command completion released replacement worker")
	default:
	}
	releaseOnce[1].Do(func() { close(releases[1]) })
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := retireRouterNodeAutomaticMTUContext(ctx, a); err != nil {
		t.Fatal("same terminal owner could not retry join", err)
	}
	for range releases {
		if err := <-writes; err != nil {
			t.Fatal(err)
		}
	}
	owner.mu.Lock()
	joined := owner.retired && owner.workers == 0 && !owner.resume
	owner.mu.Unlock()
	if !joined {
		t.Fatal("terminal receipt lost original work")
	}
}

func TestRouterNodeAutomaticMTUTerminalJoinRejectsLateHoldRelease(t *testing.T) {
	a, _ := newMTUTransactionFixture(t)
	a.cmd = &exec.Cmd{Path: "original-runtime"}
	if err := retireRouterNodeAutomaticMTUContext(context.Background(), a); err == nil {
		t.Fatal("ordinary connected owner was permanently retired")
	}
	if _, found := routerNodeAutomaticMTUs.Load(a); found {
		t.Fatal("rejected retirement mutated owner")
	}
	release, err := a.holdCapturedMTU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	if err := retireRouterNodeAutomaticMTUContext(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	raw, _ := routerNodeAutomaticMTUs.Load(a)
	owner := raw.(*routerNodeAutomaticMTU)
	release() // Actual release callback; keep the saved Auto policy unchanged.
	owner.mu.Lock()
	closed := owner.retired && owner.workers == 0 && !owner.waiting
	owner.mu.Unlock()
	if current, _ := routerNodeAutomaticMTUs.Load(a); current != owner || !closed {
		t.Fatal("late hold release replaced the terminal owner or started work")
	}
}

func TestRouterNodeAutomaticMTUTerminalCancelBeforeViewPublication(t *testing.T) {
	a, _ := newMTUTransactionFixture(t)
	a.cmd = &exec.Cmd{Path: "original-runtime"}
	sessionTrackerFor(a).dnsProofRunning = true
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	observed := make(chan error, 1)
	a.startRouterNodeAutomaticMTUWithContextRun(func(ctx context.Context, snapshot mtuRetestSnapshot) mtuAutomaticResult {
		close(entered)
		<-release // Original worker captured; no MTU view exists yet.
		observed <- ctx.Err()
		return a.runRouterNodeAutomaticMTUContext(ctx, snapshot)
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original worker did not reach pre-view boundary")
	}
	if _, found := mtuViewSlots.Load(a); found {
		t.Fatal("fixture already published a view")
	}
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := retireRouterNodeAutomaticMTUContext(ctx, a)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held pre-view worker did not remain owned", err)
	}
	once.Do(func() { close(release) })
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := retireRouterNodeAutomaticMTUContext(ctx, a); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(<-observed, context.Canceled) {
		t.Fatal("late Auto callback lost terminal cancellation")
	}
	if _, found := mtuViewSlots.Load(a); found {
		t.Fatal("retired callback published a fresh MTU view")
	}
}
