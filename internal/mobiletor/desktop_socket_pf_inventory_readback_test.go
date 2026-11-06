package mobiletor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDesktopPFReadbackInventorySharesOnlyJoinedIdenticalPaths(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	reader := newDesktopPFInventoryReadback(ctx, func(ctx context.Context, path string) ([]byte, error) {
		calls.Add(1)
		if path == "" {
			close(entered)
			<-release
		}
		return []byte("com.apple\n"), nil
	})
	var joined sync.WaitGroup
	results := make([][]byte, 2)
	failures := make([]error, 2)
	joined.Add(1)
	go func() { defer joined.Done(); results[0], failures[0] = reader.read(ctx, "") }()
	<-entered
	joined.Add(1)
	go func() { defer joined.Done(); results[1], failures[1] = reader.read(ctx, "") }()
	if _, err := reader.read(ctx, "com.apple"); err != nil {
		t.Fatal(err)
	}
	close(release)
	joined.Wait()
	if calls.Load() != 2 || failures[0] != nil || failures[1] != nil {
		t.Fatal("inventory commands were repeated or lost", calls.Load(), failures)
	}
	results[0][0] = 'X'
	if string(results[1]) != "com.apple\n" {
		t.Fatal("independent validator received mutable shared output")
	}
	again, err := reader.read(ctx, "")
	if err != nil || string(again) != "com.apple\n" || calls.Load() != 2 {
		t.Fatal("joined immutable inventory changed", err)
	}
}

func TestDesktopPFReadbackInventoryNewInspectionReadsAfterMutation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	actual := []byte("old-owner\n")
	calls := 0
	native := func(context.Context, string) ([]byte, error) { calls++; return actual, nil }
	before := newDesktopPFInventoryReadback(ctx, native)
	if raw, err := before.read(ctx, ""); err != nil || string(raw) != "old-owner\n" {
		t.Fatal(err, string(raw))
	}
	actual = []byte("new-owner\n")
	after := newDesktopPFInventoryReadback(ctx, native)
	if raw, err := after.read(ctx, ""); err != nil || string(raw) != "new-owner\n" || calls != 2 {
		t.Fatal("post-write invocation reused previous proof", err, string(raw), calls)
	}
}

type desktopPFInventoryWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *desktopPFInventoryWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestDesktopPFReadbackInventoryCancelledWaiterDoesNotDetachNativeOwner(t *testing.T) {
	owner, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	reader := newDesktopPFInventoryReadback(owner, func(context.Context, string) ([]byte, error) {
		close(entered)
		<-release
		return []byte("com.apple\n"), nil
	})
	go func() { defer close(joined); _, _ = reader.read(owner, "") }()
	<-entered
	waiter, stop := context.WithCancel(owner)
	observed := &desktopPFInventoryWaitingContext{Context: waiter, waiting: make(chan struct{})}
	waiterDone := make(chan error, 1)
	go func() {
		raw, err := reader.read(observed, "")
		if raw != nil {
			err = errors.New("cancelled waiter returned inventory")
		}
		waiterDone <- err
	}()
	<-observed.waiting // The second reader reached the in-flight wait.
	stop()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled waiter acquired inventory", err)
	}
	select {
	case <-joined:
		t.Fatal("original native command was not joined")
	default:
	}
	close(release)
	<-joined
}

func TestDesktopPFReadbackInventoryCancellationAndFailureNeverBecomeEmptyProof(t *testing.T) {
	t.Run("native-error", func(t *testing.T) {
		ctx := context.Background()
		want := errors.New("denied native inventory")
		calls := 0
		reader := newDesktopPFInventoryReadback(ctx, func(context.Context, string) ([]byte, error) { calls++; return []byte("partial"), want })
		for range 2 {
			if raw, err := reader.read(ctx, ""); raw != nil || !errors.Is(err, want) {
				t.Fatal("failed read became empty success", raw, err)
			}
		}
		if calls != 1 {
			t.Fatal("failed command was retried within same captured observation")
		}
	})
	t.Run("owner-cancelled-after-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reader := newDesktopPFInventoryReadback(ctx, func(context.Context, string) ([]byte, error) { cancel(); return []byte("com.apple"), nil })
		if raw, err := reader.read(context.Background(), ""); raw != nil || !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled owner returned successful proof", raw, err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		ctx := context.Background()
		reader := newDesktopPFInventoryReadback(ctx, func(context.Context, string) ([]byte, error) { return make([]byte, (64<<10)+1), nil })
		if raw, err := reader.read(ctx, ""); raw != nil || err == nil {
			t.Fatal("oversized inventory was truncated into authority")
		}
	})
}
