package desktopnetwork

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNetworkContextLockRetainsOriginalOwner(t *testing.T) {
	var mutex sync.Mutex
	mutex.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := LockContext(ctx, &mutex); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("queued observation did not retain its original deadline", err)
	}
	if mutex.TryLock() {
		t.Fatal("expired observation released the original mutation owner")
	}
	mutex.Unlock()
	if err := LockContext(context.Background(), &mutex); err != nil {
		t.Fatal("expired waiter retained later ownership", err)
	}
	mutex.Unlock()
}

func TestNetworkContextReadLockRetainsOriginalWriter(t *testing.T) {
	var mutex sync.RWMutex
	mutex.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	entered, done := make(chan struct{}), make(chan error, 1)
	go func() { close(entered); done <- RLockContext(ctx, &mutex) }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("queued read lost caller cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled read still waited on the original writer")
	}
	if mutex.TryRLock() {
		t.Fatal("cancelled observation released the original writer")
	}
	mutex.Unlock()
	if err := RLockContext(context.Background(), &mutex); err != nil {
		t.Fatal(err)
	}
	mutex.RUnlock()
}

func TestNetworkContextLockRejectsLateAcquisition(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var acquired, released int
	err := lockContext(ctx, func() bool { acquired++; cancel(); return true }, func() { released++ })
	if !errors.Is(err, context.Canceled) || acquired != 1 || released != 1 {
		t.Fatal("cancelled admission retained the newly acquired lock", err, acquired, released)
	}
	var mutex sync.Mutex
	if err := LockContext(ctx, &mutex); !errors.Is(err, context.Canceled) || !mutex.TryLock() {
		t.Fatal("already cancelled caller acquired ownership", err)
	}
	mutex.Unlock()
	if LockContext(nil, &mutex) == nil || LockContext(context.Background(), nil) == nil || RLockContext(context.Background(), nil) == nil {
		t.Fatal("missing caller or mutex acquired observation authority")
	}
}
