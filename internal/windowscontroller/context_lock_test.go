package windowscontroller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWindowsObservationLockKeepsCaller(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := lockObservation(ctx, &mu)
	mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held original mutex ignored bounded caller", err)
	}
	live, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	if err := lockObservation(live, &mu); err != nil {
		t.Fatal("expired caller left a mutex waiter", err)
	}
	mu.Unlock()
	if lockObservation(nil, &mu) == nil {
		t.Fatal("missing original caller accepted")
	}
}
