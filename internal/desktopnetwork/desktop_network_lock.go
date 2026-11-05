package desktopnetwork

import (
	"context"
	"errors"
	"sync"
	"time"
)

// LockContext admits the original caller to an existing mutex without a
// detached waiter. It never replaces or extends the caller's deadline. The
// ordinary Unlock still belongs to a successful caller, so existing native
// mutation and retirement owners keep their exact serialization boundary.
func LockContext(ctx context.Context, mutex *sync.Mutex) error {
	if mutex == nil {
		return errors.New("network observation has no captured mutex")
	}
	return lockContext(ctx, mutex.TryLock, mutex.Unlock)
}

// RLockContext shares the original RWMutex with writers and old readers.
func RLockContext(ctx context.Context, mutex *sync.RWMutex) error {
	if mutex == nil {
		return errors.New("network observation has no captured read mutex")
	}
	return lockContext(ctx, mutex.TryRLock, mutex.RUnlock)
}

func lockContext(ctx context.Context, acquire func() bool, release func()) error {
	if ctx == nil {
		return errors.New("network observation lost its original caller")
	}
	var tick *time.Ticker
	defer func() {
		if tick != nil {
			tick.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if acquire() {
			if err := ctx.Err(); err != nil {
				release()
				return err
			}
			return nil
		}
		if tick == nil {
			tick = time.NewTicker(time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
