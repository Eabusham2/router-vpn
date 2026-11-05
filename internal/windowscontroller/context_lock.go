package windowscontroller

import (
	"context"
	"errors"
	"sync"
	"time"
)

// lockObservation uses the original observation budget and leaves no waiter
// goroutine behind after cancellation. Retained process cleanup still owns mu.
func lockObservation(ctx context.Context, mu *sync.Mutex) error {
	if ctx == nil || mu == nil {
		return errors.New("Windows observation omitted caller or original lock")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mu.TryLock() {
			if err := ctx.Err(); err != nil {
				mu.Unlock()
				return err
			}
			return nil
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
