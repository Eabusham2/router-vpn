package mobileperf

import (
	"context"
	"errors"
	"time"
)

// HealthyContext observes the original worker and exact native route without
// converting a cancelled read into worker invalidation.
func (c *Cover) HealthyContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("cover observation has no caller")
	}
	if c == nil {
		return errors.New("cover worker is unavailable")
	}
	lock := func() error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			if c.mu.TryLock() {
				if err := ctx.Err(); err != nil {
					c.mu.Unlock()
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
	if err := lock(); err != nil {
		return err
	}
	active := !c.closed && c.running && c.status.Active
	owned, identity, lastReply, generation := c.activeCtx, c.identity, c.lastReply, c.generation
	c.mu.Unlock()
	if !active || owned == nil || owned.Err() != nil || time.Since(lastReply) > 2*time.Second {
		return errors.New("cover proof is retired or expired")
	}
	observer, ok := c.engine.(interface {
		IdentityContext(context.Context) (string, error)
	})
	if !ok {
		return errors.New("cover native owner has no bounded observation")
	}
	current, err := observer.IdentityContext(ctx)
	if err != nil {
		return err
	}
	if current == "" || current != identity {
		return errors.New("cover native route changed")
	}
	if err := lock(); err != nil {
		return err
	}
	defer c.mu.Unlock()
	if c.closed || !c.running || !c.status.Active || c.activeCtx != owned || owned.Err() != nil || c.identity != identity || c.generation != generation || time.Since(c.lastReply) > 2*time.Second {
		return errors.New("cover owner changed during observation")
	}
	return ctx.Err()
}
