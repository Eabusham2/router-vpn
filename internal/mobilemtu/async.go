package mobilemtu

import (
	"context"
	"errors"
	"time"
)

// Start publishes a cancellable operation before returning to native IPC. In
// contrast to dispatching Run from a platform worker, an immediate Cancel can
// never arrive before the request has an owner and be silently discarded.
func (c *Controller) Start(request string, force bool) error {
	if !requestPattern.MatchString(request) {
		return errors.New("invalid MTU request identity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.invalid || c.status.Running {
		return errors.New("MTU owner is busy, stopped or invalidated")
	}
	if !c.Requested() {
		return errors.New("choose Auto MTU without Jumbo before Retest")
	}
	if c.status.Request == request {
		return errors.New("MTU request identifiers cannot be reused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	done := make(chan struct{})
	c.cancel = cancel
	c.done = done
	c.status = Status{Request: request, Phase: "capturing", Running: true, Source: "unmeasured", Candidates: []Candidate{}}
	config := c.currentConfig
	go func() {
		defer close(done)
		defer cancel()
		err := c.run(ctx, config, force)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.status.Running = false
		c.status.Complete = true
		if err != nil {
			if c.status.Failure == "" {
				c.status.Failure = "MTU measurement or adoption failed"
			}
			if !c.status.Restored {
				c.status.Phase = "failed"
			}
		}
	}()
	return nil
}
func (c *Controller) Running() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.status.Running }
