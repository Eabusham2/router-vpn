package mobilemtu

import (
	"context"
	"errors"
	"time"
)

type operation struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	config string
}

// begin publishes the cancellable generation before native IPC can return.
// Both synchronous and asynchronous callers acquire the same exclusive owner.
func (c *Controller) begin(request string) (*operation, error) {
	if !requestPattern.MatchString(request) {
		return nil, errors.New("invalid MTU request identity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.invalid || c.status.Running {
		return nil, errors.New("MTU owner is busy, stopped or invalidated")
	}
	if !c.Requested() {
		return nil, errors.New("choose Auto MTU without Jumbo before Retest")
	}
	if c.status.Request == request {
		return nil, errors.New("MTU request identifiers cannot be reused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	op := &operation{ctx: ctx, cancel: cancel, done: make(chan struct{}), config: c.currentConfig}
	c.cancel = cancel
	c.done = op.done
	c.status = Status{Request: request, Phase: "capturing", Running: true, Source: "unmeasured", Candidates: []Candidate{}}
	return op, nil
}
func (c *Controller) execute(op *operation, force bool) error {
	defer op.cancel()
	err := c.run(op.ctx, op.config, force)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.Running = false
	c.status.Complete = true
	if c.closed {
		c.revokeLocked("stopped")
		err = context.Canceled
	} else if c.invalid {
		c.revokeLocked("invalidated")
		err = context.Canceled
	} else if err != nil {
		if c.status.Failure == "" {
			c.status.Failure = "MTU measurement or adoption failed"
		}
		if !c.status.Restored {
			c.status.Phase = "failed"
		}
	}
	// Drain the exact generation before another Run/Start can observe it as idle.
	close(op.done)
	return err
}

// Start publishes before launching work; an immediate Cancel cannot be lost.
func (c *Controller) Start(request string, force bool) error {
	op, err := c.begin(request)
	if err != nil {
		return err
	}
	go func() { _ = c.execute(op, force) }()
	return nil
}
func (c *Controller) Running() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.status.Running }
