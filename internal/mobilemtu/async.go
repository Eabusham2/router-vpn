package mobilemtu

import (
	"context"
	"errors"
	"time"
)

type operation struct {
	ctx    context.Context
	cancel context.CancelFunc
	finish context.CancelFunc
	done   chan struct{}
	config string
}

// begin publishes the cancellable generation before native IPC can return.
// Both synchronous and asynchronous callers acquire the same exclusive owner.
func (c *Controller) begin(request string) (*operation, error) {
	return c.beginContext(context.Background(), request, false)
}
func (c *Controller) beginContext(parent context.Context, request string, strict bool) (*operation, error) {
	return c.beginContextAdmission(parent, request, strict, nil)
}
func (c *Controller) beginContextAdmission(parent context.Context, request string, strict bool, admit func(context.Context) error) (*operation, error) {
	return c.beginContextAdmissionOn(parent, parent, request, strict, admit)
}
func (c *Controller) beginContextAdmissionOn(admission, parent context.Context, request string, strict bool, admit func(context.Context) error) (*operation, error) {
	if parent == nil || admission == nil {
		return nil, errors.New("MTU operation has no caller")
	}
	if strict {
		if _, ok := c.owner.(ContextOwner); !ok {
			return nil, errors.New("MTU owner has no bounded capture")
		}
	}

	if !requestPattern.MatchString(request) {
		return nil, errors.New("invalid MTU request identity")
	}
	if err := LockContext(admission, &c.mu); err != nil {
		return nil, err
	}
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
	budget, _, _ := c.measurementBudgets()
	ctx, finish, err := WithOperationContext(parent, budget, 8*time.Second)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	ctx = context.WithValue(ctx, boundedOperationKey{}, strict)
	op := &operation{ctx: ctx, cancel: cancel, finish: finish, done: make(chan struct{}), config: c.currentConfig}
	if admit != nil {
		call, stopCall := context.WithCancel(ctx)
		stopAdmission := context.AfterFunc(admission, stopCall)
		if deadline, ok := admission.Deadline(); ok {
			bounded, stopDeadline := context.WithDeadline(call, deadline)
			call = bounded
			defer stopDeadline()
		}
		if err := admission.Err(); err != nil {
			stopCall()
		}
		admissionErr := call.Err()
		if admissionErr == nil {
			admissionErr = admit(call)
		}
		// Preserve successful native admission so its exact generation drains,
		// but never let a late acknowledgement admit work after its caller left.
		acknowledgementErr := errors.Join(call.Err(), admission.Err())
		stopAdmission()
		stopCall()
		if err := admissionErr; err != nil {
			cancel()
			finish()
			return nil, err
		}
		if acknowledgementErr != nil {
			cancel()
		}
	}
	c.cancel = cancel
	c.done = op.done
	c.status = Status{Request: request, Phase: "capturing", Running: true, Source: "unmeasured", Candidates: []Candidate{}}
	return op, nil
}
func (c *Controller) execute(op *operation, force bool) error {
	defer op.cancel()
	defer op.finish()
	err := errors.Join(c.run(op.ctx, op.config, force), op.ctx.Err())
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
