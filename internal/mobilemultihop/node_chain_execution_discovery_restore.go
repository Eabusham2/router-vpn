package mobilemultihop

import "context"

// PlanOriginalContext validates fresh discovery while retaining every original
// frontend credential, port, source and configuration byte. The fresh challenge
// is a new acquisition authority, not permission to re-plan a restored path.
// No request is sent here. Runtime acquires its own fresh immutable attempt.
func (o *NodeChainExecutionDiscoveryOwner) PlanOriginalContext(ctx context.Context, original *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if o == nil || ctx == nil || original.validateCapture() != nil || o.prep.validateCapture() != nil ||
		o.prep.LocalSource() != original.source.LocalSource || o.prep.Execution() != original.Execution() {
		return nil, nodeChainExecutionError
	}
	if err := o.io.observe(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	raw, planned := o.raw, o.planned
	o.mu.Unlock()
	if raw == "" || planned {
		return nil, nodeChainExecutionError
	}
	// This closed method compares all original descriptor, selected DNS,
	// configured range and peer fields; it changes no native/static field.
	if _, err := original.NewAttempt(raw); err != nil {
		return nil, err
	}
	projection, err := o.prep.BindExecution(original)
	if err != nil {
		return nil, err
	}
	if err := o.io.observe(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.io.closed.Load() || ctx.Err() != nil || o.raw != raw || o.planned {
		return nil, nodeChainExecutionError
	}
	o.planned = true
	return projection, nil
}
