package mobilemultihop

import "context"

// This separate native contract proves the original Box.Close joined after
// shared IO/remote retirement. A cancelled context or closed stage is not an
// original native close receipt. Mobile restore also retains its real reader.
type NodeChainMultipleImportedExecutionRetiredObserver interface {
	MultipleImportedExecutionRetiredContext(context.Context, *NodeChain) error
}

type nodeChainMultipleImportedExecutionRestoreReceipt struct {
	self        *nodeChainMultipleImportedExecutionRestoreReceipt
	preparation *NodeChainExecutionPreparation
	old         *NodeChainExecutionRuntime
	engine      NodeChainExecutionEngine
	identity    NodeChainIdentity
}

func (c *nodeChainMultipleImportedExecutionRestoreReceipt) validate(r *NodeChainExecutionRuntime) error {
	if c == nil || c.self != c || r == nil || c.preparation != r.projection.preparation || c.preparation.multiple == nil || c.old == nil ||
		!nodeChainOpenVPNExecutionEnginePointer(c.engine) || !nodeChainOpenVPNExecutionEnginePointer(r.engine) || c.engine != r.engine || c.identity != r.identity {
		return nodeChainExecutionError
	}
	return nil
}
func (c NodeChainExecutionRestoreCapture) multipleImportedOriginalClosedContext(ctx context.Context) error {
	if ctx == nil || c.owner == nil || c.projection.validateCapture() != nil || c.projection.preparation.multiple == nil {
		return nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &c.owner.mu); err != nil {
		return err
	}
	closed := c.owner.closed && c.owner.active == nil && c.owner.identity == c.identity && c.owner.projection == c.projection && c.owner.retired.Load()
	c.owner.mu.Unlock()
	if !closed {
		return nodeChainExecutionError
	}
	return ctx.Err()
}
func (r *NodeChainExecutionRuntime) admitMultipleImportedExecutionRestoreContext(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	prep := r.projection.preparation
	if prep.multiple == nil || r.restore == nil || r.mtuResume != nil || r.restore.projection.preparation != prep {
		return nil
	}
	capture := *r.restore
	if err := capture.multipleImportedOriginalClosedContext(ctx); err != nil {
		return err
	}
	old := capture.owner
	if !nodeChainOpenVPNExecutionEnginePointer(r.engine) || !nodeChainOpenVPNExecutionEnginePointer(old.engine) || r.engine == old.engine || r.identity.EngineID == capture.identity.EngineID || r.identity.SessionID == capture.identity.SessionID {
		return nodeChainExecutionError
	}
	native, ok := old.engine.(NodeChainMultipleImportedExecutionRetiredObserver)
	if !ok {
		return nodeChainExecutionError
	}
	for i := 0; i < 2; i++ {
		if err := native.MultipleImportedExecutionRetiredContext(ctx, prep.multiple.source); err != nil {
			return err
		}
		if err := capture.multipleImportedOriginalClosedContext(ctx); err != nil {
			return err
		}
		if err := prep.observeMultipleImportedExecutionContext(ctx, r.engine); err != nil {
			return err
		}
		observed, err := r.engine.ObserveChainContext(ctx)
		if err != nil {
			return err
		}
		if observed != r.identity || !r.identityMatches(observed) {
			return nodeChainExecutionError
		}
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	defer r.mu.Unlock()
	if r.multipleRestore != nil || r.closed || r.retired.Load() || ctx.Err() != nil || r.restore == nil || r.restore.owner != old || r.restore.projection != capture.projection || r.projection != capture.projection {
		return nodeChainExecutionError
	}
	receipt := &nodeChainMultipleImportedExecutionRestoreReceipt{preparation: prep, old: old, engine: r.engine, identity: r.identity}
	receipt.self = receipt
	r.multipleRestore = receipt
	return nil
}
func (r *NodeChainExecutionRuntime) validateMultipleImportedRestoreContext(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	receipt := r.multipleRestore
	var err error
	if receipt != nil {
		err = receipt.validate(r)
	}
	r.mu.Unlock()
	return err
}

func (r *NodeChainExecutionRuntime) observeMultipleImportedExecutionCurrentContext(ctx context.Context) error {
	if err := r.validateMultipleImportedRestoreContext(ctx); err != nil {
		return err
	}
	return r.projection.preparation.observeMultipleImportedExecutionContext(ctx, r.engine)
}
