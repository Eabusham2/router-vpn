package mobilemultihop

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"router-vpn/internal/nativeopenvpn"
)

// This separate native contract is used only to authorize a fresh connected
// receipt when an opaque restore retains the same original preparation. The
// old engine must prove its exact captured source, native owner and successful
// joined Box.Close receipt. A cancelled lifetime or a closed flag is not proof.
// Mobile restore already proves its captured reader/native retirement before
// creating a new preparation and does not use this contract.
type NodeChainOpenVPNExecutionRetiredObserver interface {
	OpenVPNExecutionRetiredContext(context.Context, *NodeChain) error
}

// A restore receipt belongs to one new native engine and identity. It never
// clears or replaces the preparation's original connected anchor. Only a
// joined opaque restore can issue it; same-Box MTU resume retains it unchanged.
type nodeChainOpenVPNExecutionConnectedReceipt struct {
	self        *nodeChainOpenVPNExecutionConnectedReceipt
	preparation *NodeChainExecutionPreparation
	binding     *nodeChainOpenVPNExecutionBinding
	engine      NodeChainExecutionEngine
	identity    NodeChainIdentity
	mu          sync.Mutex
	connected   *nativeopenvpn.PacketObservation
}

func nodeChainOpenVPNExecutionEnginePointer(engine any) bool {
	value := reflect.ValueOf(engine)
	return value.IsValid() && value.Kind() == reflect.Pointer && !value.IsNil()
}

func (c *nodeChainOpenVPNExecutionConnectedReceipt) validate(p *NodeChainExecutionPreparation, engine any) error {
	if c == nil || c.self != c || p == nil || c.preparation != p || c.binding == nil || p.openvpn != c.binding ||
		!nodeChainOpenVPNExecutionEnginePointer(engine) || !nodeChainOpenVPNExecutionEnginePointer(c.engine) || engine != c.engine ||
		!nodeChainIdentityText(c.identity.EngineID) || !nodeChainIdentityText(c.identity.SessionID) || !nodeChainIdentityText(c.identity.NetworkID) {
		return nodeChainExecutionError
	}
	return nil
}

func (r *NodeChainExecutionRuntime) observeOpenVPNExecutionCurrentContext(ctx context.Context, connected bool) error {
	if r == nil || ctx == nil {
		return nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	receipt, identity := r.openvpnRestore, r.identity
	r.mu.Unlock()
	if receipt != nil && (receipt.identity != identity || receipt.validate(r.projection.preparation, r.engine) != nil) {
		return nodeChainExecutionError
	}
	return r.projection.preparation.observeOpenVPNExecutionReceiptContext(ctx, r.engine, connected, receipt)
}

func (c NodeChainExecutionRestoreCapture) openVPNOriginalClosedContext(ctx context.Context) error {
	if ctx == nil || c.owner == nil || c.projection.validateCapture() != nil || c.projection.preparation.openvpn == nil {
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

func (r *NodeChainExecutionRuntime) admitOpenVPNExecutionRestoreContext(ctx context.Context) error {
	if r == nil || ctx == nil {
		return nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	prep := r.projection.preparation
	if prep.openvpn == nil || r.restore == nil || r.mtuResume != nil || r.restore.projection.preparation != prep {
		return nil
	}
	capture := *r.restore
	if err := capture.openVPNOriginalClosedContext(ctx); err != nil {
		return err
	}
	old := capture.owner
	if !nodeChainOpenVPNExecutionEnginePointer(r.engine) || !nodeChainOpenVPNExecutionEnginePointer(old.engine) ||
		r.engine == old.engine || r.identity.EngineID == capture.identity.EngineID || r.identity.SessionID == capture.identity.SessionID {
		return nodeChainExecutionError
	}
	native, ok := old.engine.(NodeChainOpenVPNExecutionRetiredObserver)
	if !ok {
		return nodeChainExecutionError
	}
	if err := native.OpenVPNExecutionRetiredContext(ctx, prep.openvpn.source); err != nil {
		return err
	}
	if err := capture.openVPNOriginalClosedContext(ctx); err != nil {
		return err
	}
	if err := prep.observeOpenVPNExecutionOwnerContext(ctx, r.engine); err != nil {
		return err
	}
	observed, err := r.engine.ObserveChainContext(ctx)
	if err != nil || observed != r.identity || !r.identityMatches(observed) {
		return errors.Join(err, nodeChainExecutionError)
	}
	if err := native.OpenVPNExecutionRetiredContext(ctx, prep.openvpn.source); err != nil {
		return err
	}
	if err := capture.openVPNOriginalClosedContext(ctx); err != nil {
		return err
	}
	if err := prep.observeOpenVPNExecutionOwnerContext(ctx, r.engine); err != nil {
		return err
	}
	confirm, err := r.engine.ObserveChainContext(ctx)
	if err != nil || confirm != observed {
		return errors.Join(err, nodeChainExecutionError)
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return err
	}
	defer r.mu.Unlock()
	if r.openvpnRestore != nil || r.closed || r.retired.Load() || ctx.Err() != nil || r.restore == nil || r.restore.owner != old ||
		r.restore.projection != capture.projection || r.projection != capture.projection || r.identity != observed {
		return nodeChainExecutionError
	}
	receipt := &nodeChainOpenVPNExecutionConnectedReceipt{preparation: prep, binding: prep.openvpn, engine: r.engine, identity: observed}
	receipt.self = receipt
	r.openvpnRestore = receipt
	return nil
}
