package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
)

// The ordinary preparation source remains unchanged. Only this private typed
// projection can derive a nonzero mobile restore MTU. Parsing Source again
// reconstructs the ordinary graph, never this captured native observation.
type nodeChainExecutionMobileProjection struct {
	chain           *NodeChain
	executionSource string
	readback        NodeChainExecutionTUNReadback
}

func (p *NodeChainExecutionPreparation) validateMobileCapture() error {
	m := p.mobile
	if m == nil || m.chain == nil || m.chain.validateCapture() != nil || p.desktop != nil || p.source.Desktop != nil ||
		m.chain.sourceJSON != p.source.LocalSource || m.chain.projection.TargetOS != m.readback.TargetOS ||
		m.chain.projection.RestoredMTU != m.readback.MTU || m.readback.TargetOS != "android" && m.readback.TargetOS != "ios" ||
		!proofID.MatchString(m.readback.ReaderNonce) || m.readback.ReaderGeneration == 0 || !exactID.MatchString(m.readback.InterfaceName) ||
		m.readback.InterfaceIndex <= 0 || !proofID.MatchString(m.readback.Identity.ConfigSHA256) {
		return nodeChainExecutionError
	}
	bound, err := m.chain.MTUPlan()
	if err != nil || bound.Original != m.readback.MTU || bound.TUNTag != m.readback.TUNTag || m.readback.MTU > bound.Ceiling {
		return errors.Join(err, nodeChainExecutionError)
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-execution-source-v1", m.executionSource})
	if externalDigest(digest) != m.readback.Identity.SourceSHA256 {
		return nodeChainExecutionError
	}
	return nil
}

// MobileRestoreReadback exposes a copy for native actual-target/config checks.
// It cannot create a preparation or substitute native/host retirement proof.
func (p *NodeChainExecutionPreparation) MobileRestoreReadback() (NodeChainExecutionTUNReadback, error) {
	if p.validateCapture() != nil || p.mobile == nil {
		return NodeChainExecutionTUNReadback{}, nodeChainExecutionError
	}
	return p.mobile.readback, nil
}

// The opaque capsule retains both the already-proved execution result and an
// actual original native reader observation. No caller MTU, JSON record or
// newly observed interface can grant this process-owned restore authority.
type NodeChainExecutionMobileRestoreCapture struct {
	restore  NodeChainExecutionRestoreCapture
	readback NodeChainExecutionTUNReadback
	engine   NodeChainExecutionTUNReadbackEngine
}

func (r *NodeChainExecutionRuntime) CaptureMobileRestoreContext(ctx context.Context) (NodeChainExecutionMobileRestoreCapture, error) {
	engine, release, err := r.beginTUNReadbackContext(ctx)
	if err != nil {
		return NodeChainExecutionMobileRestoreCapture{}, err
	}
	defer release()
	if r.projection.preparation.desktop != nil {
		return NodeChainExecutionMobileRestoreCapture{}, nodeChainExecutionError
	}
	restore, err := r.CaptureRestoreContext(ctx)
	if err != nil {
		return NodeChainExecutionMobileRestoreCapture{}, err
	}
	readback, err := r.captureTUNReadbackContext(ctx, engine)
	if err != nil || readback.Identity != restore.identity || readback.TargetOS != "android" && readback.TargetOS != "ios" {
		return NodeChainExecutionMobileRestoreCapture{}, errors.Join(err, nodeChainExecutionError)
	}
	return NodeChainExecutionMobileRestoreCapture{restore, readback, engine}, nil
}

func (c NodeChainExecutionMobileRestoreCapture) validateRetiredContext(ctx context.Context) error {
	if ctx == nil || c.engine == nil || c.restore.owner == nil || c.restore.projection.validateCapture() != nil ||
		c.restore.projection.preparation.desktop != nil || c.readback.TargetOS != "android" && c.readback.TargetOS != "ios" ||
		c.restore.projection.validateTUNReadback(c.readback, c.restore.identity) != nil {
		return nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.sharedClosedContext(ctx); err != nil {
		return err
	}
	if err := c.engine.ExecutionTUNReadbackRetiredContext(ctx, c.readback); err != nil {
		return err
	}
	if err := c.sharedClosedContext(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func (c NodeChainExecutionMobileRestoreCapture) sharedClosedContext(ctx context.Context) error {
	owner := c.restore.owner
	if err := externalObservationLock(ctx, &owner.mu); err != nil {
		return err
	}
	closed := owner.closed && owner.active == nil && owner.identity == c.restore.identity && owner.projection == c.restore.projection
	owner.mu.Unlock()
	if !closed {
		return errors.New("original mobile execution cleanup has not joined")
	}
	return ctx.Err()
}

// SourceContext returns only the original logical execution policy after
// shared cleanup and exact captured engine/reader retirement. The bridge must
// additionally require its original daemon Instance.Close joined receipt.
func (c NodeChainExecutionMobileRestoreCapture) SourceContext(ctx context.Context) (string, error) {
	if err := c.validateRetiredContext(ctx); err != nil {
		return "", err
	}
	return c.restore.projection.Source(), nil
}

// NewPreparationContext derives only the actual captured system TUN MTU.
// Member source bytes, endpoint MTUs, DNS, order and front credentials remain
// original. This is a pure typed projection, not a native-close receipt; the
// bridge must prove its exact original Instance.Close before creating a Box.
func (c NodeChainExecutionMobileRestoreCapture) NewPreparationContext(ctx context.Context) (*NodeChainExecutionPreparation, error) {
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	p := c.restore.projection
	chain, err := ProjectNodeChain(p.policy.local, c.readback.TargetOS, c.readback.MTU)
	if err != nil {
		return nil, err
	}
	mobile := &nodeChainExecutionMobileProjection{chain, p.Source(), c.readback}
	preparation, err := newNodeChainExecutionPreparationProjected(p.preparation.LocalSource(), p.Execution(), nil, mobile)
	if err != nil {
		return nil, err
	}
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	return preparation, nil
}

// The native adapter must have constructed the actual typed preparation graph
// and adopted only its original execution policy. This preserves the proved
// choice/target and still requires a fresh EngineID and SessionID during Run.
// It never confers the bridge's separate Instance.Close authority.
func NewMobileNodeChainExecutionRestoreRuntime(ctx context.Context, capture NodeChainExecutionMobileRestoreCapture, projection *NodeChainExecutionProjection, engine NodeChainExecutionEngine) (*NodeChainExecutionRuntime, error) {
	if err := capture.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	if projection.validateCapture() != nil || projection.preparation.mobile == nil ||
		projection.preparation.mobile.readback != capture.readback ||
		projection.Source() != capture.restore.projection.Source() || projection.SourceSHA256() != capture.restore.identity.SourceSHA256 ||
		projection.Execution() != capture.restore.projection.Execution() {
		return nil, nodeChainExecutionError
	}
	runtime, err := NewNodeChainExecutionRestoreRuntime(capture.restore, engine)
	if err != nil {
		return nil, err
	}
	runtime.projection = projection
	return runtime, nil
}
