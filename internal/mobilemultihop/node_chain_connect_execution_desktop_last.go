package mobilemultihop

import (
	"context"
	"encoding/json"
)

// ValidateCONNECTDesktopProjection binds a child's saved choice to the exact adopted
// descriptor, listener and source already pinned by its original parent.
func (last NodeChainExecutionLast) ValidateCONNECTDesktopProjection(projection *NodeChainExecutionProjection) error {
	if projection.validateCapture() != nil || projection.preparation.connect == nil || projection.preparation.connect.desktop == nil {
		return nodeChainExecutionError
	}
	return last.validateProjection(projection)
}

// NewDesktopNodeChainCONNECTExecutionLastPreparation binds the already-proved choice
// and original probe target to the authenticated child preparation. It grants
// no native owner or live proof. A restoring parent must first join its old
// child/TUN and derive original from that captured policy and MTU readback.
// The new child uses fresh entry discovery and fresh isolated credentials, but
// proves only this saved choice; it must never rerun Compare.
func NewDesktopNodeChainCONNECTExecutionLastPreparation(original *DesktopNodeChainCONNECTPolicy, execution, saved string) (*NodeChainExecutionPreparation, error) {
	p, err := NewDesktopNodeChainCONNECTExecutionPreparation(original, execution)
	if err != nil || saved == "" {
		return nil, nodeChainExecutionError
	}
	last, err := ParseNodeChainExecutionLast(saved, p)
	if err != nil {
		return nil, err
	}
	p.source.DesktopLast = last.JSON()
	raw, err := json.Marshal(p.source)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, nodeChainExecutionError
	}
	p.sourceJSON = string(raw)
	digest, err := json.Marshal([]string{"routervpn-node-chain-execution-preparation-v1", p.sourceJSON})
	if err != nil {
		return nil, err
	}
	p.sourceSHA = externalDigest(digest)
	clear(digest)
	p.discovery.SourceSHA256, p.dns.DNS.SourceSHA256 = p.sourceSHA, p.sourceSHA
	p.seal = p.captureSeal()
	if p.connect.desktop.physical.Validate() != nil || last.ValidatePreparation(p) != nil {
		return nil, nodeChainExecutionError
	}
	p.rememberPreparationSeal()
	return p, nil
}

// DesktopLast returns only a validated source-bound choice. Absence means a
// fresh Server/Compare request; malformed, foreign or mobile data is an error.
func (p *NodeChainExecutionPreparation) CONNECTDesktopLast() (NodeChainExecutionLast, bool, error) {
	if p.validateCapture() != nil || p.connect == nil || p.connect.desktop == nil {
		return NodeChainExecutionLast{}, false, nodeChainExecutionError
	}
	if p.source.DesktopLast == "" {
		return NodeChainExecutionLast{}, false, nil
	}
	last, err := ParseNodeChainExecutionLast(p.source.DesktopLast, p)
	return last, err == nil, err
}

// CaptureCONNECTDesktopLastContext requires the same typed native desktop binding
// before and after the runtime's original fresh proof and selected-choice capture.
func (r *NodeChainExecutionRuntime) CaptureCONNECTDesktopLastContext(ctx context.Context) (NodeChainExecutionLast, error) {
	if r == nil || r.projection == nil || r.projection.validateCapture() != nil || r.projection.preparation.connect == nil || r.projection.preparation.connect.desktop == nil {
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	last, err := r.CaptureLastContext(ctx)
	if err != nil {
		return NodeChainExecutionLast{}, err
	}
	if err = last.ValidateCONNECTDesktopProjection(r.projection); err != nil {
		return NodeChainExecutionLast{}, err
	}
	return last, nil
}
