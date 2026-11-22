package mobilemultihop

import (
	"context"
	"encoding/json"
)

// ValidateMultipleImportedDesktopProjection binds a child's saved choice to the exact adopted
// descriptor, listener and source already pinned by its original parent.
func (last NodeChainExecutionLast) ValidateMultipleImportedDesktopProjection(projection *NodeChainExecutionProjection) error {
	if projection == nil || projection.preparation == nil || projection.preparation.multiple == nil || projection.preparation.multiple.desktop == nil {
		return nodeChainExecutionError
	}
	return last.validateProjection(projection)
}

// NewDesktopNodeChainMultipleImportedExecutionLastPreparation binds the already-proved choice
// and original probe target to the authenticated child preparation. It grants
// no native owner or live proof. A restoring parent must first join its old
// child/TUN and derive original from that captured policy and MTU readback.
// The new child uses fresh entry discovery and fresh isolated credentials, but
// proves only this saved choice; it must never rerun Compare.
func NewDesktopNodeChainMultipleImportedExecutionLastPreparation(original *DesktopNodeChainPolicy, execution, saved string) (*NodeChainExecutionPreparation, error) {
	p, err := NewDesktopNodeChainMultipleImportedExecutionPreparation(original, execution)
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
	p.rememberMultipleImportedSeal()
	if p.multiple.desktop.physical.Validate() != nil || last.ValidatePreparation(p) != nil {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

// DesktopLast returns only a validated source-bound choice. Absence means a
// fresh Server/Compare request; malformed, foreign or mobile data is an error.
func (p *NodeChainExecutionPreparation) MultipleImportedDesktopLast() (NodeChainExecutionLast, bool, error) {
	if p.validateCapture() != nil || p.multiple == nil || p.multiple.desktop == nil {
		return NodeChainExecutionLast{}, false, nodeChainExecutionError
	}
	if p.source.DesktopLast == "" {
		return NodeChainExecutionLast{}, false, nil
	}
	last, err := ParseNodeChainExecutionLast(p.source.DesktopLast, p)
	return last, err == nil, err
}

// CaptureMultipleImportedDesktopLastContext requires the same typed native desktop binding
// before and after the runtime's original fresh proof and selected-choice capture.
func (r *NodeChainExecutionRuntime) CaptureMultipleImportedDesktopLastContext(ctx context.Context) (NodeChainExecutionLast, error) {
	if r == nil || ctx == nil || r.projection == nil || r.projection.preparation == nil || r.projection.preparation.multiple == nil || r.projection.preparation.multiple.desktop == nil {
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	projection := r.projection
	preparation := projection.preparation
	binding := preparation.multiple
	desktop := binding.desktop
	physical, original, source, native := desktop.physical, desktop.original, desktop.source, desktop.native
	// Core capture validates this exact projection/Last record and brackets
	// Verify with fresh source/native health checks. Keep its original result;
	// repeating the whole source walk here adds no intervening observation.
	last, err := r.CaptureLastContext(ctx)
	if err != nil {
		return NodeChainExecutionLast{}, err
	}
	if err := ctx.Err(); err != nil {
		return NodeChainExecutionLast{}, err
	}
	if r.projection != projection || projection.preparation != preparation || preparation.multiple != binding || binding.desktop != desktop || desktop.physical != physical || desktop.original != original || desktop.source != source || desktop.native != native {
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	return last, nil
}
