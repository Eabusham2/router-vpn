package mobilemultihop

import "encoding/json"

// ValidateDesktopProjection binds a child's saved choice to the exact adopted
// descriptor, listener and source already pinned by its original parent.
func (last NodeChainExecutionLast) ValidateDesktopProjection(projection *NodeChainExecutionProjection) error {
	if projection.validateCapture() != nil || projection.preparation.desktop == nil {
		return nodeChainExecutionError
	}
	return last.validateProjection(projection)
}

// NewDesktopNodeChainExecutionLastPreparation binds the already-proved choice
// and original probe target to the authenticated child preparation. It grants
// no native owner or live proof. A restoring parent must first join its old
// child/TUN and derive original from that captured policy and MTU readback.
// The new child uses fresh entry discovery and fresh isolated credentials, but
// proves only this saved choice; it must never rerun Compare.
func NewDesktopNodeChainExecutionLastPreparation(original *DesktopNodeChainPolicy, execution, saved string) (*NodeChainExecutionPreparation, error) {
	p, err := NewDesktopNodeChainExecutionPreparation(original, execution)
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
	p.desktopPhysical, err = newDesktopNodeChainExecutionPhysicalPolicy(p)
	if err != nil || p.desktopPhysical.Validate() != nil || last.ValidatePreparation(p) != nil {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

// DesktopLast returns only a validated source-bound choice. Absence means a
// fresh Server/Compare request; malformed, foreign or mobile data is an error.
func (p *NodeChainExecutionPreparation) DesktopLast() (NodeChainExecutionLast, bool, error) {
	if p.validateCapture() != nil || p.desktop == nil {
		return NodeChainExecutionLast{}, false, nodeChainExecutionError
	}
	if p.source.DesktopLast == "" {
		return NodeChainExecutionLast{}, false, nil
	}
	last, err := ParseNodeChainExecutionLast(p.source.DesktopLast, p)
	return last, err == nil, err
}

func (r *NodeChainExecutionRuntime) desktopSavedChoiceCurrent() bool {
	saved := r.projection.preparation.source.DesktopLast
	if saved == "" {
		return true
	}
	if r.lastPlan != nil {
		return r.lastPlan.last.JSON() == saved
	}
	// A later MTU pause/resume uses the existing joined restore capsule. It
	// must retain the same saved winner/target, not re-enter fresh comparison.
	if r.restore != nil {
		last, err := ParseNodeChainExecutionLast(saved, r.projection.preparation)
		return err == nil && last.validateProjection(r.projection) == nil &&
			r.restore.execution == last.Execution() && r.restore.result.Target == last.Target()
	}
	return false
}
