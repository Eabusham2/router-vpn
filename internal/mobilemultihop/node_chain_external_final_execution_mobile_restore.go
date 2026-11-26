package mobilemultihop

import (
	"context"
	"reflect"
)

// The transport and entry remain the original source objects. Only the
// device's observed TUN can change between the old and replacement Box.
type nodeChainExternalFinalMobileRestore struct {
	mobile            *nodeChainExecutionMobileProjection
	capture           NodeChainExecutionMobileRestoreCapture
	policy            *NodeChainExecutionPolicy
	config, configSHA string
	bound             NodeChainMTUPlan
}

func (c NodeChainExecutionMobileRestoreCapture) OriginalExternalFinalPolicyContext(ctx context.Context) (*NodeChainExecutionPolicy, error) {
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	orig := c.restore.projection
	if orig == nil || orig.preparation.externalFinal == nil || orig.preparation.desktop != nil || orig.preparation.local.projection.Kind != "" || orig.policy == nil || orig.policy.externalFinal != orig.preparation.externalFinal || orig.policy.local != orig.preparation.local || orig.policy.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return orig.policy, nil
}

func (c NodeChainExecutionMobileRestoreCapture) newExternalFinalPreparationContext(ctx context.Context) (*NodeChainExecutionPreparation, error) {
	orig, err := c.OriginalExternalFinalPolicyContext(ctx)
	if err != nil {
		return nil, err
	}
	local := orig.local
	config, err := projectNodeChainTUN(local.config, local.finalPreferences(), c.readback.TargetOS, c.readback.MTU)
	if err != nil {
		return nil, err
	}
	bound, err := nodeChainProjectedMTUPlan(config, local.proofs, nodeChainProjection{TargetOS: c.readback.TargetOS, RestoredMTU: c.readback.MTU})
	if err != nil || bound.Original != c.readback.MTU || bound.TUNTag != c.readback.TUNTag || bound.Original > bound.Ceiling {
		return nil, nodeChainExecutionError
	}
	b, err := newExternalFinalExecutionBinding(local)
	if err != nil {
		return nil, err
	}
	m := &nodeChainExecutionMobileProjection{chain: local, executionSource: orig.Source(), readback: c.readback}
	m.externalFinal = &nodeChainExternalFinalMobileRestore{m, c, orig, config, externalDigest([]byte(config)), bound}
	prep, err := newNodeChainExecutionPreparationOwnedFamilies(local.sourceJSON, orig.Execution(), nil, m, local, nil, nil, nil, nil, nil, nil, nil, nil, b)
	if err != nil {
		return nil, err
	}
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	return prep, nil
}

func (d *nodeChainExternalFinalMobileRestore) validate(p *NodeChainExecutionPreparation) error {
	if d == nil || p == nil || d.mobile == nil || p.mobile != d.mobile || d.mobile.externalFinal != d || d.mobile.multiple != nil || d.mobile.socks != nil || d.mobile.connect != nil || d.mobile.openvpn != nil || d.capture.engine == nil || d.capture.restore.owner == nil || d.capture.restore.projection == nil || d.capture.restore.projection.policy != d.policy || d.policy == nil || d.policy.externalFinal == nil || p.externalFinal == nil || p.local != d.policy.local || d.mobile.chain != p.local || d.mobile.executionSource != d.policy.Source() || d.mobile.readback != d.capture.readback || !p.externalFinal.current(p) {
		return nodeChainExecutionError
	}
	r := d.capture.readback
	if r.TargetOS != "android" && r.TargetOS != "ios" || !proofID.MatchString(r.ReaderNonce) || r.ReaderGeneration == 0 || !exactID.MatchString(r.InterfaceName) || r.InterfaceIndex <= 0 || r.Identity != d.capture.restore.identity || r.Identity.SourceSHA256 != d.policy.SourceSHA256() || d.config == "" || externalDigest([]byte(d.config)) != d.configSHA || d.bound.TUNTag != r.TUNTag || d.bound.Original != r.MTU || r.MTU > d.bound.Ceiling {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionPreparation) bindExternalFinalMobileOriginal(ctx context.Context, orig *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p == nil || p.mobile == nil || p.mobile.externalFinal == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	d := p.mobile.externalFinal
	original, err := d.capture.OriginalExternalFinalPolicyContext(ctx)
	if err != nil || orig != original || orig != d.policy {
		return nil, nodeChainExecutionError
	}
	exact, err := NewNodeChainExternalFinalExecutionPolicy(p, orig.Source())
	if err != nil || !reflect.DeepEqual(exact.Request(), orig.Request()) {
		return nil, nodeChainExecutionError
	}
	projection, err := p.BindExecution(exact)
	if err != nil {
		return nil, err
	}
	if err := d.capture.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	return projection, nil
}

func (p *NodeChainExecutionPreparation) bindExternalFinalMobileProjected(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	d := p.mobile.externalFinal
	if d.validate(p) != nil || policy.Source() != p.mobile.executionSource || policy.externalFinal != p.externalFinal {
		return nil, nodeChainExecutionError
	}
	// The original sealed transition retains every original private front. The
	// platform projection can replace only the TUN recorded by this capsule.
	return p.bindProjectedExecutionAddition(policy, d.capture.restore.projection)
}
