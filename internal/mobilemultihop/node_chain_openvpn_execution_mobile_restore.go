package mobilemultihop

import (
	"context"
	"encoding/json"
	"reflect"
)

// This private adjunct can only be minted from the original joined restore
// capsule. It retains every original typed pointer and derives only the issued
// system TUN readback; it is never reconstructed from JSON or caller MTU.
type nodeChainOpenVPNExecutionMobileRestore struct {
	self         *nodeChainOpenVPNExecutionMobileRestore
	mobile       *nodeChainExecutionMobileProjection
	capture      NodeChainExecutionMobileRestoreCapture
	source       *NodeChain
	local        *NodeChain
	policy       *NodeChainExecutionPolicy
	config       string
	sealedConfig string
	bound        NodeChainMTUPlan
}

func (d *nodeChainOpenVPNExecutionMobileRestore) validate(p *NodeChainExecutionPreparation) error {
	if d == nil || d.self != d || d.mobile == nil || d.mobile.openvpn != d || p == nil || p.mobile != d.mobile || p.openvpn == nil || p.connect != nil || p.socks != nil || d.mobile.connect != nil || d.mobile.socks != nil || p.desktop != nil || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopSOCKS != nil || p.source.DesktopLast != "" || d.capture.engine == nil || d.capture.restore.owner == nil || d.capture.restore.projection.validateCapture() != nil || d.capture.restore.projection.policy != d.policy || d.capture.restore.projection.preparation.openvpn == nil || d.capture.restore.projection.preparation.openvpn.source != d.source || d.policy.local != d.local || p.local != d.local || d.mobile.chain != d.local || p.openvpn.source != d.source || d.mobile.readback != d.capture.readback || d.mobile.executionSource != d.capture.restore.projection.Source() || d.local.validateCapture() != nil {
		return nodeChainExecutionError
	}
	readback := d.mobile.readback
	if (readback.TargetOS != "android" && readback.TargetOS != "ios") || !proofID.MatchString(readback.ReaderNonce) || readback.ReaderGeneration == 0 || !exactID.MatchString(readback.InterfaceName) || readback.InterfaceIndex <= 0 || !proofID.MatchString(readback.Identity.ConfigSHA256) {
		return nodeChainExecutionError
	}
	if d.config == "" || d.config != d.sealedConfig || d.bound.Original != readback.MTU || d.bound.TUNTag != readback.TUNTag || readback.MTU > d.bound.Ceiling {
		return nodeChainExecutionError
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-openvpn-execution-source-v1", d.mobile.executionSource})
	if externalDigest(digest) != readback.Identity.SourceSHA256 {
		return nodeChainExecutionError
	}
	return nil
}
func (c NodeChainExecutionMobileRestoreCapture) newOpenVPNPreparationContext(ctx context.Context) (*NodeChainExecutionPreparation, error) {
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	original := c.restore.projection
	if original.preparation.openvpn == nil || original.preparation.openvpn.source.projection.Kind != "" {
		return nil, nodeChainExecutionError
	}
	source := original.preparation.openvpn.source
	local := original.policy.local
	if local != source || local.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	config, err := projectNodeChainTUN(local.config, local.nodes[len(local.nodes)-1].profile, c.readback.TargetOS, c.readback.MTU)
	if err != nil {
		return nil, err
	}
	bound, err := nodeChainProjectedMTUPlan(config, local.proofs, nodeChainProjection{TargetOS: c.readback.TargetOS, RestoredMTU: c.readback.MTU})
	if err != nil || bound.Original != c.readback.MTU || bound.TUNTag != c.readback.TUNTag || c.readback.MTU > bound.Ceiling {
		return nil, nodeChainExecutionError
	}
	mobile := &nodeChainExecutionMobileProjection{chain: local, executionSource: original.Source(), readback: c.readback}
	d := &nodeChainOpenVPNExecutionMobileRestore{mobile: mobile, capture: c, source: source, local: local, policy: original.policy, config: config, sealedConfig: config, bound: bound}
	d.self = d
	mobile.openvpn = d
	preparation, err := newNodeChainExecutionPreparationOwnedOpenVPN(source.sourceJSON, original.Execution(), nil, mobile, local, nil, nil, nil, nil, source)
	if err != nil {
		return nil, err
	}
	if err = c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	return preparation, nil
}

// Fresh discovery still validates the original descriptor/challenge. Only this
// process-owned capsule may reseal the exact original source under its new
// preparation; a same-content policy or unrelated capsule cannot substitute.
func (p *NodeChainExecutionPreparation) bindOpenVPNMobileOriginal(ctx context.Context, original *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p == nil || p.mobile == nil || p.mobile.openvpn == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	d := p.mobile.openvpn
	if original != d.policy || d.capture.validateRetiredContext(ctx) != nil {
		return nil, nodeChainExecutionError
	}
	rebound, err := NewNodeChainOpenVPNExecutionPolicy(p, original.Source())
	if err != nil || rebound.Source() != original.Source() || !reflect.DeepEqual(rebound.Request(), original.Request()) {
		return nil, nodeChainExecutionError
	}
	projection, err := p.BindExecution(rebound)
	if err != nil {
		return nil, err
	}
	if d.capture.validateRetiredContext(ctx) != nil {
		return nil, nodeChainExecutionError
	}
	return projection, nil
}
func (p *NodeChainExecutionPreparation) bindOpenVPNMobileProjected(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p.mobile == nil || p.mobile.openvpn == nil || p.mobile.openvpn.validate(p) != nil || policy.Source() != p.mobile.executionSource {
		return nil, nodeChainExecutionError
	}
	original, err := NewNodeChainOpenVPNExecutionPreparation(p.openvpn.source, p.Execution())
	if err != nil {
		return nil, err
	}
	exact, err := NewNodeChainOpenVPNExecutionPolicy(original, policy.Source())
	if err != nil {
		return nil, err
	}
	addition, err := original.BindExecution(exact)
	if err != nil {
		return nil, err
	}
	return p.bindProjectedExecutionAddition(policy, addition)
}

// OriginalOpenVPNPolicyContext exposes only the policy retained by this exact
// joined mobile capsule. Re-parsing identical bytes cannot recover its owner.
func (c NodeChainExecutionMobileRestoreCapture) OriginalOpenVPNPolicyContext(ctx context.Context) (*NodeChainExecutionPolicy, error) {
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	original := c.restore.projection
	if original.preparation.openvpn == nil || original.preparation.openvpn.source.projection.Kind != "" || original.policy == nil || original.policy.validateCapture() != nil || original.policy.local != original.preparation.local {
		return nil, nodeChainExecutionError
	}
	return original.policy, nil
}
