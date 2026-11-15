package mobilemultihop

import (
	"context"
	"encoding/json"
	"reflect"
)

// This private adjunct can only be minted from the original joined restore
// capsule. It retains every original typed pointer and derives only the issued
// system TUN readback; it is never reconstructed from JSON or caller MTU.
type nodeChainCONNECTExecutionMobileRestore struct {
	self         *nodeChainCONNECTExecutionMobileRestore
	mobile       *nodeChainExecutionMobileProjection
	capture      NodeChainExecutionMobileRestoreCapture
	source       *NodeChainCONNECTSource
	local        *NodeChain
	policy       *NodeChainExecutionPolicy
	config       string
	sealedConfig string
	bound        NodeChainMTUPlan
}

func (m *nodeChainExecutionMobileProjection) config() string {
	if m == nil || m.chain == nil {
		return ""
	}
	if m.socks != nil {
		return m.socks.config
	}
	if m.connect != nil {
		return m.connect.config
	}
	return m.chain.Config()
}
func (d *nodeChainCONNECTExecutionMobileRestore) validate(p *NodeChainExecutionPreparation) error {
	if d == nil || d.self != d || d.mobile == nil || d.mobile.connect != d || p == nil || p.mobile != d.mobile || p.connect == nil || p.connect.desktop != nil || p.desktop != nil || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopLast != "" || d.capture.engine == nil || d.capture.restore.owner == nil || d.capture.restore.projection.validateCapture() != nil || d.capture.restore.projection.policy != d.policy || d.capture.restore.projection.preparation.connect == nil || d.capture.restore.projection.preparation.connect.desktop != nil || d.capture.restore.projection.preparation.connect.source != d.source || d.policy.local != d.local || p.local != d.local || d.mobile.chain != d.local || p.connect.source != d.source || d.mobile.readback != d.capture.readback || d.mobile.executionSource != d.capture.restore.projection.Source() || d.source.desktop != nil || d.local.validateCONNECTSource() != nil {
		return nodeChainExecutionError
	}
	readback := d.mobile.readback
	if (readback.TargetOS != "android" && readback.TargetOS != "ios") || !proofID.MatchString(readback.ReaderNonce) || readback.ReaderGeneration == 0 || !exactID.MatchString(readback.InterfaceName) || readback.InterfaceIndex <= 0 || !proofID.MatchString(readback.Identity.ConfigSHA256) {
		return nodeChainExecutionError
	}
	if d.config == "" || d.config != d.sealedConfig || d.bound.Original != readback.MTU || d.bound.TUNTag != readback.TUNTag || readback.MTU > d.bound.Ceiling {
		return nodeChainExecutionError
	}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-connect-execution-source-v1", d.mobile.executionSource})
	if externalDigest(digest) != readback.Identity.SourceSHA256 {
		return nodeChainExecutionError
	}
	return nil
}
func (c NodeChainExecutionMobileRestoreCapture) newCONNECTPreparationContext(ctx context.Context) (*NodeChainExecutionPreparation, error) {
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	original := c.restore.projection
	if original.preparation.connect == nil || original.preparation.connect.desktop != nil {
		return nil, nodeChainExecutionError
	}
	source := original.preparation.connect.source
	local := original.policy.local
	if local.connectSource != source || local.validateCONNECTSource() != nil {
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
	d := &nodeChainCONNECTExecutionMobileRestore{mobile: mobile, capture: c, source: source, local: local, policy: original.policy, config: config, sealedConfig: config, bound: bound}
	d.self = d
	mobile.connect = d
	preparation, err := newNodeChainExecutionPreparationCaptured(source.sourceJSON, original.Execution(), nil, mobile, local, source)
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
func (p *NodeChainExecutionPreparation) bindCONNECTMobileOriginal(ctx context.Context, original *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p == nil || p.mobile == nil || p.mobile.connect == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	d := p.mobile.connect
	if original != d.policy || d.capture.validateRetiredContext(ctx) != nil {
		return nil, nodeChainExecutionError
	}
	rebound, err := NewNodeChainCONNECTExecutionPolicy(p, original.Source())
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
func (p *NodeChainExecutionPreparation) bindCONNECTMobileProjected(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if p.mobile == nil || p.mobile.connect == nil || p.mobile.connect.validate(p) != nil || policy.Source() != p.mobile.executionSource {
		return nil, nodeChainExecutionError
	}
	original, err := NewNodeChainCONNECTExecutionPreparation(p.connect.source, p.Execution())
	if err != nil {
		return nil, err
	}
	exact, err := NewNodeChainCONNECTExecutionPolicy(original, policy.Source())
	if err != nil {
		return nil, err
	}
	addition, err := original.BindExecution(exact)
	if err != nil {
		return nil, err
	}
	return p.bindProjectedExecutionAddition(policy, addition)
}

// OriginalCONNECTPolicyContext exposes only the policy retained by this exact
// joined mobile capsule. Re-parsing identical bytes cannot recover its owner.
func (c NodeChainExecutionMobileRestoreCapture) OriginalCONNECTPolicyContext(ctx context.Context) (*NodeChainExecutionPolicy, error) {
	if err := c.validateRetiredContext(ctx); err != nil {
		return nil, err
	}
	original := c.restore.projection
	if original.preparation.connect == nil || original.preparation.connect.desktop != nil || original.policy == nil || original.policy.validateCapture() != nil || original.policy.local != original.preparation.local {
		return nil, nodeChainExecutionError
	}
	return original.policy, nil
}
