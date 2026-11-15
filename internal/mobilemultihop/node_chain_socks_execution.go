package mobilemultihop

import "context"

// A typed execution binding retains the same original SOCKS source and its
// private runtime. It does not grant native construction, socket or Ready
// authority; every engine must separately observe that original native owner.
type nodeChainSOCKSExecutionBinding struct {
	self        *nodeChainSOCKSExecutionBinding
	source      *NodeChainSOCKSSource
	local       *NodeChain
	preparation *NodeChainExecutionPreparation
}

// NewNodeChainSOCKSExecutionPreparation retains the original packet entry,
// SOCKS import and paired SS final behind an initially closed application gate.
func NewNodeChainSOCKSExecutionPreparation(original *NodeChainSOCKSSource, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || execution != "server" && execution != "auto" || original.desktop != nil {
		return nil, nodeChainExecutionError
	}
	_, metadata, err := original.ReadValidated()
	if err != nil || len(metadata.Proofs) != 3 || len(original.pair.nodes) != 2 || metadata.Proofs[1].Position != 1 || metadata.Proofs[2].Mode != "shadowsocks" {
		return nil, nodeChainExecutionError
	}
	runtime, err := NewNodeChainSOCKSRuntime(original)
	if err != nil {
		return nil, err
	}
	return newNodeChainExecutionPreparationFamily(original.sourceJSON, execution, nil, nil, runtime.chain, nil, original)
}

// Restoration creates one new typed construction. It cannot replace the
// source pointer already retained by an existing native execution instance.
func ParseNodeChainSOCKSExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 3 || source.Desktop != nil || source.DesktopCONNECT != nil || source.DesktopLast != "" {
		return nil, nodeChainExecutionError
	}
	original, err := NewNodeChainSOCKSSource(source.LocalSource)
	if err != nil {
		return nil, err
	}
	p, err := NewNodeChainSOCKSExecutionPreparation(original, source.Execution)
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}
func (b *nodeChainSOCKSExecutionBinding) validate(p *NodeChainExecutionPreparation, local *NodeChain) error {
	if b == nil || b.self != b || b.preparation != p || b.local != local || p == nil || p.socks != b || p.connect != nil || local == nil || b.source == nil || local.socksSource != b.source || local.connectSource != nil || len(local.nodes) != 3 || p.desktop != nil || p.source.Schema != 3 || p.source.LocalSource != b.source.sourceJSON || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopLast != "" || b.source.desktop != nil {
		return nodeChainExecutionError
	}
	if p.mobile != nil && (p.mobile.socks == nil || p.mobile.socks.validate(p) != nil) {
		return nodeChainExecutionError
	}
	if _, _, err := b.source.ReadValidated(); err != nil || local.validateSOCKSSource() != nil {
		return nodeChainExecutionError
	}
	return nil
}

// OriginalSOCKSSource grants construction/readback identity, never readiness.
func (p *NodeChainExecutionPreparation) OriginalSOCKSSource() (*NodeChainSOCKSSource, error) {
	if p == nil || p.socks == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.socks.source, nil
}

// Native implementations retain the original source, Box, registry, packet
// prefix, SOCKS association owner and final. This check is required even while
// the application gate is closed; equal reconstructed content cannot replace it.
type NodeChainSOCKSExecutionObserver interface {
	ObserveSOCKSExecutionContext(context.Context, *NodeChainSOCKSSource) error
}

func (p *NodeChainExecutionPreparation) RequiresSOCKSExecutionObserver() bool {
	return p != nil && (p.socks != nil || p.source.Schema == 3)
}
func (p *NodeChainExecutionPreparation) observeSOCKSExecutionContext(ctx context.Context, engine any) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	if p.socks == nil {
		if p.source.Schema == 3 {
			return nodeChainExecutionError
		}
		return nil
	}
	if p.validateCapture() != nil {
		return nodeChainExecutionError
	}
	owner, ok := engine.(NodeChainSOCKSExecutionObserver)
	if !ok {
		return nodeChainExecutionError
	}
	original := p.socks
	if err := owner.ObserveSOCKSExecutionContext(ctx, original.source); err != nil {
		return err
	}
	if ctx.Err() != nil || p.socks != original || p.validateCapture() != nil {
		return nodeChainExecutionError
	}
	return nil
}

// NewNodeChainSOCKSExecutionPolicy binds authenticated discovery to the exact
// dormant preparation; another equal-content source cannot borrow that owner.
func NewNodeChainSOCKSExecutionPolicy(preparation *NodeChainExecutionPreparation, input string) (*NodeChainExecutionPolicy, error) {
	if preparation == nil || preparation.socks == nil || preparation.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPolicyFamily(input, nil, preparation.socks)
}
