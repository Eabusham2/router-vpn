package mobilemultihop

import (
	"context"
	"reflect"
)

// This private binding retains the source/compiler and its private runtime
// before native construction. Equivalent reparsed source is not this owner.
// It conveys no application, socket, TUN, lease or Server admission by itself.
type nodeChainCONNECTExecutionBinding struct {
	self        *nodeChainCONNECTExecutionBinding
	source      *NodeChainCONNECTSource
	local       *NodeChain
	preparation *NodeChainExecutionPreparation
}

// NewNodeChainCONNECTExecutionPreparation is a distinct, closed preparation
// for the exact original WG/AWG -> CONNECT -> SS trio. Generic execution and
// NodeChain parsers deliberately keep rejecting schema4, including this source.
func NewNodeChainCONNECTExecutionPreparation(original *NodeChainCONNECTSource, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || execution != "server" && execution != "auto" || original.desktop != nil {
		return nil, nodeChainExecutionError
	}
	_, meta, err := original.ReadValidated()
	if err != nil || len(meta.Proofs) != 3 || len(original.pair.nodes) != 2 || meta.Proofs[1].Position != 1 || meta.Proofs[2].Mode != "shadowsocks" {
		return nil, nodeChainExecutionError
	}
	runtime, err := NewNodeChainCONNECTRuntime(original)
	if err != nil {
		return nil, err
	}
	return newNodeChainExecutionPreparationCaptured(original.sourceJSON, execution, nil, nil, runtime.chain, original)
}

// ParseNodeChainCONNECTExecutionPreparation constructs the typed source once
// for this native instance. It grants no same-content substitution permission
// after the original native registry/Box has captured that pointer.
func ParseNodeChainCONNECTExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 4 || source.Desktop != nil || source.DesktopLast != "" {
		return nil, nodeChainExecutionError
	}
	original, err := NewNodeChainCONNECTSource(source.LocalSource)
	if err != nil {
		return nil, err
	}
	p, err := NewNodeChainCONNECTExecutionPreparation(original, source.Execution)
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func (b *nodeChainCONNECTExecutionBinding) validate(p *NodeChainExecutionPreparation, local *NodeChain) error {
	if b == nil || b.self != b || b.preparation != p || b.local != local || local == nil || b.source == nil || local.connectSource != b.source || len(local.nodes) != 3 || b.source.desktop != nil || p == nil || p.desktop != nil || p.mobile != nil || p.source.Schema != 4 || p.source.DesktopLast != "" || p.source.LocalSource != b.source.sourceJSON {
		return nodeChainExecutionError
	}
	if _, _, err := b.source.ReadValidated(); err != nil || local.validateCONNECTSource() != nil {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionPreparation) validateCONNECTExecutionCapture() error {
	if p == nil || p.local == nil {
		return nodeChainExecutionError
	}
	if p.connect == nil {
		if p.source.Schema != 1 || p.local.connectSource != nil || p.local.socksSource != nil {
			return nodeChainExecutionError
		}
		return nil
	}
	return p.connect.validate(p, p.local)
}

// OriginalCONNECTSource is construction/readback authority only. The native
// engine must retain this pointer and independently prove original registry,
// lower packet endpoint, middle stream owner and final UoT-v2 owner.
func (p *NodeChainExecutionPreparation) OriginalCONNECTSource() (*NodeChainCONNECTSource, error) {
	if p == nil || p.connect == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.connect.source, nil
}

// ObserveCONNECTExecutionContext must read the same actual source, registry,
// Box, original lower/middle/final objects, including while application is
// closed. It never substitutes a newly parsed equivalent source or a direct
// physical dialer. Remote suffix ownership has its own typed observer.
type NodeChainCONNECTExecutionObserver interface {
	ObserveCONNECTExecutionContext(context.Context, *NodeChainCONNECTSource) error
}

func (p *NodeChainExecutionPreparation) observeCONNECTExecutionContext(ctx context.Context, engine any) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.validateCapture() != nil {
		return nodeChainExecutionError
	}
	if p.connect == nil {
		return nil
	}
	owner, ok := engine.(NodeChainCONNECTExecutionObserver)
	if !ok {
		return nodeChainExecutionError
	}
	original := p.connect
	if err := owner.ObserveCONNECTExecutionContext(ctx, original.source); err != nil {
		return err
	}
	if ctx.Err() != nil || p.connect != original || p.validateCapture() != nil {
		return nodeChainExecutionError
	}
	return nil
}

// NewNodeChainCONNECTExecutionPolicy requires the exact dormant preparation.
// A second same-content source cannot borrow its native construction identity.
func NewNodeChainCONNECTExecutionPolicy(preparation *NodeChainExecutionPreparation, input string) (*NodeChainExecutionPolicy, error) {
	if preparation == nil || preparation.connect == nil || preparation.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPolicyCaptured(input, preparation.connect)
}

func (b *nodeChainCONNECTExecutionBinding) physicalEgress(config, entryTag string) ([]PhysicalEgress, error) {
	if b == nil || b.preparation == nil || b.validate(b.preparation, b.local) != nil {
		return nil, nodeChainExecutionError
	}
	members, closures, err := nodeChainCONNECTMembers(b.source.pair, b.source.middle)
	if err != nil {
		return nil, err
	}
	scope, err := newNodeChainCONNECTProofScope(b.source.pair, b.source.middle, closures)
	if err != nil {
		return nil, err
	}
	original, proofs, _, _, err := compileNodeChainClosuresWithCONNECT(members, closures, b.source.metadata.Physical, scope)
	if err != nil || original != b.source.config || !reflect.DeepEqual(proofs, b.local.proofs) {
		return nil, nodeChainExecutionError
	}
	capture, err := scope.capturePhysical(config, b.local.proofs)
	if err != nil {
		return nil, err
	}
	return scope.physicalEgress(config, []string{"tcp", "udp"}, entryTag, capture)
}

// The only execution public member is the exact original imported trio middle.
// A protocol label or nil node alone never substitutes for its captured owner.
func (p *NodeChainExecutionPolicy) importedPublicMiddle() bool {
	if p == nil || p.local == nil || len(p.local.nodes) != 3 || p.local.nodes[1] != nil {
		return false
	}
	if p.connect != nil {
		return p.source.Schema == 4 && p.local.connectSource == p.connect.source && p.connect.local == p.local && p.connect.source != nil
	}
	return p.source.Schema == 1 && p.local.importedMiddle != nil && p.local.connectSource == nil
}
func (p *NodeChainExecutionPolicy) importedExpectedPublicIP() string {
	if !p.importedPublicMiddle() {
		return ""
	}
	if p.connect != nil {
		return p.connect.source.middle.selection.ExpectedPublicIP
	}
	return p.local.importedMiddle.selection.ExpectedPublicIP
}

func (p *NodeChainExecutionPreparation) RequiresCONNECTExecutionObserver() bool {
	return p != nil && (p.connect != nil || p.source.Schema == 4)
}
