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
	desktop     *nodeChainCONNECTExecutionDesktop
}

// NewNodeChainCONNECTExecutionPreparation is a distinct, closed preparation
// for the complete original WG/AWG prefix -> CONNECT -> SS graph. Generic execution and
// NodeChain parsers deliberately keep rejecting schema4, including this source.
func NewNodeChainCONNECTExecutionPreparation(original *NodeChainCONNECTSource, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || execution != "server" && execution != "auto" || original.desktop != nil {
		return nil, nodeChainExecutionError
	}
	_, meta, err := original.ReadValidated()
	if err != nil || len(meta.Proofs) < 3 || len(meta.Proofs) > NodeChainMaximumNodes || len(original.pair.nodes) != len(meta.Proofs)-1 || meta.Proofs[len(meta.Proofs)-2].Position != len(meta.Proofs)-2 || meta.Proofs[len(meta.Proofs)-1].Mode != "shadowsocks" {
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
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 4 || source.Desktop != nil || source.DesktopCONNECT != nil || source.DesktopSOCKS != nil || source.DesktopLast != "" {
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
	if b == nil || b.self != b || b.preparation != p || b.local != local || local == nil || b.source == nil || local.connectSource != b.source || (len(local.nodes) < 3 || len(local.nodes) > NodeChainMaximumNodes) || p == nil || p.desktop != nil || p.source.DesktopSOCKS != nil || p.source.Schema != 4 || p.source.LocalSource != b.source.sourceJSON {
		return nodeChainExecutionError
	}
	if p.mobile != nil && (b.desktop != nil || p.mobile.connect == nil || p.mobile.connect.validate(p) != nil) {
		return nodeChainExecutionError
	}
	if b.desktop == nil {
		if b.source.desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopLast != "" {
			return nodeChainExecutionError
		}
	} else if b.desktop.validate(p, b) != nil {
		return nodeChainExecutionError
	}
	if local.validateCONNECTSource() != nil {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionPreparation) validateCONNECTExecutionCapture() error {
	if p == nil || p.local == nil {
		return nodeChainExecutionError
	}
	if p.connect == nil {
		if p.source.Schema != 1 || p.local.connectSource != nil || p.local.socksSource != nil || p.source.DesktopCONNECT != nil || p.source.DesktopSOCKS != nil {
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
	if b.desktop != nil {
		return b.desktop.physicalEgress(config, entryTag)
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

// The public member belongs to its original captured penultimate import.
// Schema2 and typed CONNECT retain complete paired prefixes. SOCKS keeps
// its separately bounded trio; all families retain original source pointers.
func (p *NodeChainExecutionPolicy) importedPublicPosition() int {
	if p == nil || p.local == nil || len(p.local.nodes) < 3 {
		return -1
	}
	position := len(p.local.nodes) - 2
	if p.local.nodes[position] != nil {
		return -1
	}
	if p.socks != nil {
		if len(p.local.nodes) == 3 && p.connect == nil && p.source.Schema == 3 && p.local.socksSource == p.socks.source && p.socks.local == p.local && p.socks.source != nil {
			return position
		}
		return -1
	}
	if p.connect != nil {
		if len(p.local.nodes) <= NodeChainMaximumNodes && p.source.Schema == 4 && p.local.connectSource == p.connect.source && p.connect.local == p.local && p.connect.source != nil {
			return position
		}
		return -1
	}
	if p.source.Schema == 1 && p.source.Server.Schema == 2 && nodeChainImportedExecutionMemberSupported(p.local.importedMiddle, len(p.local.nodes)) && p.local.connectSource == nil && p.local.socksSource == nil {
		return position
	}
	return -1
}
func (p *NodeChainExecutionPolicy) importedPublicMiddle() bool {
	return p.importedPublicPosition() >= 0
}
func (p *NodeChainExecutionPolicy) importedExpectedPublicIP() string {
	if !p.importedPublicMiddle() {
		return ""
	}
	if p.socks != nil {
		return p.socks.source.middle.selection.ExpectedPublicIP
	}
	if p.connect != nil {
		return p.connect.source.middle.selection.ExpectedPublicIP
	}
	return p.local.importedMiddle.selection.ExpectedPublicIP
}

func (p *NodeChainExecutionPreparation) RequiresCONNECTExecutionObserver() bool {
	return p != nil && (p.connect != nil || p.source.Schema == 4)
}
