package mobilemultihop

import (
	"context"
	"encoding/json"
	"reflect"
)

// This binding is issued only for the complete original schema-six source.
// It is construction authority; each candidate still needs its own actual
// public, private, selected-DNS and (for Server) fresh remote lease proofs.
type nodeChainMultipleImportedExecutionBinding struct {
	desktop            *nodeChainMultipleImportedExecutionDesktop
	originalSeal       *nodeChainMultipleImportedPreparationSeal
	self               *nodeChainMultipleImportedExecutionBinding
	preparation        *NodeChainExecutionPreparation
	source, local      *NodeChain
	owners             *nodeChainImportedNodes
	sourceSeal, launch string
}

func NewNodeChainMultipleImportedExecutionPreparation(original *NodeChain, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || original.validateCapture() != nil || original.importedNodes == nil || original.importedNodes.customEntry ||
		original.importedMiddle != nil || original.openVPNMiddle != nil || original.socksSource != nil || original.connectSource != nil ||
		execution != "server" && execution != "auto" || len(original.nodes) < 3 || len(original.nodes) > NodeChainMaximumNodes && (original.ExtendedLocalNodeCount() != len(original.nodes) || original.ExtendedMixedLocalPacketCount() != 0) ||
		original.nodes[len(original.nodes)-1] == nil || original.nodes[len(original.nodes)-1].mode != "shadowsocks" ||
		original.projection.Kind != "" || original.projection.TargetOS != "" && original.projection.TargetOS != "ios" && original.projection.TargetOS != "android" {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPreparationOwnedMultiple(original.sourceJSON, execution, nil, nil, original, nil, nil, nil, nil, nil, original)
}

func ParseNodeChainMultipleImportedExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 6 || source.MultipleImportedLocalLaunch == "" ||
		source.OpenVPNLocalLaunch != "" || source.Desktop != nil || source.DesktopCONNECT != nil || source.DesktopSOCKS != nil || source.DesktopOpenVPN != nil || source.DesktopMultipleImported != nil || source.DesktopLast != "" {
		return nil, nodeChainExecutionError
	}
	original, err := ParseNodeChainLaunchInput(source.MultipleImportedLocalLaunch)
	if err != nil || original.sourceJSON != source.LocalSource {
		return nil, nodeChainExecutionError
	}
	p, err := NewNodeChainMultipleImportedExecutionPreparation(original, source.Execution)
	// Exact canonical equality also rejects cross-family fields present with
	// empty/null values. The sealed launch is not reconstructed from raw source.
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func (b *nodeChainMultipleImportedExecutionBinding) validate(p *NodeChainExecutionPreparation, local *NodeChain) error {
	if b == nil || b.self != b || p == nil || b.preparation != p || p.multiple != b || local == nil || b.source != local || b.local != local || p.local != local ||
		b.owners == nil || local.importedNodes != b.owners || b.sourceSeal == "" || b.sourceSeal != local.seal ||
		local.importedMiddle != nil || local.openVPNMiddle != nil || local.socksSource != nil || local.connectSource != nil ||
		p.connect != nil || p.socks != nil || p.openvpn != nil || p.desktop != nil ||
		p.source.Schema != 6 || p.source.LocalSource != local.sourceJSON || p.source.MultipleImportedLocalLaunch == "" || p.source.MultipleImportedLocalLaunch != b.launch ||
		p.source.OpenVPNLocalLaunch != "" || p.source.Desktop != nil || p.source.DesktopCONNECT != nil || p.source.DesktopSOCKS != nil || p.source.DesktopOpenVPN != nil {
		return nodeChainExecutionError
	}
	if b.desktop != nil {
		if b.desktop.validate(p, b) != nil {
			return nodeChainExecutionError
		}
	} else if local.validateCapture() != nil || p.source.DesktopMultipleImported != nil || p.source.DesktopLast != "" {
		return nodeChainExecutionError
	}
	if p.mobile != nil && (p.mobile.multiple == nil || p.mobile.multiple.validate(p) != nil) {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionPreparation) OriginalMultipleImportedSource() (*NodeChain, error) {
	if p == nil || p.multiple == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.multiple.source, nil
}

// ExtendedOriginalNodeCount is construction metadata for the exact original
// multi-import preparation. A stopped or unproved runtime grants no traffic
// authority through this read.
func (p *NodeChainExecutionPreparation) ExtendedOriginalNodeCount() int {
	original, err := p.OriginalMultipleImportedSource()
	if err != nil {
		return 0
	}
	return original.ExtendedLocalNodeCount()
}

func (p *NodeChainExecutionPreparation) ExtendedOriginalStatusLimit() int {
	original, err := p.OriginalMultipleImportedSource()
	if err != nil {
		return 0
	}
	return original.ExtendedLocalStatusLimit()
}

// ReadMultipleImportedNativeMembers returns the original and all of its
// captured public slots from one complete validation of the same preparation.
func (p *NodeChainExecutionPreparation) ReadMultipleImportedNativeMembers() (*NodeChain, []NodeChainPublicMeasurementCapture, error) {
	original, err := p.OriginalMultipleImportedSource()
	if err != nil {
		return nil, nil, err
	}
	members, _, err := original.publicMeasurementCapturesValidated()
	if err != nil || len(members) == 0 {
		return nil, nil, nodeChainExecutionError
	}
	return original, members, nil
}

func (p *NodeChainExecutionPreparation) RequiresMultipleImportedExecutionObserver() bool {
	return p != nil && (p.multiple != nil || p.source.Schema == 6)
}

// The native observer must retain the original Box, complete source registry,
// per-position concrete transport owners and selected resolver. A pending
// Local transport does not disqualify the independently provisioned Server.
type NodeChainMultipleImportedExecutionObserver interface {
	ObserveMultipleImportedExecutionContext(context.Context, *NodeChain) error
}

func (p *NodeChainExecutionPreparation) observeMultipleImportedExecutionContext(ctx context.Context, engine any) error {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	if p.multiple == nil {
		if p.source.Schema == 6 {
			return nodeChainExecutionError
		}
		return nil
	}
	if p.validateCapture() != nil {
		return nodeChainExecutionError
	}
	original := p.multiple
	observer, ok := engine.(NodeChainMultipleImportedExecutionObserver)
	if !ok {
		return nodeChainExecutionError
	}
	if err := observer.ObserveMultipleImportedExecutionContext(ctx, original.source); err != nil {
		return err
	}
	if ctx.Err() != nil || p.multiple != original || p.validateCapture() != nil {
		return nodeChainExecutionError
	}
	return nil
}

func NewNodeChainMultipleImportedExecutionPolicy(preparation *NodeChainExecutionPreparation, input string) (*NodeChainExecutionPolicy, error) {
	if preparation == nil || preparation.multiple == nil || preparation.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPolicyFamilyMultiple(input, nil, nil, nil, preparation.multiple)
}

// Singleton contracts remain unchanged. Only this distinct typed inventory
// can admit several public prefixes at their actual original positions.
func (p *NodeChainExecutionPolicy) importedPublicAt(position int) bool {
	if p == nil || p.local == nil || position < 0 || position >= len(p.local.nodes) {
		return false
	}
	if p.multiple != nil {
		return p.source.Schema == 6 && p.source.Server.Schema == 6 && p.multiple.local == p.local && p.local.importedSSMemberAt(position) != nil
	}
	return position == p.importedPublicPosition()
}

func (p *NodeChainExecutionPolicy) importedExpectedPublicIPAt(position int) string {
	if !p.importedPublicAt(position) {
		return ""
	}
	if p.multiple != nil {
		return p.local.importedSSMemberAt(position).selection.ExpectedPublicIP
	}
	return p.importedExpectedPublicIP()
}

// Copy-out grants only fixed public measurement through each captured prefix.
// The native adapter still checks its original owner, selected epoch and DNS
// before and after a real dial; no caller-provided tag or source is accepted.
func (p *NodeChainExecutionProjection) ImportedPublicMeasurementCaptures(execution string) ([]NodeChainPublicMeasurementCapture, bool, error) {
	if p.validateCapture() != nil || p.policy.multiple == nil || p.preparation.multiple != p.policy.multiple {
		return nil, false, nodeChainExecutionError
	}
	original := p.preparation.multiple.source
	captured, ipv6, err := original.PublicMeasurementCaptures()
	if err != nil || len(captured) == 0 {
		return nil, false, nodeChainExecutionError
	}
	proofs, err := p.policy.proofInventoryValidated(execution)
	if err != nil || len(proofs) != len(original.proofs) {
		return nil, false, nodeChainExecutionError
	}
	for index, value := range captured {
		if value.Position <= 0 || value.Position >= len(proofs)-1 {
			return nil, false, nodeChainExecutionError
		}
		proof, local := proofs[value.Position], original.proofs[value.Position]
		compare := proof
		compare.Tag = local.Tag
		if !reflect.DeepEqual(compare, local) || proof.Kind != "public-path" || proof.NodeKind != "external" || proof.NodeID != "" || proof.Mode != "shadowsocks" || proof.Tag == "" || value.SourceSHA256 != proof.SourceSHA256 {
			return nil, false, nodeChainExecutionError
		}
		captured[index].Tag = proof.Tag
	}
	return captured, ipv6, nil
}

// ValidateMultipleImportedLatencyCapture checks the saved selected inventory against
// the sealed original Local member inputs. Live authority comes from the retained
// measurement's separate ValidateClosedCapture check at publication.
func (c *NodeChain) ValidateMultipleImportedLatencyCapture(raw string) error {
	if c.validateCapture() != nil || c.importedNodes == nil || c.importedNodes.customEntry {
		return nodeChainExecutionError
	}
	var capture struct {
		Schema           int                                        `json:"schema"`
		SourceSHA256     string                                     `json:"source_sha256"`
		ConfigSHA256     string                                     `json:"config_sha256"`
		GenerationSHA256 string                                     `json:"generation_sha256"`
		Execution        string                                     `json:"selected_execution"`
		Nodes            []nodeChainExecutionLatencyHop             `json:"nodes"`
		Multiple         *nodeChainExecutionLatencyMultipleImported `json:"multiple_imported"`
	}
	if exactJSON([]byte(raw), &capture, 64<<10) != nil || capture.Schema != 1 || capture.Multiple == nil ||
		capture.Multiple.Schema != 6 || capture.Multiple.OriginalSourceSHA256 != c.SourceSHA256() || !proofID.MatchString(capture.SourceSHA256) ||
		!proofID.MatchString(capture.ConfigSHA256) || !proofID.MatchString(capture.GenerationSHA256) ||
		capture.Execution != "local" && capture.Execution != "server" || len(capture.Nodes) != len(c.proofs) {
		return nodeChainExecutionError
	}
	canonical, err := json.Marshal(capture)
	if err != nil || string(canonical) != raw {
		return nodeChainExecutionError
	}
	public, _, err := c.PublicMeasurementCaptures()
	if err != nil || len(public) == 0 || len(public) != len(capture.Multiple.Public) {
		return nodeChainExecutionError
	}
	for index, member := range public {
		tag := member.Tag
		if capture.Execution == "server" {
			tag = nodeChainExecutionServerTag(member.Position, capture.SourceSHA256)
		}
		if capture.Multiple.Public[index] != (nodeChainExecutionLatencyPublic{member.Position, tag, member.SourceSHA256}) {
			return nodeChainExecutionError
		}
	}
	for position, proof := range c.proofs {
		role, kind := "intermediate", "private-node"
		if position == 0 {
			role = "entry"
		} else if position == len(c.proofs)-1 {
			role = "exit"
		}
		if c.importedSSMemberAt(position) != nil {
			kind = "public-path"
		}
		if capture.Nodes[position] != (nodeChainExecutionLatencyHop{proof.ProfileID, position, role, kind}) {
			return nodeChainExecutionError
		}
	}
	return nil
}
