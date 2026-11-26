package mobilemultihop

import (
	"context"
	"encoding/json"
	"reflect"

	"router-vpn/internal/multihoprelay"
)

type nodeChainExternalFinalExecutionBinding struct {
	preparation                            *NodeChainExecutionPreparation
	local                                  *NodeChain
	launch, localSeal, policySHA, dnsOwner string
	binding                                multihoprelay.NodeChainExternalFinalBinding
}

func newExternalFinalExecutionBinding(local *NodeChain) (*nodeChainExternalFinalExecutionBinding, error) {
	if !local.HasExternalFinal() || local.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	launch, err := local.LaunchInput()
	if err != nil {
		return nil, err
	}
	last := len(local.proofs) - 1
	entry := local.nodes[0]
	final := local.importedNodes.members[last]
	transport, err := externalFinalStreamCommitment(final)
	if err != nil {
		return nil, err
	}
	profiles := []map[string]any{entry.profile}
	for _, member := range local.importedNodes.members[1:] {
		profiles = append(profiles, member.selection.Profile)
	}
	ipv6, _, err := externalDevicePolicy(profiles...)
	if err != nil {
		return nil, err
	}
	tree, meta, err := externalSelectedDNS(final.selection, ipv6, true)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	public, err := entry.PacketClientPublicKey()
	if err != nil {
		return nil, err
	}
	peers, err := externalFinalPacketPeerAddresses(entry)
	if err != nil {
		return nil, err
	}
	b := &nodeChainExternalFinalExecutionBinding{local: local, launch: launch, localSeal: local.seal, policySHA: externalDigest(raw), dnsOwner: "external-final"}
	if meta.mode == "home" {
		b.dnsOwner = "entry-home"
	}
	localFinal, err := externalFinalOriginalCapture(final)
	if err != nil {
		return nil, err
	}
	entryDigest, err := externalFinalOriginalEntry(local)
	if err != nil {
		return nil, err
	}
	b.binding = multihoprelay.NodeChainExternalFinalBinding{FinalTransportSHA256: transport, EntrySourceSHA256: entryDigest, EntryStartLayer: local.proofs[0].StartLayer, EntryClientPublicKey: public, EntryPeerAddresses: peers, DNSOwner: b.dnsOwner, LocalFinalSourceSHA256: localFinal}
	return b, nil
}

func (b *nodeChainExternalFinalExecutionBinding) current(p *NodeChainExecutionPreparation) bool {
	return b != nil && p != nil && b.preparation == p && p.externalFinal == b && p.local == b.local && b.local != nil && b.local.importedNodes != nil && b.local.importedNodes.externalFinal && b.local.validateCapture() == nil && b.local.seal == b.localSeal && p.source.Schema == 8 && p.source.LocalSource == b.local.sourceJSON && p.source.ExternalFinalLocalLaunch == b.launch && p.socks == nil && p.connect == nil && p.openvpn == nil && p.multiple == nil && p.source.MultipleImportedLocalLaunch == "" && p.source.OpenVPNLocalLaunch == ""
}

func (b *nodeChainExternalFinalExecutionBinding) matches(d multihoprelay.NodeChainDescriptor) bool {
	return b != nil && b.current(b.preparation) && d.Validate() == nil && b.matchesOriginalDescriptor(d)
}

// Constructors and changed sources validate the complete public descriptor
// first. Repeated observations compare those same original source values; the
// preparation separately revalidates the Local packet and every stream owner.
func (b *nodeChainExternalFinalExecutionBinding) matchesOriginalDescriptor(d multihoprelay.NodeChainDescriptor) bool {
	if b == nil || d.Schema != 8 || d.ExternalFinal == nil || !reflect.DeepEqual(*d.ExternalFinal, b.binding) || d.DNSPolicySHA256 != b.policySHA || len(d.Members) != len(b.local.proofs)-1 {
		return false
	}
	entry := b.local.nodes[0]
	if d.EntryID != predecessorText(entry.profile, "id") || d.EntryNodeID != predecessorText(entry.profile, "node_proof_id") || d.EntryMode != entry.mode {
		return false
	}
	for i, m := range d.Members {
		pos := i + 1
		row := b.local.proofs[pos]
		original := b.local.importedNodes.members[pos]
		if m.Position != pos || m.ProfileID != row.ProfileID || m.Mode != row.Mode || m.StartLayer != row.StartLayer || m.NodeKind != row.NodeKind || m.ProofKind != row.Kind || original.selection.ExpectedPublicIP != m.ExpectedPublicIP || pos < len(b.local.proofs)-1 && m.SourceSHA256 != row.SourceSHA256 {
			return false
		}
	}
	return true
}

func NewNodeChainExternalFinalExecutionPreparation(local *NodeChain, execution string) (*NodeChainExecutionPreparation, error) {
	if execution != "server" && execution != "auto" {
		return nil, nodeChainExecutionError
	}
	b, err := newExternalFinalExecutionBinding(local)
	if err != nil {
		return nil, err
	}
	return newNodeChainExecutionPreparationOwnedFamilies(local.sourceJSON, execution, nil, nil, local, nil, nil, nil, nil, nil, nil, nil, nil, b)
}

func ParseNodeChainExternalFinalExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var src NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &src, NodeChainInputLimit) != nil || src.Schema != 8 || src.ExternalFinalLocalLaunch == "" {
		return nil, nodeChainExecutionError
	}
	local, err := ParseNodeChainLaunchInput(src.ExternalFinalLocalLaunch)
	if err != nil || local.sourceJSON != src.LocalSource {
		return nil, nodeChainExecutionError
	}
	p, err := NewNodeChainExternalFinalExecutionPreparation(local, src.Execution)
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func NewNodeChainExternalFinalExecutionPolicy(p *NodeChainExecutionPreparation, input string) (*NodeChainExecutionPolicy, error) {
	if p == nil || !p.externalFinal.current(p) || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return newNodeChainExecutionPolicyFamilyExternalFinal(input, nil, nil, nil, nil, p.externalFinal)
}

func (b *nodeChainExternalFinalExecutionBinding) resolverTag() string {
	if b != nil && b.dnsOwner == "entry-home" {
		return b.local.proofs[0].Tag
	}
	return SelectorTag
}

func (p *NodeChainExecutionPreparation) RequiresExternalFinalExecutionObserver() bool {
	return p != nil && (p.externalFinal != nil || p.source.Schema == 8)
}

func (p *NodeChainExecutionPreparation) OriginalExternalFinalSource() (*NodeChain, error) {
	if p == nil || p.externalFinal == nil || p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p.externalFinal.local, nil
}

// ReadExternalFinalNativeMembers derives every SS2022 member from the same
// validated preparation. Its final position belongs to the public exit.
func (p *NodeChainExecutionPreparation) ReadExternalFinalNativeMembers() (*NodeChain, []NodeChainPublicMeasurementCapture, error) {
	original, err := p.OriginalExternalFinalSource()
	if err != nil {
		return nil, nil, err
	}
	members := make([]NodeChainPublicMeasurementCapture, 0, len(original.proofs)-1)
	for pos, proof := range original.proofs[1:] {
		members = append(members, NodeChainPublicMeasurementCapture{Position: pos + 1, Tag: proof.Tag, SourceSHA256: proof.SourceSHA256})
	}
	return original, members, nil
}

type NodeChainExternalFinalExecutionObserver interface {
	ObserveExternalFinalExecutionContext(context.Context, *NodeChain) error
}

func (p *NodeChainExecutionPreparation) observeExternalFinalExecution(ctx context.Context, engine any) error {
	if !p.RequiresExternalFinalExecutionObserver() {
		return nil
	}
	source, err := p.OriginalExternalFinalSource()
	observer, ok := engine.(NodeChainExternalFinalExecutionObserver)
	if err != nil || !ok || ctx == nil || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	if err := observer.ObserveExternalFinalExecutionContext(ctx, source); err != nil {
		return err
	}
	again, err := p.OriginalExternalFinalSource()
	if err != nil || again != source || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionProjection) ExternalFinalPublicMeasurementCaptures(execution string) ([]NodeChainPublicMeasurementCapture, bool, error) {
	if p.validateCapture() != nil || p.policy.externalFinal == nil || p.policy.externalFinal != p.preparation.externalFinal {
		return nil, false, nodeChainExecutionError
	}
	local := p.policy.externalFinal.local
	original, ipv6, err := local.PublicMeasurementCaptures()
	if err != nil || len(original) != len(local.proofs)-1 {
		return nil, false, nodeChainExecutionError
	}
	selected, err := p.policy.proofInventoryValidated(execution)
	if err != nil {
		return nil, false, err
	}
	for i, row := range original {
		pos := i + 1
		proof := selected[pos]
		old := local.proofs[pos]
		expected := old.SourceSHA256
		if execution == "server" {
			expected = p.policy.source.Server.Members[i].SourceSHA256
		}
		if row.Position != pos || row.Tag != old.Tag || row.SourceSHA256 != old.SourceSHA256 || proof.SourceSHA256 != expected || proof.Kind != "public-path" || proof.NodeID != "" || proof.Position != pos || proof.ProfileID != old.ProfileID {
			return nil, false, nodeChainExecutionError
		}
		original[i].Tag, original[i].SourceSHA256 = proof.Tag, proof.SourceSHA256
	}
	return original, ipv6, nil
}

type NodeChainExternalFinalExecutionRetiredObserver interface {
	ExternalFinalExecutionRetiredContext(context.Context, *NodeChain) error
}

// The original grant, private front and native Box must have joined before a
// replacement engine can acquire a fresh grant or reopen its application gate.
func (r *NodeChainExecutionRuntime) checkExternalFinalRetirement(ctx context.Context) error {
	if r.restore == nil || r.mtuResume != nil || r.projection.preparation.externalFinal == nil {
		return nil
	}
	c := r.restore
	old := c.owner
	if old == nil || old == r || c.projection == nil || c.projection.preparation.externalFinal == nil || c.projection.policy.local != r.projection.policy.local || !nodeChainOpenVPNExecutionEnginePointer(r.engine) || !nodeChainOpenVPNExecutionEnginePointer(old.engine) || old.engine == r.engine {
		return nodeChainExecutionError
	}
	test, ok := old.engine.(NodeChainExternalFinalExecutionRetiredObserver)
	if !ok {
		return nodeChainExecutionError
	}
	if _, err := c.Source(); err != nil {
		return err
	}
	if err := test.ExternalFinalExecutionRetiredContext(ctx, c.projection.policy.local); err != nil {
		return err
	}
	if _, err := c.Source(); err != nil {
		return err
	}
	return ctx.Err()
}
