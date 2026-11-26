package mobilemultihop

import (
	"reflect"
	"slices"
)

// Packet and typed desktop preparations seal these values before a runtime starts.
// Keep the original canonical digest while its complete inputs still match.
// Mutable metadata is copied separately from the source pointers.
type nodeChainExecutionPreparationSeal struct {
	packet                                         *nodeChainMultipleImportedLocalSeal
	owner                                          *NodeChainExecutionPreparation
	externalFinal                                  *nodeChainExternalFinalExecutionBinding
	source                                         NodeChainExecutionPreparationSource
	kind                                           string
	metadata                                       DesktopNodeChainMetadata
	discovery                                      NodeChainExecutionDiscoveryCapture
	dns                                            NodeChainExecutionDNSCapture
	physical                                       []PhysicalEgress
	sourceJSON, sourceSHA, config, configSHA, seal string
}

func (p *NodeChainExecutionPreparation) typedDesktopMetadata() (string, *DesktopNodeChainMetadata) {
	if p.desktop != nil || p.mobile != nil || p.openvpn != nil || p.multiple != nil ||
		p.source.Desktop != nil || p.source.DesktopOpenVPN != nil || p.source.DesktopMultipleImported != nil {
		return "", nil
	}
	if m := p.source.DesktopSOCKS; m != nil && p.socks != nil && p.socks.desktop != nil && p.connect == nil && p.source.DesktopCONNECT == nil {
		return m.Kind, &m.DesktopNodeChainMetadata
	}
	if m := p.source.DesktopCONNECT; m != nil && p.connect != nil && p.connect.desktop != nil && p.socks == nil && p.source.DesktopSOCKS == nil {
		return m.Kind, &m.DesktopNodeChainMetadata
	}
	return "", nil
}

// An ordinary non-mobile preparation has no nested desktop metadata or
// platform-specific source. Every source field in its seal is a value here.
func (p *NodeChainExecutionPreparation) plainPacketPreparation() bool {
	return p.desktop == nil && p.mobile == nil && p.socks == nil && p.connect == nil && p.openvpn == nil && p.multiple == nil &&
		p.source.Schema == 1 && p.source.Desktop == nil && p.source.DesktopSOCKS == nil && p.source.DesktopCONNECT == nil &&
		p.source.DesktopOpenVPN == nil && p.source.DesktopMultipleImported == nil && ordinaryExecutionPacketGraph(p.local)
}

func (p *NodeChainExecutionPreparation) plainExternalFinalPreparation() bool {
	return p.externalFinal != nil && p.externalFinal.preparation == p && p.externalFinal.local == p.local &&
		p.desktop == nil && p.mobile == nil && p.source.Schema == 8 && p.source.Desktop == nil &&
		p.source.DesktopSOCKS == nil && p.source.DesktopCONNECT == nil && p.source.DesktopOpenVPN == nil &&
		p.source.DesktopMultipleImported == nil && p.connect == nil && p.socks == nil && p.openvpn == nil && p.multiple == nil
}

func (p *NodeChainExecutionPreparation) rememberPreparationSeal() {
	kind, metadata := p.typedDesktopMetadata()
	var captured DesktopNodeChainMetadata
	if metadata != nil {
		captured = metadata.clone()
	} else if !p.plainPacketPreparation() && !p.plainExternalFinalPreparation() {
		return
	}
	p.originalPreparationSeal = &nodeChainExecutionPreparationSeal{
		owner: p, externalFinal: p.externalFinal, source: p.source, kind: kind, metadata: captured, discovery: p.discovery,
		dns: p.dns, physical: slices.Clone(p.physical), sourceJSON: p.sourceJSON, sourceSHA: p.sourceSHA,
		config: p.config, configSHA: p.configSHA, seal: p.seal,
	}
	if p.plainPacketPreparation() {
		p.originalPreparationSeal.packet = snapshotOriginalNodeChain(p.local)
	}
}

func (s *nodeChainExecutionPreparationSeal) localPacketCurrent(p *NodeChainExecutionPreparation) bool {
	return s != nil && s.owner == p && s.packet != nil && p.plainPacketPreparation() && currentDesktopPacketGraph(s.packet, p.local)
}

func (s *nodeChainExecutionPreparationSeal) matches(p *NodeChainExecutionPreparation) bool {
	if s == nil || s.owner != p || p.source != s.source || p.sourceJSON != s.sourceJSON || p.sourceSHA != s.sourceSHA ||
		p.config != s.config || p.configSHA != s.configSHA || p.discovery != s.discovery || p.dns != s.dns ||
		(p.physical == nil) != (s.physical == nil) || !slices.Equal(p.physical, s.physical) {
		return false
	}
	kind, metadata := p.typedDesktopMetadata()
	if metadata == nil {
		return p.plainPacketPreparation() || s.externalFinal != nil && s.externalFinal == p.externalFinal && p.plainExternalFinalPreparation()
	}
	return kind == s.kind && sameDesktopNodeChainMetadata(*metadata, s.metadata)
}

// The constructor has already hashed the complete desktop derivation. This
// copy covers each input to that same hash; runtime health is always read separately.
type nodeChainTypedDesktopExecutionSeal struct {
	original, source, native, seal string
	inputs                         desktopNodePolicyInputs
	kind                           string
	metadata                       DesktopNodeChainMetadata
	physical                       DesktopPhysicalMetadata
	capture                        DesktopPhysicalCapture
}

func newTypedDesktopExecutionSeal(original, source, native, seal string, inputs desktopNodePolicyInputs, kind string, metadata DesktopNodeChainMetadata, physical DesktopPhysicalMetadata, capture DesktopPhysicalCapture) *nodeChainTypedDesktopExecutionSeal {
	frozen, err := nodeChainSOCKSIntegrityCopy(capture)
	if err != nil {
		return nil
	}
	metadata = metadata.clone()
	return &nodeChainTypedDesktopExecutionSeal{original, source, native, seal, inputs, kind, metadata, physical, frozen}
}

func (s *nodeChainTypedDesktopExecutionSeal) matches(original, source, native string, inputs desktopNodePolicyInputs, kind string, metadata DesktopNodeChainMetadata, physical DesktopPhysicalMetadata, capture DesktopPhysicalCapture) bool {
	return s != nil && s.original == original && s.source == source && s.native == native &&
		s.inputs == inputs && s.kind == kind && s.physical == physical && sameDesktopNodeChainMetadata(s.metadata, metadata) && reflect.DeepEqual(s.capture, capture)
}

func sameTypedSlice[T comparable](current, original []T) bool {
	return (current == nil) == (original == nil) && slices.Equal(current, original)
}

func sameNodeChainMTUPlan(a, b NodeChainMTUPlan) bool {
	return a.Original == b.Original && a.Ceiling == b.Ceiling &&
		a.TUNTag == b.TUNTag && sameTypedSlice(a.Prefixes, b.Prefixes)
}

func sameDesktopNodeChainMetadata(a, b DesktopNodeChainMetadata) bool {
	if (a.ExternalFinal == nil) != (b.ExternalFinal == nil) ||
		a.ExternalFinal != nil && *a.ExternalFinal != *b.ExternalFinal {
		return false
	}
	return a.Schema == b.Schema && a.SessionID == b.SessionID &&
		a.TargetOS == b.TargetOS && a.SourceSHA256 == b.SourceSHA256 &&
		a.ConfigSHA256 == b.ConfigSHA256 && a.OriginalSourceSHA256 == b.OriginalSourceSHA256 &&
		a.OriginalConfigSHA256 == b.OriginalConfigSHA256 && a.OriginalMetadataSHA256 == b.OriginalMetadataSHA256 &&
		a.OriginalCaptureSHA256 == b.OriginalCaptureSHA256 && a.ProfileID == b.ProfileID &&
		a.NodeID == b.NodeID && a.Mode == b.Mode &&
		a.StartLayer == b.StartLayer && a.FinalTag == b.FinalTag &&
		a.TUNTag == b.TUNTag && a.OriginalTUNSHA256 == b.OriginalTUNSHA256 &&
		a.DerivedTUNSHA256 == b.DerivedTUNSHA256 && sameTypedSlice(a.Prefixes, b.Prefixes) &&
		sameTypedSlice(a.Roots, b.Roots) && a.KillSwitchPolicy == b.KillSwitchPolicy &&
		a.IPv6Mode == b.IPv6Mode && a.HomeLANAccess == b.HomeLANAccess &&
		a.DeviceRevision == b.DeviceRevision && a.DeviceFixedMTU == b.DeviceFixedMTU &&
		a.RestoredMTU == b.RestoredMTU
}

func sameNodeChainSOCKSSourceMetadata(a, b NodeChainSOCKSSourceMetadata) bool {
	return a.Kind == b.Kind && a.Schema == b.Schema &&
		a.NativeAdmission == b.NativeAdmission && a.SourceSHA256 == b.SourceSHA256 &&
		a.ConfigSHA256 == b.ConfigSHA256 && sameTypedSlice(a.Proofs, b.Proofs) &&
		a.DNS == b.DNS && sameTypedSlice(a.Physical, b.Physical) &&
		sameNodeChainMTUPlan(a.MTU, b.MTU) && sameTypedSlice(a.Devices, b.Devices)
}

func sameNodeChainCONNECTSourceMetadata(a, b NodeChainCONNECTSourceMetadata) bool {
	return a.Kind == b.Kind && a.Schema == b.Schema &&
		a.TransportCapability == b.TransportCapability && a.NativeAdmission == b.NativeAdmission &&
		a.SourceSHA256 == b.SourceSHA256 && a.ConfigSHA256 == b.ConfigSHA256 &&
		sameTypedSlice(a.Proofs, b.Proofs) && a.DNS == b.DNS &&
		sameTypedSlice(a.Physical, b.Physical) && sameNodeChainMTUPlan(a.MTU, b.MTU) &&
		sameTypedSlice(a.Devices, b.Devices)
}

// The saved SOCKS/CONNECT inputs are private deep copies. The common JSON
// value comparison avoids reflecting through each profile map on every dial.
// A different representation still uses the original exact Go equality.
func sameTypedNodeProfile(current *NodeProfile, original *NodeProfile) bool {
	return current.config == original.config && current.source == original.source &&
		current.metadata == original.metadata && current.mode == original.mode &&
		current.inputs == original.inputs && current.desktopSeal == original.desktopSeal &&
		(sameMultipleImportedJSON(current.profile, original.profile) || reflect.DeepEqual(current.profile, original.profile))
}

func sameTypedExternalCapture(current, original externalPolicyCapture) bool {
	return sameMultipleImportedCapture(current, original) || reflect.DeepEqual(current, original)
}

func sameTypedExternalPolicy(current, original *ExternalPolicy) bool {
	return current.config == original.config && current.metadata == original.metadata && current.source == original.source &&
		current.desktopSeal == original.desktopSeal && sameTypedExternalCapture(current.capture, original.capture)
}
