package mobilemultihop

import (
	"reflect"
	"slices"
)

// One ordinary desktop preparation retains three independently validated packet
// graphs. These snapshots belong to that preparation alone. They hold no
// socket, process, reader, activity or runtime health observations.
type nodeChainDesktopPacketObservation struct {
	owner                                                      *NodeChainExecutionPreparation
	desktop                                                    *DesktopNodeChainPolicy
	local, original, native                                    *nodeChainMultipleImportedLocalSeal
	metadata                                                   DesktopNodeChainMetadata
	source                                                     NodeChainExecutionPreparationSource
	discovery                                                  NodeChainExecutionDiscoveryCapture
	dns                                                        NodeChainExecutionDNSCapture
	physical                                                   []PhysicalEgress
	sourceJSON, sourceSHA, config, configSHA, seal, policySeal string
}

func ordinaryExecutionPacketGraph(c *NodeChain) bool {
	return c != nil && c.importedMiddle == nil && c.importedOwners == nil && c.importedNodes == nil &&
		c.openVPNMiddle == nil && c.openVPNOwners == nil && c.socksSource == nil && c.connectSource == nil
}

func (p *NodeChainExecutionPreparation) rememberDesktopPacketObservation() {
	d := p.desktop
	if d == nil || p.source.Schema != 1 || p.source.Desktop == nil || p.mobile != nil || p.multiple != nil ||
		p.connect != nil || p.socks != nil || p.openvpn != nil || p.source.DesktopMultipleImported != nil ||
		p.source.DesktopOpenVPN != nil || p.source.DesktopCONNECT != nil || p.source.DesktopSOCKS != nil ||
		!ordinaryExecutionPacketGraph(p.local) || !ordinaryExecutionPacketGraph(d.original) || !ordinaryExecutionPacketGraph(d.chain) {
		return
	}
	// The caller has just sealed the complete canonical preparation. Validate
	// its original graphs now, before issuing any equivalent-value snapshot.
	if p.validateCapture() != nil {
		return
	}
	metadata := d.metadata
	metadata.Prefixes, metadata.Roots = slices.Clone(d.metadata.Prefixes), slices.Clone(d.metadata.Roots)
	p.packetDesktop = &nodeChainDesktopPacketObservation{
		owner: p, desktop: d, local: snapshotOriginalNodeChain(p.local), original: snapshotOriginalNodeChain(d.original),
		native: snapshotOriginalNodeChain(d.chain), metadata: metadata, source: p.source, discovery: p.discovery, dns: p.dns, physical: slices.Clone(p.physical),
		sourceJSON: p.sourceJSON, sourceSHA: p.sourceSHA, config: p.config, configSHA: p.configSHA, seal: p.seal, policySeal: d.seal,
	}
}

func (s *nodeChainDesktopPacketObservation) matchesPreparation(p *NodeChainExecutionPreparation) bool {
	return s != nil && s.owner == p && p.desktop == s.desktop && p.mobile == nil && p.multiple == nil && p.openvpn == nil && p.socks == nil && p.connect == nil &&
		p.source == s.source && p.source.Desktop != nil && reflect.DeepEqual(*p.source.Desktop, s.metadata) &&
		p.sourceJSON == s.sourceJSON && p.sourceSHA == s.sourceSHA && p.config == s.config && p.configSHA == s.configSHA &&
		p.discovery == s.discovery && p.dns == s.dns && (p.physical == nil) == (s.physical == nil) && slices.Equal(p.physical, s.physical)
}

func currentDesktopPacketGraph(s *nodeChainMultipleImportedLocalSeal, c *NodeChain) bool {
	if !ordinaryExecutionPacketGraph(c) || !s.matches(c) || c.seal != s.seal || len(c.nodes) != len(s.packets) {
		return false
	}
	for i, node := range c.nodes {
		proof := c.proofs[i]
		if !s.packets[i].matches(node) || proof.Position != i || node.source != proof.SourceSHA256 || node.mode != proof.Mode ||
			predecessorText(node.profile, "id") != proof.ProfileID || predecessorText(node.profile, "node_proof_id") != proof.NodeID {
			return false
		}
	}
	return true
}

func (s *nodeChainDesktopPacketObservation) localCurrent(p *NodeChainExecutionPreparation) bool {
	return s != nil && s.owner == p && p.desktop == s.desktop && currentDesktopPacketGraph(s.local, p.local)
}

func (s *nodeChainDesktopPacketObservation) policyCurrent(p *NodeChainExecutionPreparation, d *DesktopNodeChainPolicy) bool {
	return s != nil && s.owner == p && s.desktop == d && d.seal == s.policySeal && reflect.DeepEqual(s.metadata, d.metadata) &&
		currentDesktopPacketGraph(s.original, d.original) && currentDesktopPacketGraph(s.native, d.chain)
}
