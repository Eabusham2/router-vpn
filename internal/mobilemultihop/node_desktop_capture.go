package mobilemultihop

import (
	"errors"
	"net/netip"
	"sort"
)

// NodeDesktopCapture describes one immutable, fully compiled private Router
// node. It grants no native socket, TUN or firewall authority. Physical roots
// retain their complete original object identities; selected application DNS
// and private node proof targets never become physical allow-list entries.
type NodeDesktopCapture struct {
	SourceSHA256, ConfigSHA256, MetadataSHA256, CaptureSHA256 string
	ProfileID, NodeID, Mode, StartLayer                       string
	FinalTag, TUNTag                                          string
	KillSwitchPolicy, IPv6Mode                                string
	HomeLANAccess, UDPAvailable                               bool
	BlockedLANCIDRs                                           []string
	MTUPolicy                                                 string
	ConfiguredMTU                                             int
	SelectedDNS                                               ExternalDesktopDNS
	BootstrapDNS                                              []ExternalDesktopDNS
	PhysicalRoots                                             []ExternalDesktopPhysicalRoot
	PrivateDestinations                                       []PhysicalEgress
}

type nodeProfileMetadata struct {
	Schema        int    `json:"schema"`
	SourceSHA256  string `json:"source_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
	ProfileID     string `json:"profile_id"`
	NodeID        string `json:"node_id"`
	Mode          string `json:"mode"`
	StartLayer    string `json:"start_layer"`
	DNSMode       string `json:"dns_mode"`
	DNSProtocol   string `json:"dns_protocol"`
	DNSServer     string `json:"dns_server"`
	ConfiguredMTU int    `json:"configured_mtu"`
	Measurement   string `json:"measurement"`
}

var nodeDesktopCaptureError = errors.New("desktop Router node capture lost its complete validated constructor source")

// DesktopCapture first checks the private construction seal, then traverses the
// actual validated graph. Each call creates fresh maps, slices and DNS-query
// pointers. It does not read the current selected node or run DNS/MTU probes.
func (p *NodeProfile) DesktopCapture() (NodeDesktopCapture, error) {
	var result NodeDesktopCapture
	if p.validateNodeDesktopCapture() != nil {
		return result, nodeDesktopCaptureError
	}
	var meta nodeProfileMetadata
	if exactJSON([]byte(p.metadata), &meta, 64<<10) != nil || meta.Schema != 1 || meta.SourceSHA256 != p.source ||
		meta.ConfigSHA256 != externalDigest([]byte(p.config)) || meta.Mode != p.mode || meta.Measurement != "pending-live-proof" ||
		meta.ProfileID != predecessorText(p.profile, "id") || meta.NodeID != predecessorText(p.profile, "node_proof_id") {
		return result, nodeDesktopCaptureError
	}
	if ValidateNodePredecessor(p.mode, p.inputs.ProfileJSON, p.config) != nil {
		return result, nodeDesktopCaptureError
	}
	kill, err := externalDesktopKillPolicy(p.profile)
	if err != nil {
		return result, err
	}
	ipv6, blocked, err := externalDevicePolicy(p.profile)
	if err != nil {
		return result, err
	}
	mtuPolicy := "auto"
	if fixed, err := fixedMTU(p.profile); err != nil {
		return result, err
	} else if fixed != 0 {
		mtuPolicy = "fixed"
	}
	var graph map[string]any
	if exactJSON([]byte(p.config), &graph, 4<<20) != nil || graph == nil {
		return result, nodeDesktopCaptureError
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) != 1 {
		return result, nodeDesktopCaptureError
	}
	tun, ok := ins[0].(map[string]any)
	if !ok || tun["type"] != "tun" || !exactID.MatchString(predecessorText(tun, "tag")) ||
		tun["mtu"] != float64(meta.ConfiguredMTU) || meta.ConfiguredMTU < 1280 || meta.ConfiguredMTU > 9000 {
		return result, nodeDesktopCaptureError
	}
	collector := &externalDesktopRecorder{
		families: map[string]string{}, roots: map[string]*ExternalDesktopPhysicalRoot{},
		bootstrap: map[string]ExternalDesktopDNS{},
	}
	// Every admitted Router family carries both payload transports. The graph
	// traversal maps them to actual outer protocols, including composite lanes,
	// PQ exchanges, Start Layers and explicit native resolver dependencies.
	tuples, err := compiledPhysicalEgressWithDesktop(p.config, []string{"tcp", "udp"}, collector)
	if err != nil || collector.selected.Tag != ExternalDNSTag || collector.selected.Type != meta.DNSProtocol ||
		collector.selected.Host != meta.DNSServer || collector.selected.Detour != "proxy" || collector.selected.Physical || len(collector.roots) == 0 {
		return result, nodeDesktopCaptureError
	}
	launch, err := p.LaunchInput()
	if err != nil {
		return result, nodeDesktopCaptureError
	}
	result = NodeDesktopCapture{
		SourceSHA256: p.source, ConfigSHA256: meta.ConfigSHA256, MetadataSHA256: externalDigest([]byte(p.metadata)),
		CaptureSHA256: externalDigest([]byte(launch)), ProfileID: meta.ProfileID, NodeID: meta.NodeID, Mode: meta.Mode,
		StartLayer: meta.StartLayer, FinalTag: "proxy", TUNTag: predecessorText(tun, "tag"),
		KillSwitchPolicy: kill, IPv6Mode: ipv6, HomeLANAccess: len(blocked) == 0, UDPAvailable: true,
		BlockedLANCIDRs: append([]string(nil), blocked...), MTUPolicy: mtuPolicy, ConfiguredMTU: meta.ConfiguredMTU,
		SelectedDNS: collector.selected,
	}
	result.SelectedDNS.Mode = meta.DNSMode
	for _, server := range collector.bootstrap {
		result.BootstrapDNS = append(result.BootstrapDNS, server)
	}
	sort.Slice(result.BootstrapDNS, func(i, j int) bool { return result.BootstrapDNS[i].Tag < result.BootstrapDNS[j].Tag })
	for _, root := range collector.roots {
		sort.Strings(root.Networks)
		sortPhysicalEgress(root.Destinations)
		result.PhysicalRoots = append(result.PhysicalRoots, *root)
	}
	sort.Slice(result.PhysicalRoots, func(i, j int) bool {
		if result.PhysicalRoots[i].Family != result.PhysicalRoots[j].Family {
			return result.PhysicalRoots[i].Family < result.PhysicalRoots[j].Family
		}
		return result.PhysicalRoots[i].Tag < result.PhysicalRoots[j].Tag
	})
	for _, tuple := range tuples {
		address, err := netip.ParseAddr(tuple.Host)
		if err == nil && address.IsPrivate() {
			result.PrivateDestinations = append(result.PrivateDestinations, tuple)
		}
	}
	return result, nil
}
