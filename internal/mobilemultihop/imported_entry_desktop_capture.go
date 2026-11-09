package mobilemultihop

import (
	"errors"
	"net/netip"
	"sort"
)

// ImportedDesktopCapture describes one sealed imported entry followed by its
// independently paired final. The final owns application DNS and protection;
// the two original profiles jointly constrain IPv6, LAN and packet capacity.
// None of these comparison values grants a native socket or firewall permit.
type ImportedDesktopCapture struct {
	SourceSHA256, ConfigSHA256, MetadataSHA256, CaptureSHA256 string
	EntryID, ExitID, ExitNodeID, EntryMode, ExitMode          string
	EntryStartLayer, ExitStartLayer                           string
	EntryTag, FinalTag, TUNTag                                string
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

var importedDesktopCaptureError = errors.New("desktop imported path lost its complete independently captured entry and paired final")

// ImportedDesktopCapture revalidates the complete seven-input constructor and
// traverses its original graph. The returned slices and resolver query values
// belong to this read; neither metadata nor an edited graph can manufacture it.
func (c *Controller) ImportedDesktopCapture() (ImportedDesktopCapture, error) {
	var result ImportedDesktopCapture
	if c == nil || c.validateImportedDesktopCapture() != nil {
		return result, importedDesktopCaptureError
	}
	var entry externalPolicyCapture
	var final, selected map[string]any
	if exactJSON([]byte(c.imported.inputs.EntryCapture), &entry, 8<<20) != nil ||
		exactJSON([]byte(c.imported.inputs.ExitProfile), &final, 256<<10) != nil || final == nil ||
		exactJSON([]byte(c.imported.profile), &selected, 256<<10) != nil || selected == nil ||
		c.meta.EntryKind != "external" || c.meta.Execution != "local" || c.meta.EntryTag != "entry-wg" ||
		c.meta.EntryID != entry.ExitID || c.meta.ExitID != predecessorText(final, "id") ||
		c.meta.ExitNodeID != predecessorText(final, "node_proof_id") || !proofID.MatchString(c.meta.ExitNodeID) {
		return result, importedDesktopCaptureError
	}
	kill, err := externalDesktopKillPolicy(final)
	if err != nil {
		return result, err
	}
	ipv6, blocked, err := externalDevicePolicy(final, entry.Profile)
	if err != nil {
		return result, err
	}
	mtuPolicy := "auto"
	if fixed, err := fixedMTU(selected); err != nil {
		return result, err
	} else if fixed != 0 {
		mtuPolicy = "fixed"
	}
	var graph map[string]any
	if exactJSON([]byte(c.config), &graph, 4<<20) != nil || graph == nil {
		return result, importedDesktopCaptureError
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) != 2 {
		return result, importedDesktopCaptureError
	}
	tun, ok := ins[0].(map[string]any)
	if !ok || tun["type"] != "tun" || !exactID.MatchString(predecessorText(tun, "tag")) ||
		tun["auto_route"] != true || tun["strict_route"] != true {
		return result, importedDesktopCaptureError
	}
	mtu, err := mtuNumber(tun["mtu"])
	if err != nil {
		return result, err
	}
	proof, ok := ins[1].(map[string]any)
	if !ok || len(proof) != 4 || proof["type"] != "mixed" || proof["tag"] != "routervpn-proof" ||
		proof["listen"] != "127.0.0.1" || proof["listen_port"] != float64(1099) {
		return result, importedDesktopCaptureError
	}
	collector := &externalDesktopRecorder{
		families: map[string]string{}, roots: map[string]*ExternalDesktopPhysicalRoot{},
		bootstrap: map[string]ExternalDesktopDNS{},
	}
	tuples, err := c.importedPhysicalEgress(collector)
	if err != nil || collector.selected.Tag != ExternalDNSTag || collector.selected.Detour != "proxy" ||
		collector.selected.Physical || len(collector.roots) == 0 {
		return result, importedDesktopCaptureError
	}
	launch, err := c.ImportedLaunchInput()
	if err != nil {
		return result, importedDesktopCaptureError
	}
	result = ImportedDesktopCapture{
		SourceSHA256: c.imported.source, ConfigSHA256: externalDigest([]byte(c.config)),
		MetadataSHA256: externalDigest([]byte(c.imported.metadata)), CaptureSHA256: externalDigest([]byte(launch)),
		EntryID: c.meta.EntryID, ExitID: c.meta.ExitID, ExitNodeID: c.meta.ExitNodeID,
		EntryMode: c.meta.EntryMode, ExitMode: c.meta.ExitMode,
		EntryStartLayer: c.meta.EntryStartLayer, ExitStartLayer: c.meta.ExitStartLayer,
		EntryTag: c.meta.EntryTag, FinalTag: "proxy", TUNTag: predecessorText(tun, "tag"),
		KillSwitchPolicy: kill, IPv6Mode: ipv6, HomeLANAccess: len(blocked) == 0,
		UDPAvailable: c.meta.TransportCapability != "tcp-only", BlockedLANCIDRs: append([]string(nil), blocked...),
		MTUPolicy: mtuPolicy, ConfiguredMTU: mtu, SelectedDNS: collector.selected,
	}
	result.SelectedDNS.Mode = predecessorText(final, "dns_mode")
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
