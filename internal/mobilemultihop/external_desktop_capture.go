package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
)

// ExternalDesktopCapture is a copied description of an already compiled
// ordinary path. It owns no native object and authorizes no socket or firewall
// exception. A desktop host must separately capture its OS, session, actual
// interface, kernel identity, complete derived graph and live proof lifecycle.
// Callers cannot construct an ExternalPolicy from this value.
type ExternalDesktopCapture struct {
	SourceSHA256, ConfigSHA256, MetadataSHA256, CaptureSHA256 string
	PolicyID, ExitID, EntryID, EntryTag, PredecessorSHA256    string
	ExpectedPublicIP, EntryNodeID, DNSBootstrapSHA256         string
	Protocol, StartLayer, EntryStartLayer, Execution          string
	FinalTag, TUNTag                                          string
	KillSwitchPolicy, IPv6Mode                                string
	HomeLANAccess, UDPAvailable                               bool
	BlockedLANCIDRs                                           []string
	MTUPolicy                                                 string
	ConfiguredMTU, EntryMTU                                   int
	SelectedDNS                                               ExternalDesktopDNS
	BootstrapDNS                                              []ExternalDesktopDNS
	PhysicalRoots                                             []ExternalDesktopPhysicalRoot
	PrivateDestinations                                       []PhysicalEgress
}

// ExternalDesktopDNSQuery preserves the complete captured query selection.
// Optional pointers distinguish an explicit false/zero from an omitted value;
// every accessor call allocates fresh values. ConfigSHA256 also covers the
// original string-versus-object query representation.
type ExternalDesktopDNSQuery struct {
	Present, StrategySet, TimeoutSet, ClientSubnetSet bool
	Server, Strategy, Timeout, ClientSubnet           string
	DisableCache, DisableOptimisticCache              *bool
	RewriteTTL                                        *uint32
	ConfigSHA256                                      string
}

// ConfigSHA256 identifies the complete original DNS object, including TLS and
// query fields not rewritten by a native lower-path adapter. Physical is true
// only for a resolver dependency actually reached outside an encrypted node;
// selected application/Home DNS is never promoted into a physical exception.
type ExternalDesktopDNS struct {
	Tag, Type, Mode, Host, ServerName, Path, Detour, ConfigSHA256 string
	Port                                                          int
	Physical                                                      bool
	Resolver                                                      ExternalDesktopDNSQuery
}

// A root selects one exact compiled lower transport by family, tag and complete
// object digest. Destinations are source intent, not measured/resolved grants.
// A hostname cannot add a private exception. Networks describes actual outer
// transports; it does not authorize every port or another runtime owner.
type ExternalDesktopPhysicalRoot struct {
	Family, Tag, Type, ConfigSHA256 string
	Resolver                        ExternalDesktopDNSQuery
	Networks                        []string
	Destinations                    []PhysicalEgress
	DynamicSOCKSUDP                 bool
	SOCKSControl                    *PhysicalEgress
	SOCKSVersion                    string
}

var externalDesktopCaptureError = errors.New("ordinary desktop capture lost its complete validated source")

func (p *ExternalPolicy) desktopCaptureSeal() (string, string, error) {
	if p == nil || p.config == "" || p.metadata == "" || !proofID.MatchString(p.source) || p.capture.Profile == nil {
		return "", "", externalDesktopCaptureError
	}
	capture, err := json.Marshal(p.capture)
	if err != nil || len(capture) > 8<<20 {
		return "", "", externalDesktopCaptureError
	}
	sealed, err := json.Marshal([]string{"routervpn-external-desktop-capture-v1", p.source, p.config, p.metadata, string(capture)})
	if err != nil {
		return "", "", externalDesktopCaptureError
	}
	return externalDigest(sealed), externalDigest(capture), nil
}

func (p *ExternalPolicy) sealDesktopCapture() error {
	seal, _, err := p.desktopCaptureSeal()
	if err != nil {
		return err
	}
	p.desktopSeal = seal
	return nil
}

// DesktopCapture accepts only the immutable result of NewExternalPolicy. Its
// private construction seal binds the exact source/config/metadata and decoded
// private selection; stale or partially replaced fields fail before traversal.
// It neither relaxes PhysicalEgress's dynamic-relay rejection nor accepts an
// additional caller-supplied graph, profile, resolver or policy object.
func (p *ExternalPolicy) DesktopCapture() (ExternalDesktopCapture, error) {
	var result ExternalDesktopCapture
	seal, captureSHA, err := p.desktopCaptureSeal()
	if err != nil || p.desktopSeal == "" || p.desktopSeal != seal {
		return result, externalDesktopCaptureError
	}
	var meta externalPolicyMetadata
	if exactJSON([]byte(p.metadata), &meta, 64<<10) != nil || meta.Schema != 1 ||
		meta.SourceSHA256 != p.source || meta.ConfigSHA256 != externalDigest([]byte(p.config)) ||
		meta.FinalTag != ExternalFinalTag || meta.DNSProof != "required" || meta.PublicExitProof != "required" {
		return result, externalDesktopCaptureError
	}
	kill, err := externalDesktopKillPolicy(p.capture.Profile)
	if err != nil {
		return result, err
	}
	collector := &externalDesktopRecorder{
		families: map[string]string{}, roots: map[string]*ExternalDesktopPhysicalRoot{},
		bootstrap: map[string]ExternalDesktopDNS{},
	}
	networks := []string{"tcp"}
	if meta.UDPAvailable {
		networks = append(networks, "udp")
	}
	tuples, err := compiledPhysicalEgressWithDesktop(p.config, networks, collector)
	if err != nil {
		return result, err
	}
	if collector.selected.Tag != ExternalDNSTag || collector.selected.Type != meta.DNSProtocol || collector.selected.Host != meta.DNSServer ||
		collector.selected.Port != meta.DNSPort || collector.selected.ServerName != meta.DNSServerName || collector.selected.Path != meta.DNSPath ||
		collector.selected.Detour != meta.DNSDetour || collector.selected.Physical {
		return result, externalDesktopCaptureError
	}
	result = ExternalDesktopCapture{
		SourceSHA256: p.source, ConfigSHA256: meta.ConfigSHA256, MetadataSHA256: externalDigest([]byte(p.metadata)), CaptureSHA256: captureSHA,
		PolicyID: meta.PolicyID, ExitID: meta.ExitID, EntryID: meta.EntryID, EntryTag: meta.EntryTag, PredecessorSHA256: meta.PredecessorSHA256,
		ExpectedPublicIP: meta.ExpectedPublicIP, EntryNodeID: meta.EntryNodeID, DNSBootstrapSHA256: meta.DNSBootstrapSHA256,
		Protocol: meta.Protocol, StartLayer: meta.StartLayer, EntryStartLayer: meta.EntryStartLayer, Execution: meta.Execution,
		FinalTag: meta.FinalTag, TUNTag: meta.TUNTag, KillSwitchPolicy: kill, IPv6Mode: meta.IPv6Mode,
		HomeLANAccess: meta.HomeLANAccess, UDPAvailable: meta.UDPAvailable, BlockedLANCIDRs: append([]string(nil), meta.BlockedLANCIDRs...),
		MTUPolicy: meta.MTUPolicy, ConfiguredMTU: meta.ConfiguredMTU, EntryMTU: meta.EntryMTU,
		SelectedDNS: collector.selected,
	}
	result.SelectedDNS.Mode = meta.DNSMode
	for _, dns := range collector.bootstrap {
		result.BootstrapDNS = append(result.BootstrapDNS, dns)
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
	if len(result.PhysicalRoots) == 0 {
		return ExternalDesktopCapture{}, externalDesktopCaptureError
	}
	return result, nil
}

func externalDesktopKillPolicy(profile map[string]any) (string, error) {
	legacy := false
	if raw, exists := profile["kill_switch"]; exists {
		var ok bool
		legacy, ok = raw.(bool)
		if !ok {
			return "", externalDesktopCaptureError
		}
	}
	value, err := externalOptionalString(profile, "kill_switch_policy")
	if err != nil {
		return "", externalDesktopCaptureError
	}
	if value == "" {
		if legacy {
			return "on-connect", nil
		}
		return "off", nil
	}
	if value != "off" && value != "on-connect" && value != "always" {
		return "", externalDesktopCaptureError
	}
	return value, nil
}

type externalDesktopRecorder struct {
	families  map[string]string
	roots     map[string]*ExternalDesktopPhysicalRoot
	bootstrap map[string]ExternalDesktopDNS
	selected  ExternalDesktopDNS
}

func externalDesktopObjectSHA(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 4<<20 {
		return "", externalDesktopCaptureError
	}
	return externalDigest(raw), nil
}

func externalDesktopQuery(value any) (ExternalDesktopDNSQuery, error) {
	var result ExternalDesktopDNSQuery
	if value == nil {
		return result, nil
	}
	var query map[string]any
	switch value := value.(type) {
	case string:
		query = map[string]any{"server": value}
	case map[string]any:
		query = value
	default:
		return result, externalDesktopCaptureError
	}
	result.Server = predecessorText(query, "server")
	if !exactID.MatchString(result.Server) || externalDNSQuery(query, result.Server) != nil {
		return result, externalDesktopCaptureError
	}
	result.Present = true
	result.Strategy, result.StrategySet = query["strategy"].(string)
	result.Timeout, result.TimeoutSet = query["timeout"].(string)
	result.ClientSubnet, result.ClientSubnetSet = query["client_subnet"].(string)
	if raw, exists := query["disable_cache"]; exists {
		value := raw.(bool)
		result.DisableCache = &value
	}
	if raw, exists := query["disable_optimistic_cache"]; exists {
		value := raw.(bool)
		result.DisableOptimisticCache = &value
	}
	if raw, exists := query["rewrite_ttl"]; exists {
		value := uint32(raw.(float64))
		result.RewriteTTL = &value
	}
	var err error
	result.ConfigSHA256, err = externalDesktopObjectSHA(value)
	return result, err
}

func (r *externalDesktopRecorder) root(tag string, value map[string]any) (*ExternalDesktopPhysicalRoot, error) {
	family := r.families[tag]
	if family != "endpoints" && family != "outbounds" || !exactID.MatchString(tag) {
		return nil, externalDesktopCaptureError
	}
	if existing := r.roots[tag]; existing != nil {
		return existing, nil
	}
	root := &ExternalDesktopPhysicalRoot{Family: family, Tag: tag, Type: predecessorText(value, "type")}
	var err error
	root.ConfigSHA256, err = externalDesktopObjectSHA(value)
	if err != nil {
		return nil, err
	}
	root.Resolver, err = externalDesktopQuery(value["domain_resolver"])
	if err != nil {
		return nil, err
	}
	r.roots[tag] = root
	return root, nil
}

func (r *externalDesktopRecorder) node(p *nodeEgressProjection, tag string, value map[string]any, socket PhysicalEgress) error {
	if _, err := netip.ParseAddr(socket.Host); err == nil {
		if err := p.add(socket.Host, float64(socket.Port), socket.Network); err != nil {
			return err
		}
	} else if !externalDNSHostname(socket.Host) || socket.Port < 1 || socket.Port > 65535 || socket.Network != "tcp" && socket.Network != "udp" {
		return externalDesktopCaptureError
	}
	root, err := r.root(tag, value)
	if err != nil {
		return err
	}
	root.Networks = externalDesktopNetwork(root.Networks, socket.Network)
	for _, previous := range root.Destinations {
		if previous == socket {
			return nil
		}
	}
	if len(root.Destinations) >= 16 || len(r.roots) > 32 {
		return externalDesktopCaptureError
	}
	root.Destinations = append(root.Destinations, socket)
	return nil
}

func externalDesktopNetwork(networks []string, value string) []string {
	for _, previous := range networks {
		if previous == value {
			return networks
		}
	}
	return append(networks, value)
}

func (r *externalDesktopRecorder) socks(p *nodeEgressProjection, tag string, value map[string]any) error {
	if value["type"] != "socks" || value["version"] != "5" || predecessorText(value, "detour") != "" {
		return externalDesktopCaptureError
	}
	// Reuse the ordinary TCP projection for authentication/control. No UDP
	// target is inferred from its server port; the native association must
	// capture and prove the actual negotiated relay before granting a socket.
	if err := p.node(tag, "tcp"); err != nil {
		return err
	}
	root := r.roots[tag]
	if root == nil || len(root.Destinations) != 1 || root.Destinations[0].Network != "tcp" {
		return externalDesktopCaptureError
	}
	control := root.Destinations[0]
	root.DynamicSOCKSUDP, root.SOCKSVersion, root.SOCKSControl = true, "5", &control
	root.Networks = externalDesktopNetwork(root.Networks, "udp")
	return nil
}

func (r *externalDesktopRecorder) dns(tag string, value map[string]any, bootstrap, physical bool, port int) error {
	result := ExternalDesktopDNS{
		Tag: tag, Type: predecessorText(value, "type"), Host: predecessorText(value, "server"), Port: port,
		Path: predecessorText(value, "path"), Detour: predecessorText(value, "detour"), Physical: physical,
	}
	if tls, ok := value["tls"].(map[string]any); ok {
		result.ServerName = predecessorText(tls, "server_name")
	}
	var err error
	result.ConfigSHA256, err = externalDesktopObjectSHA(value)
	if err != nil {
		return err
	}
	result.Resolver, err = externalDesktopQuery(value["domain_resolver"])
	if err != nil {
		return err
	}
	if tag == ExternalDNSTag && !bootstrap {
		r.selected = result
	} else if bootstrap {
		r.bootstrap[tag] = result
	}
	return nil
}

func sortPhysicalEgress(values []PhysicalEgress) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Host != values[j].Host {
			return values[i].Host < values[j].Host
		}
		if values[i].Port != values[j].Port {
			return values[i].Port < values[j].Port
		}
		return values[i].Network < values[j].Network
	})
}
