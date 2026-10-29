package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativecomposite"
	"router-vpn/internal/nativeopenvpn"
)

// PhysicalEgress has the same wire shape as nativeopenvpn.LayerEgress. Each
// item authorizes one outer address/port/transport, never every port on a host.
type PhysicalEgress struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

var nodePhysicalEgressError = errors.New("captured Router graph has no exact bounded physical egress")

// A physically dialed SOCKS UDP relay is negotiated at runtime. Its address or
// port cannot be invented from the control endpoint. A caller must retain its
// existing dynamic-path boundary until an owned socket broker supplies it.
var ErrDynamicPhysicalEgress = errors.New("captured physical path requires an owned dynamic UDP relay")

// NodePhysicalEgress projects a complete, already captured Router graph onto
// its actual physical sockets. It performs no resolution, file or network I/O.
// A detoured service, private proof target or application DNS server is not a
// physical exception. Protocol conversion is applied at every hop: WG/PQ and
// Hysteria use UDP; Xray and Naive H2 use TCP; a composite retains both lanes.
func NodePhysicalEgress(mode, profileJSON, configJSON string) ([]PhysicalEgress, error) {
	if err := ValidateNodePredecessor(mode, profileJSON, configJSON); err != nil {
		return nil, err
	}
	return compiledPhysicalEgress(configJSON, []string{"tcp", "udp"})
}

// DirectPhysicalEgress accepts only this already validated ordinary direct
// policy. Callers must declare the actual payload transports they need. SOCKS
// UDP relay negotiation is not a fixed server-port exception, and HTTP CONNECT
// cannot gain datagram authority by being placed before another protocol.
func (p *ExternalPolicy) DirectPhysicalEgress(networks []string) ([]PhysicalEgress, error) {
	if p == nil || p.capture.Entry != nil || p.capture.EntryTag != "" || p.capture.Execution != nil || p.capture.PredecessorConfig != "" ||
		len(networks) == 0 || len(networks) > 2 {
		return nil, nodePhysicalEgressError
	}
	seen := map[string]bool{}
	for _, network := range networks {
		if network != "tcp" && network != "udp" || seen[network] {
			return nil, nodePhysicalEgressError
		}
		seen[network] = true
	}
	return compiledPhysicalEgress(p.config, networks)
}

// PhysicalEgress projects the complete captured ordinary path, including its
// actual predecessor, selected DNS dependencies and Start Layers. No currently
// selected profile or unauthenticated remote can add a physical exception.
func (p *ExternalPolicy) PhysicalEgress() ([]PhysicalEgress, error) {
	if p == nil || p.config == "" || p.capture.Profile == nil {
		return nil, nodePhysicalEgressError
	}
	var metadata externalPolicyMetadata
	if json.Unmarshal([]byte(p.metadata), &metadata) != nil || metadata.Schema != 1 ||
		metadata.SourceSHA256 != p.source || metadata.ConfigSHA256 != externalDigest([]byte(p.config)) {
		return nil, nodePhysicalEgressError
	}
	networks := []string{"tcp"}
	if metadata.UDPAvailable {
		networks = append(networks, "udp")
	}
	return compiledPhysicalEgress(p.config, networks)
}

// Source constructors validate the complete graph before this private helper.
// It never accepts an arbitrary caller's JSON as firewall authority.
func compiledPhysicalEgress(configJSON string, networks []string) ([]PhysicalEgress, error) {
	return compiledPhysicalEgressWithDesktop(configJSON, networks, nil)
}

func compiledPhysicalEgressWithDesktop(configJSON string, networks []string, desktop *externalDesktopRecorder) ([]PhysicalEgress, error) {
	var graph map[string]any
	if exactJSON([]byte(configJSON), &graph, 4<<20) != nil {
		return nil, nodePhysicalEgressError
	}
	p := nodeEgressProjection{
		nodes: map[string]map[string]any{}, resolvers: map[string]map[string]any{},
		active: map[string]bool{}, visited: map[string]bool{}, tuples: map[PhysicalEgress]bool{},
		desktop: desktop,
	}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := graph[family].([]any)
		for _, raw := range rows {
			node := raw.(map[string]any)
			p.nodes[predecessorText(node, "tag")] = node
			if desktop != nil {
				desktop.families[predecessorText(node, "tag")] = family
			}
		}
	}
	dns := graph["dns"].(map[string]any)
	for _, raw := range dns["servers"].([]any) {
		server := raw.(map[string]any)
		p.resolvers[predecessorText(server, "tag")] = server
	}
	final := predecessorText(graph["route"].(map[string]any), "final")
	for _, network := range networks {
		if err := p.node(final, network); err != nil {
			return nil, err
		}
	}
	// Application DNS retains its encrypted route. Only an explicit resolver
	// dependency actually needed to resolve a hostname may add a physical DNS
	// tuple; merely declaring another DNS server cannot open an exception.
	if err := p.dns(predecessorText(dns, "final"), false); err != nil {
		return nil, err
	}
	if len(p.tuples) == 0 || len(p.tuples) > 16 {
		return nil, nodePhysicalEgressError
	}
	result := make([]PhysicalEgress, 0, len(p.tuples))
	for tuple := range p.tuples {
		result = append(result, tuple)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Host != result[j].Host {
			return result[i].Host < result[j].Host
		}
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Network < result[j].Network
	})
	return result, nil
}

type nodeEgressProjection struct {
	nodes, resolvers map[string]map[string]any
	active, visited  map[string]bool
	tuples           map[PhysicalEgress]bool
	desktop          *externalDesktopRecorder
}

func (p *nodeEgressProjection) add(host string, port any, network string) error {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.String() != host || ip.Is4In6() || ip.Zone() != "" || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !externalPort(port) ||
		network != "tcp" && network != "udp" {
		return nodePhysicalEgressError
	}
	if ip.Is4() {
		v4 := ip.As4()
		if v4[0] == 0 || v4[0] >= 224 {
			return nodePhysicalEgressError
		}
	}
	p.tuples[PhysicalEgress{host, int(port.(float64)), network}] = true
	if len(p.tuples) > 16 {
		return nodePhysicalEgressError
	}
	return nil
}

func (p *nodeEgressProjection) node(tag, payload string) error {
	key := "node:" + tag + ":" + payload
	value := p.nodes[tag]
	if value == nil || p.active[key] || len(p.active) > 96 || payload != "tcp" && payload != "udp" {
		return nodePhysicalEgressError
	}
	if p.visited[key] {
		return nil
	}
	p.active[key] = true
	defer delete(p.active, key)
	if value["type"] == "selector" {
		// This selector can only be emitted by the validated ordinary
		// Local/Server compiler. Capture both candidate paths before trials;
		// never follow an arbitrary default or rerun Compare selection.
		children, ok := value["outbounds"].([]any)
		if tag != ExternalFinalTag || len(value) != 5 || !ok || len(children) != 2 ||
			children[0] != LocalTag || children[1] != ServerTag ||
			value["default"] != LocalTag && value["default"] != ServerTag ||
			value["interrupt_exist_connections"] != true {
			return nodePhysicalEgressError
		}
		for _, child := range []string{LocalTag, ServerTag} {
			if err := p.node(child, payload); err != nil {
				return err
			}
		}
		p.visited[key] = true
		return nil
	}
	if value["type"] == nativecomposite.Type {
		if err := p.node(predecessorText(value, payload), payload); err != nil {
			return err
		}
		p.visited[key] = true
		return nil
	}
	// The qualified native Xray compiler checks the full nested protocol, not
	// just the outer type label or an arbitrary recursively found address.
	if p.desktop != nil && value["type"] == "naive" && value["domain_resolver"] != nil {
		// Naive retains an explicit native resolver even for a literal server.
		// The desktop wrapper must preserve that compiled bootstrap dependency;
		// the legacy fixed-tuple projection keeps its existing behavior.
		if err := p.resolve(value); err != nil {
			return err
		}
	}
	var sockets []PhysicalEgress
	switch value["type"] {
	case "socks":
		if payload == "udp" {
			if !externalPort(value["server_port"]) {
				return nodePhysicalEgressError
			}
			detour := predecessorText(value, "detour")
			if detour == "" {
				if p.desktop != nil {
					if err := p.desktop.socks(p, tag, value); err != nil {
						return err
					}
					p.visited[key] = true
					return nil
				}
				return ErrDynamicPhysicalEgress
			}
			// Both SOCKS control and its negotiated relay traverse the captured
			// predecessor. Only that predecessor's real outer sockets belong
			// to the physical firewall, never the negotiated inner relay.
			if _, err := netip.ParseAddr(predecessorText(value, "server")); err != nil {
				if err := p.resolve(value); err != nil {
					return err
				}
			}
			for _, network := range []string{"tcp", "udp"} {
				if err := p.node(detour, network); err != nil {
					return err
				}
			}
			p.visited[key] = true
			return nil
		}
		fallthrough
	case "http":
		if payload != "tcp" || !externalPort(value["server_port"]) {
			return nodePhysicalEgressError
		}
		sockets = append(sockets, PhysicalEgress{predecessorText(value, "server"), int(value["server_port"].(float64)), "tcp"})
	case externalOpenVPNType:
		remotes, err := p.openVPNRemotes(value)
		if err != nil {
			return nodePhysicalEgressError
		}
		sockets = append(sockets, remotes...)
	case "wireguard", AmneziaType, PQType:
		peers, ok := value["peers"].([]any)
		if !ok || len(peers) != 1 {
			return nodePhysicalEgressError
		}
		peer := peers[0].(map[string]any)
		if !externalPort(peer["port"]) {
			return nodePhysicalEgressError
		}
		sockets = append(sockets, PhysicalEgress{predecessorText(peer, "address"), int(peer["port"].(float64)), "udp"})
		if value["type"] == PQType {
			pq, ok := value["pq"].(map[string]any)
			address, err := netip.ParseAddrPort(predecessorText(pq, "endpoint"))
			if !ok || err != nil || address.Port() == 0 || address.String() != predecessorText(pq, "endpoint") {
				return nodePhysicalEgressError
			}
			sockets = append(sockets, PhysicalEgress{address.Addr().String(), int(address.Port()), "udp"})
		}
	case applexray.Type:
		plan, err := applexray.Prepare(predecessorText(value, "mode"), []byte(predecessorText(value, "config_json")))
		if err != nil || !plan.Server.IsValid() {
			return nodePhysicalEgressError
		}
		sockets = append(sockets, PhysicalEgress{plan.ServerHost, int(plan.ServerPort), "tcp"})
	case "shadowsocks", "routervpn-aes-xor", "hysteria2", "naive":
		network := payload
		switch value["type"] {
		case "hysteria2":
			network = "udp"
		case "naive":
			network = "tcp"
			if value["quic"] == true {
				network = "udp"
			}
		case "shadowsocks":
			if value["plugin"] != nil {
				if payload != "tcp" || value["network"] != "tcp" {
					return nodePhysicalEgressError
				}
				network = "tcp"
			}
		}
		if !externalPort(value["server_port"]) {
			return nodePhysicalEgressError
		}
		sockets = append(sockets, PhysicalEgress{predecessorText(value, "server"), int(value["server_port"].(float64)), network})
	default:
		return nodePhysicalEgressError
	}
	for _, socket := range sockets {
		if _, err := netip.ParseAddr(socket.Host); err != nil {
			if err := p.resolve(value); err != nil {
				return err
			}
		}
		if detour := predecessorText(value, "detour"); detour != "" {
			if err := p.through(detour, socket); err != nil {
				return err
			}
		} else {
			if p.desktop != nil {
				if err := p.desktop.node(p, tag, value, socket); err != nil {
					return err
				}
			} else if err := p.add(socket.Host, float64(socket.Port), socket.Network); err != nil {
				return err
			}
		}
	}
	p.visited[key] = true
	return nil
}

func (p *nodeEgressProjection) openVPNRemotes(value map[string]any) ([]PhysicalEgress, error) {
	remotes, err := nativeopenvpn.Remotes(value)
	if err == nil {
		result := make([]PhysicalEgress, len(remotes))
		for i, remote := range remotes {
			result[i] = PhysicalEgress{remote.Host, remote.Port, remote.Network}
		}
		return result, nil
	}
	// A validated same-host Start Layer rewrites the inner OpenVPN remotes
	// to its private API address. The public-import Remotes validator must
	// keep rejecting those addresses. This projection accepts them only
	// inside the already-compiled fixed layer and never grants them physical
	// access; node() subsequently follows that exact layer's outer sockets.
	layer := p.nodes[predecessorText(value, "detour")]
	if layer == nil || layer["type"] != "shadowsocks" && layer["type"] != "routervpn-aes-xor" {
		return nil, nodePhysicalEgressError
	}
	rows := []any{map[string]any{"server": value["server"], "server_port": value["server_port"], "network": value["network"]}}
	if raw, exists := value["servers"]; exists {
		var ok bool
		rows, ok = raw.([]any)
		if !ok || len(rows) < 2 || len(rows) > 16 || value["server"] != nil || value["server_port"] != nil {
			return nil, nodePhysicalEgressError
		}
	}
	result := make([]PhysicalEgress, 0, len(rows))
	for i, raw := range rows {
		remote, ok := raw.(map[string]any)
		if !ok || len(remote) != 3 || !externalPort(remote["server_port"]) {
			return nil, nodePhysicalEgressError
		}
		host := predecessorText(remote, "server")
		address, err := netip.ParseAddr(host)
		if err != nil || !address.IsPrivate() || address.Is4In6() || address.Zone() != "" || address.String() != host {
			return nil, nodePhysicalEgressError
		}
		network := predecessorText(remote, "network")
		if i == 0 && value["network"] != network {
			return nil, nodePhysicalEgressError
		}
		switch network {
		case "tcp4", "tcp6":
			network = "tcp"
		case "udp4", "udp6":
			network = "udp"
		}
		if network != "tcp" && network != "udp" {
			return nil, nodePhysicalEgressError
		}
		result = append(result, PhysicalEgress{host, int(remote["server_port"].(float64)), network})
	}
	return result, nil
}

func (p *nodeEgressProjection) through(tag string, socket PhysicalEgress) error {
	value := p.nodes[tag]
	if value == nil {
		return nodePhysicalEgressError
	}
	if value["type"] != nativeopenvpn.LayerMapType {
		return p.node(tag, socket.Network)
	}
	// Every OpenVPN remote keeps its exact owned Start Layer; another remote
	// or unrelated child cannot contribute a physical exception.
	copy := predecessorCopy(value)
	delete(copy, "type")
	delete(copy, "tag")
	raw, err := json.Marshal(copy)
	var mapping nativeopenvpn.LayerMap
	if err != nil || json.Unmarshal(raw, &mapping) != nil {
		return nodePhysicalEgressError
	}
	found := false
	for _, remote := range mapping.Remotes {
		if remote.Host == socket.Host && remote.Port == socket.Port && remote.Network == socket.Network {
			found = true
			break
		}
	}
	if !found {
		return nodePhysicalEgressError
	}
	layer := mapping.Layers[socket.Host]
	port := layer.Transport["server_port"]
	if mapping.Mode == "aes-256-gcm+xor-whitening" {
		port = float64(8389)
	}
	if mapping.Detour != "" {
		return p.node(mapping.Detour, socket.Network)
	}
	if p.desktop != nil {
		if !externalPort(port) {
			return nodePhysicalEgressError
		}
		return p.desktop.node(p, tag, value, PhysicalEgress{socket.Host, int(port.(float64)), socket.Network})
	}
	return p.add(socket.Host, port, socket.Network)
}

func (p *nodeEgressProjection) resolve(value map[string]any) error {
	if p.desktop != nil {
		query, err := externalDesktopQuery(value["domain_resolver"])
		if err != nil || !query.Present {
			return externalDesktopCaptureError
		}
		return p.dns(query.Server, true)
	}
	query, err := predecessorResolverSelection(value["domain_resolver"])
	if err != nil {
		return nodePhysicalEgressError
	}
	return p.dns(predecessorText(query, "server"), true)
}

func (p *nodeEgressProjection) dns(tag string, bootstrap bool) error {
	key := "dns:" + tag
	server := p.resolvers[tag]
	if server == nil || p.active[key] || len(p.active) > 96 {
		return nodePhysicalEgressError
	}
	// Check this before the visited shortcut so a direct bootstrap resolver
	// cannot later be adopted as the application's selected DNS route.
	detour := predecessorText(server, "detour")
	physical := detour == "" || p.nodes[detour] != nil && p.nodes[detour]["type"] == "direct"
	if physical && !bootstrap {
		return nodePhysicalEgressError
	}
	if p.visited[key] {
		return nil
	}
	p.active[key] = true
	defer delete(p.active, key)
	host := predecessorText(server, "server")
	if _, err := netip.ParseAddr(host); err != nil {
		if err := p.resolve(server); err != nil {
			return err
		}
	}
	network, port := "tcp", float64(53)
	switch server["type"] {
	case "udp":
		network = "udp"
	case "tcp":
	case "tls":
		port = 853
	case "https":
		port = 443
	case "h3":
		network, port = "udp", 443
	case "quic":
		network, port = "udp", 853
	default:
		return nodePhysicalEgressError
	}
	if value, exists := server["server_port"]; exists {
		if !externalPort(value) {
			return nodePhysicalEgressError
		}
		port = value.(float64)
	}
	if p.desktop != nil {
		if err := p.desktop.dns(tag, server, bootstrap, physical, int(port)); err != nil {
			return err
		}
	}
	if physical {
		if err := p.add(host, port, network); err != nil {
			return err
		}
	} else if err := p.node(detour, network); err != nil {
		return err
	}
	p.visited[key] = true
	return nil
}
