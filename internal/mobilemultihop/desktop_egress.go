package mobilemultihop

import (
	"errors"
	"net/netip"
	"sort"

	"router-vpn/internal/applexray"
	"router-vpn/internal/nativecomposite"
)

// PhysicalEgress has the same wire shape as nativeopenvpn.LayerEgress. Each
// item authorizes one outer address/port/transport, never every port on a host.
type PhysicalEgress struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Network string `json:"network"`
}

var nodePhysicalEgressError = errors.New("captured Router graph has no exact bounded physical egress")

// NodePhysicalEgress projects a complete, already captured Router graph onto
// its actual physical sockets. It performs no resolution, file or network I/O.
// A detoured service, private proof target or application DNS server is not a
// physical exception. Protocol conversion is applied at every hop: WG/PQ and
// Hysteria use UDP; Xray and Naive H2 use TCP; a composite retains both lanes.
func NodePhysicalEgress(mode, profileJSON, configJSON string) ([]PhysicalEgress, error) {
	if err := ValidateNodePredecessor(mode, profileJSON, configJSON); err != nil {
		return nil, err
	}
	var graph map[string]any
	if exactJSON([]byte(configJSON), &graph, 4<<20) != nil {
		return nil, nodePhysicalEgressError
	}
	p := nodeEgressProjection{
		nodes: map[string]map[string]any{}, resolvers: map[string]map[string]any{},
		active: map[string]bool{}, visited: map[string]bool{}, tuples: map[PhysicalEgress]bool{},
	}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, _ := graph[family].([]any)
		for _, raw := range rows {
			node := raw.(map[string]any)
			p.nodes[predecessorText(node, "tag")] = node
		}
	}
	dns := graph["dns"].(map[string]any)
	for _, raw := range dns["servers"].([]any) {
		server := raw.(map[string]any)
		p.resolvers[predecessorText(server, "tag")] = server
	}
	final := predecessorText(graph["route"].(map[string]any), "final")
	for _, network := range []string{"tcp", "udp"} {
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
	if value["type"] == nativecomposite.Type {
		if err := p.node(predecessorText(value, payload), payload); err != nil {
			return err
		}
		p.visited[key] = true
		return nil
	}
	// The qualified native Xray compiler checks the full nested protocol, not
	// just the outer type label or an arbitrary recursively found address.
	var sockets []PhysicalEgress
	switch value["type"] {
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
			if err := p.node(detour, socket.Network); err != nil {
				return err
			}
		} else if err := p.add(socket.Host, float64(socket.Port), socket.Network); err != nil {
			return err
		}
	}
	p.visited[key] = true
	return nil
}

func (p *nodeEgressProjection) resolve(value map[string]any) error {
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
