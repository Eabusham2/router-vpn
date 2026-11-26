package mobilemultihop

import (
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strconv"
)

// The worker's dedicated native DNS transport can contact only this registered
// private AdGuard tuple, using the paired gateway from its authenticated lease.
// Application fronts and public measurements are never given this outbound.
const NodeChainServerEntryHomeTag = "routervpn-registered-entry-home-dns"

type NodeChainServerHomeDNS struct {
	SourceSHA256 string `json:"source_sha256"`
	Network      string `json:"network"`
	Address      string `json:"address"`
}

func (h NodeChainServerHomeDNS) outbound() map[string]any {
	return map[string]any{"tag": NodeChainServerEntryHomeTag, "type": NodeChainServerEntryHomeTag, "source_sha256": h.SourceSHA256, "network": h.Network, "address": h.Address}
}

func externalFinalWorkerResolver(selected externalPolicyCapture, ipv6, owner, sourceSHA string, registered map[string]any) (map[string]any, *NodeChainServerHomeDNS, error) {
	if owner == "external-final" {
		dns, meta, err := externalSelectedDNS(selected, ipv6, true)
		if err != nil || meta.mode == "home" || meta.detour != ExternalFinalTag {
			return nil, nil, nodeChainServerError
		}
		raw, _ := json.Marshal(dns)
		got, _ := json.Marshal(registered)
		if string(raw) != string(got) {
			return nil, nil, nodeChainServerError
		}
		return dns, nil, nil
	}
	rows, ok := registered["servers"].([]any)
	mode := predecessorText(selected.Profile, "dns_mode")
	if owner != "entry-home" || mode != "" && mode != "home" || !ok || len(rows) != 1 || selected.DNSBootstrap != nil {
		return nil, nil, nodeChainServerError
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		return nil, nil, nodeChainServerError
	}
	host := predecessorText(row, "server")
	ip, err := netip.ParseAddr(host)
	requested := predecessorText(selected.Profile, "dns_host")
	if err != nil || !ip.IsPrivate() || ip.Is4In6() || ip.Zone() != "" || ip.String() != host || requested != "" && requested != host {
		return nil, nil, nodeChainServerError
	}
	// Rebuild the exact wire resolver from the standalone final's preferences
	// and the one registered Home address. No paired API secret is synthesized.
	selected.Profile = predecessorCopy(selected.Profile)
	selected.Profile["dns_mode"], selected.Profile["dns_host"] = "custom", host
	if predecessorText(selected.Profile, "dns_protocol") == "" {
		selected.Profile["dns_protocol"] = "udp"
	}
	dns, meta, err := externalSelectedDNS(selected, ipv6, true)
	if err != nil {
		return nil, nil, err
	}
	resolver := dns["servers"].([]any)[0].(map[string]any)
	resolver["detour"] = externalEntryTag
	raw, _ := json.Marshal(dns)
	got, _ := json.Marshal(registered)
	if string(raw) != string(got) {
		return nil, nil, nodeChainServerError
	}
	network := "tcp"
	if meta.protocol == "udp" || meta.protocol == "h3" {
		network = "udp"
	}
	h := &NodeChainServerHomeDNS{sourceSHA, network, net.JoinHostPort(host, strconv.Itoa(meta.port))}
	return dns, h, nil
}

func (h *NodeChainServerHomeDNS) physical(p *nodeEgressProjection, resolver map[string]any, bootstrap bool, tag, host, network string, port any) error {
	if h == nil || bootstrap || resolver["detour"] != NodeChainServerEntryHomeTag || resolver["domain_resolver"] != nil || !proofID.MatchString(h.SourceSHA256) || !reflect.DeepEqual(p.nodes[NodeChainServerEntryHomeTag], h.outbound()) || h.Network != network || !externalPort(port) || h.Address != net.JoinHostPort(host, strconv.Itoa(int(port.(float64)))) || p.desktop != nil {
		return nodePhysicalEgressError
	}
	if err := p.add(host, port, network); err != nil {
		return err
	}
	p.visited["dns:"+tag] = true
	return nil
}
