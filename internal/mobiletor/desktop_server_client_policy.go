package mobiletor

import (
	"encoding/json"
	"errors"
)

// NewDesktopServerTorPolicy keeps the same captured TUN/device policy compiler
// but gives its final outbound an explicit leased-server owner. Lowering the
// common entry graph does not create Local Tor authority: both its metadata and
// actual native outbound require Server, and the local-child factory rejects it.
func NewDesktopServerTorPolicy(source, session, isolation, targetOS string, predecessor *DesktopPredecessor) (*DesktopBridgePolicy, error) {
	profile, err := profileObject(source, 256<<10)
	if err != nil || predecessor == nil || !predecessor.IsRouter() || profileString(profile, "multihop_execution") != "server" || profile["multihop_enabled"] != true || profileString(profile, "multihop_entry_id") != predecessor.ID() || profileString(profile, "multihop_exit_id") != profileString(profile, "id") {
		return nil, errors.New("Tor Server requires its exact captured private Router entry and saved execution")
	}
	profile["multihop_execution"] = "local"
	normalizeDesktopServerDNSMode(profile)
	lowered, _ := json.Marshal(profile)
	policy, err := newDesktopBridgePolicy(string(lowered), session, isolation, targetOS, predecessor)
	if err != nil {
		return nil, err
	}
	server, err := desktopServerTorSource(policy)
	if err != nil {
		return nil, err
	}
	graph, err := profileObject(policy.Config(), 4<<20)
	if err != nil {
		return nil, err
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok {
		return nil, errServerTorClient
	}
	replaced := 0
	for i, row := range outbounds {
		outbound, ok := row.(map[string]any)
		if !ok {
			return nil, errServerTorClient
		}
		if outbound["tag"] == ProfileOutboundTag {
			if outbound["type"] != "socks" {
				return nil, errServerTorClient
			}
			outbounds[i] = map[string]any{"type": ServerTorClientType, "tag": ProfileOutboundTag, "entry_tag": predecessor.Tag(), "entry_profile": predecessor.Profile(), "server_source": server.Source(), "session_id": session}
			replaced++
		}
	}
	if replaced != 1 {
		return nil, errServerTorClient
	}
	// The remote worker owns bridge/broker bootstrap. Keep the captured entry's
	// existing resolver dependencies and the user's selected client DNS, but
	// remove the extra local-PT bootstrap transport synthesized by the common
	// graph compiler. The leased private origin/front are literal TCP targets.
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return nil, errServerTorClient
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return nil, errServerTorClient
	}
	retained := make([]any, 0, len(servers))
	removed := 0
	for _, row := range servers {
		server, ok := row.(map[string]any)
		if !ok {
			return nil, errServerTorClient
		}
		if server["tag"] == bootstrapDNS {
			removed++
			continue
		}
		retained = append(retained, row)
	}
	if removed != 1 {
		return nil, errServerTorClient
	}
	dns["servers"] = retained
	identity, _ := json.Marshal([]string{"routervpn-desktop-server-tor-v1", source, session, isolation, targetOS, predecessor.profile, predecessor.config, predecessor.assets, server.Source()})
	sourceSHA := desktopDigest(identity)
	services, ok := graph["services"].([]any)
	if !ok {
		return nil, errServerTorClient
	}
	observed := 0
	for _, row := range services {
		service, ok := row.(map[string]any)
		if !ok {
			return nil, errServerTorClient
		}
		if service["type"] == "routervpn-desktop-tor-network" {
			if service["source_sha256"] != policy.SourceSHA256() || service["session_id"] != session {
				return nil, errServerTorClient
			}
			service["source_sha256"], observed = sourceSHA, observed+1
		}
	}
	if observed != 1 {
		return nil, errServerTorClient
	}
	encoded, err := json.Marshal(graph)
	if err != nil || len(encoded) > 4<<20 {
		return nil, errServerTorClient
	}
	policy.source, policy.config, policy.server = source, string(encoded), server
	policy.metadata.SourceSHA256, policy.metadata.ConfigSHA256 = sourceSHA, desktopDigest(encoded)
	policy.metadata.Execution, policy.metadata.SocksPort = "server", 0
	policy.metadata.BootstrapDNSTag = ""
	policy.metadata.ServerSourceSHA256, policy.metadata.ServerDNSPolicySHA256 = server.SourceSHA256(), server.DNSPolicySHA256()
	return policy, nil
}

// The registry stores canonical policy, while source identity still binds the
// exact saved application selection. Desktop transport aliases select the same
// resolver/transport as Custom; an omitted mode retains Home AdGuard.
func normalizeDesktopServerDNSMode(profile map[string]any) {
	switch mode := profileString(profile, "dns_mode"); mode {
	case "":
		profile["dns_mode"] = "home"
	case "dot", "doh", "doh3":
		profile["dns_mode"], profile["dns_protocol"] = "custom", mode
	}
}

func desktopServerTorSource(policy *DesktopBridgePolicy) (*ServerTorPolicy, error) {
	if policy == nil || policy.predecessor == nil || !policy.predecessor.IsRouter() {
		return nil, errServerTorClient
	}
	source := map[string]any{"schema": 1, "id": policy.metadata.NodeID, "entry_node_id": policy.predecessor.proof.node, "mode": policy.Mode(), "dns": policy.metadata.DNS}
	if policy.Mode() == "tor-bridge" {
		plan, err := policy.Plan()
		if err != nil {
			return nil, err
		}
		bridges := make([]string, len(plan.Bridges))
		for i, bridge := range plan.Bridges {
			bridges[i] = bridge.Line
		}
		source["tor_bridge"] = map[string]any{"transport": "custom", "bridges": bridges}
	} else if policy.Mode() != "tor" {
		return nil, errServerTorClient
	}
	if policy.metadata.DNS.Mode == "home" {
		entry, err := profileObject(policy.predecessor.profile, 256<<10)
		if err != nil {
			return nil, err
		}
		for _, key := range []string{"adguard_ipv4", "adguard_ipv6"} {
			if value, exists := entry[key]; exists && value != "" {
				source[key] = value
			}
		}
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	return NewServerTorPolicy(string(raw), policy.predecessor.proof.node)
}
