package mobilemultihop

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
)

const nodeChainImportedResolver = "routervpn-middle-transport-dns"

// This is source-only authority for one middle position. It is deliberately
// not an ExternalPolicy: an unresolved hostname cannot acquire a standalone
// physical socket, resolver grant, selected application DNS or ready receipt.
type nodeChainImportedHostname struct {
	Config string
	Device nodeChainImportedDevicePolicy
}
type nodeChainImportedDevicePolicy struct {
	KillSwitchPolicy string
	IPv6Mode         string
	HomeLANAccess    bool
}

func (m *nodeChainImportedMember) devicePolicy() (nodeChainImportedDevicePolicy, error) {
	if m.validate() != nil {
		return nodeChainImportedDevicePolicy{}, nodeChainError
	}
	if m.hostname != nil {
		return m.hostname.Device, nil
	}
	capture, err := m.policy.DesktopCapture()
	if err != nil {
		return nodeChainImportedDevicePolicy{}, err
	}
	return nodeChainImportedDevicePolicy{capture.KillSwitchPolicy, capture.IPv6Mode, capture.HomeLANAccess}, nil
}

func parseNodeChainImportedHostname(input string, record nodeChainImportedInput, selected externalPolicyCapture) (*nodeChainImportedMember, bool, error) {
	bad := errors.New("hostname middle requires its original SS2022 source and explicitly saved Custom TCP literal resolver")
	var graph map[string]any
	if exactJSON([]byte(record.Config), &graph, 4<<20) != nil {
		return nil, false, nil
	}
	outs, ok := graph["outbounds"].([]any)
	if !ok || len(outs) != 1 {
		return nil, false, nil
	}
	out, ok := outs[0].(map[string]any)
	if !ok {
		return nil, false, nil
	}
	host := predecessorText(out, "server")
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, false, nil
	}
	fail := func() (*nodeChainImportedMember, bool, error) { return nil, true, bad }
	if !externalDNSHostname(host) || strings.HasSuffix(host, ".") ||
		!maxFields(out, "type", "tag", "server", "server_port", "method", "password") ||
		out["type"] != "shadowsocks" || out["tag"] != ExternalFinalTag || !externalPort(out["server_port"]) ||
		strings.Contains(predecessorText(out, "password"), ":") || !importedSS2022Credentials(predecessorText(out, "method"), predecessorText(out, "password")) {
		return fail()
	}
	id, err := externalProfileIdentity(selected.Profile)
	ext, ok := selected.Profile["external"].(map[string]any)
	ss, ssOK := ext["shadowsocks"].(map[string]any)
	if err != nil || id != selected.ExitID || !ok || ext["protocol"] != "shadowsocks" ||
		!ssOK || !maxFields(ss, "server", "port", "method", "password") ||
		ext["expected_public_ip"] != selected.ExpectedPublicIP || !externalPublicIP(selected.ExpectedPublicIP) ||
		selected.Profile["endpoint"] != host || ext["start_layer"] != nil || externalCapturedTransport(out, selected.Profile) != nil {
		return fail()
	}
	// An explicit lookup policy is mandatory. Do not reinterpret Home, Fastest,
	// Rescue, UDP or encrypted-DNS settings as a convenient TCP bootstrap.
	if selected.Profile["dns_mode"] != "custom" || selected.Profile["dns_protocol"] != "tcp" || selected.DNSBootstrap != nil || selected.Profile["dns_bootstrap"] != nil {
		return fail()
	}
	for _, name := range []string{"dns_server_name", "dns_path"} {
		value, err := externalOptionalString(selected.Profile, name)
		if err != nil || value != "" {
			return fail()
		}
	}
	resolverHost := predecessorText(selected.Profile, "dns_host")
	ip, err := netip.ParseAddr(resolverHost)
	if err != nil || ip.String() != resolverHost || !externalPort(selected.Profile["dns_port"]) {
		return fail()
	}
	ipv6, blocked, err := externalDevicePolicy(selected.Profile)
	if err != nil {
		return fail()
	}
	kill, err := externalDesktopKillPolicy(selected.Profile)
	if err != nil {
		return fail()
	}
	dns, _, err := externalSelectedDNS(selected, ipv6, true)
	if err != nil {
		return fail()
	}
	// Validate the complete ordinary source envelope without substituting any
	// literal endpoint or passing it through the physical-root constructor.
	tun, route, err := nodeChainImportedHostnameEnvelope(graph, dns)
	if err != nil {
		return fail()
	}
	if _, _, _, err = externalMTUPolicy(tun, out, nil, selected.Profile, nil); err != nil {
		return fail()
	}
	rules := []any{}
	if ipv6 == "off" {
		rules = append(rules, map[string]any{"inbound": []string{predecessorText(tun, "tag")}, "ip_version": 6, "action": "reject"})
	}
	if len(blocked) != 0 {
		rules = append(rules, map[string]any{"inbound": []string{predecessorText(tun, "tag")}, "ip_cidr": blocked, "action": "reject"})
	}
	route["rules"] = rules
	resolver := dns["servers"].([]any)[0].(map[string]any)
	resolver["tag"] = nodeChainImportedResolver
	delete(resolver, "detour")
	// compileNodeChainClosures binds this exact dependency and the hostname
	// transport to the same preceding packet-prefix proof tag. It then proves
	// that all physical roots still belong to the original first node.
	query := map[string]any{"server": nodeChainImportedResolver}
	if strategy, exists := dns["strategy"]; exists {
		query["strategy"] = strategy
	}
	out["domain_resolver"] = query
	dns["final"] = nodeChainImportedResolver
	graph["dns"] = dns
	encoded, err := json.Marshal(graph)
	if err != nil || len(encoded) > 4<<20 {
		return fail()
	}
	lan := true
	if value, exists := selected.Profile["home_lan_access"]; exists {
		lan = value.(bool)
	} // checked by externalDevicePolicy
	digest, _ := json.Marshal([]string{"routervpn-node-chain-imported-member-v1", input})
	member := &nodeChainImportedMember{input: input, source: externalDigest(digest), selection: selected,
		hostname: &nodeChainImportedHostname{string(encoded), nodeChainImportedDevicePolicy{kill, ipv6, lan}}}
	member.seal = member.digest()
	return member, true, member.validate()
}

// Only the existing generated one-TUN envelope (and its fixed local proof
// listener) is admitted. Every original field is checked before composition;
// arbitrary routes, DNS trees, listeners or native services are not discarded.
func nodeChainImportedHostnameEnvelope(graph, selectedDNS map[string]any) (map[string]any, map[string]any, error) {
	bad := errors.New("hostname middle source contains an unowned native graph option")
	fail := func() (map[string]any, map[string]any, error) { return nil, nil, bad }
	if !maxFields(graph, "log", "dns", "inbounds", "endpoints", "outbounds", "route", "services") {
		return fail()
	}
	for _, name := range []string{"endpoints", "services"} {
		if raw, exists := graph[name]; exists {
			values, ok := raw.([]any)
			if !ok || len(values) != 0 {
				return fail()
			}
		}
	}
	if raw, exists := graph["log"]; exists {
		value, ok := raw.(map[string]any)
		if !ok || !maxFields(value, "level", "timestamp") {
			return fail()
		}
		if level, exists := value["level"]; exists {
			switch level {
			case "trace", "debug", "info", "warn", "error", "fatal", "panic":
			default:
				return fail()
			}
		}
		if stamp, exists := value["timestamp"]; exists {
			if _, ok := stamp.(bool); !ok {
				return fail()
			}
		}
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) < 1 || len(ins) > 2 {
		return fail()
	}
	first, ok := ins[0].(map[string]any)
	if !ok || first["type"] != "tun" {
		return fail()
	}
	var tun map[string]any
	seen := map[string]bool{}
	for _, raw := range ins {
		in, ok := raw.(map[string]any)
		if !ok {
			return fail()
		}
		tag := predecessorText(in, "tag")
		if !exactID.MatchString(tag) || seen[tag] {
			return fail()
		}
		seen[tag] = true
		if in["type"] != "tun" {
			if len(in) != 4 || in["type"] != "mixed" || tag != "standard-exit-proof" || in["listen"] != "127.0.0.1" || in["listen_port"] != float64(1099) {
				return fail()
			}
			continue
		}
		if tun != nil || in["auto_route"] != true || in["strict_route"] != true || !maxFields(in, "type", "tag", "interface_name", "address", "mtu", "auto_route", "strict_route", "stack") {
			return fail()
		}
		if name, exists := in["interface_name"]; exists {
			s, ok := name.(string)
			if !ok || s == "" || len(s) > 64 || strings.ContainsAny(s, "\x00\r\n/") {
				return fail()
			}
		}
		if stack, exists := in["stack"]; exists && stack != "system" && stack != "gvisor" && stack != "mixed" {
			return fail()
		}
		addresses, ok := in["address"].([]any)
		if !ok || len(addresses) != 2 {
			return fail()
		}
		v4, v6 := false, false
		for _, raw := range addresses {
			s, ok := raw.(string)
			if !ok {
				return fail()
			}
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Addr().Is4In6() || !p.Addr().IsPrivate() || p.Bits() == 0 {
				return fail()
			}
			if p.Addr().Is4() {
				v4 = true
			} else {
				v6 = true
			}
		}
		if !v4 || !v6 {
			return fail()
		}
		tun = in
	}
	if tun == nil {
		return fail()
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != ExternalFinalTag || !maxFields(route, "final", "auto_detect_interface", "rules") {
		return fail()
	}
	if raw, exists := route["auto_detect_interface"]; exists && raw != true {
		return fail()
	}
	if raw, exists := route["rules"]; exists {
		rules, ok := raw.([]any)
		if !ok || len(rules) > 1 {
			return fail()
		}
		for _, raw := range rules {
			rule, ok := raw.(map[string]any)
			if !ok || len(rule) != 2 || rule["protocol"] != "dns" || rule["action"] != "hijack-dns" {
				return fail()
			}
		}
	}
	if raw, exists := graph["dns"]; exists && !reflect.DeepEqual(raw, selectedDNS) {
		return fail()
	}
	return tun, route, nil
}
