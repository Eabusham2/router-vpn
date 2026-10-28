package mobilemultihop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"

	"router-vpn/internal/multihoprelay"
)

const ExternalFinalTag = "custom-exit"
const ExternalDNSTag = "selected-dns"

// ExternalPolicy is a compilation of one immutable ordinary external-exit
// graph and its exact selected policies. It owns no socket or OS interface.
// Its metadata describes the configured path; it is not a successful live DNS,
// node, public-address or Auto-MTU proof.
type ExternalPolicy struct {
	config, metadata, source string
	capture                  externalPolicyCapture
}

func (p *ExternalPolicy) Config() string       { return p.config }
func (p *ExternalPolicy) Metadata() string     { return p.metadata }
func (p *ExternalPolicy) SourceSHA256() string { return p.source }

type externalPolicyCapture struct {
	Schema            int                       `json:"schema"`
	ExitID            string                    `json:"exit_id"`
	Protocol          string                    `json:"protocol"`
	ExpectedPublicIP  string                    `json:"expected_public_ip"`
	Profile           map[string]any            `json:"profile"`
	EntryTag          string                    `json:"entry_tag,omitempty"`
	Entry             map[string]any            `json:"entry,omitempty"`
	PredecessorConfig string                    `json:"predecessor_config,omitempty"`
	DNSBootstrap      *externalDNSBootstrap     `json:"dns_bootstrap,omitempty"`
	Execution         *externalExecutionCapture `json:"execution,omitempty"`
}

type externalPolicyMetadata struct {
	Schema              int      `json:"schema"`
	SourceSHA256        string   `json:"source_sha256"`
	ConfigSHA256        string   `json:"config_sha256"`
	ExitID              string   `json:"exit_id"`
	PolicyID            string   `json:"policy_id"`
	Protocol            string   `json:"protocol"`
	StartLayer          string   `json:"start_layer,omitempty"`
	ExpectedPublicIP    string   `json:"expected_public_ip"`
	EntryID             string   `json:"entry_id,omitempty"`
	EntryNodeID         string   `json:"entry_node_id,omitempty"`
	EntryTag            string   `json:"entry_tag,omitempty"`
	EntryStartLayer     string   `json:"entry_start_layer,omitempty"`
	PredecessorSHA256   string   `json:"predecessor_sha256,omitempty"`
	FinalTag            string   `json:"final_tag"`
	TUNTag              string   `json:"tun_tag"`
	DNSMode             string   `json:"dns_mode"`
	DNSProtocol         string   `json:"dns_protocol"`
	DNSServer           string   `json:"dns_server"`
	DNSPort             int      `json:"dns_port"`
	DNSServerName       string   `json:"dns_server_name,omitempty"`
	DNSPath             string   `json:"dns_path,omitempty"`
	DNSDetour           string   `json:"dns_detour"`
	DNSBootstrapSHA256  string   `json:"dns_bootstrap_sha256,omitempty"`
	DNSDefaultMigrated  bool     `json:"dns_default_migrated,omitempty"`
	DNSProof            string   `json:"dns_proof"`
	PublicExitProof     string   `json:"public_exit_proof"`
	EntryProof          string   `json:"entry_proof,omitempty"`
	IPv6Mode            string   `json:"ipv6_mode"`
	HomeLANAccess       bool     `json:"home_lan_access"`
	BlockedLANCIDRs     []string `json:"blocked_lan_cidrs"`
	MTUPolicy           string   `json:"mtu_policy"`
	ConfiguredMTU       int      `json:"configured_mtu"`
	EntryMTU            int      `json:"entry_mtu,omitempty"`
	AutoMTU             string   `json:"auto_mtu"`
	AutoMTUReason       string   `json:"auto_mtu_reason,omitempty"`
	UDPAvailable        bool     `json:"udp_available"`
	Execution           string   `json:"execution,omitempty"`
	LastNodeMeasurement string   `json:"last_node_measurement,omitempty"`
}

// CompileExternalPolicy is the string-only host bridge. The returned strings
// remain private session inputs and must be checked against SourceSHA256 before
// adoption. The original graph and profiles are never updated in place.
func CompileExternalPolicy(config, capture string) (string, error) {
	p, err := NewExternalPolicy(config, capture)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(map[string]any{
		"schema": 1, "source_sha256": p.SourceSHA256(),
		"config_json": p.Config(), "metadata_json": p.Metadata(),
	})
	return string(encoded), err
}

// NewExternalPolicy applies the saved DNS, IPv6, LAN and MTU selections to a
// transport-validated ordinary external graph. Native ordinary exits
// may connect directly, through an ordinary external entry, or through one
// complete captured Router VPN predecessor. The latter preserves its native
// layers, helper owners and bootstrap resolvers inside the same OS TUN.
func NewExternalPolicy(config, capture string) (*ExternalPolicy, error) {
	var selection externalPolicyCapture
	if exactJSON([]byte(capture), &selection, 8<<20) != nil || selection.Schema != 1 ||
		!exactID.MatchString(selection.ExitID) || selection.Profile == nil {
		return nil, errors.New("external policy requires one bounded exact saved selection")
	}
	profileID, err := externalProfileIdentity(selection.Profile)
	if err != nil {
		return nil, err
	}
	if !externalOrdinaryProtocol(selection.Protocol) {
		return nil, errors.New("external policy requires a native ordinary exit protocol")
	}
	if selection.Protocol == "openvpn" && selection.Profile["node_kind"] != "external" {
		return nil, errors.New("OpenVPN requires its exact captured external inline profile")
	}
	if selection.Protocol == "amneziawg" && selection.Profile["node_kind"] != "external" {
		return nil, errors.New("imported AmneziaWG requires its exact captured external peer and parameters")
	}
	if !externalPublicIP(selection.ExpectedPublicIP) {
		return nil, errors.New("external policy requires the selected public exit proof address")
	}
	if kind, _ := selection.Profile["node_kind"].(string); kind == "external" {
		ext, ok := selection.Profile["external"].(map[string]any)
		if profileID != selection.ExitID || !ok || ext["protocol"] != selection.Protocol || ext["expected_public_ip"] != selection.ExpectedPublicIP {
			return nil, errors.New("external policy and protocol/proof identity belong to different saved exits")
		}
	}
	if (selection.Entry == nil) != (selection.EntryTag == "") {
		return nil, errors.New("external entry policy and graph tag must be captured together")
	}
	entryID, entryProtocol := "", ""
	if selection.Entry != nil {
		entryID, err = externalProfileIdentity(selection.Entry)
		if err != nil {
			return nil, err
		}
		if entryID == selection.ExitID || !exactID.MatchString(selection.EntryTag) || selection.EntryTag == ExternalFinalTag || selection.EntryTag == ExternalDNSTag {
			return nil, errors.New("external entry and exit identities must remain distinct")
		}
		kind, _ := selection.Entry["node_kind"].(string)
		if kind == "external" {
			ext, ok := selection.Entry["external"].(map[string]any)
			if !ok {
				return nil, errors.New("external predecessor has no captured protocol")
			}
			entryProtocol, _ = ext["protocol"].(string)
			if !externalOrdinaryProtocol(entryProtocol) {
				return nil, errors.New("unsupported ordinary external predecessor protocol")
			}
		} else {
			entryProtocol = "wireguard"
		}
	}
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil || graph == nil {
		return nil, errors.New("external policy requires one bounded exact native graph")
	}
	entryKind, _ := selection.Entry["node_kind"].(string)
	predecessor, err := newExternalPredecessor(selection)
	if err != nil {
		return nil, err
	}
	graphEntryProtocol, graphEntryTag := entryProtocol, selection.EntryTag
	if predecessor != nil {
		graphEntryProtocol, graphEntryTag = "", ""
	}
	tun, exit, entry, route, err := externalOwnedGraph(graph, selection.Protocol, graphEntryProtocol, graphEntryTag, selection.Entry != nil && entryKind != "external")
	if err != nil {
		return nil, err
	}
	if kind, _ := selection.Profile["node_kind"].(string); kind == "external" {
		if err := externalCapturedTransport(exit, selection.Profile); err != nil {
			return nil, err
		}
	}
	if kind, _ := selection.Entry["node_kind"].(string); kind == "external" {
		if err := externalCapturedTransport(entry, selection.Entry); err != nil {
			return nil, err
		}
	}
	ipv6, blocked, err := externalDevicePolicy(selection.Profile, selection.Entry)
	if err != nil {
		return nil, err
	}
	var mtu, entryMTU int
	var mtuPolicy string
	if predecessor != nil {
		mtu, entryMTU, mtuPolicy, err = predecessor.applyMTU(tun, exit, selection)
	} else {
		mtu, entryMTU, mtuPolicy, err = externalMTUPolicy(tun, exit, entry, selection.Profile, selection.Entry)
	}
	if err != nil {
		return nil, err
	}
	udp := externalUDP(selection.Protocol) && (entryProtocol == "" || externalUDP(entryProtocol))
	if entryProtocol != "" && !externalUDP(entryProtocol) && externalExitRequiresUDP(exit, selection.Protocol) {
		return nil, errors.New("the selected TCP-only predecessor cannot carry this exit's UDP transport")
	}
	if selection.Protocol == "openvpn" {
		// The owned OpenVPN IP stack carries both application TCP and UDP,
		// including DNS, even when its authenticated outer link uses TCP.
		udp = true
	}
	dns, dnsMeta, err := externalSelectedDNS(selection, ipv6, udp)
	if err != nil {
		return nil, err
	}
	graph["dns"] = dns
	tunTag := tun["tag"].(string)
	rules := []any{}
	if ipv6 == "off" {
		rules = append(rules, map[string]any{"inbound": []string{tunTag}, "ip_version": 6, "action": "reject"})
	}
	// Both the decoded protocol and traditional port are captured. TUN traffic
	// cannot evade DNS selection merely by arriving before protocol sniffing.
	rules = append(rules,
		map[string]any{"inbound": []string{tunTag}, "protocol": "dns", "action": "hijack-dns"},
		map[string]any{"inbound": []string{tunTag}, "port": 53, "action": "hijack-dns"})
	if len(blocked) != 0 {
		rules = append(rules, map[string]any{"inbound": []string{tunTag}, "ip_cidr": blocked, "action": "reject"})
	}
	// No Router API or general private-LAN exception is invented for a third-
	// party exit. Native DNS detours do not enter this ordinary TUN rule path.
	route["rules"] = rules
	tun["route_address"] = append([]string{"0.0.0.0/0", "::/0"}, blocked...)
	if predecessor != nil {
		if err := predecessor.merge(graph, tun, exit); err != nil {
			return nil, err
		}
	}
	entryStartLayer, err := externalApplyEntryStartLayer(graph, entry, selection, entryProtocol)
	if err != nil {
		return nil, err
	}
	startLayer, err := externalApplyStartLayer(graph, exit, selection)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(graph)
	if err != nil || len(body) > 4<<20 {
		return nil, errors.New("compiled external graph exceeds its bound")
	}
	sourceBytes, _ := json.Marshal([]string{"routervpn-external-policy-v1", config, capture})
	meta := externalPolicyMetadata{
		Schema: 1, SourceSHA256: externalDigest(sourceBytes), ConfigSHA256: externalDigest(body),
		ExitID: selection.ExitID, PolicyID: profileID, Protocol: selection.Protocol, StartLayer: startLayer, ExpectedPublicIP: selection.ExpectedPublicIP,
		EntryID: entryID, EntryTag: selection.EntryTag, EntryStartLayer: entryStartLayer, FinalTag: ExternalFinalTag, TUNTag: tunTag,
		DNSMode: dnsMeta.mode, DNSProtocol: dnsMeta.protocol, DNSServer: dnsMeta.host, DNSPort: dnsMeta.port,
		DNSServerName: dnsMeta.serverName, DNSPath: dnsMeta.path, DNSDetour: dnsMeta.detour,
		DNSBootstrapSHA256: dnsMeta.bootstrapSHA256, DNSDefaultMigrated: dnsMeta.migrated,
		DNSProof: "required", PublicExitProof: "required", IPv6Mode: ipv6,
		HomeLANAccess: len(blocked) == 0, BlockedLANCIDRs: blocked,
		MTUPolicy: mtuPolicy, ConfiguredMTU: mtu, EntryMTU: entryMTU, UDPAvailable: udp,
		AutoMTU: "not-requested",
	}
	if predecessor != nil {
		meta.PredecessorSHA256 = externalDigest([]byte(selection.PredecessorConfig))
	}
	if selection.Entry != nil {
		meta.EntryProof = "required"
		if selection.Entry["node_kind"] != "external" {
			meta.EntryNodeID, _ = selection.Entry["node_proof_id"].(string)
			api, _ := selection.Entry["router_api"].(string)
			token, _ := selection.Entry["api_token"].(string)
			if !proofID.MatchString(meta.EntryNodeID) || token == "" || len(token) > 4096 || strings.TrimSpace(token) != token {
				return nil, errors.New("external route requires the captured entry's private node proof")
			}
			for _, ch := range token {
				if ch < 0x21 || ch > 0x7e {
					return nil, errors.New("external entry proof credential is invalid")
				}
			}
			if _, err := privateAPI(api); err != nil {
				return nil, errors.New("external entry proof endpoint is invalid")
			}
		} else {
			external, _ := selection.Entry["external"].(map[string]any)
			ip, _ := external["expected_public_ip"].(string)
			if !externalPublicIP(ip) {
				return nil, errors.New("external entry requires its own expected public address")
			}
		}
	}
	if mtuPolicy == "auto" {
		meta.AutoMTU = "unmeasured"
		meta.AutoMTUReason = "This external exit has no captured authenticated packet-probe owner; the configured MTU is a baseline, not an Auto-MTU result."
	}
	if err := compileExternalExecution(graph, selection, &meta); err != nil {
		return nil, err
	}
	body, err = json.Marshal(graph)
	if err != nil || len(body) > 4<<20 {
		return nil, errors.New("compiled external execution exceeds its bound")
	}
	meta.ConfigSHA256 = externalDigest(body)
	metadata, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return &ExternalPolicy{config: string(body), metadata: string(metadata), source: meta.SourceSHA256, capture: selection}, nil
}

func externalDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func externalProfileIdentity(profile map[string]any) (string, error) {
	id, ok := profile["id"].(string)
	if !ok || !exactID.MatchString(id) {
		return "", errors.New("external policy has no exact saved profile identity")
	}
	kind := "router-vpn"
	if raw, exists := profile["node_kind"]; exists {
		kind, ok = raw.(string)
		if !ok {
			return "", errors.New("external policy node kind must be a string")
		}
	}
	if kind != "" && kind != "router-vpn" && kind != "external" {
		return "", errors.New("unknown external policy node kind")
	}
	return id, nil
}

func externalOrdinaryProtocol(protocol string) bool {
	switch protocol {
	case "wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn":
		return true
	default:
		return false
	}
}

func externalUDP(protocol string) bool {
	return protocol != "http-connect" && protocol != "https-connect"
}

func externalPublicIP(text string) bool {
	address, err := netip.ParseAddr(text)
	return err == nil && address.Zone() == "" && address.String() == text && !address.Is4In6() && address.IsGlobalUnicast() &&
		!address.IsPrivate() && !address.IsLoopback() && !netip.MustParsePrefix("100.64.0.0/10").Contains(address)
}

func externalOwnedGraph(graph map[string]any, protocol, entryProtocol, entryTag string, routerEntry bool) (tun, exit, entry, route map[string]any, err error) {
	bad := errors.New("external policy graph lost its exact full-device transport owners")
	for key, raw := range graph {
		switch key {
		case "log", "dns", "inbounds", "endpoints", "outbounds", "route":
		case "services":
			if list, ok := raw.([]any); !ok || len(list) != 0 {
				return nil, nil, nil, nil, bad
			}
		default:
			return nil, nil, nil, nil, bad
		}
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) < 1 || len(ins) > 2 {
		return nil, nil, nil, nil, bad
	}
	inTags := map[string]bool{}
	for _, raw := range ins {
		in, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, nil, nil, bad
		}
		tag, ok := in["tag"].(string)
		if !ok || !exactID.MatchString(tag) || inTags[tag] {
			return nil, nil, nil, nil, bad
		}
		inTags[tag] = true
		if in["type"] == "tun" {
			if tun != nil || in["auto_route"] != true || in["strict_route"] != true {
				return nil, nil, nil, nil, bad
			}
			tun = in
			for key := range in {
				switch key {
				case "type", "tag", "interface_name", "address", "mtu", "auto_route", "strict_route", "stack":
				default:
					return nil, nil, nil, nil, errors.New("external policy cannot adopt an unknown TUN filter or route option")
				}
			}
			addresses, ok := in["address"].([]any)
			if !ok || len(addresses) != 2 {
				return nil, nil, nil, nil, bad
			}
			v4, v6 := false, false
			for _, raw := range addresses {
				text, ok := raw.(string)
				if !ok {
					return nil, nil, nil, nil, bad
				}
				prefix, err := netip.ParsePrefix(text)
				if err != nil || prefix.Addr().Is4In6() || !prefix.Addr().IsPrivate() || prefix.Bits() == 0 {
					return nil, nil, nil, nil, bad
				}
				if prefix.Addr().Is4() {
					v4 = true
				} else {
					v6 = true
				}
			}
			if !v4 || !v6 {
				return nil, nil, nil, nil, errors.New("external policy must capture both IP families even when IPv6 is off")
			}
		} else if in["type"] != "mixed" || tag != "standard-exit-proof" || in["listen"] != "127.0.0.1" || in["listen_port"] != float64(1099) || len(in) != 4 {
			return nil, nil, nil, nil, errors.New("external policy cannot adopt an unowned listener")
		}
	}
	if tun == nil {
		return nil, nil, nil, nil, bad
	}
	route, ok = graph["route"].(map[string]any)
	if !ok || route["final"] != ExternalFinalTag {
		return nil, nil, nil, nil, bad
	}
	for key, raw := range route {
		switch key {
		case "final":
		case "auto_detect_interface":
			if raw != true {
				return nil, nil, nil, nil, bad
			}
		case "rules":
			rules, ok := raw.([]any)
			if !ok || len(rules) > 1 {
				return nil, nil, nil, nil, bad
			}
			for _, raw := range rules {
				rule, ok := raw.(map[string]any)
				if !ok || len(rule) != 2 || rule["protocol"] != "dns" || rule["action"] != "hijack-dns" {
					return nil, nil, nil, nil, errors.New("external policy cannot discard custom routing")
				}
			}
		default:
			return nil, nil, nil, nil, errors.New("external policy has an unowned route option")
		}
	}
	if raw, exists := graph["dns"]; exists {
		dns, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, nil, nil, bad
		}
		for key, raw := range dns {
			switch key {
			case "servers":
				servers, ok := raw.([]any)
				if !ok || len(servers) > 1 {
					return nil, nil, nil, nil, errors.New("existing bootstrap DNS must be captured explicitly")
				}
				for _, raw := range servers {
					server, ok := raw.(map[string]any)
					if !ok || server["tag"] != ExternalDNSTag {
						return nil, nil, nil, nil, bad
					}
					for key := range server {
						switch key {
						case "type", "tag", "server", "server_port", "detour", "tls", "path":
						default:
							return nil, nil, nil, nil, errors.New("existing bootstrap DNS must be captured explicitly")
						}
					}
				}
			case "final":
				if raw != ExternalDNSTag {
					return nil, nil, nil, nil, bad
				}
			case "strategy":
				if raw != "prefer_ipv4" && raw != "ipv4_only" && raw != "" {
					return nil, nil, nil, nil, bad
				}
			default:
				return nil, nil, nil, nil, errors.New("external policy cannot discard custom DNS routing")
			}
		}
	}
	count := 0
	for _, family := range []string{"endpoints", "outbounds"} {
		values := []any{}
		if raw, exists := graph[family]; exists {
			values, ok = raw.([]any)
			if !ok {
				return nil, nil, nil, nil, bad
			}
		}
		for _, raw := range values {
			out, ok := raw.(map[string]any)
			if !ok {
				return nil, nil, nil, nil, bad
			}
			tag, ok := out["tag"].(string)
			if !ok || !exactID.MatchString(tag) {
				return nil, nil, nil, nil, bad
			}
			want, detour := "", ""
			switch tag {
			case ExternalFinalTag:
				if exit != nil {
					return nil, nil, nil, nil, bad
				}
				exit, want, detour = out, protocol, entryTag
			case entryTag:
				if entryTag == "" || entry != nil {
					return nil, nil, nil, nil, bad
				}
				entry, want = out, entryProtocol
			default:
				return nil, nil, nil, nil, errors.New("external graph has an extra or unresolved transport owner")
			}
			if err := externalTransport(out, want, detour, family, routerEntry && tag == entryTag); err != nil {
				return nil, nil, nil, nil, err
			}
			count++
		}
	}
	wantCount := 1
	if entryTag != "" {
		wantCount++
	}
	if exit == nil || count != wantCount || (entryTag != "") != (entry != nil) {
		return nil, nil, nil, nil, bad
	}
	return tun, exit, entry, route, nil
}

func externalTransport(out map[string]any, protocol, detour, family string, routerEntry bool) error {
	bad := errors.New("external transport or detour differs from the captured protocol")
	if detour == "" {
		if _, exists := out["detour"]; exists {
			return bad
		}
	} else if out["detour"] != detour {
		return bad
	}
	// These adapters accept only literal physical/remote transport addresses.
	// A different hostname owner must finish resolution before this boundary.
	if protocol == "openvpn" {
		if family != "endpoints" || out["type"] != externalOpenVPNType || out["system"] != false || out["mode"] != "tls" {
			return bad
		}
		// Full option/remote/TLS/credential validation follows immediately in
		// externalCapturedOpenVPN using the original selected inline profile.
		return nil
	}
	if protocol == "amneziawg" {
		if family != "endpoints" || out["type"] != AmneziaType {
			return bad
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			return bad
		}
		_, err = AmneziaRuntimeConfig(string(encoded))
		return err
	}
	if protocol == "wireguard" {
		if family != "endpoints" || out["type"] != "wireguard" {
			return bad
		}
		allowed := map[string]bool{"type": true, "tag": true, "address": true, "private_key": true, "peers": true, "mtu": true, "detour": true}
		if raw, exists := out["system"]; exists {
			if raw != false {
				return errors.New("external WireGuard must retain its userspace endpoint in the one OS TUN")
			}
			allowed["system"] = true
		}
		if raw, exists := out["listen_port"]; exists {
			n, ok := raw.(float64)
			if !routerEntry || !ok || n < 0 || n > 65535 || float64(int(n)) != n {
				return errors.New("external WireGuard listener is not owned by the captured Router VPN entry")
			}
			allowed["listen_port"] = true
		}
		for key := range out {
			if !allowed[key] {
				return bad
			}
		}
		key, _ := out["private_key"].(string)
		if !validWGKey(key) {
			return bad
		}
		if !externalPrefixes(out["address"], false) {
			return bad
		}
		peers, ok := out["peers"].([]any)
		if !ok || len(peers) != 1 {
			return bad
		}
		peer, ok := peers[0].(map[string]any)
		if !ok {
			return bad
		}
		for field := range peer {
			if field != "address" && field != "port" && field != "public_key" && field != "pre_shared_key" && field != "allowed_ips" && field != "persistent_keepalive_interval" {
				return bad
			}
		}
		host, _ := peer["address"].(string)
		pub, _ := peer["public_key"].(string)
		if !wireGuardServerIP(host) || !validWGKey(pub) || !externalPort(peer["port"]) || !externalPrefixes(peer["allowed_ips"], true) {
			return bad
		}
		if psk, exists := peer["pre_shared_key"]; exists {
			key, ok := psk.(string)
			if !ok || !validWGKey(key) {
				return bad
			}
		}
		if keepalive, exists := peer["persistent_keepalive_interval"]; exists {
			n, ok := keepalive.(float64)
			if !ok || n < 0 || n > 65535 || float64(int(n)) != n {
				return bad
			}
		}
		if raw, exists := out["mtu"]; exists {
			if _, err := mtuNumber(raw); err != nil {
				return err
			}
		}
		return nil
	}
	if family != "outbounds" {
		return bad
	}
	host, _ := out["server"].(string)
	if !wireGuardServerIP(host) || !externalPort(out["server_port"]) {
		return bad
	}
	allowed := map[string]bool{"type": true, "tag": true, "server": true, "server_port": true, "detour": true}
	switch protocol {
	case "socks5":
		if out["type"] != "socks" || out["version"] != "5" {
			return bad
		}
		allowed["version"], allowed["username"], allowed["password"] = true, true, true
		if !externalCredentialPair(out) {
			return bad
		}
	case "http-connect", "https-connect":
		if out["type"] != "http" {
			return bad
		}
		allowed["username"], allowed["password"] = true, true
		if !externalCredentialPair(out) {
			return bad
		}
		if protocol == "https-connect" {
			allowed["tls"] = true
			if !externalTLS(out["tls"]) {
				return bad
			}
		}
	case "shadowsocks":
		if out["type"] != "shadowsocks" {
			return bad
		}
		allowed["method"], allowed["password"] = true, true
		method, _ := out["method"].(string)
		switch method {
		case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		default:
			return bad
		}
		if password, ok := out["password"].(string); !ok || len(password) == 0 || len(password) > 4096 {
			return bad
		}
	case "hysteria2":
		if out["type"] != "hysteria2" || !externalTLS(out["tls"]) {
			return bad
		}
		allowed["password"], allowed["tls"] = true, true
		if password, ok := out["password"].(string); !ok || len(password) == 0 || len(password) > 4096 {
			return bad
		}
	default:
		return bad
	}
	for key := range out {
		if !allowed[key] {
			return bad
		}
	}
	return nil
}

// Saved external credentials and native transport material must be the same
// captured source. Matching only the protocol/tag could adopt another user's
// keys or TLS name while claiming the selected profile's identity.
func externalCapturedTransport(out, profile map[string]any) error {
	bad := errors.New("native external transport differs from its exact saved protocol credentials")
	ext, ok := profile["external"].(map[string]any)
	if !ok || out == nil {
		return bad
	}
	protocol, _ := ext["protocol"].(string)
	if err := multihoprelay.ValidateExternalServerPeer(protocol, ext); err != nil {
		return err
	}
	if err := multihoprelay.ValidateExternalOpenVPNPairing(protocol, ext); err != nil {
		return err
	}
	if err := multihoprelay.ValidateExternalOpenVPNResponseProbes(protocol, ext); err != nil {
		return err
	}
	key := strings.ReplaceAll(protocol, "-", "_")
	source, ok := ext[key].(map[string]any)
	if !ok {
		return bad
	}
	equal := func(target, field string) bool { return reflect.DeepEqual(out[target], source[field]) }
	optional := func(target, field string) bool {
		want, hasWant := source[field]
		actual, hasActual := out[target]
		if !hasWant || want == "" {
			return !hasActual || actual == ""
		}
		return reflect.DeepEqual(actual, want)
	}
	switch protocol {
	case "openvpn":
		return externalCapturedOpenVPN(out, source)
	case "wireguard", "amneziawg":
		if protocol == "amneziawg" {
			if err := externalCapturedAmnezia(out, source); err != nil {
				return err
			}
		}
		peers, ok := out["peers"].([]any)
		if !ok || len(peers) != 1 {
			return bad
		}
		peer, ok := peers[0].(map[string]any)
		if !ok || !equal("private_key", "private_key") || !equal("address", "addresses") ||
			!reflect.DeepEqual(peer["public_key"], source["peer_public_key"]) || !reflect.DeepEqual(peer["allowed_ips"], source["allowed_ips"]) {
			return bad
		}
		if !externalCapturedKeepalive(peer, source) {
			return bad
		}
		endpoint, _ := source["endpoint"].(string)
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil || peer["address"] != host || fmt.Sprint(peer["port"]) != port {
			return bad
		}
		want, _ := source["preshared_key"].(string)
		actual, _ := peer["pre_shared_key"].(string)
		if want != actual {
			return bad
		}
		if mtu, exists := source["mtu"]; exists && mtu != float64(0) && !reflect.DeepEqual(out["mtu"], mtu) {
			return bad
		}
	case "socks5", "http-connect", "https-connect":
		if !equal("server", "host") || !equal("server_port", "port") || !optional("username", "username") || !optional("password", "password") {
			return bad
		}
		if protocol == "https-connect" {
			tls, ok := out["tls"].(map[string]any)
			if !ok || len(tls) != 2 || tls["server_name"] != source["tls_server_name"] {
				return bad
			}
		}
	case "shadowsocks":
		if !equal("server", "server") || !equal("server_port", "port") || !equal("method", "method") || !equal("password", "password") {
			return bad
		}
	case "hysteria2":
		tls, ok := out["tls"].(map[string]any)
		if !ok || len(tls) != 2 || !equal("server", "server") || !equal("server_port", "port") || !equal("password", "password") || tls["server_name"] != source["tls_server_name"] {
			return bad
		}
	default:
		return bad
	}
	return nil
}

func externalCredentialPair(out map[string]any) bool {
	u, uok := out["username"].(string)
	p, pok := out["password"].(string)
	_, hasU := out["username"]
	_, hasP := out["password"]
	if !hasU && !hasP {
		return true
	}
	return uok && pok && (u == "") == (p == "") && len(u) <= 4096 && len(p) <= 4096
}

func externalPort(raw any) bool {
	n, ok := raw.(float64)
	return ok && n >= 1 && n <= 65535 && float64(int(n)) == n
}

func externalPrefixes(raw any, routes bool) bool {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 || len(values) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		text, ok := value.(string)
		if !ok || seen[text] {
			return false
		}
		seen[text] = true
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Addr().Is4In6() || routes && prefix != prefix.Masked() {
			return false
		}
	}
	return true
}

func externalTLS(raw any) bool {
	tls, ok := raw.(map[string]any)
	if !ok || tls["enabled"] != true {
		return false
	}
	name, ok := tls["server_name"].(string)
	if !ok || !externalTLSName(name) {
		return false
	}
	for key, raw := range tls {
		switch key {
		case "enabled", "server_name":
		case "certificate":
			switch value := raw.(type) {
			case string:
				if !validEntryCertificate([]byte(value)) {
					return false
				}
			case []any:
				if len(value) == 0 || len(value) > 8 {
					return false
				}
				for _, raw := range value {
					text, ok := raw.(string)
					if !ok || !validEntryCertificate([]byte(text)) {
						return false
					}
				}
			default:
				return false
			}
		default:
			return false
		}
	}
	return true
}

func externalDevicePolicy(profiles ...map[string]any) (string, []string, error) {
	ipv6 := "auto"
	blocked := map[string]bool{}
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}
	for _, profile := range profiles {
		if profile == nil {
			continue
		}
		mode, err := externalOptionalString(profile, "ipv6_mode")
		if err != nil {
			return "", nil, err
		}
		switch mode {
		case "", "auto":
		case "on":
			if ipv6 != "off" {
				ipv6 = "on"
			}
		case "off":
			ipv6 = "off"
		default:
			return "", nil, errors.New("invalid frozen external IPv6 policy")
		}
		allow := true
		if raw, exists := profile["home_lan_access"]; exists {
			var ok bool
			allow, ok = raw.(bool)
			if !ok {
				return "", nil, errors.New("external LAN access must be an explicit boolean")
			}
		}
		values := []any{}
		if raw, exists := profile["home_lan_cidrs"]; exists {
			var ok bool
			values, ok = raw.([]any)
			if !ok || len(values) > 32 {
				return "", nil, errors.New("invalid captured external LAN ranges")
			}
		}
		for _, raw := range values {
			text, ok := raw.(string)
			if !ok {
				return "", nil, errors.New("external LAN ranges must be strings")
			}
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
				return "", nil, errors.New("external LAN requires canonical private ranges")
			}
			contained := false
			for _, allowed := range private {
				if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
					contained = true
				}
			}
			if !contained {
				return "", nil, errors.New("external LAN cannot replace a public, default or link-local route")
			}
			if !allow {
				blocked[prefix.String()] = true
			}
		}
		if !allow && len(values) == 0 {
			for _, prefix := range private {
				blocked[prefix.String()] = true
			}
		}
	}
	networks := make([]string, 0, len(blocked))
	for network := range blocked {
		networks = append(networks, network)
	}
	sort.Strings(networks)
	return ipv6, networks, nil
}

func externalMTUPolicy(tun, exit, entry, profile, entryProfile map[string]any) (mtu, entryMTU int, policy string, err error) {
	return externalMTUPolicyWithPacketEnvelope(tun, exit, entry, profile, entryProfile, 0)
}

func externalMTUPolicyWithPacketEnvelope(tun, exit, entry, profile, entryProfile map[string]any, envelope int) (mtu, entryMTU int, policy string, err error) {
	if envelope != 0 && ((exit["type"] != "wireguard" && exit["type"] != AmneziaType) || profile["node_kind"] != "router-vpn" || envelope < 60 || envelope > 4096) {
		return 0, 0, "", errors.New("nested packet envelope is not owned by the captured Router exit")
	}
	mtu, err = mtuNumber(tun["mtu"])
	if err != nil {
		return
	}
	policy, err = externalOptionalString(profile, "mtu_policy")
	if err != nil {
		return
	}
	if policy == "" {
		policy = "auto"
	}
	fixed, err := fixedMTU(profile)
	if err != nil {
		return 0, 0, "", err
	}
	entryFixed := 0
	if entryProfile != nil {
		entryFixed, err = fixedMTU(entryProfile)
		if err != nil {
			return 0, 0, "", err
		}
	}
	jumbo, err := externalJumboPreference(profile)
	if err != nil {
		return 0, 0, "", err
	}
	entryJumbo, err := externalJumboPreference(entryProfile)
	if err != nil {
		return 0, 0, "", err
	}
	packetInterface := func(endpoint map[string]any) bool {
		return endpoint["type"] == "wireguard" || endpoint["type"] == AmneziaType || endpoint["type"] == PQType || endpoint["type"] == externalOpenVPNType
	}
	if entryJumbo && (entry == nil || packetInterface(entry)) {
		return 0, 0, "", errors.New("Jumbo applies to the shared proxy TUN, not an entry packet interface")
	}
	if (jumbo || entryJumbo) && packetInterface(exit) {
		return 0, 0, "", errors.New("Jumbo requires a compatible proxy TUN, not a raw packet exit")
	}
	if entry != nil {
		if entry["type"] == "wireguard" || entry["type"] == AmneziaType || entry["type"] == externalOpenVPNType {
			entryMTU = 1280
			if entry["type"] == externalOpenVPNType {
				entryMTU = 1500
			}
			if raw, exists := entry["mtu"]; exists {
				entryMTU, err = mtuNumber(raw)
				if err != nil {
					return 0, 0, "", err
				}
			}
			if entryFixed != 0 {
				entryMTU = entryFixed
			}
			entry["mtu"] = entryMTU
		} else if entryFixed != 0 {
			if fixed != 0 && fixed != entryFixed {
				return 0, 0, "", errors.New("entry and exit fixed MTUs conflict for the one OS TUN")
			}
			fixed = entryFixed
		}
	}
	if fixed != 0 {
		mtu, policy = fixed, "fixed"
	}
	if jumbo || entryJumbo {
		if fixed != 0 && fixed != 9000 {
			return 0, 0, "", errors.New("Jumbo conflicts with the saved fixed MTU of the shared proxy TUN")
		}
		// Virtual proxy capacity is not a demonstrated path packet size. The
		// captured packet entry keeps its own MTU and the live optimizer keeps
		// the original Auto/Default selection and separate proof requirement.
		mtu = 9000
	}
	if exit["type"] == "wireguard" || exit["type"] == AmneziaType {
		exitMTU := 1280
		if raw, exists := exit["mtu"]; exists {
			exitMTU, err = mtuNumber(raw)
			if err != nil {
				return 0, 0, "", err
			}
		}
		if fixed != 0 {
			exitMTU = fixed
		}
		if entryMTU != 0 {
			peer := exit["peers"].([]any)[0].(map[string]any)
			host := peer["address"].(string)
			overhead := 60
			if strings.Contains(host, ":") {
				overhead = 80
			}
			if exit["type"] == AmneziaType {
				encoded, _ := json.Marshal(exit)
				runtime, failure := AmneziaRuntimeConfig(string(encoded))
				if failure != nil {
					return 0, 0, "", failure
				}
				overhead += runtime.TransportPadding
			}
			layerOverhead, failure := externalPacketLayerOverhead(profile)
			if failure != nil {
				return 0, 0, "", failure
			}
			overhead += layerOverhead
			if envelope != 0 {
				overhead = envelope
			}
			limit := (entryMTU - overhead) / 16 * 16
			if limit < 1280 {
				return 0, 0, "", errors.New("entry MTU cannot carry the dual-stack nested WireGuard packet")
			}
			if exitMTU > limit {
				if fixed != 0 {
					return 0, 0, "", errors.New("fixed external exit MTU does not fit its captured entry")
				}
				exitMTU = limit
			}
		}
		exit["mtu"] = exitMTU
		if fixed == 0 && mtu > exitMTU {
			mtu = exitMTU
		}
		if selection, _ := externalSavedExecution(profile); selection != "local" {
			ext, _ := profile["external"].(map[string]any)
			if captured, ok := ext["server_peer"].(map[string]any); ok {
				serverMTU, failure := mtuNumber(captured["mtu"])
				if failure != nil {
					return 0, 0, "", failure
				}
				if fixed > serverMTU {
					return 0, 0, "", errors.New("fixed MTU exceeds the captured independent server peer interface")
				}
				if fixed == 0 && mtu > serverMTU {
					mtu = serverMTU
				}
			}
		}
	}
	if exit["type"] == externalOpenVPNType {
		layerOverhead, failure := externalPacketLayerOverhead(profile)
		if failure != nil {
			return 0, 0, "", failure
		}
		mtu, err = externalOpenVPNMTU(tun, exit, mtu, entryMTU, fixed, layerOverhead)
		if err != nil {
			return 0, 0, "", err
		}
		if selection, _ := externalSavedExecution(profile); selection != "local" {
			ext, _ := profile["external"].(map[string]any)
			pair, _ := ext["openvpn_pairing"].(map[string]any)
			server, _ := pair["server"].(map[string]any)
			transport, _ := server["transport"].(map[string]any)
			serverMTU, failure := mtuNumber(transport["mtu"])
			if failure != nil {
				return 0, 0, "", errors.New("OpenVPN server execution lost its captured provider interface MTU")
			}
			if fixed > serverMTU {
				return 0, 0, "", errors.New("fixed MTU exceeds the independently owned OpenVPN server interface")
			}
			if fixed == 0 && mtu > serverMTU {
				mtu = serverMTU
			}
		}
	}
	// Historical effective_mtu and its old network/probe fingerprints never
	// enter this calculation. An Auto owner must measure the live path later.
	tun["mtu"] = mtu
	return
}

func externalJumboPreference(profile map[string]any) (bool, error) {
	raw, present := profile["jumbo_tun"]
	if !present {
		return false, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return false, errors.New("external Jumbo policy must be a saved boolean")
	}
	return value, nil
}

func externalOptionalString(profile map[string]any, key string) (string, error) {
	raw, exists := profile[key]
	if !exists {
		return "", nil
	}
	text, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("external %s policy must be a string", key)
	}
	if text != strings.TrimSpace(text) {
		return "", fmt.Errorf("external %s policy must be canonical", key)
	}
	return text, nil
}
