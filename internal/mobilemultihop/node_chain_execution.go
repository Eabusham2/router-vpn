package mobilemultihop

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"router-vpn/internal/multihoprelay"
)

// NodeChainExecutionSource joins the original Local path with authenticated
// entry-agent discovery and an exact precompiled listener proposal. It is
// private native handoff data, not a persisted public profile or a client-
// supplied server configuration. Port bounds come from that same discovery.
type NodeChainExecutionSource struct {
	Schema      int                               `json:"schema"`
	Execution   string                            `json:"execution"`
	LocalSource string                            `json:"local_source"`
	Server      multihoprelay.NodeChainDescriptor `json:"server"`
	Request     multihoprelay.NodeChainRequest    `json:"request"`
	FirstPort   int                               `json:"first_port"`
	LastPort    int                               `json:"last_port"`
}

// A successful returned lease must match every front field before adoption.
// Host comes only from the original captured entry API, never a lease reply.
type NodeChainExecutionFront struct {
	Host              string                        `json:"host"`
	Peer              string                        `json:"peer"`
	Port              int                           `json:"port"`
	UDPOverTCPVersion int                           `json:"udp_over_tcp_version"`
	Users             []multihoprelay.NodeChainUser `json:"users"`
}

// DNS names and TLS/query policy stay original. Only the final encrypted
// detour follows the captured selector; SelectedTag must be read back on the
// same original native owner before and after an actual DNS proof.
type NodeChainExecutionDNSCapture struct {
	Execution       string              `json:"execution"`
	SelectorTag     string              `json:"selector_tag"`
	SelectedTag     string              `json:"selected_tag"`
	DNSPolicySHA256 string              `json:"dns_policy_sha256"`
	DNS             NodeChainDNSCapture `json:"dns"`
}

type NodeChainExecutionPolicy struct {
	sourceJSON, sourceSHA, config, configSHA, seal string
	source                                         NodeChainExecutionSource
	local                                          *NodeChain
	front                                          NodeChainExecutionFront
	localProofs, serverProofs                      []NodeChainProof
	dns                                            NodeChainDNSCapture
	physical                                       []PhysicalEgress
}

var nodeChainExecutionError = errors.New("ordered execution lost its original path, discovery or listener proposal")

func NewNodeChainExecutionPolicy(sourceJSON string) (*NodeChainExecutionPolicy, error) {
	var source NodeChainExecutionSource
	if exactJSON([]byte(sourceJSON), &source, NodeChainInputLimit) != nil || source.Schema != 1 ||
		source.Execution != "server" && source.Execution != "auto" || source.Request.Validate(source.Server) != nil ||
		source.FirstPort < 1024 || source.LastPort > 65535 || source.LastPort < source.FirstPort || source.LastPort-source.FirstPort > 63 ||
		source.Request.Port < source.FirstPort || source.Request.Port > source.LastPort {
		return nil, nodeChainExecutionError
	}
	local, err := NewNodeChain(source.LocalSource)
	if err != nil || local.importedMiddle != nil || local.validateCapture() != nil || len(local.nodes) != len(source.Server.Members)+1 {
		return nil, nodeChainExecutionError
	}
	var original NodeChainSource
	if exactJSON([]byte(source.LocalSource), &original, NodeChainInputLimit) != nil || original.Schema != 1 || len(original.IdentitySources) != len(local.nodes) {
		return nil, nodeChainExecutionError
	}
	entry := local.nodes[0]
	if entry.mode != source.Server.EntryMode || predecessorText(entry.profile, "id") != source.Server.EntryID ||
		predecessorText(entry.profile, "node_proof_id") != source.Server.EntryNodeID {
		return nil, nodeChainExecutionError
	}
	api, err := privateAPI(predecessorText(entry.profile, "router_api"))
	if err != nil {
		return nil, nodeChainExecutionError
	}
	host, err := netip.ParseAddr(api.Hostname())
	if err != nil || host.Is4In6() || host.String() != api.Hostname() {
		return nil, nodeChainExecutionError
	}
	for index, node := range local.nodes {
		if index < len(local.nodes)-1 {
			key, err := node.PacketClientPublicKey()
			if err != nil || key != source.Request.LocalPacketPublicKeys[index] {
				return nil, nodeChainExecutionError
			}
		}
		if index == 0 {
			closure, err := nodeMultihopPredecessor(node)
			if err != nil {
				return nil, nodeChainExecutionError
			}
			addresses, ok := closure.final["address"].([]any)
			matched := false
			for _, value := range addresses {
				text, ok := value.(string)
				prefix, err := netip.ParsePrefix(text)
				matched = matched || ok && err == nil && prefix.Addr().String() == source.Request.Peer
			}
			if !ok || !matched {
				return nil, nodeChainExecutionError
			}
			continue
		}
		member := source.Server.Members[index-1]
		proof := local.proofs[index]
		if member.Position != index || member.ProfileID != proof.ProfileID || member.NodeID != proof.NodeID ||
			member.Mode != proof.Mode || member.StartLayer != proof.StartLayer {
			return nil, nodeChainExecutionError
		}
		if index < len(local.nodes)-1 {
			closure, err := nodeMultihopPredecessor(node)
			if err != nil {
				return nil, nodeChainExecutionError
			}
			peers, ok := closure.final["peers"].([]any)
			if !ok || len(peers) != 1 {
				return nil, nodeChainExecutionError
			}
			peer, ok := peers[0].(map[string]any)
			if !ok || member.ServerPublicKey != predecessorText(peer, "public_key") {
				return nil, nodeChainExecutionError
			}
		}
	}
	last := local.nodes[len(local.nodes)-1]
	var finalGraph map[string]any
	if exactJSON([]byte(last.config), &finalGraph, 4<<20) != nil {
		return nil, nodeChainExecutionError
	}
	dnsRaw, err := json.Marshal(finalGraph["dns"])
	if err != nil || externalDigest(dnsRaw) != source.Server.DNSPolicySHA256 {
		return nil, nodeChainExecutionError
	}
	// Canonicalize only the enclosing source. Every private original nested
	// source string remains byte-for-byte captured, including standard identity.
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, nodeChainExecutionError
	}
	p := &NodeChainExecutionPolicy{source: source, sourceJSON: string(raw), local: local}
	digest, _ := json.Marshal([]string{"routervpn-node-chain-execution-source-v1", p.sourceJSON})
	p.sourceSHA = externalDigest(digest)
	clear(digest)
	p.front = NodeChainExecutionFront{Host: host.String(), Peer: source.Request.Peer, Port: source.Request.Port,
		UDPOverTCPVersion: 2, Users: append([]multihoprelay.NodeChainUser(nil), source.Request.Users...)}
	if err := p.compile(); err != nil {
		return nil, err
	}
	p.seal = p.captureSeal()
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func (p *NodeChainExecutionPolicy) compile() error {
	var graph map[string]any
	if exactJSON([]byte(p.local.config), &graph, 4<<20) != nil {
		return nodeChainExecutionError
	}
	p.localProofs = p.local.ProofInventory()
	p.serverProofs = p.local.ProofInventory()
	localFinal := p.localProofs[len(p.localProofs)-1].Tag
	entryTag := p.localProofs[0].Tag
	outbounds := graph["outbounds"].([]any)
	var selector map[string]any
	for _, raw := range outbounds {
		row := raw.(map[string]any)
		if row["tag"] == SelectorTag {
			selector = row
		}
	}
	if selector == nil || selector["type"] != "selector" || selector["default"] != localFinal {
		return nodeChainExecutionError
	}
	for index, user := range p.source.Request.Users {
		position := index + 1
		tag := fmt.Sprintf("routervpn-chain-server-%d-%s", position, p.sourceSHA[:16])
		out := map[string]any{"type": "socks", "tag": tag, "server": p.front.Host, "server_port": p.front.Port,
			"version": "5", "username": user.Username, "password": user.Password, "detour": entryTag, "network": "tcp"}
		if position == len(p.localProofs)-1 {
			out["network"] = []string{"tcp", "udp"}
			out["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
		}
		outbounds = append(outbounds, out)
		p.serverProofs[position].Tag = tag
	}
	serverFinal := p.serverProofs[len(p.serverProofs)-1].Tag
	selector["outbounds"] = []string{localFinal, serverFinal}
	selector["default"] = localFinal
	if p.source.Execution == "server" {
		selector["default"] = serverFinal
	}
	graph["outbounds"] = outbounds
	dns := graph["dns"].(map[string]any)
	var selected map[string]any
	for _, value := range dns["servers"].([]any) {
		row := value.(map[string]any)
		if row["detour"] == localFinal {
			// This includes the exact explicit bootstrap tree of final DNS.
			// Earlier endpoint resolver owners retain their original detours.
			row["detour"] = SelectorTag
		}
		if row["tag"] == p.local.dns.ResolverTag {
			selected = row
		}
	}
	if selected == nil || selected["detour"] != SelectorTag {
		return nodeChainExecutionError
	}
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return nodeChainExecutionError
	}
	p.config, p.configSHA = string(raw), externalDigest(raw)
	resolver, _ := json.Marshal(selected)
	p.dns = p.local.dns
	p.dns.SourceSHA256, p.dns.ConfigSHA256, p.dns.FinalTag = p.sourceSHA, p.configSHA, SelectorTag
	p.dns.ResolverSHA256 = externalDigest(resolver)
	expected, err := p.local.PhysicalEgress()
	if err != nil {
		return nodeChainExecutionError
	}
	// Verify each explicit branch, including its selected DNS, against the
	// same original entry's physical tuple inventory. The private SOCKS front
	// and every final/prefix proof remain encrypted destinations, not grants.
	for _, final := range []string{localFinal, serverFinal} {
		branch := predecessorCopy(graph)
		branch["route"].(map[string]any)["final"] = final
		// The generic projection intentionally admits only its legacy exact
		// selector family. Resolve our independently validated two-choice DNS
		// detour to this explicit branch without widening that generic gate.
		for _, value := range branch["dns"].(map[string]any)["servers"].([]any) {
			row := value.(map[string]any)
			if row["detour"] == SelectorTag {
				row["detour"] = final
			}
		}
		encoded, _ := json.Marshal(branch)
		physical, err := compiledPhysicalEgressWithDesktopProof(string(encoded), []string{"tcp", "udp"}, nil, entryTag)
		if err != nil || !nodeChainSamePhysical(physical, expected) {
			return nodeChainExecutionError
		}
	}
	p.physical = append([]PhysicalEgress(nil), expected...)
	return nil
}

func (p *NodeChainExecutionPolicy) captureSeal() string {
	if p == nil {
		return ""
	}
	raw, err := json.Marshal([]any{"routervpn-node-chain-execution-capture-v1", p.sourceJSON, p.sourceSHA, p.config, p.configSHA,
		p.source, p.front, p.localProofs, p.serverProofs, p.dns, p.physical})
	if err != nil {
		return ""
	}
	digest := externalDigest(raw)
	clear(raw)
	return digest
}

func (p *NodeChainExecutionPolicy) validateCapture() error {
	if p == nil || p.seal == "" || p.seal != p.captureSeal() || p.local == nil || p.local.validateCapture() != nil ||
		p.source.Request.Validate(p.source.Server) != nil || !reflect.DeepEqual(p.localProofs, p.local.ProofInventory()) {
		return nodeChainExecutionError
	}
	return nil
}

func (p *NodeChainExecutionPolicy) Source() string       { return p.sourceJSON }
func (p *NodeChainExecutionPolicy) SourceSHA256() string { return p.sourceSHA }
func (p *NodeChainExecutionPolicy) Config() string       { return p.config }
func (p *NodeChainExecutionPolicy) ConfigSHA256() string { return p.configSHA }
func (p *NodeChainExecutionPolicy) Execution() string    { return p.source.Execution }
func (p *NodeChainExecutionPolicy) Request() multihoprelay.NodeChainRequest {
	return p.source.Request.Clone()
}
func (p *NodeChainExecutionPolicy) Descriptor() multihoprelay.NodeChainDescriptor {
	return p.source.Server.Clone()
}
func (p *NodeChainExecutionPolicy) Front() NodeChainExecutionFront {
	result := p.front
	result.Users = append([]multihoprelay.NodeChainUser(nil), result.Users...)
	return result
}

// ValidateFront is the mandatory host/port part of lease adoption. It is not
// sufficient on its own: the runtime must also match the complete original
// request, owner, registry and fresh authenticated native proof receipt.
func (p *NodeChainExecutionPolicy) ValidateFront(host string, port int) error {
	if p.validateCapture() != nil || host != p.front.Host || port != p.front.Port {
		return nodeChainExecutionError
	}
	return nil
}
func (p *NodeChainExecutionPolicy) ProofInventory(execution string) ([]NodeChainProof, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	switch execution {
	case "local":
		return append([]NodeChainProof(nil), p.localProofs...), nil
	case "server":
		return append([]NodeChainProof(nil), p.serverProofs...), nil
	default:
		return nil, nodeChainExecutionError
	}
}
func (p *NodeChainExecutionPolicy) DNSCapture(execution string) (NodeChainExecutionDNSCapture, error) {
	proofs, err := p.ProofInventory(execution)
	if err != nil {
		return NodeChainExecutionDNSCapture{}, err
	}
	return NodeChainExecutionDNSCapture{execution, SelectorTag, proofs[len(proofs)-1].Tag, p.source.Server.DNSPolicySHA256, p.dns}, nil
}
func (p *NodeChainExecutionPolicy) PhysicalEgress() ([]PhysicalEgress, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	return append([]PhysicalEgress(nil), p.physical...), nil
}

type nodeChainExecutionLaunch struct {
	Kind string `json:"kind"`
	NodeChainExecutionSource
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
}

func (p *NodeChainExecutionPolicy) LaunchInput() (string, error) {
	if p.validateCapture() != nil {
		return "", nodeChainExecutionError
	}
	raw, err := json.Marshal(nodeChainExecutionLaunch{"native-node-chain-execution", p.source, p.sourceSHA, p.configSHA})
	if err != nil || len(raw) > NodeChainInputLimit {
		return "", nodeChainExecutionError
	}
	return string(raw), nil
}
func ParseNodeChainExecutionLaunchInput(raw string) (*NodeChainExecutionPolicy, error) {
	var launch nodeChainExecutionLaunch
	if exactJSON([]byte(raw), &launch, NodeChainInputLimit) != nil || launch.Kind != "native-node-chain-execution" {
		return nil, nodeChainExecutionError
	}
	source, err := json.Marshal(launch.NodeChainExecutionSource)
	if err != nil {
		return nil, nodeChainExecutionError
	}
	p, err := NewNodeChainExecutionPolicy(string(source))
	if err != nil || p.sourceSHA != launch.SourceSHA256 || p.configSHA != launch.ConfigSHA256 {
		return nil, nodeChainExecutionError
	}
	canonical, err := p.LaunchInput()
	if err != nil || canonical != raw {
		return nil, nodeChainExecutionError
	}
	return p, nil
}
