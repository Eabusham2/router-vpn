package mobilemultihop

import (
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"

	"router-vpn/internal/multihoprelay"
)

const nodeChainServerPrefixSourceKind = "routervpn-server-node-chain-prefix-source"

// Nodes contains only the independently provisioned server suffix. The entry's
// client source is represented by public commitments, never a copied private peer.
type NodeChainServerPrefixSource struct {
	Kind                     string                                               `json:"kind"`
	Schema                   int                                                  `json:"schema"`
	LocalPrefix              []multihoprelay.NodeChainPrefixMember                `json:"local_prefix"`
	EntryPeerAddresses       []string                                             `json:"entry_peer_addresses"`
	Nodes                    []string                                             `json:"nodes"`
	IdentitySources          []string                                             `json:"identity_sources"`
	Candidates               []string                                             `json:"candidates"`
	CandidateIdentitySources []string                                             `json:"candidate_identity_sources"`
	PacketCandidatePairs     []multihoprelay.NodeChainPrefixPacketCandidatePair   `json:"packet_candidate_pairs,omitempty"`
	HysteriaCandidatePairs   []multihoprelay.NodeChainPrefixHysteriaCandidatePair `json:"hysteria_candidate_pairs,omitempty"`
}
type NodeChainServerPrefixPolicy struct {
	self                                       *NodeChainServerPrefixPolicy
	record                                     NodeChainServerPrefixSource
	nodes, originalNodes                       []*NodeProfile
	candidates, originalCandidates             []*NodeProfile
	responses                                  []candidateResponseSource
	prefix                                     *NodeChainCandidateAppendSource
	capturedPrefix                             *NodeChainCandidateAppendSource
	plan                                       *NodeChainCandidatePlan
	descriptor                                 multihoprelay.NodeChainPrefixDescriptor
	proofs                                     []NodeChainServerProof
	source, sourceSHA, config, configSHA, seal string
}

func nodeChainPrefixPacketMember(node *NodeProfile, position int) (multihoprelay.NodeChainPrefixMember, error) {
	if node == nil || !NodeChainPrefixMode(node.mode) || !packetPairLayerOff(node) || node.validateNodeDesktopCapture() != nil {
		return multihoprelay.NodeChainPrefixMember{}, errNodeChainAppendExecution
	}
	client, server, err := nodeChainPacketKeys(node)
	if err != nil {
		return multihoprelay.NodeChainPrefixMember{}, err
	}
	return multihoprelay.NodeChainPrefixMember{Position: position, ProfileID: predecessorText(node.profile, "id"), NodeID: predecessorText(node.profile, "node_proof_id"), Mode: node.mode, StartLayer: "off", SourceSHA256: node.source, ClientPublicKey: client, ServerPublicKey: server}, nil
}
func NewNodeChainServerPrefixPolicy(input string) (*NodeChainServerPrefixPolicy, error) {
	var source NodeChainServerPrefixSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Kind != nodeChainServerPrefixSourceKind || (source.Schema != 1 && source.Schema != 2 && source.Schema != 3 && source.Schema != 4 && source.Schema != 5 && source.Schema != 6 && source.Schema != 7) ||
		source.Nodes == nil || source.IdentitySources == nil || len(source.LocalPrefix) < 1 || len(source.LocalPrefix) > multihoprelay.NodeChainPrefixMaximumMembers ||
		len(source.Nodes) != len(source.LocalPrefix)-1 || len(source.IdentitySources) != len(source.Nodes) || len(source.Candidates) < 1 || len(source.Candidates) > multihoprelay.NodeChainPrefixMaximumCandidates || len(source.Candidates) != len(source.CandidateIdentitySources) {
		return nil, errNodeChainAppendExecution
	}
	packetCandidates := nodeChainPrefixHasPacketCandidates(source)
	hysteriaCandidates := nodeChainPrefixHasHysteriaCandidates(source)
	if hysteriaCandidates {
		if len(source.HysteriaCandidatePairs) != len(source.Candidates) {
			return nil, errNodeChainAppendExecution
		}
	} else if source.HysteriaCandidatePairs != nil {
		return nil, errNodeChainAppendExecution
	}
	if packetCandidates {
		if len(source.PacketCandidatePairs) != len(source.Candidates) {
			return nil, errNodeChainAppendExecution
		}
	} else if source.PacketCandidatePairs != nil {
		return nil, errNodeChainAppendExecution
	}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, errNodeChainAppendExecution
	}
	p := &NodeChainServerPrefixPolicy{record: source, source: string(raw), nodes: make([]*NodeProfile, 0, len(source.Nodes)), proofs: make([]NodeChainServerProof, 0, len(source.Nodes))}
	p.self = p
	domain := "routervpn-server-node-chain-prefix-source-v1"
	if source.Schema == 2 {
		domain = "routervpn-server-node-chain-prefix-source-v2"
	} else if source.Schema == 3 {
		domain = "routervpn-server-node-chain-prefix-source-v3"
	} else if source.Schema == 4 {
		domain = "routervpn-server-node-chain-prefix-source-v4"
	} else if source.Schema == 5 {
		domain = "routervpn-server-node-chain-prefix-source-v5"
	} else if source.Schema == 6 {
		domain = "routervpn-server-node-chain-prefix-source-v6"
	} else if source.Schema == 7 {
		domain = "routervpn-server-node-chain-prefix-source-v7"
	}
	p.sourceSHA, err = nodeChainAppendExecutionDigest(domain, source)
	if err != nil {
		return nil, err
	}
	p.descriptor = multihoprelay.NodeChainPrefixDescriptor{Schema: source.Schema, Purpose: multihoprelay.NodeChainPrefixPurpose, SourceSHA256: p.sourceSHA, EntryNodeID: source.LocalPrefix[0].NodeID, EntryPeerAddresses: append([]string(nil), source.EntryPeerAddresses...), LocalPrefix: append([]multihoprelay.NodeChainPrefixMember(nil), source.LocalPrefix...), Members: make([]multihoprelay.NodeChainPrefixMember, 0, len(source.Nodes)), Candidates: make([]multihoprelay.NodeChainPrefixCandidate, 0, len(source.Candidates))}
	memberSchema := source.Schema
	if source.Schema == 3 {
		memberSchema = 1
	}
	if packetCandidates {
		p.descriptor.PacketCandidatePairs = append([]multihoprelay.NodeChainPrefixPacketCandidatePair(nil), source.PacketCandidatePairs...)
	}
	if hysteriaCandidates {
		p.descriptor.HysteriaCandidatePairs = append([]multihoprelay.NodeChainPrefixHysteriaCandidatePair(nil), source.HysteriaCandidatePairs...)
	}
	for i, input := range source.Nodes {
		node, err := ParseNodeLaunchInput(input)
		if err != nil || node == nil || validateNodeChainIdentity(source.IdentitySources[i], node) != nil {
			return nil, errNodeChainAppendExecution
		}
		member, err := nodeChainPrefixCapturedMember(node, source.IdentitySources[i], i+1, memberSchema)
		if err != nil {
			return nil, err
		}
		p.nodes = append(p.nodes, node)
		p.descriptor.Members = append(p.descriptor.Members, member)
	}
	for i, input := range source.Candidates {
		node, err := ParseNodeLaunchInput(input)
		if err != nil || node == nil || validateNodeChainIdentity(source.CandidateIdentitySources[i], node) != nil {
			return nil, errNodeChainAppendExecution
		}
		var response candidateResponseSource
		descriptorSource := node.source
		if packetCandidates {
			pair := source.PacketCandidatePairs[i]
			if !nodeChainPrefixPacketServerMatches(pair, node) || pair.Position != len(source.LocalPrefix) {
				return nil, errNodeChainAppendExecution
			}
			response, err = parseCandidateNativeResponseSource(input, pair.Mode)
			descriptorSource = pair.LocalSourceSHA256
		} else if hysteriaCandidates {
			pair := source.HysteriaCandidatePairs[i]
			if !nodeChainPrefixHysteriaServerMatches(pair, node, source.CandidateIdentitySources[i]) || pair.Position != len(source.LocalPrefix) {
				return nil, errNodeChainAppendExecution
			}
			response, err = parseCandidateNativeResponseSource(input, "hysteria2")
			descriptorSource = pair.LocalSourceSHA256
		} else {
			if node.mode != "shadowsocks" {
				return nil, errNodeChainAppendExecution
			}
			closure, e := nodeMultihopPredecessor(node)
			if e != nil || !nodeChainCapturedSSClosure(closure) || !packetPairLayerOff(node) {
				return nil, errNodeChainAppendExecution
			}
			response, err = parseCandidateResponseSource(input)
		}
		if err != nil {
			return nil, err
		}
		p.candidates = append(p.candidates, node)
		p.responses = append(p.responses, response)
		p.descriptor.Candidates = append(p.descriptor.Candidates, multihoprelay.NodeChainPrefixCandidate{ProfileID: response.Target.ID, NodeID: response.NodeID, Mode: node.mode, StartLayer: "off", SourceSHA256: descriptorSource})
	}
	if p.descriptor.Validate() != nil {
		return nil, errNodeChainAppendExecution
	}
	all := append(append([]*NodeProfile(nil), p.nodes...), p.candidates...)
	identities := append(append([]string(nil), source.IdentitySources...), source.CandidateIdentitySources...)
	if validateAppendMemberAliases(all, make([]*nodeChainImportedMember, len(all))) != nil {
		return nil, errNodeChainAppendExecution
	}
	keySet, addressSet := map[string]bool{}, map[string]bool{}
	for _, member := range source.LocalPrefix {
		client, server := member.ClientPublicKey, member.ServerPublicKey
		if member.Mode == "shadowsocks" || (source.Schema == 5 || source.Schema == 6) && member.Mode == "hysteria2" {
			client, server = member.CompanionClientPublicKey, member.CompanionServerPublicKey
		}
		keySet[client], keySet[server] = true, true
	}
	for i, node := range all {
		public, remote, err := chainCompanionKeys(identities[i], node.profile)
		if err != nil || !privateStreamCompanionUnique(externalDigest([]byte(public)), all, identities, i) {
			return nil, errNodeChainAppendExecution
		}
		if i >= len(p.nodes) && (keySet[public] || keySet[remote]) {
			return nil, errNodeChainAppendExecution
		}
	}
	for _, response := range p.responses {
		if packetCandidates {
			if response.PacketOptions == "" || response.Method != "" || response.Password != "" || addressSet[response.Target.Address] {
				return nil, errNodeChainAppendExecution
			}
			addressSet[response.Target.Address] = true
			continue
		}
		if hysteriaCandidates {
			var options map[string]any
			if response.Hysteria2Options == "" || response.PacketOptions != "" || response.ClientKey != "" || response.ServerKey != "" ||
				response.Method != "" || response.Password != "" || addressSet[response.Target.Address] || json.Unmarshal([]byte(response.Hysteria2Options), &options) != nil {
				return nil, errNodeChainAppendExecution
			}
			keys, e := nodeChainAppendHysteriaKeys(options)
			if e != nil {
				return nil, e
			}
			for key := range keys {
				if keySet[key] {
					return nil, errNodeChainAppendExecution
				}
			}
			for key := range keys {
				keySet[key] = true
			}
			addressSet[response.Target.Address] = true
			continue
		}
		key := importedSS2022KeyIdentity(response.Method, response.Password)
		if key == "" || keySet[key] || addressSet[response.Target.Address] {
			return nil, errNodeChainAppendExecution
		}
		keySet[key], addressSet[response.Target.Address] = true, true
	}
	// The nonempty source has exactly its real suffix. The pure append compiler
	// supplies closure/alias/MTU validation; its application TUN is never started.
	if len(p.nodes) > 0 {
		suffixSchema := 1
		if source.Schema == 2 || source.Schema == 4 {
			suffixSchema = 2
			if p.nodes[0].mode == "shadowsocks" {
				suffixSchema = 3
			}
		}
		if source.Schema == 5 || source.Schema == 6 {
			for _, node := range p.nodes {
				if !NodeChainPrefixMode(node.mode) {
					suffixSchema = 2
					break
				}
			}
			if p.nodes[0].mode == "shadowsocks" || p.nodes[0].mode == "hysteria2" {
				suffixSchema = 3
			}
		}
		if source.Schema == 7 {
			suffixSchema = 3
		}
		nextMode := "shadowsocks"
		if hysteriaCandidates {
			nextMode = "hysteria2"
		}
		if packetCandidates {
			nextMode = p.descriptor.PacketCandidateMode()
			if !nodeChainAppendExecutionPacketMode(nextMode) {
				return nil, errNodeChainAppendExecution
			}
		}
		record := nodeChainCandidateAppendSourceRecord{Kind: nodeChainCandidateAppendSourceKind, Schema: suffixSchema, Execution: "local", DraftRevision: p.sourceSHA, DeviceRevision: p.sourceSHA, DeviceSource: source.Nodes[0], NextMode: nextMode, AppendPosition: len(source.Nodes), Nodes: source.Nodes, IdentitySources: source.IdentitySources}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		p.prefix, err = NewNodeChainCandidateAppendSource(string(encoded))
		if err != nil {
			return nil, err
		}
		p.capturedPrefix = p.prefix
		inventorySource := NodeChainCandidateInventory{Schema: 1, Revision: p.sourceSHA, Inputs: source.Candidates, ResponseMode: nextMode}
		if hysteriaCandidates {
			inventorySource.IdentitySources = append([]string(nil), source.CandidateIdentitySources...)
		}
		inventory, err := json.Marshal(inventorySource)
		if err != nil {
			return nil, err
		}
		p.plan, err = p.prefix.newCandidatePlan(string(inventory))
		if err != nil || p.plan == nil {
			return nil, errNodeChainAppendExecution
		}
		if packetCandidates {
			if len(p.plan.responses) != len(p.responses) {
				return nil, errNodeChainAppendExecution
			}
			for i, response := range p.responses {
				if !nodeChainPrefixPacketResponseEqual(response, p.plan.responses[i]) || p.plan.responses[i].PacketOptions == "" {
					return nil, errNodeChainAppendExecution
				}
			}
			// Only the original prospective packet plan supplies the nested MTU.
			p.responses = append([]candidateResponseSource(nil), p.plan.responses...)
		} else if !reflect.DeepEqual(p.plan.responses, p.responses) {
			return nil, errNodeChainAppendExecution
		}
		var graph map[string]any
		if exactJSON([]byte(p.prefix.Config()), &graph, 4<<20) != nil {
			return nil, errNodeChainAppendExecution
		}
		graph["inbounds"] = []any{}
		route, ok := graph["route"].(map[string]any)
		if !ok || route["final"] != NodeChainExecutionGateTag {
			return nil, errNodeChainAppendExecution
		}
		finalTag := p.prefix.proofs[len(p.prefix.proofs)-1].Tag
		route["rules"], route["final"] = []any{}, finalTag
		outs, ok := graph["outbounds"].([]any)
		if !ok {
			return nil, errNodeChainAppendExecution
		}
		// This worker has no application inbound. Remove only the exact
		// inherited closed gate and its selector as a pair; leaving the gate
		// behind would retain a native dependency on the removed selector.
		kept := make([]any, 0, len(outs))
		selectors, gates := 0, 0
		for _, value := range outs {
			out, ok := value.(map[string]any)
			if !ok {
				return nil, errNodeChainAppendExecution
			}
			switch out["tag"] {
			case SelectorTag:
				if !reflect.DeepEqual(out, map[string]any{"type": "selector", "tag": SelectorTag, "outbounds": []any{finalTag}, "default": finalTag, "interrupt_exist_connections": true}) {
					return nil, errNodeChainAppendExecution
				}
				selectors++
			case NodeChainExecutionGateTag:
				if !reflect.DeepEqual(out, map[string]any{"type": NodeChainExecutionGateType, "tag": NodeChainExecutionGateTag, "detour": SelectorTag}) {
					return nil, errNodeChainAppendExecution
				}
				gates++
			default:
				kept = append(kept, out)
			}
		}
		if selectors != 1 || gates != 1 {
			return nil, errNodeChainAppendExecution
		}
		graph["outbounds"] = kept
		encoded, err = json.Marshal(graph)
		if err != nil || len(encoded) > 4<<20 {
			return nil, errNodeChainAppendExecution
		}
		p.config = string(encoded)
		p.configSHA = externalDigest(encoded)
		for i, node := range p.nodes {
			proof := p.prefix.proofs[i]
			proof.Position = i + 1
			api := predecessorText(node.profile, "router_api")
			url, err := privateAPI(api)
			if err != nil {
				return nil, err
			}
			p.proofs = append(p.proofs, NodeChainServerProof{Proof: proof, API: api, Token: predecessorText(node.profile, "api_token"), Network: "tcp", Address: url.Host})
		}
	} else {
		// No Box, endpoint, fake proof row, selector or final source exists here.
		// Each candidate later obtains its own actual physical TCP or UDP route observer.
		p.config, p.configSHA = "", ""
	}
	p.originalNodes = append([]*NodeProfile(nil), p.nodes...)
	p.originalCandidates = append([]*NodeProfile(nil), p.candidates...)
	p.seal = p.digest()
	return p, p.validate()
}
func (p *NodeChainServerPrefixPolicy) digest() string {
	if p == nil || p.self != p {
		return ""
	}
	seals := make([]string, 0, len(p.nodes)+len(p.candidates))
	for _, node := range append(append([]*NodeProfile(nil), p.nodes...), p.candidates...) {
		if node == nil || node.validateNodeDesktopCapture() != nil {
			return ""
		}
		seals = append(seals, node.desktopSeal)
	}
	prefix, plan := "", ""
	if p.prefix != nil {
		prefix = p.prefix.seal
	}
	if p.plan != nil {
		plan = p.plan.seal
	}
	raw, err := json.Marshal([]any{"routervpn-server-prefix-policy-seal-v1", p.record, p.descriptor, p.source, p.sourceSHA, p.config, p.configSHA, p.proofs, p.responses, seals, prefix, plan})
	if err != nil {
		return ""
	}
	defer clear(raw)
	return externalDigest(raw)
}
func (p *NodeChainServerPrefixPolicy) validate() error {
	if p == nil || p.self != p || p.seal == "" || p.seal != p.digest() || p.descriptor.Validate() != nil || len(p.nodes) != len(p.record.Nodes) || len(p.originalNodes) != len(p.nodes) || len(p.originalCandidates) != len(p.candidates) || len(p.candidates) != len(p.responses) || len(p.proofs) != len(p.nodes) {
		return errNodeChainAppendExecution
	}
	for i, node := range p.nodes {
		if node != p.originalNodes[i] || node.source != p.descriptor.Members[i].SourceSHA256 {
			return errNodeChainAppendExecution
		}
	}
	for i, node := range p.candidates {
		if node != p.originalCandidates[i] {
			return errNodeChainAppendExecution
		}
		if nodeChainPrefixHasPacketCandidates(p.record) {
			if i >= len(p.record.PacketCandidatePairs) || i >= len(p.descriptor.PacketCandidatePairs) ||
				p.record.PacketCandidatePairs[i] != p.descriptor.PacketCandidatePairs[i] ||
				p.record.PacketCandidatePairs[i].LocalSourceSHA256 != p.descriptor.Candidates[i].SourceSHA256 ||
				!nodeChainPrefixPacketServerMatches(p.record.PacketCandidatePairs[i], node) {
				return errNodeChainAppendExecution
			}
		} else if nodeChainPrefixHasHysteriaCandidates(p.record) {
			if i >= len(p.record.HysteriaCandidatePairs) || i >= len(p.descriptor.HysteriaCandidatePairs) ||
				p.record.HysteriaCandidatePairs[i] != p.descriptor.HysteriaCandidatePairs[i] ||
				p.record.HysteriaCandidatePairs[i].LocalSourceSHA256 != p.descriptor.Candidates[i].SourceSHA256 ||
				!nodeChainPrefixHysteriaServerMatches(p.record.HysteriaCandidatePairs[i], node, p.record.CandidateIdentitySources[i]) {
				return errNodeChainAppendExecution
			}
		} else if node.source != p.descriptor.Candidates[i].SourceSHA256 {
			return errNodeChainAppendExecution
		}
	}
	if len(p.nodes) == 0 {
		if p.prefix != nil || p.capturedPrefix != nil || p.plan != nil || p.config != "" || p.configSHA != "" {
			return errNodeChainAppendExecution
		}
	} else if p.prefix == nil || p.prefix != p.capturedPrefix || p.prefix.validate() != nil || p.plan == nil || p.plan.appendSource != p.prefix || p.plan.validateAppend() != nil {
		return errNodeChainAppendExecution
	}
	return nil
}
func (p *NodeChainServerPrefixPolicy) Source() string {
	if p.validate() != nil {
		return ""
	}
	return p.source
}
func (p *NodeChainServerPrefixPolicy) SourceSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.sourceSHA
}
func (p *NodeChainServerPrefixPolicy) Config() string {
	if p.validate() != nil {
		return ""
	}
	return p.config
}
func (p *NodeChainServerPrefixPolicy) ConfigSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.configSHA
}
func (p *NodeChainServerPrefixPolicy) Descriptor() (multihoprelay.NodeChainPrefixDescriptor, error) {
	if p.validate() != nil {
		return multihoprelay.NodeChainPrefixDescriptor{}, errNodeChainAppendExecution
	}
	return p.descriptor.Clone(), nil
}
func (p *NodeChainServerPrefixPolicy) Proofs() ([]NodeChainServerProof, error) {
	if p.validate() != nil {
		return nil, errNodeChainAppendExecution
	}
	return append([]NodeChainServerProof{}, p.proofs...), nil
}
func (p *NodeChainServerPrefixPolicy) BindCapture(c multihoprelay.NodeChainPrefixCapture) error {
	if p.validate() != nil || c.Validate() != nil {
		return errNodeChainAppendExecution
	}
	a, err := p.descriptor.Digest()
	b, other := c.Source.Digest()
	if err != nil || other != nil || a != b {
		return errNodeChainAppendExecution
	}
	return nil
}
func (p *NodeChainServerPrefixPolicy) candidate(c multihoprelay.NodeChainPrefixCandidateCapture) (candidateResponseSource, error) {
	if p.BindCapture(c.Lease) != nil || c.Validate() != nil {
		return candidateResponseSource{}, errNodeChainAppendExecution
	}
	for i, ref := range p.descriptor.Candidates {
		if ref == c.Candidate && ref.ProfileID == c.Request.CandidateID && ref.SourceSHA256 == c.Request.CandidateSourceSHA256 {
			return p.responses[i], nil
		}
	}
	return candidateResponseSource{}, errNodeChainAppendExecution
}
func (p *NodeChainServerPrefixPolicy) candidatePhysical(c multihoprelay.NodeChainPrefixCandidateCapture) (PhysicalEgress, error) {
	response, err := p.candidate(c)
	if err != nil || len(p.nodes) != 0 {
		return PhysicalEgress{}, errNodeChainAppendExecution
	}
	host, port, err := net.SplitHostPort(response.Target.Address)
	numeric, e := strconv.Atoi(port)
	ip, fail := netip.ParseAddr(host)
	if err != nil || e != nil || fail != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" || numeric < 1 || numeric > 65535 {
		return PhysicalEgress{}, errNodeChainAppendExecution
	}
	network := "tcp"
	if c.Request.IsPacket() || c.Request.IsHysteria() {
		network = "udp"
	}
	return PhysicalEgress{Network: network, Host: host, Port: numeric}, nil
}

// The operator plan validates the genuine Local prefix as well as every
// independent server peer, then publishes only commitments and private suffixes.
func NewNodeChainServerPrefixPlan(input string) (*NodeChainServerPrefixPolicy, error) {
	var plan map[string]any
	if exactJSON([]byte(input), &plan, NodeChainInputLimit) != nil || !nodeChainPlanKeys(plan, []string{"schema", "purpose", "entry_node_id", "entry", "members", "candidates"}, nil) || (plan["schema"] != float64(1) && plan["schema"] != float64(2) && plan["schema"] != float64(3) && plan["schema"] != float64(4) && plan["schema"] != float64(5) && plan["schema"] != float64(6) && plan["schema"] != float64(7)) || plan["purpose"] != multihoprelay.NodeChainPrefixPurpose {
		return nil, errNodeChainAppendExecution
	}
	schema := int(plan["schema"].(float64))
	entryRaw, ok := plan["entry"].(map[string]any)
	members, memberOK := plan["members"].([]any)
	candidates, candidateOK := plan["candidates"].([]any)
	if !ok || !memberOK || !candidateOK || len(members) >= multihoprelay.NodeChainPrefixMaximumMembers || len(candidates) < 1 || len(candidates) > multihoprelay.NodeChainPrefixMaximumCandidates {
		return nil, errNodeChainAppendExecution
	}
	entry, err := nodeChainPlanCapture(entryRaw)
	if err != nil || entry == nil || entry.node == nil || plan["entry_node_id"] != predecessorText(entry.profile, "node_proof_id") {
		return nil, errNodeChainAppendExecution
	}
	entryInput, err := entry.node.LaunchInput()
	if err != nil {
		return nil, err
	}
	entryMember, peers, err := nodeChainPrefixPlanEntry(entry, schema == 7)
	if err != nil {
		return nil, err
	}
	source := NodeChainServerPrefixSource{Kind: nodeChainServerPrefixSourceKind, Schema: schema, LocalPrefix: []multihoprelay.NodeChainPrefixMember{entryMember}, EntryPeerAddresses: peers, Nodes: []string{}, IdentitySources: []string{}, Candidates: []string{}, CandidateIdentitySources: []string{}}
	localNodes, localIdentities := []string{entryInput}, []string{entry.identity}
	localCandidates := make([]string, 0, len(candidates))
	candidateMode := "shadowsocks"
	memberSchema := schema
	if schema == 3 {
		memberSchema = 1
	}
	allLocal := []*NodeProfile{entry.node}
	for i, value := range members {
		row, ok := value.(map[string]any)
		if !ok || !nodeChainPlanKeys(row, []string{"paired", "server_peer"}, nil) {
			return nil, errNodeChainAppendExecution
		}
		pairedRaw, a := row["paired"].(map[string]any)
		peerRaw, b := row["server_peer"].(map[string]any)
		if !a || !b || !nodeChainPlanKeys(peerRaw, []string{"bundle", "profile_id"}, nil) {
			return nil, errNodeChainAppendExecution
		}
		paired, err := nodeChainPlanCapture(pairedRaw)
		if err != nil || (!NodeChainPrefixMode(paired.mode) && !(paired.mode == "shadowsocks" && (schema == 2 || schema == 4 || schema == 5 || schema == 6 || schema == 7) || paired.mode == "hysteria2" && (schema == 5 || schema == 6))) || !packetPairLayerOff(paired.node) {
			return nil, errNodeChainAppendExecution
		}
		bundle, profile, err := nodeChainPlanSelectedBundle(peerRaw["bundle"], peerRaw["profile_id"])
		if err != nil {
			return nil, err
		}
		for _, key := range []string{"node_proof_id", "endpoint", "router_api"} {
			if !reflect.DeepEqual(paired.profile[key], profile[key]) {
				return nil, errNodeChainAppendExecution
			}
		}
		server, err := nodeChainPlanNodeFromBundle(bundle, paired.profile, paired.mode, paired.bootstrap)
		if err != nil || paired.identityKey == server.identityKey || !nodeChainPlanTransportEqual(paired.node, server.node) {
			return nil, errNodeChainAppendExecution
		}
		localInput, err := paired.node.LaunchInput()
		if err != nil {
			return nil, err
		}
		serverInput, err := server.node.LaunchInput()
		if err != nil {
			return nil, err
		}
		localMember, err := nodeChainPrefixCapturedMember(paired.node, paired.identity, i+1, memberSchema)
		if err != nil {
			return nil, err
		}
		source.LocalPrefix = append(source.LocalPrefix, localMember)
		source.Nodes = append(source.Nodes, serverInput)
		source.IdentitySources = append(source.IdentitySources, server.identity)
		localNodes, localIdentities = append(localNodes, localInput), append(localIdentities, paired.identity)
		allLocal = append(allLocal, paired.node)
	}
	if schema == 2 {
		actualSchema, err := nodeChainPrefixLocalSchema(allLocal)
		if err != nil || actualSchema != schema {
			return nil, errNodeChainAppendExecution
		}
	}
	packetCandidates := schema == 3
	if schema == 4 {
		first, ok := candidates[0].(map[string]any)
		if !ok {
			return nil, errNodeChainAppendExecution
		}
		packetCandidates = nodeChainPlanKeys(first, []string{"paired", "server_peer"}, nil)
	}
	hysteriaCandidates := false
	if schema == 5 {
		first, ok := candidates[0].(map[string]any)
		if !ok {
			return nil, errNodeChainAppendExecution
		}
		hysteriaCandidates = nodeChainPlanKeys(first, []string{"paired", "server_peer"}, nil)
	}
	if schema == 6 {
		first, ok := candidates[0].(map[string]any)
		if !ok {
			return nil, errNodeChainAppendExecution
		}
		if nodeChainPlanKeys(first, []string{"paired", "server_peer"}, nil) {
			pairedRaw, ok := first["paired"].(map[string]any)
			if !ok {
				return nil, errNodeChainAppendExecution
			}
			paired, err := nodeChainPlanCapture(pairedRaw)
			if err != nil || paired == nil || !packetPairLayerOff(paired.node) {
				return nil, errNodeChainAppendExecution
			}
			packetCandidates = nodeChainAppendExecutionPacketMode(paired.mode)
			hysteriaCandidates = paired.mode == "hysteria2"
			if !packetCandidates && !hysteriaCandidates {
				return nil, errNodeChainAppendExecution
			}
		}
	}
	for _, value := range candidates {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, errNodeChainAppendExecution
		}
		if hysteriaCandidates {
			paired, server, pair, err := nodeChainPrefixHysteriaPlanPair(row, len(source.LocalPrefix))
			if err != nil {
				return nil, err
			}
			localInput, err := paired.node.LaunchInput()
			if err != nil {
				return nil, err
			}
			serverInput, err := server.node.LaunchInput()
			if err != nil {
				return nil, err
			}
			candidateMode = "hysteria2"
			source.HysteriaCandidatePairs = append(source.HysteriaCandidatePairs, pair)
			source.Candidates = append(source.Candidates, serverInput)
			source.CandidateIdentitySources = append(source.CandidateIdentitySources, server.identity)
			localCandidates = append(localCandidates, localInput)
			allLocal = append(allLocal, paired.node)
			localIdentities = append(localIdentities, paired.identity)
			continue
		}
		if packetCandidates {
			if !nodeChainPlanKeys(row, []string{"paired", "server_peer"}, nil) {
				return nil, errNodeChainAppendExecution
			}
			pairedRaw, a := row["paired"].(map[string]any)
			peerRaw, b := row["server_peer"].(map[string]any)
			if !a || !b || !nodeChainPlanKeys(peerRaw, []string{"bundle", "profile_id"}, nil) {
				return nil, errNodeChainAppendExecution
			}
			paired, err := nodeChainPlanCapture(pairedRaw)
			if err != nil || !nodeChainAppendExecutionPacketMode(paired.mode) || !packetPairLayerOff(paired.node) {
				return nil, errNodeChainAppendExecution
			}
			bundle, profile, err := nodeChainPlanSelectedBundle(peerRaw["bundle"], peerRaw["profile_id"])
			if err != nil {
				return nil, err
			}
			for _, key := range []string{"node_proof_id", "endpoint", "router_api"} {
				if !reflect.DeepEqual(paired.profile[key], profile[key]) {
					return nil, errNodeChainAppendExecution
				}
			}
			server, err := nodeChainPlanNodeFromBundle(bundle, paired.profile, paired.mode, paired.bootstrap)
			if err != nil || paired.identityKey == server.identityKey || !nodeChainPlanTransportEqual(paired.node, server.node) {
				return nil, errNodeChainAppendExecution
			}
			pair, err := nodeChainPrefixPacketPair(len(source.LocalPrefix), paired.node, server.node)
			if err != nil || len(source.PacketCandidatePairs) > 0 && candidateMode != pair.Mode {
				return nil, errNodeChainAppendExecution
			}
			localInput, err := paired.node.LaunchInput()
			if err != nil {
				return nil, err
			}
			serverInput, err := server.node.LaunchInput()
			if err != nil {
				return nil, err
			}
			candidateMode = pair.Mode
			source.PacketCandidatePairs = append(source.PacketCandidatePairs, pair)
			source.Candidates = append(source.Candidates, serverInput)
			source.CandidateIdentitySources = append(source.CandidateIdentitySources, server.identity)
			localCandidates = append(localCandidates, localInput)
			allLocal = append(allLocal, paired.node)
			localIdentities = append(localIdentities, paired.identity)
			continue
		}
		candidate, err := nodeChainPlanCapture(row)
		if err != nil || candidate.mode != "shadowsocks" || !packetPairLayerOff(candidate.node) {
			return nil, errNodeChainAppendExecution
		}
		input, err := candidate.node.LaunchInput()
		if err != nil {
			return nil, err
		}
		source.Candidates = append(source.Candidates, input)
		source.CandidateIdentitySources = append(source.CandidateIdentitySources, candidate.identity)
		localCandidates = append(localCandidates, input)
		allLocal = append(allLocal, candidate.node)
		localIdentities = append(localIdentities, candidate.identity)
	}
	for i, node := range allLocal {
		public, _, err := chainCompanionKeys(localIdentities[i], node.profile)
		if err != nil || !privateStreamCompanionUnique(externalDigest([]byte(public)), allLocal, localIdentities, i) {
			return nil, errNodeChainAppendExecution
		}
	}
	localSchema := schema
	if schema == 3 {
		localSchema = 1
	} else if schema == 4 {
		actualLocal, actualRemote, err := nodeChainPrefixExecutionSchemas(allLocal[:len(localNodes)], candidateMode)
		if err != nil || actualLocal != 2 || actualRemote != 4 {
			return nil, errNodeChainAppendExecution
		}
		localSchema = actualLocal
	} else if schema == 5 || schema == 6 || schema == 7 {
		actualLocal, actualRemote, err := nodeChainPrefixExecutionSchemas(allLocal[:len(localNodes)], candidateMode)
		if err != nil || actualRemote != schema {
			return nil, errNodeChainAppendExecution
		}
		localSchema = actualLocal
	}
	local := nodeChainCandidateAppendSourceRecord{Kind: nodeChainCandidateAppendSourceKind, Schema: localSchema, Execution: "local", DraftRevision: "operator-original-local-prefix", DeviceRevision: "operator-original-entry-device", DeviceSource: entryInput, NextMode: candidateMode, AppendPosition: len(localNodes), Nodes: localNodes, IdentitySources: localIdentities[:len(localNodes)]}
	raw, err := json.Marshal(local)
	if err != nil {
		return nil, err
	}
	original, err := NewNodeChainCandidateAppendSource(string(raw))
	if err != nil {
		return nil, err
	}
	inventorySource := NodeChainCandidateInventory{Schema: 1, Revision: "operator-original-private-candidates", Inputs: localCandidates, ResponseMode: candidateMode}
	if hysteriaCandidates {
		inventorySource.IdentitySources = append([]string(nil), localIdentities[len(localNodes):]...)
	}
	inventory, err := json.Marshal(inventorySource)
	if err != nil {
		return nil, err
	}
	if _, err = original.newCandidatePlan(string(inventory)); err != nil {
		return nil, err
	}
	sort.Strings(source.EntryPeerAddresses)
	raw, err = json.Marshal(source)
	if err != nil {
		return nil, err
	}
	return NewNodeChainServerPrefixPolicy(string(raw))
}

// The original runner reserves these actual native keys in its existing ledger.
func (p *NodeChainServerPrefixPolicy) PacketRuntimeKeys() ([]string, error) {
	if p.validate() != nil {
		return nil, errNodeChainAppendExecution
	}
	keys := make([]string, 0, 2*len(p.nodes))
	seen := map[string]bool{}
	for _, node := range p.nodes {
		if (p.record.Schema == 2 || p.record.Schema == 4 || p.record.Schema == 5 || p.record.Schema == 6 || p.record.Schema == 7) && node.mode == "shadowsocks" || (p.record.Schema == 5 || p.record.Schema == 6) && node.mode == "hysteria2" {
			continue
		}
		client, server, err := nodeChainPacketKeys(node)
		if err != nil || seen[client] || seen[server] {
			return nil, errNodeChainAppendExecution
		}
		seen[client], seen[server] = true, true
		keys = append(keys, client, server)
	}
	return keys, nil
}
