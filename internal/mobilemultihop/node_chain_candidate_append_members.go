package mobilemultihop

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"strings"
)

// Imported captures belong to this unfinished source, never to a fabricated
// complete NodeChain. Empty identity companions select only this exact parser.
func (s *NodeChainCandidateAppendSource) captureMembers() error {
	s.nodes = make([]*NodeProfile, len(s.record.Nodes))
	s.imports = make([]*nodeChainImportedMember, len(s.record.Nodes))
	s.importOwners = make([]*nodeChainAppendImportedSeal, len(s.record.Nodes))
	for position, input := range s.record.Nodes {
		if s.record.IdentitySources[position] == "" {
			if s.record.Schema != 2 || position == 0 {
				return nodeChainCandidateAppendError
			}
			member, err := parseNodeChainImportedMember(input)
			if err != nil || member == nil {
				return errors.Join(err, nodeChainCandidateAppendError)
			}
			original, err := rememberAppendImportedMember(member)
			if err != nil {
				return err
			}
			s.imports[position], s.importOwners[position] = member, original
			continue
		}
		node, err := ParseNodeLaunchInput(input)
		if err != nil || node == nil ||
			!NodeChainPrefixMode(node.mode) && (!nodeChainAppendProxyMode(node.mode) || s.record.Schema != 3 && (s.record.Schema != 2 || position == 0)) ||
			validateNodeChainIdentity(s.record.IdentitySources[position], node) != nil {
			return nodeChainCandidateAppendError
		}
		s.nodes[position] = node
	}
	s.originalNodes = append([]*NodeProfile(nil), s.nodes...)
	s.originalImports = append([]*nodeChainImportedMember(nil), s.imports...)
	if s.memberCapturesCurrent() != nil {
		return nodeChainCandidateAppendError
	}
	return validateAppendMemberAliases(s.nodes, s.imports)
}

func (s *NodeChainCandidateAppendSource) memberCapturesCurrent() error {
	if s == nil || s.self != s || s.device == nil || s.device != s.originalDevice ||
		s.device.validateNodeDesktopCapture() != nil || s.record.Schema != 1 && s.record.Schema != 2 && s.record.Schema != 3 ||
		len(s.nodes) < 1 || len(s.nodes) != len(s.originalNodes) || len(s.nodes) != len(s.imports) ||
		len(s.nodes) != len(s.originalImports) || len(s.nodes) != len(s.importOwners) || len(s.nodes) != len(s.record.Nodes) ||
		len(s.nodes) != len(s.record.IdentitySources) || s.nodes[0] == nil ||
		s.record.Schema != 3 && !NodeChainPrefixMode(s.nodes[0].mode) ||
		s.record.Schema == 3 && (s.record.NextKind != "" || !pairedProxyEntryPrefixNodes(s.nodes)) {
		return nodeChainCandidateAppendError
	}
	streams := 0
	for position, node := range s.nodes {
		member := s.imports[position]
		if node != s.originalNodes[position] || member != s.originalImports[position] {
			return nodeChainCandidateAppendError
		}
		if member != nil {
			if s.record.Schema != 2 || position == 0 || node != nil ||
				member.input != s.record.Nodes[position] || member.validate() != nil || !s.importOwners[position].matches(member) ||
				s.record.IdentitySources[position] != "" {
				return nodeChainCandidateAppendError
			}
			streams++
			continue
		}
		if node == nil || s.importOwners[position] != nil || node.validateNodeDesktopCapture() != nil || s.record.IdentitySources[position] == "" {
			return nodeChainCandidateAppendError
		}
		if !NodeChainPrefixMode(node.mode) {
			if !nodeChainAppendProxyMode(node.mode) || s.record.Schema != 3 && (s.record.Schema != 2 || position == 0) ||
				predecessorText(node.profile, "start_layer") != "" && predecessorText(node.profile, "start_layer") != "off" {
				return nodeChainCandidateAppendError
			}
			streams++
		}
	}
	if s.record.Schema == 2 && streams == 0 || s.record.Schema == 1 && streams != 0 {
		return nodeChainCandidateAppendError
	}
	return nil
}

func validateAppendMemberAliases(nodes []*NodeProfile, imports []*nodeChainImportedMember) error {
	if len(nodes) != len(imports) {
		return nodeChainCandidateAppendError
	}
	ids, proofs, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for position, node := range nodes {
		if member := imports[position]; member != nil {
			if node != nil || member.validate() != nil || ids[member.id()] {
				return nodeChainCandidateAppendError
			}
			ids[member.id()] = true
			continue
		}
		if node == nil {
			return nodeChainCandidateAppendError
		}
		id, proof := predecessorText(node.profile, "id"), predecessorText(node.profile, "node_proof_id")
		if ids[id] || proofs[proof] {
			return nodeChainCandidateAppendError
		}
		ids[id], proofs[proof] = true, true
		if NodeChainPrefixMode(node.mode) {
			client, server, err := nodeChainPacketKeys(node)
			if err != nil || client == server || keys[client] || keys[server] {
				return nodeChainCandidateAppendError
			}
			keys[client], keys[server] = true, true
		}
	}
	return nil
}

// The stream is a genuine UDP-capable, literal, unlayered SS2022 capture. A
// paired stream keeps its private proof identity; an import keeps public proof.
func nodeChainAppendSSClosure(closure *externalPredecessor) bool {
	return nodeChainCapturedSSClosure(closure)
}

// Pure captured transport validation; execution authority belongs to the
// caller's distinct original append or complete-source owner.
func nodeChainCapturedSSClosure(closure *externalPredecessor) bool {
	if closure == nil || closure.final == nil || len(closure.nodes) != 1 {
		return false
	}
	out := closure.final
	ip, err := netip.ParseAddr(predecessorText(out, "server"))
	return err == nil && ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast() &&
		out["type"] == "shadowsocks" && out["detour"] == nil && out["domain_resolver"] == nil &&
		out["network"] == nil && out["udp_over_tcp"] == nil && out["multiplex"] == nil &&
		out["plugin"] == nil && out["plugin_opts"] == nil &&
		!strings.Contains(predecessorText(out, "password"), ":") &&
		importedSS2022Credentials(predecessorText(out, "method"), predecessorText(out, "password"))
}

// This typed construction scope admits the first captured prefix resolver and
// the validated stream MTU walk only for the actual unfinished source. It
// supplies no complete-chain, selected-execution or live native authority.
type nodeChainAppendGraphScope struct {
	owner    *NodeChainCandidateAppendSource
	nodes    []*NodeProfile
	imports  []*nodeChainImportedMember
	closures []*externalPredecessor
}

func (scope *nodeChainAppendGraphScope) validate(members []nodeChainGraphMember, closures []*externalPredecessor, physical []PhysicalEgress) error {
	if scope == nil || scope.owner == nil ||
		scope.owner.memberCapturesCurrent() != nil || len(scope.nodes) != len(scope.imports) ||
		len(scope.nodes) != len(members) || len(closures) != len(members) || len(scope.closures) != len(members) ||
		len(members) < len(scope.owner.nodes) || len(members) > len(scope.owner.nodes)+1 {
		return nodeChainCandidateAppendError
	}
	// A schema-one source may prospectively append its first import. The
	// original prefix stays schema one; only this captured extra slot needs
	// the append resolver scope. It is never a complete imported route.
	last := len(scope.nodes) - 1
	if scope.owner.record.Schema != 2 && scope.owner.record.Schema != 3 && (scope.owner.record.Schema != 1 ||
		len(scope.nodes) != len(scope.owner.nodes)+1 || scope.owner.record.NextKind != "external" ||
		scope.imports[last] == nil) {
		return nodeChainCandidateAppendError
	}
	for i, node := range scope.nodes {
		member := scope.imports[i]
		if i < len(scope.owner.nodes) {
			if node != scope.owner.nodes[i] || member != scope.owner.imports[i] {
				return nodeChainCandidateAppendError
			}
		} else if member != nil {
			if node != nil || scope.owner.record.NextKind != "external" || scope.owner.record.NextMode != "shadowsocks" ||
				!nodeChainAppendImportCaptured(member) {
				return nodeChainCandidateAppendError
			}
		} else if scope.owner.record.NextKind != "" || node == nil || node.mode != scope.owner.record.NextMode ||
			node.validateNodeDesktopCapture() != nil ||
			predecessorText(node.profile, "start_layer") != "" && predecessorText(node.profile, "start_layer") != "off" {
			return nodeChainCandidateAppendError
		}
		if closures[i] == nil || closures[i] != scope.closures[i] || members[i].externalHome {
			return nodeChainCandidateAppendError
		}
		if member != nil {
			if node != nil || member.validate() != nil || !members[i].imported ||
				members[i].source != member.source || members[i].mode != "shadowsocks" ||
				!reflect.DeepEqual(members[i].profile, member.selection.Profile) {
				return nodeChainCandidateAppendError
			}
		} else if node == nil || members[i].imported || members[i].source != node.source ||
			members[i].mode != node.mode || !reflect.DeepEqual(members[i].profile, node.profile) {
			return nodeChainCandidateAppendError
		}
	}
	expected, err := scope.owner.nodes[0].PhysicalEgress()
	if err != nil || !nodeChainSamePhysical(expected, physical) {
		return errors.Join(err, nodeChainCandidateAppendError)
	}
	return nil
}

func (s *NodeChainCandidateAppendSource) compileGraph(candidate *NodeProfile) (string, []NodeChainProof, []PhysicalEgress, error) {
	return s.compileGraphCandidate(candidate, nil)
}

func (s *NodeChainCandidateAppendSource) compileGraphCandidate(candidate *NodeProfile, imported *nodeChainImportedMember) (string, []NodeChainProof, []PhysicalEgress, error) {
	fail := func(err error) (string, []NodeChainProof, []PhysicalEgress, error) {
		return "", nil, nil, errors.Join(err, nodeChainCandidateAppendError)
	}
	if s.memberCapturesCurrent() != nil {
		return fail(nil)
	}
	nodes := append([]*NodeProfile(nil), s.nodes...)
	imports := append([]*nodeChainImportedMember(nil), s.imports...)
	if candidate != nil {
		if imported != nil || s.record.NextKind != "" || candidate.mode != s.record.NextMode || candidate.validateNodeDesktopCapture() != nil ||
			predecessorText(candidate.profile, "start_layer") != "" && predecessorText(candidate.profile, "start_layer") != "off" {
			return fail(nil)
		}
		nodes, imports = append(nodes, candidate), append(imports, nil)
	}
	if imported != nil {
		if candidate != nil || s.record.NextKind != "external" || s.record.NextMode != "shadowsocks" ||
			!nodeChainAppendImportCaptured(imported) {
			return fail(nil)
		}
		nodes, imports = append(nodes, nil), append(imports, imported)
	}
	if len(nodes) > NodeChainExtendedLocalMaximumNodes || validateAppendMemberAliases(nodes, imports) != nil {
		return fail(nil)
	}
	closures := make([]*externalPredecessor, len(nodes))
	members := make([]nodeChainGraphMember, len(nodes))
	streams := make([]*externalPredecessor, 0, len(nodes))
	targets := map[netip.AddrPort]bool{}
	withStreams := s.record.Schema == 2 || s.record.Schema == 3 || imported != nil || candidate != nil && nodeChainAppendProxyMode(candidate.mode)
	for i, node := range nodes {
		var closure *externalPredecessor
		var err error
		if member := imports[i]; member != nil {
			closure, err = member.closure()
			members[i] = nodeChainGraphMember{profile: member.selection.Profile, source: member.source, mode: "shadowsocks", imported: true}
		} else {
			closure, err = nodeMultihopPredecessor(node)
			members[i] = nodeChainGraphMember{profile: node.profile, source: node.source, mode: node.mode}
		}
		if err != nil || closure == nil || closure.final == nil {
			return fail(err)
		}
		if services, _ := closure.graph["services"].([]any); len(services) != 0 {
			return fail(nil)
		}
		if members[i].mode == "shadowsocks" {
			if i == 0 && s.record.Schema != 3 || imports[i] == nil && !nodeChainAppendSSClosure(closure) || imports[i] != nil && !nodeChainAppendImportedClosure(imports[i], closure) {
				return fail(nil)
			}
			streams = append(streams, closure)
		} else if members[i].mode == "hysteria2" {
			if i == 0 && s.record.Schema != 3 || !nodeChainAppendHysteriaClosure(node, closure) {
				return fail(nil)
			}
			streams = append(streams, closure)
		} else if node == nil || !NodeChainPrefixMode(node.mode) || closure.final["type"] != nodeChainPrefixType(node.mode) {
			return fail(nil)
		} else if withStreams {
			sockets, err := node.PhysicalEgress()
			if err != nil {
				return fail(err)
			}
			for _, socket := range sockets {
				ip, err := netip.ParseAddr(socket.Host)
				if err != nil || ip.Zone() != "" || ip.Is4In6() || socket.Port < 1 || socket.Port > 65535 {
					return fail(err)
				}
				target := netip.AddrPortFrom(ip, uint16(socket.Port))
				if targets[target] {
					return fail(pairedStreamConflict)
				}
				targets[target] = true
			}
		}
		closures[i] = closure
	}
	if withStreams {
		if len(streams) == 0 {
			return fail(nil)
		}
		if err := s.validateAppendProxyTargets(closures, imports, targets); err != nil {
			return fail(err)
		}
	}
	if s.record.Schema == 3 {
		if err := validateNodeChainCapturedTransportKeys(closures); err != nil {
			return fail(err)
		}
	} else if err := validateNodeChainAppendHybridKeys(closures); err != nil {
		return fail(err)
	}
	expected, err := nodes[0].PhysicalEgress()
	if err != nil {
		return fail(err)
	}
	var config string
	var proofs []NodeChainProof
	var physical []PhysicalEgress
	if s.record.Schema == 1 && imported == nil {
		config, proofs, _, physical, err = compileNodeChainGraph(members, closures, expected, nil, nil, nil)
	} else {
		scope := &nodeChainAppendGraphScope{owner: s, nodes: nodes, imports: imports, closures: append([]*externalPredecessor(nil), closures...)}
		config, proofs, _, physical, err = compileNodeChainGraphWithAppend(members, closures, expected, nil, nil, nil, nil, scope)
	}
	if err != nil || !nodeChainSamePhysical(physical, expected) {
		return fail(err)
	}
	return config, proofs, physical, nil
}

// Read every original transport row retained by the append source. The sets
// reject a proposed SS peer that aliases a prefix packet, SS stream or layer;
// they never grant a dialer, resolver, candidate or complete-route identity.
func (s *NodeChainCandidateAppendSource) streamCandidateAliases() (map[string]bool, map[string]bool, error) {
	rows, err := candidatePrefixClosure(s.config, s.proofs)
	if err != nil {
		return nil, nil, err
	}
	keys, addresses := map[string]bool{}, map[string]bool{}
	rememberKey := func(value string) bool {
		if value == "" {
			return true
		}
		raw, err := base64.StdEncoding.DecodeString(value)
		defer clear(raw)
		if err != nil || len(raw) != 32 {
			return false
		}
		keys[base64.StdEncoding.EncodeToString(raw)] = true
		return true
	}
	rememberAddress := func(host string, value any) bool {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			address, err := appendHostnameAddress(host, value)
			if err != nil {
				return false
			}
			addresses[address] = true
			return true
		}
		port, ok := value.(float64)
		if ip.Zone() != "" || ip.Is4In6() || !ok || !externalPort(port) {
			return false
		}
		addresses[netip.AddrPortFrom(ip, uint16(port)).String()] = true
		return true
	}
	for label, raw := range rows {
		if !strings.HasPrefix(label, "outbounds/") && !strings.HasPrefix(label, "endpoints/") {
			continue
		}
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, nodeChainCandidateAppendError
		}
		switch predecessorText(row, "type") {
		case "shadowsocks", "routervpn-aes-xor":
			key := importedSS2022KeyIdentity(predecessorText(row, "method"), predecessorText(row, "password"))
			if key == "" || !rememberAddress(predecessorText(row, "server"), row["server_port"]) {
				return nil, nil, nodeChainCandidateAppendError
			}
			keys[key] = true
		case "hysteria2":
			captured, err := nodeChainAppendHysteriaKeys(row)
			if err != nil || !rememberAddress(predecessorText(row, "server"), row["server_port"]) {
				return nil, nil, nodeChainCandidateAppendError
			}
			for key := range captured {
				keys[key] = true
			}
		case "wireguard", AmneziaType:
			if !rememberKey(predecessorText(row, "private_key")) {
				return nil, nil, nodeChainCandidateAppendError
			}
			peers, ok := row["peers"].([]any)
			if !ok || len(peers) != 1 {
				return nil, nil, nodeChainCandidateAppendError
			}
			peer, ok := peers[0].(map[string]any)
			if !ok || !rememberKey(predecessorText(peer, "public_key")) || !rememberKey(predecessorText(peer, "pre_shared_key")) ||
				!rememberAddress(predecessorText(peer, "address"), peer["port"]) {
				return nil, nil, nodeChainCandidateAppendError
			}
		}
	}
	return keys, addresses, nil
}
