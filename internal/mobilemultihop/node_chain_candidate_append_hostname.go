package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"router-vpn/internal/hopmeasure"
)

// This append owner does not widen the complete literal-import policy seal.
// A hostname keeps its exact original capture object and no ExternalPolicy.
type nodeChainAppendImportedSeal struct {
	self                                *nodeChainAppendImportedSeal
	owner                               *nodeChainImportedMember
	literal                             *nodeChainMultipleImportedMemberSeal
	hostname                            *nodeChainImportedHostname
	input, source, seal, hostnameConfig string
}

func rememberAppendImportedMember(member *nodeChainImportedMember) (*nodeChainAppendImportedSeal, error) {
	if member == nil || member.validate() != nil {
		return nil, nodeChainCandidateAppendError
	}
	if member.hostname == nil {
		if err := member.rememberMultipleImportedMember(); err != nil {
			return nil, err
		}
	} else if member.multipleSeal != nil || member.policy != nil || member.policyOwner != nil || member.policySeal != "" {
		return nil, nodeChainCandidateAppendError
	}
	original := &nodeChainAppendImportedSeal{owner: member, literal: member.multipleSeal, hostname: member.hostname, input: member.input, source: member.source, seal: member.seal}
	original.self = original
	if member.hostname != nil {
		original.hostnameConfig = member.hostname.Config
	}
	return original, nil
}

func (s *nodeChainAppendImportedSeal) matches(member *nodeChainImportedMember) bool {
	if s == nil || s.self != s || member == nil || s.owner != member || s.input != member.input || s.source != member.source || s.seal != member.seal || member.validate() != nil {
		return false
	}
	if s.hostname != nil {
		return member.hostname == s.hostname && member.hostname.Config == s.hostnameConfig && member.multipleSeal == nil && s.literal == nil
	}
	return member.hostname == nil && s.literal != nil && member.multipleSeal == s.literal && s.literal.matches(member)
}

func nodeChainAppendImportCaptured(member *nodeChainImportedMember) bool {
	if member == nil || member.validate() != nil {
		return false
	}
	if member.hostname != nil {
		return member.multipleSeal == nil && member.policy == nil && member.policyOwner == nil && member.policySeal == ""
	}
	return member.multipleSeal != nil && member.multipleSeal.matches(member)
}

// Hostnames remain original imported sources. This append-only check reuses
// their strict saved Custom TCP DNS capture without granting a complete route.
func nodeChainAppendImportedClosure(member *nodeChainImportedMember, closure *externalPredecessor) bool {
	if member == nil || member.validate() != nil || closure == nil {
		return false
	}
	if member.hostname == nil {
		return nodeChainAppendSSClosure(closure)
	}
	original, err := member.closure()
	return err == nil && original != nil && len(closure.nodes) == 1 && len(closure.resolvers) == 1 &&
		reflect.DeepEqual(closure.graph, original.graph) && externalDNSHostname(predecessorText(closure.final, "server"))
}

func appendHostnameAddress(host string, port any) (string, error) {
	number, ok := port.(float64)
	if !ok || !externalPort(number) || !externalDNSHostname(host) || strings.HasSuffix(host, ".") {
		return "", nodeChainCandidateAppendError
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(int(number))), nil
}

func appendHostnameExclusions(targets map[netip.AddrPort]bool, port uint16) []string {
	excluded := []string{}
	seen := map[string]bool{}
	for target := range targets {
		if target.Port() == port && !seen[target.Addr().String()] {
			seen[target.Addr().String()] = true
			excluded = append(excluded, target.Addr().String())
		}
	}
	slices.Sort(excluded)
	return excluded
}

func appendHostnameExcludedRow(out map[string]any) ([]string, error) {
	raw, exists := out[nodeChainOriginalPeerExclusions]
	if !exists {
		return nil, nodeChainCandidateAppendError
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var excluded []string
	if json.Unmarshal(encoded, &excluded) != nil || excluded == nil {
		return nil, nodeChainCandidateAppendError
	}
	seen := map[string]bool{}
	for _, value := range excluded {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.String() != value || ip.Zone() != "" || ip.Is4In6() || seen[value] {
			return nil, nodeChainCandidateAppendError
		}
		seen[value] = true
	}
	return excluded, nil
}

// Retain every original hostname guard exactly in a prospective compilation.
// Newly proposed aliases are checked by the preparation's captured DNS owner,
// not by rewriting an already captured prefix transport.
func (s *NodeChainCandidateAppendSource) validateAppendProxyTargets(closures []*externalPredecessor, imports []*nodeChainImportedMember, targets map[netip.AddrPort]bool) error {
	if len(closures) != len(imports) {
		return nodeChainCandidateAppendError
	}
	var literal []*externalPredecessor
	hostnames := map[string]bool{}
	keys := map[string]bool{}
	for i, closure := range closures {
		if closure == nil || closure.final == nil {
			return nodeChainCandidateAppendError
		}
		mode := predecessorText(closure.final, "type")
		if mode != "shadowsocks" && mode != "hysteria2" {
			continue
		}
		if mode == "shadowsocks" {
			key := importedSS2022KeyIdentity(predecessorText(closure.final, "method"), predecessorText(closure.final, "password"))
			if key == "" || keys[key] {
				return pairedStreamConflict
			}
			keys[key] = true
		}
		if imports[i] != nil && imports[i].hostname != nil {
			if !nodeChainAppendImportedClosure(imports[i], closure) {
				return nodeChainCandidateAppendError
			}
			address, err := appendHostnameAddress(predecessorText(closure.final, "server"), closure.final["server_port"])
			if err != nil || hostnames[address] {
				return pairedStreamConflict
			}
			hostnames[address] = true
		} else {
			literal = append(literal, closure)
		}
	}
	if err := validateNodeChainAppendProxyTargets(literal, targets); err != nil {
		return err
	}
	var original map[string]any
	if s.config != "" {
		rows, err := candidatePrefixClosure(s.config, s.proofs)
		if err != nil {
			return err
		}
		original = rows
	}
	for i, member := range imports {
		if member == nil || member.hostname == nil {
			continue
		}
		out := closures[i].final
		port, ok := out["server_port"].(float64)
		if !ok || !externalPort(port) {
			return nodeChainCandidateAppendError
		}
		excluded := appendHostnameExclusions(targets, uint16(port))
		if i < len(s.proofs) && original != nil {
			row, ok := original["outbounds/"+s.proofs[i].Tag].(map[string]any)
			if !ok {
				return nodeChainCandidateAppendError
			}
			var err error
			excluded, err = appendHostnameExcludedRow(row)
			if err != nil {
				return err
			}
		}
		out[nodeChainOriginalPeerExclusions] = excluded
	}
	return nil
}

func (s *NodeChainCandidateAppendSource) appendPublicCandidateMember(member *nodeChainImportedMember) (candidatePublicResponseSource, error) {
	if member == nil || member.validate() != nil {
		return candidatePublicResponseSource{}, nodeChainCandidateAppendError
	}
	if member.hostname == nil {
		return publicCandidateMember(member)
	}
	if !externalPublicIP(member.selection.ExpectedPublicIP) {
		return candidatePublicResponseSource{}, nodeChainCandidateAppendError
	}
	closure, err := member.closure()
	if err != nil || !nodeChainAppendImportedClosure(member, closure) {
		return candidatePublicResponseSource{}, nodeChainCandidateAppendError
	}
	out := closure.final
	address, err := appendHostnameAddress(predecessorText(out, "server"), out["server_port"])
	key := importedSS2022KeyIdentity(predecessorText(out, "method"), predecessorText(out, "password"))
	if err != nil || key == "" {
		return candidatePublicResponseSource{}, nodeChainCandidateAppendError
	}
	tag := nodeChainNamespace(len(s.nodes), member.source, "dns", nodeChainImportedResolver)
	resolver := predecessorCopy(closure.resolvers[nodeChainImportedResolver])
	if resolver == nil || resolver["type"] != "tcp" {
		return candidatePublicResponseSource{}, nodeChainCandidateAppendError
	}
	resolver["tag"], resolver["detour"] = tag, s.proofs[len(s.proofs)-1].Tag
	query, ok := out["domain_resolver"].(map[string]any)
	if !ok {
		return candidatePublicResponseSource{}, nodeChainCandidateAppendError
	}
	query = predecessorCopy(query)
	query["server"] = tag
	resolverJSON, err := json.Marshal(resolver)
	if err != nil {
		return candidatePublicResponseSource{}, err
	}
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return candidatePublicResponseSource{}, err
	}
	return candidatePublicResponseSource{
		Target:     hopmeasure.CandidateTarget{ID: member.id(), SourceSHA256: member.source, Address: address},
		ExpectedIP: member.selection.ExpectedPublicIP, Method: predecessorText(out, "method"), Password: predecessorText(out, "password"), keyIdentity: key,
		appendResolver: string(resolverJSON), appendQuery: string(queryJSON),
	}, nil
}

func (s *NodeChainCandidateAppendSource) appendHostnameCandidateOut(closure *externalPredecessor, proof NodeChainProof) (map[string]any, error) {
	want := predecessorCopy(closure.final)
	want["tag"], want["detour"] = proof.Tag, s.proofs[len(s.proofs)-1].Tag
	names := map[string]string{nodeChainImportedResolver: nodeChainNamespace(len(s.nodes), proof.SourceSHA256, "dns", nodeChainImportedResolver)}
	if err := predecessorRelabelResolver(want, names); err != nil {
		return nil, err
	}
	targets, err := s.appendOriginalProxyTargets()
	if err != nil {
		return nil, err
	}
	port, ok := want["server_port"].(float64)
	if !ok || !externalPort(port) {
		return nil, nodeChainCandidateAppendError
	}
	excluded := appendHostnameExclusions(targets, uint16(port))
	values := make([]any, len(excluded))
	for i, value := range excluded {
		values[i] = value
	}
	want[nodeChainOriginalPeerExclusions] = values
	return want, nil
}

func (p *NodeChainCandidatePlan) appendPreparationConfig() (string, error) {
	if p.validateAppend() != nil {
		return "", nodeChainCandidateAppendError
	}
	var added []any
	for _, response := range p.publicResponses {
		if response.appendResolver == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(response.appendResolver), &row) != nil || row["type"] != "tcp" || row["detour"] != p.prefix.Tag {
			return "", nodeChainCandidateAppendError
		}
		added = append(added, row)
	}
	if len(added) == 0 {
		return p.appendSource.config, nil
	}
	var graph map[string]any
	if json.Unmarshal([]byte(p.appendSource.config), &graph) != nil {
		return "", nodeChainCandidateAppendError
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok {
		return "", nodeChainCandidateAppendError
	}
	servers, ok := dns["servers"].([]any)
	if !ok {
		return "", nodeChainCandidateAppendError
	}
	tags := map[string]bool{}
	for _, raw := range servers {
		row, ok := raw.(map[string]any)
		if !ok || predecessorText(row, "tag") == "" || tags[predecessorText(row, "tag")] {
			return "", nodeChainCandidateAppendError
		}
		tags[predecessorText(row, "tag")] = true
	}
	for _, raw := range added {
		row := raw.(map[string]any)
		tag := predecessorText(row, "tag")
		if tag == "" || tags[tag] {
			return "", nodeChainCandidateAppendError
		}
		tags[tag] = true
		servers = append(servers, row)
	}
	dns["servers"] = servers
	encoded, err := json.Marshal(graph)
	if err != nil || len(encoded) > 4<<20 {
		return "", nodeChainCandidateAppendError
	}
	original, err := candidatePrefixClosure(p.appendSource.config, p.appendSource.proofs)
	if err != nil {
		return "", err
	}
	retained, err := candidatePrefixClosure(string(encoded), p.appendSource.proofs)
	if err != nil || !reflect.DeepEqual(original, retained) {
		return "", nodeChainCandidateAppendError
	}
	return string(encoded), nil
}

// Descriptive construction input for the original native preparation only.
// No address is a route, candidate, resolver or measurement capability by itself.
type NodeChainAppendHostnameTarget struct {
	Address, PrefixTag, ResolverTag, Query string
	Candidate                              bool
	Exclusions                             []string
}
type NodeChainAppendHostnamePolicy struct {
	Targets        []NodeChainAppendHostnameTarget
	LiteralTargets []string
}

func (p *NodeChainCandidatePreparation) AppendHostnamePolicy() (NodeChainAppendHostnamePolicy, error) {
	var policy NodeChainAppendHostnamePolicy
	if p == nil || p.validate() != nil {
		return policy, nodeChainCandidateAppendError
	}
	if p.appendSource == nil {
		return policy, nil
	}
	s := p.appendSource
	hasHostname := false
	for _, member := range s.imports {
		if member != nil && member.hostname != nil {
			hasHostname = true
		}
	}
	for _, response := range p.candidates.publicResponses {
		if response.appendResolver != "" {
			hasHostname = true
		}
	}
	if !hasHostname {
		return policy, nil
	}
	rows, err := candidatePrefixClosure(s.config, s.proofs)
	if err != nil {
		return policy, err
	}
	for position, member := range s.imports {
		if member == nil || member.hostname == nil {
			continue
		}
		if position == 0 {
			return policy, nodeChainCandidateAppendError
		}
		row, ok := rows["outbounds/"+s.proofs[position].Tag].(map[string]any)
		if !ok {
			return policy, nodeChainCandidateAppendError
		}
		address, err := appendHostnameAddress(predecessorText(row, "server"), row["server_port"])
		if err != nil {
			return policy, err
		}
		query, ok := row["domain_resolver"].(map[string]any)
		if !ok {
			return policy, nodeChainCandidateAppendError
		}
		excluded, err := appendHostnameExcludedRow(row)
		if err != nil {
			return policy, err
		}
		raw, err := json.Marshal(query)
		if err != nil {
			return policy, err
		}
		policy.Targets = append(policy.Targets, NodeChainAppendHostnameTarget{Address: address, PrefixTag: s.proofs[position-1].Tag, ResolverTag: predecessorText(query, "server"), Query: string(raw), Exclusions: excluded})
	}
	_, addresses, err := s.streamCandidateAliases()
	if err != nil {
		return policy, err
	}
	for _, target := range p.candidates.targets {
		addresses[target.Address] = true
	}
	for address := range addresses {
		if target, err := netip.ParseAddrPort(address); err == nil {
			policy.LiteralTargets = append(policy.LiteralTargets, target.String())
		}
	}
	slices.Sort(policy.LiteralTargets)
	originalTargets, err := s.appendOriginalProxyTargets()
	if err != nil {
		return policy, err
	}
	for _, response := range p.candidates.publicResponses {
		if response.appendResolver == "" {
			continue
		}
		var query map[string]any
		if json.Unmarshal([]byte(response.appendQuery), &query) != nil {
			return policy, nodeChainCandidateAppendError
		}
		_, port, err := net.SplitHostPort(response.Target.Address)
		number, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || number < 1 || number > 65535 {
			return policy, nodeChainCandidateAppendError
		}
		policy.Targets = append(policy.Targets, NodeChainAppendHostnameTarget{Address: response.Target.Address, PrefixTag: p.candidates.prefix.Tag, ResolverTag: predecessorText(query, "server"), Query: response.appendQuery, Candidate: true, Exclusions: appendHostnameExclusions(originalTargets, uint16(number))})
	}
	return policy, nil
}

func (p *NodeChainCandidatePlan) AppendPublicResponseCandidateTarget(position int, id, tag string, target hopmeasure.CandidateTarget) bool {
	if p.AppendPublicResponseCandidateDepth(position, id, tag) == 0 {
		return false
	}
	for _, source := range p.publicResponses {
		if source.Target == target && source.appendResolver != "" && source.appendQuery != "" {
			return true
		}
	}
	return false
}

// DNS admission is synchronous inside the original Start lifetime. A copied
// source or a generic owner cannot authorize a prepared hostname inventory.
type nodeChainAppendHostnameOwner interface {
	PrepareAppendHostnameContext(context.Context, *NodeChainCandidatePreparation) error
}

func (r *NodeChainCandidatePreparationRuntime) prepareAppendHostnames(ctx context.Context) error {
	policy, err := r.preparation.AppendHostnamePolicy()
	if err != nil || len(policy.Targets) == 0 {
		return err
	}
	owner, ok := r.owner.(nodeChainAppendHostnameOwner)
	if !ok {
		return errors.New("hostname append requires its original native captured resolver owner")
	}
	if err := owner.PrepareAppendHostnameContext(ctx, r.preparation); err != nil {
		return err
	}
	return r.nativeCurrent(ctx)
}

// Bind conservative envelope arithmetic to the exact retained hostname query.
// The original compiler produced these tags; no caller-provided family or
// fabricated endpoint can replace the captured resolver policy.
func (s *NodeChainCandidateAppendSource) appendHostnameFamilies(config string, proofs []NodeChainProof) (map[string]bool, error) {
	if s.memberCapturesCurrent() != nil || len(proofs) < len(s.nodes) {
		return nil, nodeChainCandidateAppendError
	}
	families := map[string]bool{}
	var rows map[string]any
	for position, member := range s.imports {
		if member == nil || member.hostname == nil {
			continue
		}
		if position == 0 || proofs[position].SourceSHA256 != member.source || proofs[position].ProfileID != member.id() {
			return nil, nodeChainCandidateAppendError
		}
		if rows == nil {
			var err error
			rows, err = candidatePrefixClosure(config, proofs)
			if err != nil {
				return nil, err
			}
		}
		out, ok := rows["outbounds/"+proofs[position].Tag].(map[string]any)
		if !ok {
			return nil, nodeChainCandidateAppendError
		}
		closure, err := member.closure()
		if err != nil || predecessorText(out, "server") != predecessorText(closure.final, "server") {
			return nil, nodeChainCandidateAppendError
		}
		query, ok := out["domain_resolver"].(map[string]any)
		original, originalOK := closure.final["domain_resolver"].(map[string]any)
		resolver := nodeChainNamespace(position, member.source, "dns", nodeChainImportedResolver)
		if !ok || !originalOK {
			return nil, nodeChainCandidateAppendError
		}
		expected := predecessorCopy(original)
		expected["server"] = resolver
		if !reflect.DeepEqual(query, expected) {
			return nil, nodeChainCandidateAppendError
		}
		onlyIPv4 := predecessorText(query, "strategy") == "ipv4_only"
		if onlyIPv4 != (member.hostname.Device.IPv6Mode == "off") {
			return nil, nodeChainCandidateAppendError
		}
		families[proofs[position].Tag] = onlyIPv4
	}
	return families, nil
}

// These are exactly the targets used by the original graph compiler's peer
// exclusions. Native admission additionally checks every captured inner/layer
// endpoint from streamCandidateAliases without rewriting the prefix closure.
func (s *NodeChainCandidateAppendSource) appendOriginalProxyTargets() (map[netip.AddrPort]bool, error) {
	targets := map[netip.AddrPort]bool{}
	for position, node := range s.nodes {
		if node != nil && NodeChainPrefixMode(node.mode) {
			physical, err := node.PhysicalEgress()
			if err != nil {
				return nil, err
			}
			for _, socket := range physical {
				ip, err := netip.ParseAddr(socket.Host)
				if err != nil || socket.Port < 1 || socket.Port > 65535 {
					return nil, nodeChainCandidateAppendError
				}
				targets[netip.AddrPortFrom(ip, uint16(socket.Port))] = true
			}
			continue
		}
		var closure *externalPredecessor
		var err error
		if member := s.imports[position]; member != nil {
			if member.hostname != nil {
				continue
			}
			closure, err = member.closure()
		} else {
			closure, err = nodeMultihopPredecessor(node)
		}
		if err != nil || closure == nil || closure.final == nil {
			return nil, nodeChainCandidateAppendError
		}
		ip, err := netip.ParseAddr(predecessorText(closure.final, "server"))
		port, ok := closure.final["server_port"].(float64)
		if err != nil || !ok || !externalPort(port) {
			return nil, nodeChainCandidateAppendError
		}
		targets[netip.AddrPortFrom(ip, uint16(port))] = true
	}
	return targets, nil
}
