package mobilemultihop

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"

	"router-vpn/internal/multihoprelay"
)

// The registered worker receives independently imported suffix transports and
// the original resolver tree. The paired client entry exists only in the
// administrator's transient plan and in the client's Local capture.
type nodeChainExternalFinalServerSource struct {
	Schema            int                                         `json:"schema"`
	EntryID           string                                      `json:"entry_id"`
	EntryNodeID       string                                      `json:"entry_node_id"`
	EntryMode         string                                      `json:"entry_mode"`
	ExternalFinal     multihoprelay.NodeChainExternalFinalBinding `json:"external_final"`
	Nodes             []string                                    `json:"nodes"`
	DNSPolicy         json.RawMessage                             `json:"dns_policy"`
	EntryBlockIPv6    bool                                        `json:"entry_block_ipv6"`
	EntryBlockedCIDRs []string                                    `json:"entry_blocked_cidrs"`
}

// All of these objects have already passed their original constructors. Keep
// numbers lossless and asset contents exact while normalizing object key order
// and JSON escaping across administrator, desktop and mobile encoders.
func externalFinalSourceObject(raw string) (map[string]any, error) {
	if raw == "" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, nodeChainServerPlanError
	}
	return object, nil
}

func externalFinalOriginalEntry(c *NodeChain) (string, error) {
	if !c.HasExternalFinal() || c.validateCapture() != nil {
		return "", nodeChainServerPlanError
	}
	var source NodeChainSource
	if err := json.Unmarshal([]byte(c.sourceJSON), &source); err != nil || len(source.IdentitySources) != len(c.proofs) || source.IdentitySources[0] == "" {
		return "", nodeChainServerPlanError
	}
	entry := c.nodes[0].inputs
	binding := []any{"routervpn-external-final-paired-entry-v1", entry.Mode}
	for _, raw := range []string{entry.ProfileJSON, entry.Files, entry.Start, entry.DNSBootstrap, source.IdentitySources[0]} {
		obj, err := externalFinalSourceObject(raw)
		if err != nil {
			return "", err
		}
		binding = append(binding, obj)
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	return externalDigest(raw), nil
}

// Desktop and mobile can order JSON object fields differently. Bind every
// original paired input value while retaining the user's exact saved launch
// separately for Local proofs, replay, and inventory. Nested asset strings
// remain byte-for-byte values. The predecessor graph is itself a JSON object.
func externalFinalOriginalCapture(m *nodeChainImportedMember) (string, error) {
	if m == nil || m.validate() != nil {
		return "", nodeChainServerPlanError
	}
	var record nodeChainImportedInput
	if exactJSON([]byte(m.input), &record, NodeChainInputLimit) != nil || record.Kind != externalFinalInputKind {
		return "", nodeChainServerPlanError
	}
	config, err := externalFinalSourceObject(record.Config)
	if err != nil || config == nil {
		return "", nodeChainServerPlanError
	}
	capture, err := externalFinalSourceObject(record.Capture)
	if err != nil || capture == nil {
		return "", nodeChainServerPlanError
	}
	predecessor, ok := capture["predecessor_config"].(string)
	if !ok || predecessor == "" {
		return "", nodeChainServerPlanError
	}
	capture["predecessor_config"], err = externalFinalSourceObject(predecessor)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal([]any{"routervpn-external-final-local-capture-v1", record.Kind, record.Schema, config, capture})
	if err != nil {
		return "", err
	}
	defer clear(raw)
	return externalDigest(raw), nil
}

// Both the original paired-final input and the independent registered stream
// must prove the same transport without publishing its private cipher key.
func externalFinalStreamCommitment(m *nodeChainImportedMember) (string, error) {
	s, err := publicCandidateMember(m)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal([]string{"routervpn-external-final-stream-v1", s.Target.ID, s.ExpectedIP, s.Target.Address, s.Method, s.keyIdentity})
	if err != nil {
		return "", err
	}
	return externalDigest(raw), nil
}

func NewNodeChainExternalFinalServerPlan(input string) (*NodeChainServerPolicy, error) {
	var plan map[string]any
	if exactJSON([]byte(input), &plan, NodeChainInputLimit) != nil || !nodeChainPlanKeys(plan, []string{"schema", "entry_node_id", "entry", "members"}, nil) || plan["schema"] != float64(8) {
		return nil, nodeChainServerPlanError
	}
	selected, ok := plan["entry"].(map[string]any)
	if !ok {
		return nil, nodeChainServerPlanError
	}
	entry, err := nodeChainPlanCapture(selected)
	if err != nil || !NodeChainPrefixMode(entry.mode) || plan["entry_node_id"] != entry.profile["node_proof_id"] {
		return nil, nodeChainServerPlanError
	}
	rows, ok := plan["members"].([]any)
	if !ok || len(rows) < 2 || len(rows) >= NodeChainExtendedLocalMaximumNodes {
		return nil, nodeChainServerPlanError
	}
	entryInput, err := entry.node.LaunchInput()
	if err != nil {
		return nil, err
	}
	local := NodeChainSource{Schema: 8, Execution: "local", Nodes: []string{entryInput}, IdentitySources: []string{entry.identity}}
	source := nodeChainExternalFinalServerSource{Schema: 8, EntryID: predecessorText(entry.profile, "id"), EntryNodeID: predecessorText(entry.profile, "node_proof_id"), EntryMode: entry.mode}
	for i, raw := range rows {
		role := "imported"
		if i == len(rows)-1 {
			role = "external_final"
		}
		row, ok := raw.(map[string]any)
		if !ok || !nodeChainPlanKeys(row, []string{role}, nil) {
			return nil, nodeChainServerPlanError
		}
		imported, ok := row[role].(map[string]any)
		if !ok || !nodeChainPlanKeys(imported, []string{"config", "capture"}, nil) {
			return nil, nodeChainServerPlanError
		}
		config, configOK := imported["config"].(string)
		capture, captureOK := imported["capture"].(string)
		if !configOK || !captureOK {
			return nil, nodeChainServerPlanError
		}
		member, err := NodeChainImportedMemberInput(config, capture)
		if err != nil {
			return nil, err
		}
		source.Nodes = append(source.Nodes, member)
		if role == "external_final" {
			member, err = NodeChainExternalFinalFromEntry(entryInput, member)
			if err != nil {
				return nil, err
			}
		}
		local.Nodes = append(local.Nodes, member)
		local.IdentitySources = append(local.IdentitySources, "")
	}
	raw, err := json.Marshal(local)
	if err != nil {
		return nil, err
	}
	original, err := NewNodeChain(string(raw))
	clear(raw)
	if err != nil || !original.HasExternalFinal() {
		return nil, nodeChainServerPlanError
	}
	last := len(original.proofs) - 1
	pair := original.importedNodes.members[last]
	transport, err := externalFinalStreamCommitment(pair)
	if err != nil {
		return nil, err
	}
	// Include the original aggregate IPv6 policy when closing over DNS. A
	// blocked IPv6 family in an intermediate cannot disappear at the worker.
	profiles := []map[string]any{entry.profile}
	for _, m := range original.importedNodes.members[1:] {
		profiles = append(profiles, m.selection.Profile)
	}
	ipv6, _, err := externalDevicePolicy(profiles...)
	if err != nil {
		return nil, err
	}
	dns, selectedDNS, err := externalSelectedDNS(pair.selection, ipv6, true)
	if err != nil {
		return nil, err
	}
	source.DNSPolicy, err = json.Marshal(dns)
	if err != nil {
		return nil, err
	}
	entryIPv6, blocked, err := externalDevicePolicy(entry.profile)
	if err != nil {
		return nil, err
	}
	source.EntryBlockIPv6, source.EntryBlockedCIDRs = entryIPv6 == "off", blocked
	public, err := original.nodes[0].PacketClientPublicKey()
	if err != nil {
		return nil, err
	}
	peers, err := externalFinalPacketPeerAddresses(original.nodes[0])
	if err != nil {
		return nil, err
	}
	first := original.proofs[0]
	entryDigest, err := externalFinalOriginalEntry(original)
	if err != nil {
		return nil, err
	}
	localFinal, err := externalFinalOriginalCapture(pair)
	if err != nil {
		return nil, err
	}
	source.ExternalFinal = multihoprelay.NodeChainExternalFinalBinding{FinalTransportSHA256: transport, EntrySourceSHA256: entryDigest, EntryStartLayer: first.StartLayer, EntryClientPublicKey: public, EntryPeerAddresses: peers, DNSOwner: "external-final", LocalFinalSourceSHA256: localFinal}
	if selectedDNS.mode == "home" {
		source.ExternalFinal.DNSOwner = "entry-home"
	}
	raw, err = json.Marshal(source)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return NewNodeChainExternalFinalServerPolicy(string(raw))
}

func externalFinalPacketPeerAddresses(entry *NodeProfile) ([]string, error) {
	closure, err := nodeMultihopPredecessor(entry)
	if err != nil {
		return nil, err
	}
	rows, ok := closure.final["address"].([]any)
	if !ok || len(rows) == 0 || len(rows) > 64 {
		return nil, nodeChainServerPlanError
	}
	peers := make([]string, 0, len(rows))
	for _, row := range rows {
		text, ok := row.(string)
		prefix, err := netip.ParsePrefix(text)
		if !ok || err != nil || prefix.String() != text || !prefix.Addr().IsPrivate() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, nodeChainServerPlanError
		}
		peers = append(peers, prefix.Addr().String())
	}
	sort.Strings(peers)
	for i := 1; i < len(peers); i++ {
		if peers[i] == peers[i-1] {
			return nil, nodeChainServerPlanError
		}
	}
	return peers, nil
}
