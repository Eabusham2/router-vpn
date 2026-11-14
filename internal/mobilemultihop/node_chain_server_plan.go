package mobilemultihop

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"

	"router-vpn/internal/multihoprelay"
)

// A plan is private administrator input. It resolves complete selected bundle
// members through the original node compilers; it grants no registry, lease,
// listener or network authority. Each paired suffix needs an independently
// provisioned server bundle, including the final SS member's WG identity asset.
// No private key is generated or copied from a Local packet source into Server.
var nodeChainServerPlanError = errors.New("invalid private ordered server bundle plan")

type nodeChainPlanNode struct {
	node            *NodeProfile
	identity        string
	identityKey     string
	identityRemote  string
	profile         map[string]any
	bundle          map[string]any
	mode, bootstrap string
}

// NewNodeChainServerPlan accepts schema 1 with entry_node_id, an explicit
// entry {bundle,profile_id,mode[,dns_bootstrap]}, and ordered members. A member
// is either {paired:{bundle,profile_id,mode[,dns_bootstrap]},server_peer:
// {bundle,profile_id}} or {imported:{config,capture}}. Imported strings are the
// original captured bytes, never a reconstructed semantically similar source.
func NewNodeChainServerPlan(input string) (*NodeChainServerPolicy, error) {
	bad := nodeChainServerPlanError
	var plan map[string]any
	if exactJSON([]byte(input), &plan, NodeChainInputLimit) != nil || !nodeChainPlanKeys(plan, []string{"schema", "entry_node_id", "entry", "members"}, nil) || plan["schema"] != float64(1) {
		return nil, bad
	}
	entryNode, ok := plan["entry_node_id"].(string)
	entryRaw, entryOK := plan["entry"].(map[string]any)
	rows, rowsOK := plan["members"].([]any)
	if !ok || !proofID.MatchString(entryNode) || !entryOK || !rowsOK || len(rows) < 1 || len(rows) > multihoprelay.NodeChainMaximumMembers {
		return nil, bad
	}
	entry, err := nodeChainPlanCapture(entryRaw)
	if err != nil || !NodeChainPrefixMode(entry.mode) || predecessorText(entry.profile, "node_proof_id") != entryNode {
		return nil, bad
	}
	entryInput, err := entry.node.LaunchInput()
	if err != nil {
		return nil, bad
	}
	local := NodeChainSource{Schema: 1, Execution: "local", Nodes: []string{entryInput}, IdentitySources: []string{entry.identity}}
	source := NodeChainServerSource{Schema: 1, EntryID: predecessorText(entry.profile, "id"), EntryNodeID: entryNode, EntryMode: entry.mode}
	localKeys := map[string]bool{entry.identityKey: true}
	entryKey, err := entry.node.PacketClientPublicKey()
	if err != nil {
		return nil, bad
	}
	localKeys[entryKey] = true
	remoteKeys := map[string]bool{entry.identityRemote: true}
	if !nodeChainPlanRememberRemote(entry.node, remoteKeys) {
		return nil, bad
	}
	serverKeys := map[string]bool{}
	for position, row := range rows {
		member, ok := row.(map[string]any)
		if !ok {
			return nil, bad
		}
		if nodeChainPlanKeys(member, []string{"imported"}, nil) {
			imported, ok := member["imported"].(map[string]any)
			if !ok || position != 0 || len(rows) != 2 || !nodeChainPlanKeys(imported, []string{"config", "capture"}, nil) {
				return nil, bad
			}
			config, configOK := imported["config"].(string)
			capture, captureOK := imported["capture"].(string)
			if !configOK || !captureOK {
				return nil, bad
			}
			original, err := NodeChainImportedMemberInput(config, capture)
			if err != nil {
				return nil, bad
			}
			local.Schema, source.Schema = 2, 2
			local.Nodes, source.Nodes = append(local.Nodes, original), append(source.Nodes, original)
			local.IdentitySources, source.IdentitySources = append(local.IdentitySources, ""), append(source.IdentitySources, "")
			continue
		}
		if !nodeChainPlanKeys(member, []string{"paired", "server_peer"}, nil) {
			return nil, bad
		}
		pairedRaw, pairedOK := member["paired"].(map[string]any)
		peerRaw, peerOK := member["server_peer"].(map[string]any)
		if !pairedOK || !peerOK || !nodeChainPlanKeys(peerRaw, []string{"bundle", "profile_id"}, nil) {
			return nil, bad
		}
		paired, err := nodeChainPlanCapture(pairedRaw)
		if err != nil || position == len(rows)-1 && paired.mode != "shadowsocks" || position < len(rows)-1 && !NodeChainPrefixMode(paired.mode) {
			return nil, bad
		}
		peerBundle, peerProfile, err := nodeChainPlanSelectedBundle(peerRaw["bundle"], peerRaw["profile_id"])
		if err != nil {
			return nil, bad
		}
		// The independently selected bundle must name this same actual node.
		// Its UI defaults never replace the captured Local policy or credentials.
		for _, key := range []string{"node_proof_id", "endpoint", "router_api"} {
			if !reflect.DeepEqual(paired.profile[key], peerProfile[key]) {
				return nil, bad
			}
		}
		server, err := nodeChainPlanNodeFromBundle(peerBundle, paired.profile, paired.mode, paired.bootstrap)
		if err != nil || paired.identityKey == server.identityKey || !nodeChainPlanTransportEqual(paired.node, server.node) {
			return nil, bad
		}
		localKeys[paired.identityKey] = true
		remoteKeys[paired.identityRemote] = true
		if !nodeChainPlanRememberRemote(paired.node, remoteKeys) {
			return nil, bad
		}
		if serverKeys[server.identityKey] {
			return nil, bad
		}
		serverKeys[server.identityKey] = true
		if NodeChainPrefixMode(paired.mode) {
			localKey, localErr := paired.node.PacketClientPublicKey()
			serverKey, serverErr := server.node.PacketClientPublicKey()
			if localErr != nil || serverErr != nil || localKey == serverKey || serverKeys[serverKey] && serverKey != server.identityKey {
				return nil, bad
			}
			localKeys[localKey], serverKeys[serverKey] = true, true
		}
		localInput, localErr := paired.node.LaunchInput()
		serverInput, serverErr := server.node.LaunchInput()
		if localErr != nil || serverErr != nil {
			return nil, bad
		}
		local.Nodes, source.Nodes = append(local.Nodes, localInput), append(source.Nodes, serverInput)
		local.IdentitySources, source.IdentitySources = append(local.IdentitySources, paired.identity), append(source.IdentitySources, server.identity)
	}
	for key := range serverKeys {
		if localKeys[key] || remoteKeys[key] {
			return nil, bad
		}
	}
	for key := range localKeys {
		if remoteKeys[key] {
			return nil, bad
		}
	}
	localJSON, err := json.Marshal(local)
	if err != nil {
		return nil, bad
	}
	defer clear(localJSON)
	if _, err := NewNodeChain(string(localJSON)); err != nil {
		return nil, bad
	}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > NodeChainInputLimit {
		return nil, bad
	}
	defer clear(raw)
	policy, err := NewNodeChainServerPolicy(string(raw))
	if err != nil {
		return nil, bad
	}
	return policy, nil
}

func nodeChainPlanKeys(value map[string]any, required, optional []string) bool {
	if value == nil || len(value) < len(required) || len(value) > len(required)+len(optional) {
		return false
	}
	allowed := map[string]bool{}
	for _, key := range required {
		if _, ok := value[key]; !ok || value[key] == nil {
			return false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, value := range value {
		if !allowed[key] || value == nil {
			return false
		}
	}
	return true
}

func nodeChainPlanCapture(selection map[string]any) (*nodeChainPlanNode, error) {
	bad := nodeChainServerPlanError
	if !nodeChainPlanKeys(selection, []string{"bundle", "profile_id", "mode"}, []string{"dns_bootstrap"}) {
		return nil, bad
	}
	mode, modeOK := selection["mode"].(string)
	if !modeOK || !NodeChainPrefixMode(mode) && mode != "shadowsocks" {
		return nil, bad
	}
	bundle, profile, err := nodeChainPlanSelectedBundle(selection["bundle"], selection["profile_id"])
	if err != nil {
		return nil, bad
	}
	bootstrap := ""
	if value, present := selection["dns_bootstrap"]; present {
		var ok bool
		bootstrap, ok = value.(string)
		if !ok || bootstrap == "" {
			return nil, bad
		}
	}
	return nodeChainPlanNodeFromBundle(bundle, profile, mode, bootstrap)
}

func nodeChainPlanSelectedBundle(raw, selected any) (map[string]any, map[string]any, error) {
	bad := nodeChainServerPlanError
	bundle, bundleOK := raw.(map[string]any)
	id, idOK := selected.(string)
	if !bundleOK || !idOK || !exactID.MatchString(id) {
		return nil, nil, bad
	}
	profiles, ok := bundle["routerProfiles"].([]any)
	if !ok || len(profiles) == 0 || len(profiles) > 256 {
		return nil, nil, bad
	}
	var profile map[string]any
	for _, row := range profiles {
		candidate, ok := row.(map[string]any)
		if !ok {
			return nil, nil, bad
		}
		if candidate["id"] == id {
			if profile != nil {
				return nil, nil, bad
			}
			profile = candidate
		}
	}
	if profile == nil || profile["node_kind"] != "router-vpn" {
		return nil, nil, bad
	}
	if node, present := bundle["nodeProofId"]; present && node != profile["node_proof_id"] {
		return nil, nil, bad
	}
	return bundle, profile, nil
}

func nodeChainPlanNodeFromBundle(bundle, profile map[string]any, mode, bootstrap string) (*nodeChainPlanNode, error) {
	bad := nodeChainServerPlanError
	all, ok := bundle["profiles"].(map[string]any)
	if !ok {
		return nil, bad
	}
	files, filesOK := all[mode].(map[string]any)
	identity, identityOK := all["wg"].(map[string]any)
	if !filesOK || !identityOK {
		return nil, bad
	}
	filesJSON, filesErr := json.Marshal(files)
	identityJSON, identityErr := json.Marshal(identity)
	profileJSON, profileErr := json.Marshal(profile)
	if filesErr != nil || identityErr != nil || profileErr != nil {
		return nil, bad
	}
	defer clear(filesJSON)
	defer clear(identityJSON)
	defer clear(profileJSON)
	start := ""
	layer := predecessorText(profile, "start_layer")
	if layer != "" && layer != "off" && mode != "shadowsocks" {
		assets, ok := all["shadowsocks"].(map[string]any)
		if !ok {
			return nil, bad
		}
		raw, err := json.Marshal(assets)
		if err != nil {
			return nil, bad
		}
		start = string(raw)
		clear(raw)
	}
	node, err := NewNodeProfile(mode, string(filesJSON), string(profileJSON), start, bootstrap)
	if err != nil || validateNodeChainIdentity(string(identityJSON), node) != nil {
		return nil, bad
	}
	assets, err := nodeProfileAssets(string(identityJSON))
	if err != nil {
		return nil, bad
	}
	defer clearNodeChainIdentityAssets(assets)
	wgRaw, err := NativeBaseSourceForEndpoint("wg", assets, predecessorText(profile, "endpoint"))
	if err != nil {
		return nil, bad
	}
	defer clear(wgRaw)
	wg, err := parseWireGuardProfile(string(wgRaw), predecessorText(profile, "node_proof_id"))
	encoded, ok := wg.Endpoint["private_key"].(string)
	if err != nil || !ok {
		return nil, bad
	}
	private, err := base64.StdEncoding.Strict().DecodeString(encoded)
	defer clear(private)
	if err != nil || len(private) != 32 {
		return nil, bad
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, bad
	}
	peers, ok := wg.Endpoint["peers"].([]any)
	if !ok || len(peers) != 1 {
		return nil, bad
	}
	peer, ok := peers[0].(map[string]any)
	remote := predecessorText(peer, "public_key")
	public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	if !ok || !nodeChainCanonicalPeer(remote) || public == remote {
		return nil, bad
	}
	return &nodeChainPlanNode{node: node, identity: string(identityJSON), identityKey: public, identityRemote: remote,
		profile: profile, bundle: bundle, mode: mode, bootstrap: bootstrap}, nil
}

func nodeChainPlanRememberRemote(node *NodeProfile, keys map[string]bool) bool {
	if node == nil {
		return false
	}
	if node.mode == "shadowsocks" {
		return true
	}
	var graph map[string]any
	if exactJSON([]byte(node.Config()), &graph, 4<<20) != nil {
		return false
	}
	rows, ok := graph["endpoints"].([]any)
	if !ok || len(rows) != 1 {
		return false
	}
	endpoint, ok := rows[0].(map[string]any)
	if !ok {
		return false
	}
	peers, ok := endpoint["peers"].([]any)
	if !ok || len(peers) != 1 {
		return false
	}
	peer, ok := peers[0].(map[string]any)
	key := predecessorText(peer, "public_key")
	if !ok || !nodeChainCanonicalPeer(key) {
		return false
	}
	keys[key] = true
	return true
}

// Only explicit independently provisioned packet credentials/addresses may
// differ. Selected DNS, layers, remote identities, endpoint and AWG protocol
// parameters remain identical. SS keeps its complete selected transport.
func nodeChainPlanTransportEqual(local, server *NodeProfile) bool {
	if local == nil || server == nil || local.mode != server.mode {
		return false
	}
	if local.mode == "shadowsocks" {
		return local.Config() == server.Config()
	}
	var a, b map[string]any
	if exactJSON([]byte(local.Config()), &a, 4<<20) != nil || exactJSON([]byte(server.Config()), &b, 4<<20) != nil {
		return false
	}
	addresses := make([]map[netip.Addr]bool, 0, 2)
	for _, graph := range []map[string]any{a, b} {
		rows, ok := graph["endpoints"].([]any)
		if !ok || len(rows) != 1 {
			return false
		}
		endpoint, ok := rows[0].(map[string]any)
		if !ok {
			return false
		}
		rawAddresses, ok := endpoint["address"].([]any)
		if !ok || len(rawAddresses) == 0 {
			return false
		}
		captured := map[netip.Addr]bool{}
		for _, raw := range rawAddresses {
			value, ok := raw.(string)
			prefix, err := netip.ParsePrefix(value)
			if !ok || err != nil || captured[prefix.Addr()] {
				return false
			}
			captured[prefix.Addr()] = true
		}
		addresses = append(addresses, captured)
		peers, ok := endpoint["peers"].([]any)
		if !ok || len(peers) != 1 {
			return false
		}
		peer, ok := peers[0].(map[string]any)
		if !ok {
			return false
		}
		delete(endpoint, "private_key")
		delete(endpoint, "address")
		delete(peer, "pre_shared_key")
	}
	for address := range addresses[0] {
		if addresses[1][address] {
			return false
		}
	}
	return reflect.DeepEqual(a, b)
}
