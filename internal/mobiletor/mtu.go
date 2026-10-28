package mobiletor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// torMTUPreferences is copied from a complete frozen profile. It describes
// requested virtual-interface capacity, not a measured transport packet size.
type torMTUPreferences struct {
	policy string
	jumbo  bool
	fixed  int
}

func capturedTorMTUPreferences(profile map[string]any) (torMTUPreferences, error) {
	p := torMTUPreferences{policy: "default"}
	if raw, exists := profile["mtu_policy"]; exists {
		value, ok := raw.(string)
		if !ok {
			return p, errors.New("Tor interface MTU policy requires a saved string")
		}
		if value != "" {
			p.policy = value
		}
	}
	if raw, exists := profile["jumbo_tun"]; exists {
		value, ok := raw.(bool)
		if !ok {
			return p, errors.New("Tor Jumbo policy requires a saved boolean")
		}
		p.jumbo = value
	}
	switch p.policy {
	case "auto", "default":
	case "manual", "fixed":
		value, err := profileInteger(profile, "manual_mtu", 0)
		if err != nil || value < 1280 || value > 9000 {
			return p, errors.New("Native Tor interface MTU must be 1280..9000")
		}
		p.fixed = value
	default:
		return p, errors.New("Invalid captured Tor interface MTU policy")
	}
	if p.jumbo && p.fixed != 0 && p.fixed != 9000 {
		return p, errors.New("Tor Jumbo conflicts with the saved fixed MTU")
	}
	return p, nil
}

func compatibleTorMTUPreferences(exit, entry torMTUPreferences) error {
	if exit.fixed != 0 && entry.fixed != 0 && exit.fixed != entry.fixed ||
		exit.jumbo && entry.fixed != 0 && entry.fixed != 9000 ||
		entry.jumbo && exit.fixed != 0 && exit.fixed != 9000 {
		return errors.New("Tor entry and exit require conflicting settings for their single VPN interface")
	}
	return nil
}

func torMTUInterface(graph map[string]any) (map[string]any, string, int, error) {
	failure := errors.New("Tor MTU requires its single captured strict VPN interface")
	inbounds, ok := graph["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return nil, "", 0, failure
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true || !profileIdentifier.MatchString(profileString(tun, "tag")) {
		return nil, "", 0, failure
	}
	mtu, err := profileInteger(tun, "mtu", 0)
	if err != nil || mtu < 1280 || mtu > 9000 {
		return nil, "", 0, failure
	}
	return tun, profileString(tun, "tag"), mtu, nil
}

// MTUInterface identifies configured capacity only. Native adoption must match
// this exact tag and MTU to its live, captured OS reader; this is not PMTU proof
// and does not broaden the optimizer's separate transport-safe envelope.
func MTUInterface(config string) (string, int, error) {
	graph, err := profileObject(config, 4<<20)
	if err != nil {
		return "", 0, err
	}
	_, tag, mtu, err := torMTUInterface(graph)
	return tag, mtu, err
}

// The compiler binds the complete frozen profile before native construction.
// In particular, auto and default policies otherwise produce the same TUN.
// A successful proof must not authorize changing that policy after connection.
func torProfileDigest(profile map[string]any) (string, error) {
	if value, exists := profile["jumbo_tun"]; exists {
		if _, ok := value.(bool); !ok {
			return "", errors.New("Tor Jumbo policy requires a saved boolean")
		}
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		return "", errors.New("Tor frozen profile cannot be encoded")
	}
	sum := sha256.Sum256(append([]byte("routervpn-tor-profile-v1\x00"), encoded...))
	return hex.EncodeToString(sum[:]), nil
}

// MTUAuthority is consumed only after the native Box has matched config to its
// immutable construction snapshot and retained successful Tor proof. It binds
// the original policy, not a mutable UI selection or a fixed expected Tor IP.
func MTUAuthority(config, profileJSON, sessionID string) (string, error) {
	return torMTUAuthority(config, profileJSON, sessionID, nil, false)
}

// MTUAuthorityWithPredecessor retains the exact private entry already held by
// successful native proof. An inherited Jumbo or Fixed interface remains owned
// by that entry without rewriting the saved exit's Auto/Default preference.
func MTUAuthorityWithPredecessor(config, profileJSON, sessionID string, predecessor *PredecessorProof) (string, error) {
	if predecessor == nil {
		return torMTUAuthority(config, profileJSON, sessionID, nil, true)
	}
	return torMTUAuthority(config, profileJSON, sessionID, predecessor, true)
}

// MTUAuthorityWithExternalPredecessor binds the same single interface to an
// already-proved ordinary provider without manufacturing private Router proof.
func MTUAuthorityWithExternalPredecessor(config, profileJSON, sessionID string, predecessor *ExternalPredecessorProof) (string, error) {
	if predecessor == nil {
		return "", errors.New("Tor ordinary MTU requires its proved captured predecessor")
	}
	return torMTUAuthority(config, profileJSON, sessionID, predecessor, true)
}

func torMTUAuthority(config, profileJSON, sessionID string, predecessor capturedTorEntryProof, captured bool) (string, error) {
	profile, err := profileObject(profileJSON, 256<<10)
	if err != nil || profile["node_kind"] != "external" || !profileIdentifier.MatchString(profileString(profile, "id")) {
		return "", errors.New("Tor MTU requires the captured external profile")
	}
	external, ok := profile["external"].(map[string]any)
	if !ok || (external["protocol"] != "tor" && external["protocol"] != "tor-bridge") ||
		(external["expected_public_ip"] != nil && external["expected_public_ip"] != "") {
		return "", errors.New("Tor MTU requires dynamic Tor exit identity")
	}
	digest, err := torProfileDigest(profile)
	if err != nil {
		return "", err
	}
	graph, err := profileObject(config, 4<<20)
	if err != nil || !profileIdentifier.MatchString(sessionID) {
		return "", errors.New("Tor MTU configuration or session is invalid")
	}
	route, _ := graph["route"].(map[string]any)
	dns, _ := graph["dns"].(map[string]any)
	if route["final"] != ProfileOutboundTag || dns["final"] != profileDNS {
		return "", errors.New("Tor MTU lost the captured traffic or DNS route")
	}
	outbounds, _ := graph["outbounds"].([]any)
	matched := 0
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("Tor MTU configuration contains a malformed owner")
		}
		if outbound["type"] == "routervpn-tor" || outbound["tag"] == ProfileOutboundTag {
			if outbound["type"] != "routervpn-tor" || outbound["tag"] != ProfileOutboundTag ||
				outbound["session_id"] != sessionID || outbound["profile_sha256"] != digest {
				return "", errors.New("Tor MTU profile differs from the captured native policy")
			}
			matched++
		}
	}
	if matched != 1 {
		return "", errors.New("Tor MTU requires exactly one captured Tor owner")
	}
	exit, err := capturedTorMTUPreferences(profile)
	if err != nil {
		return "", err
	}
	_, _, mtu, err := torMTUInterface(graph)
	if err != nil {
		return "", err
	}
	var entry torMTUPreferences
	for _, raw := range outbounds {
		outbound := raw.(map[string]any)
		if outbound["tag"] != ProfileOutboundTag {
			continue
		}
		if predecessor != nil {
			if !captured || profile["multihop_enabled"] != true || profile["multihop_entry_id"] != predecessor.capturedID() ||
				profile["multihop_exit_id"] != profile["id"] || profile["multihop_exit_mode"] != external["protocol"] ||
				(profileString(profile, "multihop_execution") != "" && profileString(profile, "multihop_execution") != "local") ||
				!profileIdentifier.MatchString(profileString(outbound, "detour")) || outbound["entry_sha256"] != predecessor.Fingerprint() {
				return "", errors.New("Tor MTU predecessor differs from its proved captured entry")
			}
			entry = predecessor.capturedMTU()
		} else if captured && (profile["multihop_enabled"] == true || profileString(outbound, "detour") != "" || outbound["entry_sha256"] != nil) {
			return "", errors.New("Tor MTU requires its proved captured predecessor")
		}
	}
	if err := compatibleTorMTUPreferences(exit, entry); err != nil {
		return "", err
	}
	jumbo := exit.jumbo || entry.jumbo
	if jumbo && mtu != 9000 || exit.fixed != 0 && mtu != exit.fixed || entry.fixed != 0 && mtu != entry.fixed ||
		mtu > 1500 && !jumbo && exit.fixed == 0 && entry.fixed == 0 {
		return "", errors.New("Tor MTU configuration differs from its captured interface policy")
	}
	source := sha256.Sum256([]byte(config))
	authority := map[string]any{"schema": 1, "source_kind": "tor", "id": profile["id"],
		"source_sha256": hex.EncodeToString(source[:]), "mtu_policy": exit.policy, "jumbo_tun": jumbo}
	if entry.fixed != 0 {
		authority["entry_fixed_mtu"] = entry.fixed
	}
	encoded, err := json.Marshal(authority)
	return string(encoded), err
}
