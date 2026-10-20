package mobiletor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

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
	policy := profileString(profile, "mtu_policy")
	if policy == "" {
		policy = "default"
	}
	if policy != "auto" && policy != "default" && policy != "fixed" && policy != "manual" {
		return "", errors.New("Tor MTU policy is invalid")
	}
	jumbo, _ := profile["jumbo_tun"].(bool)
	source := sha256.Sum256([]byte(config))
	encoded, err := json.Marshal(map[string]any{"schema": 1, "source_kind": "tor", "id": profile["id"],
		"source_sha256": hex.EncodeToString(source[:]), "mtu_policy": policy, "jumbo_tun": jumbo})
	return string(encoded), err
}
