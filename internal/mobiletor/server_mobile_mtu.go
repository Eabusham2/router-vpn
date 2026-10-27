package mobiletor

import (
	"encoding/json"
	"errors"
)

// ServerMTUAuthority accepts only the graph reproduced from the exact native
// Server inputs. The shared interface rules are then evaluated independently;
// no Local runtime or Local source identity is emitted to the mobile host.
func ServerMTUAuthority(config, profileJSON, session string, predecessor *PredecessorProof) (string, error) {
	failure := errors.New("Tor Server MTU requires its exact proved private entry and native graph")
	graph, err := profileObject(config, 4<<20)
	if err != nil || predecessor == nil {
		return "", failure
	}
	var options MobileServerTorOptions
	matched := 0
	rows, _ := graph["outbounds"].([]any)
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return "", failure
		}
		if row["tag"] == ProfileOutboundTag || row["type"] == ServerTorClientType {
			encoded, _ := json.Marshal(row)
			if row["tag"] != ProfileOutboundTag || row["type"] != ServerTorClientType || json.Unmarshal(encoded, &options) != nil {
				return "", failure
			}
			matched++
		}
	}
	if matched != 1 || options.SessionID != session {
		return "", failure
	}
	policy, err := NewMobileServerTorPolicy(options)
	if err != nil || policy.EntryProof().Fingerprint() != predecessor.Fingerprint() {
		return "", failure
	}
	canonical, _ := json.Marshal(graph)
	if string(canonical) != policy.Config() {
		return "", failure
	}
	supplied, _, err := capturedTorProfileValues(profileJSON)
	if err != nil {
		return "", failure
	}
	expected, _, err := capturedTorProfileValues(options.Profile)
	if err != nil {
		return "", failure
	}
	suppliedDigest, _ := torProfileDigest(supplied)
	expectedDigest, _ := torProfileDigest(expected)
	if suppliedDigest != expectedDigest {
		return "", failure
	}
	localSource, err := mobileServerLocalTemplate(expected)
	if err != nil {
		return "", err
	}
	localConfig, err := CompileProfileWithPredecessor(localSource, session, options.EntryConfig, options.EntryProfile)
	if err != nil {
		return "", err
	}
	authority, err := MTUAuthorityWithPredecessor(localConfig, localSource, session, predecessor)
	if err != nil {
		return "", err
	}
	value, err := profileObject(authority, 16<<10)
	if err != nil {
		return "", err
	}
	value["source_sha256"] = capturedDigest([]byte(config))
	encoded, err := json.Marshal(value)
	return string(encoded), err
}
