package mobiletor

import (
	"encoding/json"
	"errors"
)

// CompileProfileWithExternalPredecessor retains the original ordinary provider
// source and independently reconstructs its policy. The provider's public-IP
// proof never grants private Router, Home DNS, or Server execution authority.
// Native adoption must verify that same source and prove the actual lower path.
func CompileProfileWithExternalPredecessor(profileJSON, sessionID, sourceConfigJSON, predecessorProfileJSON string) (string, error) {
	entry, err := NewExternalPredecessorProof(predecessorProfileJSON, sourceConfigJSON)
	if err != nil {
		return "", err
	}
	profile, err := profileObject(profileJSON, 256<<10)
	if err != nil || profileString(profile, "multihop_entry_mode") != entry.Protocol() {
		return "", errors.New("Tor ordinary predecessor mode differs from its captured transport")
	}
	compiled, err := compileProfileWithEntryProof(profileJSON, sessionID, entry.Config(), entry.Profile(), true, entry)
	if err != nil {
		return "", err
	}
	graph, err := profileObject(compiled, 4<<20)
	if err != nil {
		return "", err
	}
	for _, raw := range graph["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		if outbound["tag"] == ProfileOutboundTag {
			outbound["external_tor_profile"] = profileJSON
			outbound["external_predecessor_profile"] = entry.Profile()
			outbound["external_predecessor_config"] = entry.SourceConfig()
		}
	}
	encoded, err := json.Marshal(graph)
	if err != nil || len(encoded) > 4<<20 {
		return "", errors.New("Tor ordinary predecessor exceeds its bounded native graph")
	}
	return string(encoded), nil
}

// ExternalProfileDigest binds the exit policy independently from its provider.
func ExternalProfileDigest(profileJSON string) (string, error) {
	profile, _, err := capturedTorProfile(profileJSON)
	if err != nil {
		return "", err
	}
	return torProfileDigest(profile)
}

// MatchesProfile compares immutable canonical source, not a mutable node label.
func (p *ExternalPredecessorProof) MatchesProfile(profileJSON string) bool {
	if p == nil {
		return false
	}
	profile, err := profileObject(profileJSON, 4<<20)
	if err != nil {
		return false
	}
	encoded, err := json.Marshal(profile)
	return err == nil && string(encoded) == p.profile
}
