package mobiletor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// LocalPaddingSource keeps the original exit and predecessor inputs inside
// the native graph. The constructor recompiles them; a host supplied source
// hash or a different graph cannot stand in for their captured policy.
type LocalPaddingSource struct {
	Profile            string `json:"profile"`
	PredecessorProfile string `json:"predecessor_profile,omitempty"`
	PredecessorConfig  string `json:"predecessor_config,omitempty"`
}

// LocalPaddingCapture is a pure source descriptor. It grants no socket,
// control generation or traffic proof. Native admission separately binds its
// exact compiled graph, single TUN, selected DNS and resident circuit owner.
type LocalPaddingCapture struct {
	policy                      TorPaddingPolicy
	config                      string
	sessionSHA256, sourceSHA256 string
}

func localPaddingDigest(data string) string {
	digest := sha256.Sum256([]byte(data))
	return hex.EncodeToString(digest[:])
}

// NewLocalPaddingCapture reconstructs only enabled Local selections, including
// ordinary providers without private Router or Home DNS authority. Both the
// native constructor and host receipt validation use this independent capture.
func NewLocalPaddingCapture(source *LocalPaddingSource, sessionID string) (*LocalPaddingCapture, error) {
	bad := errors.New("Local Tor padding requires its complete captured source and policy")
	if source == nil || !profileIdentifier.MatchString(sessionID) {
		return nil, bad
	}
	profile, _, err := capturedTorProfileValues(source.Profile)
	if err != nil {
		return nil, err
	}
	policy, _, err := capturedTorPaddingPolicy(profile)
	if err != nil || !policy.Enabled || profileString(profile, "multihop_execution") != "" && profileString(profile, "multihop_execution") != "local" ||
		(source.PredecessorProfile == "") != (source.PredecessorConfig == "") {
		return nil, bad
	}
	ordinary := false
	if source.PredecessorProfile != "" {
		entry, err := profileObject(source.PredecessorProfile, 4<<20)
		if err != nil {
			return nil, bad
		}
		ordinary = entry["node_kind"] == "external"
	}
	var config string
	if ordinary {
		config, err = compileProfileWithExternalPredecessorPolicy(source.Profile, sessionID, source.PredecessorConfig, source.PredecessorProfile, true)
	} else {
		config, err = compileProfileWithEntryProofPolicy(source.Profile, sessionID, source.PredecessorConfig, source.PredecessorProfile, true, nil, true)
	}
	if err != nil {
		return nil, err
	}
	return &LocalPaddingCapture{policy: policy, config: config, sessionSHA256: localPaddingDigest(sessionID), sourceSHA256: localPaddingDigest(config)}, nil
}

func (c *LocalPaddingCapture) Policy() TorPaddingPolicy { return c.policy }
func (c *LocalPaddingCapture) Config() string           { return c.config }
func (c *LocalPaddingCapture) SessionSHA256() string    { return c.sessionSHA256 }
func (c *LocalPaddingCapture) SourceSHA256() string     { return c.sourceSHA256 }

// LocalPaddingSourceSHA256 independently validates the actual host graph and
// selected exit before returning the expected receipt identity. Off returns
// empty and cannot accept a hidden Local padding owner. Whitespace outside
// captured raw sources does not change the canonical compiled graph.
func LocalPaddingSourceSHA256(configJSON, profileJSON, sessionID string) (string, error) {
	bad := errors.New("Local Tor padding graph differs from the captured source, selection or session")
	profile, _, err := capturedTorProfileValues(profileJSON)
	if err != nil || !profileIdentifier.MatchString(sessionID) {
		return "", bad
	}
	policy, _, err := capturedTorPaddingPolicy(profile)
	if err != nil {
		return "", err
	}
	graph, err := profileObject(configJSON, 4<<20)
	if err != nil {
		return "", bad
	}
	rows, ok := graph["outbounds"].([]any)
	if !ok {
		return "", bad
	}
	var native map[string]any
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return "", bad
		}
		if row["tag"] == ProfileOutboundTag {
			if native != nil {
				return "", bad
			}
			native = row
		}
	}
	if native == nil || native["session_id"] != sessionID {
		return "", bad
	}
	if !policy.Enabled {
		if native["padding_source"] != nil {
			return "", bad
		}
		return "", nil
	}
	if native["type"] != "routervpn-tor" || native["padding_source"] == nil {
		return "", bad
	}
	encoded, err := json.Marshal(native["padding_source"])
	if err != nil {
		return "", bad
	}
	var source LocalPaddingSource
	if json.Unmarshal(encoded, &source) != nil {
		return "", bad
	}
	captured, err := NewLocalPaddingCapture(&source, sessionID)
	if err != nil {
		return "", err
	}
	expectedProfile, _, err := capturedTorProfileValues(source.Profile)
	if err != nil {
		return "", bad
	}
	expected, _ := json.Marshal(expectedProfile)
	selected, _ := json.Marshal(profile)
	actual, err := json.Marshal(graph)
	if err != nil || string(selected) != string(expected) || string(actual) != captured.config {
		return "", bad
	}
	return captured.sourceSHA256, nil
}

// NativePaddingProofStatus is a memory-only snapshot of a proved native lease.
// The two proof timestamps are actual completion times. Re-reading this object
// cannot extend a native grant or manufacture a new selected-DNS/path proof.
type NativePaddingProofStatus struct {
	Receipt       *PaddingReceipt `json:"receipt"`
	PathCheckedAt int64           `json:"path_checked_at"`
	DNSCheckedAt  int64           `json:"dns_checked_at"`
}

func ValidateNativePaddingStatus(status *NativePaddingProofStatus, policy TorPaddingPolicy, sessionSHA, sourceSHA string, now time.Time) error {
	bad := errors.New("Local Tor padding has no fresh captured path and selected-DNS proof")
	if !policy.Enabled {
		if status != nil {
			return bad
		}
		return ValidatePaddingReceipt(nil, policy, sessionSHA, sourceSHA, time.Time{}, now)
	}
	if status == nil || status.PathCheckedAt <= 0 || status.DNSCheckedAt <= 0 || status.DNSCheckedAt > status.PathCheckedAt ||
		status.PathCheckedAt > now.UnixMilli() || now.IsZero() {
		return bad
	}
	until := time.UnixMilli(status.DNSCheckedAt).Add(PaddingProofMaxAge)
	if !until.After(now) {
		return bad
	}
	return ValidatePaddingReceipt(status.Receipt, policy, sessionSHA, sourceSHA, until, now)
}

func ValidateNativePaddingProgress(previous, current *NativePaddingProofStatus) error {
	if previous == nil {
		return nil
	}
	if current == nil || previous.Receipt == nil || current.Receipt == nil {
		return errors.New("Local Tor padding lost its retained native receipt")
	}
	a, b := previous.Receipt, current.Receipt
	if a.SessionSHA256 != b.SessionSHA256 || a.SourceSHA256 != b.SourceSHA256 || a.Generation != b.Generation || a.RateKbps != b.RateKbps ||
		b.ChannelCells < a.ChannelCells || b.ChannelBytes < a.ChannelBytes || b.ObservedAt < a.ObservedAt ||
		current.DNSCheckedAt < previous.DNSCheckedAt || current.PathCheckedAt < previous.PathCheckedAt {
		return errors.New("Local Tor padding changed its native generation or regressed proof and counters")
	}
	return nil
}
