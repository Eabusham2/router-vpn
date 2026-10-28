package mobiletor

import (
	"errors"

	"router-vpn/internal/common"
)

const PaddingDefaultRateKbps = 192

// TorPaddingPolicy captures the requested outgoing Tor relay-cell cover. It
// does not authorize activation: the native host must own a fresh path/DNS
// proof, the exact circuit isolation credentials and the native cell counter.
// Off retains its saved rate, including zero (unset), without starting cover.
type TorPaddingPolicy struct {
	Enabled  bool `json:"enabled"`
	RateKbps int  `json:"rate_kbps"`
}

// CapturedTorPaddingPolicy validates the saved outgoing-cover choice without
// granting permission to start it. Each host must still bind the resulting
// policy to its actual native control, path, DNS and isolation owners.
func CapturedTorPaddingPolicy(profile map[string]any) (TorPaddingPolicy, bool, error) {
	return capturedTorPaddingPolicy(profile)
}

func capturedTorPaddingPolicy(profile map[string]any) (TorPaddingPolicy, bool, error) {
	requested := false
	_, selected := profile["daita_enabled"]
	_, hasRate := profile["daita_rate_kbps"]
	if raw, exists := profile["daita_enabled"]; exists {
		var ok bool
		requested, ok = raw.(bool)
		if !ok {
			return TorPaddingPolicy{}, false, errors.New("Tor padding selection must be a boolean")
		}
	}
	rate, err := profileInteger(profile, "daita_rate_kbps", 0)
	if err != nil || rate != 0 && (rate < common.DAITALikeMinRateKbps || rate > common.DAITALikeMaxRateKbps) {
		return TorPaddingPolicy{}, false, errors.New("Tor padding rate must be an integer of 0 or 32..192 kbps")
	}
	if requested && rate == 0 {
		rate = PaddingDefaultRateKbps
	}
	return TorPaddingPolicy{Enabled: requested, RateKbps: rate}, selected || hasRate, nil
}

// Native Local and Server owners bind this policy to fresh path/DNS proof,
// exact isolation credentials, an acknowledged lease and actual accounting.
// This validates saved values; it cannot itself grant runtime authority.
func validateTorPaddingPolicy(profile map[string]any) error {
	_, _, err := capturedTorPaddingPolicy(profile)
	return err
}
