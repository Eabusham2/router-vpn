package mobiletor

import (
	"errors"

	"router-vpn/internal/common"
)

// validateTorPaddingPolicy keeps a requested exit policy from becoming only a
// source digest. The current Tor owner does not implement the application's
// bounded cover service. Tor's built-in connection/circuit padding is a
// different policy and cannot satisfy this request by implication.
//
// A valid dormant rate remains saved while padding is Off. Zero is the common
// profile's unset value; neither it nor an absent enabled flag starts padding.
// This admission boundary is not completion of the native padding requirement.
func validateTorPaddingPolicy(profile map[string]any) error {
	requested := false
	if raw, exists := profile["daita_enabled"]; exists {
		var ok bool
		requested, ok = raw.(bool)
		if !ok {
			return errors.New("Tor padding selection must be a boolean")
		}
	}
	rate, err := profileInteger(profile, "daita_rate_kbps", 0)
	if err != nil || rate != 0 && (rate < common.DAITALikeMinRateKbps || rate > common.DAITALikeMaxRateKbps) {
		return errors.New("Tor padding rate must be an integer of 0 or 32..192 kbps")
	}
	if requested {
		return errors.New("requested Tor padding requires its bounded native circuit owner, which is not implemented for this path")
	}
	return nil
}
