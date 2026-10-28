package multihoprelay

import (
	"time"

	"router-vpn/internal/mobilepq"
)

// NativeStartupAllowance is the existing initial-key phase of one exact
// captured native transport. Raw Xray max and PQ REALITY do not start a
// Rosenpass peer and therefore cannot widen the ordinary startup deadline.
func NativeStartupAllowance(mode string) time.Duration {
	if mobilepq.IsMode(mode) || CompleteMAXMode(mode) {
		return mobilepq.InitialKeyTimeout
	}
	return 0
}

// AcquisitionTimeout reserves authenticated readiness time after the native
// exit's initial key. Renewals, status and deletion retain their own shorter
// deadlines; a mode label does not bypass registry or credential validation.
func AcquisitionTimeout(mode string) time.Duration {
	return 8*time.Second + NativeStartupAllowance(mode)
}
