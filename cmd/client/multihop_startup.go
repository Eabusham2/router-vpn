package main

import (
	"net/http"
	"time"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

const desktopMultihopMaximumTimeout = 420 * time.Second

// Each native candidate owns the captured entry and exit initial-key phases.
// Server execution removes the local exit closure and starts that phase on the
// entry server, so it receives one exit allowance, not two. The ordinary
// startup/proof caps stay unchanged; this never lengthens an individual probe.
func desktopMultihopStartupBudgets(sel multihopSelection, modes []string, execution routechoice.Execution) (startup, total time.Duration) {
	startup, total = 25*time.Second, 180*time.Second
	entry := multihoprelay.NativeStartupAllowance(sel.EntryMode)
	for _, mode := range modes {
		phases := entry + multihoprelay.NativeStartupAllowance(mode)
		if candidate := 25*time.Second + phases; candidate > startup {
			startup = candidate
		}
		if execution == "auto" {
			// Each Local/Server trial may be started once for scoring and once
			// for final proof. A failed final proof can try the next survivor.
			total += 4 * phases
		}
	}
	return startup, total
}

func nativeMultihopProofTimeout(sel multihopSelection) time.Duration {
	return 20*time.Second + multihoprelay.NativeStartupAllowance(sel.EntryMode) + multihoprelay.NativeStartupAllowance(sel.ExitMode)
}

func (o *desktopRelayOwner) controlTimeout(method string) time.Duration {
	if method == http.MethodPut && !o.renewed {
		return multihoprelay.AcquisitionTimeout(o.request.ExitMode)
	}
	// Capability discovery, renewal and release retain their short bound.
	return 8 * time.Second
}
