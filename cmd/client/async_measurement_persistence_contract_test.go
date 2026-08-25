package main

import (
	"os"
	"strings"
	"testing"
)

func TestAsyncMeasurementPersistenceRequiresFreshIdentityAndSession(t *testing.T) {
	raw, err := os.ReadFile("extras.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, marker := range []string{
		"router profile identity changed while durable latency measurement was running",
		"VPN session/path changed while public-exit lookup was running",
		"active VPN path changed while public-exit lookup was running",
		"VPN session/path changed while DNS Retest was running",
		"selected node or DNS policy changed while DNS Retest was running",
		"profileAtStart := fastestProfileSnapshotToken([]common.RouterProfile{p})",
		"sessionAtStart, sessionErr := captureAsyncMeasurementSession(a)",
		"stateAtStart := mtuStateSnapshotToken(a.state)",
		"sameAsyncMeasurementSession(sessionAtStart, sessionTrackerFor(a).snapshot(0))",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("async measurement persistence contract missing %q", marker)
		}
	}
	if strings.Contains(text, "x.DNSHost = payload.Winner.Address") {
		t.Fatal("DNS Retest must merge measurement fields only; it must not silently rewrite DNS policy")
	}
}
