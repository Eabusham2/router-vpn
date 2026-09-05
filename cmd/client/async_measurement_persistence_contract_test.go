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
		"captureAsyncMeasurementSession",
		"sameAsyncMeasurementSession",
		"activeAsyncMeasurementProfile",
		"validateAsyncMeasurementProfile",
		"asyncMeasurementProfileToken",
		"VPN session/path changed while live proof was running",
		"active VPN node/mode/base/path changed while live proof was running",
		"active VPN profile or policy changed while live proof was running",
		"targetProfile, stateAtStart, err := a.activeAsyncMeasurementProfile()",
		"active VPN path or policy changed before public-exit persistence",
		"p, stateAtStart, err := a.activeAsyncMeasurementProfile()",
		"active node/path or DNS policy changed before DNS Retest persistence",
		"previousStore := cloneRouterProfileStore(a.profiles)",
		"a.rollbackProfilesLocked(previousStore)",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("async measurement persistence contract missing %q", marker)
		}
	}
	if strings.Contains(text, "x.DNSHost = payload.Winner.Address") {
		t.Fatal("DNS Retest must merge measurement fields only; it must not silently rewrite DNS policy")
	}
}
