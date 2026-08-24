package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFastestLiveLatencyCannotOverwriteDurableBenchmark(t *testing.T) {
	telemetryPath := filepath.Join("telemetry.go")
	data, err := os.ReadFile(telemetryPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "func (a *app) fastestProfile")
	end := strings.Index(text, "func activeLatencyTarget")
	if start < 0 || end <= start {
		t.Fatal("could not isolate fastestProfile implementation")
	}
	fastest := text[start:end]
	for _, forbidden := range []string{
		"updateStoredLiveLatency",
		"LatencySamples",
		"LatencyMinMs",
		"LatencyMedianMs",
		"LatencyTrimmedMeanMs",
		"LatencyAverageMs",
		"LatencyP90Ms",
		"LatencyMaxMs",
		"LatencyLastTest",
	} {
		if strings.Contains(fastest, forbidden) {
			t.Fatalf("lightweight fastest-node path must not write durable benchmark field/helper %q", forbidden)
		}
	}
	for _, required := range []string{
		"q.Samples = clampLiveSamples(q.Samples, 5)",
		"selectionAtStart := a.profiles.SelectedID",
		"profilesAtStart := fastestProfileSnapshotToken(profiles)",
		"sessionAtStart := sessionTrackerFor(a).snapshot(0).ID",
		"VPN session changed while fastest-node measurement was running",
		"selected node changed while fastest-node measurement was running",
		"linked node catalog changed while fastest-node measurement was running",
		"a.profiles.SelectedID = winner.ID",
		"persistErr = a.persistProfilesLocked()",
		"does not overwrite the durable 50-sample node benchmark",
	} {
		if !strings.Contains(fastest, required) {
			t.Fatalf("fastest-node separation contract missing %q", required)
		}
	}
}

func TestDurableNodeLatencyKeepsMinimumFiftySamplesAndRealTrimmedMean(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("extras.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{
		"q.Samples = max(50, q.Samples)",
		"trim := len(values) / 10",
		"trimmedV := average(trimmed)",
		"LatencyTrimmedMeanMs = resp.TrimmedMs",
		"LatencySamples = resp.Samples",
		"LatencyLastTest = now.Format(time.RFC3339)",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("durable 50-sample benchmark contract missing %q", required)
		}
	}
}
