package main

import (
	"testing"

	"router-vpn/internal/common"
)

func TestSortPublicProfileStoreOrdersCurrentRecentAndLatency(t *testing.T) {
	store := common.RouterProfileStore{
		SelectedID: "b",
		Profiles: []common.RouterProfile{
			{ID: "a", Name: "Alpha", UseCount: 3, LastUsedAt: "2026-08-15T03:00:00Z", LatencySamples: 50, LatencyMedianMs: 22, LatencyP90Ms: 30},
			{ID: "b", Name: "Beta", UseCount: 1, LastUsedAt: "2026-08-14T03:00:00Z", LatencySamples: 50, LatencyMedianMs: 12, LatencyP90Ms: 18},
			{ID: "c", Name: "Gamma", UseCount: 8},
		},
	}

	current := sortPublicProfileStore(store, "current")
	if got := current.Profiles[0].ID; got != "b" { t.Fatalf("current order first=%q want b", got) }
	recent := sortPublicProfileStore(store, "last-used")
	if got := recent.Profiles[0].ID; got != "a" { t.Fatalf("last-used order first=%q want a", got) }
	latency := sortPublicProfileStore(store, "latency")
	if got := latency.Profiles[0].ID; got != "b" { t.Fatalf("latency order first=%q want b", got) }
	if got := latency.Profiles[2].ID; got != "c" { t.Fatalf("unmeasured node should sort last; got %q", got) }
	if got := lowestLatencyProfileID(store); got != "b" { t.Fatalf("lowestLatencyProfileID=%q want b", got) }

	// Sorting a public copy must not mutate persisted profile order.
	if store.Profiles[0].ID != "a" || store.Profiles[1].ID != "b" { t.Fatalf("source store order mutated: %#v", store.Profiles) }
}

func TestLowestLatencyProfileIDRequiresMeasurement(t *testing.T) {
	store := common.RouterProfileStore{Profiles: []common.RouterProfile{{ID:"a",Name:"A"},{ID:"b",Name:"B",LatencySamples:50}}}
	if got := lowestLatencyProfileID(store); got != "" { t.Fatalf("unmeasured latency selected: %q", got) }
}
