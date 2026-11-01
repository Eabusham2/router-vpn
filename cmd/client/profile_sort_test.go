package main

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"router-vpn/internal/common"
)

func sortFixtureStore() common.RouterProfileStore {
	return common.RouterProfileStore{
		SchemaVersion: common.RouterProfileStoreVersion,
		SelectedID:    "b",
		Profiles: []common.RouterProfile{
			{SchemaVersion: common.RouterProfileSchemaVersion, ID: "a", Name: "Alpha", UseCount: 3, LastUsedAt: "2026-08-15T03:00:00Z", LatencySamples: 50, LatencyMedianMs: 22, LatencyP90Ms: 30},
			{SchemaVersion: common.RouterProfileSchemaVersion, ID: "b", Name: "Beta", UseCount: 1, LastUsedAt: "2026-08-14T03:00:00Z", LatencySamples: 50, LatencyMedianMs: 12, LatencyP90Ms: 18},
			{SchemaVersion: common.RouterProfileSchemaVersion, ID: "c", Name: "Gamma", UseCount: 8},
		},
	}
}

func TestSortPublicProfileStoreOrdersCurrentRecentAndLatency(t *testing.T) {
	store := sortFixtureStore()

	current := sortPublicProfileStore(store, "current")
	if got := current.Profiles[0].ID; got != "b" {
		t.Fatalf("current order first=%q want b", got)
	}
	recent := sortPublicProfileStore(store, "last-used")
	if got := recent.Profiles[0].ID; got != "a" {
		t.Fatalf("last-used order first=%q want a", got)
	}
	latency := sortPublicProfileStore(store, "latency")
	if got := latency.Profiles[0].ID; got != "b" {
		t.Fatalf("latency order first=%q want b", got)
	}
	if got := latency.Profiles[2].ID; got != "c" {
		t.Fatalf("unmeasured node should sort last; got %q", got)
	}
	if got := lowestLatencyProfileID(store); got != "b" {
		t.Fatalf("lowestLatencyProfileID=%q want b", got)
	}

	// Sorting a public copy must not mutate persisted profile order.
	if store.Profiles[0].ID != "a" || store.Profiles[1].ID != "b" {
		t.Fatalf("source store order mutated: %#v", store.Profiles)
	}
}

func TestLowestLatencyProfileIDRequiresMeasurement(t *testing.T) {
	store := common.RouterProfileStore{Profiles: []common.RouterProfile{{ID: "a", Name: "A"}, {ID: "b", Name: "B", LatencySamples: 50}}}
	if got := lowestLatencyProfileID(store); got != "" {
		t.Fatalf("unmeasured latency selected: %q", got)
	}
}

func TestPublicNodesHTTPHonorsLatencySortWithoutChangingSelection(t *testing.T) {
	a := &app{profiles: sortFixtureStore()}
	rr := httptest.NewRecorder()
	a.listPublicNodes(rr, httptest.NewRequest("GET", "/api/nodes?sort=latency", nil))
	if rr.Code != 200 {
		t.Fatalf("/api/nodes latency sort status=%d: %s", rr.Code, rr.Body.String())
	}
	var got publicProfileStore
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode public nodes: %v\n%s", err, rr.Body.String())
	}
	if got.SelectedID != "b" {
		t.Fatalf("selected_id=%q want b", got.SelectedID)
	}
	if len(got.Profiles) != 3 {
		t.Fatalf("profile count=%d want 3", len(got.Profiles))
	}
	if got.Profiles[0].ID != "b" || got.Profiles[1].ID != "a" || got.Profiles[2].ID != "c" {
		t.Fatalf("latency API order=%v want [b a c]", []string{got.Profiles[0].ID, got.Profiles[1].ID, got.Profiles[2].ID})
	}
}

func TestPublicProfilesDefaultToCurrentThenRecent(t *testing.T) {
	got := publicProfileStoreFor(sortFixtureStore())
	if got.SelectedID != "b" {
		t.Fatalf("selected_id=%q want b", got.SelectedID)
	}
	if len(got.Profiles) != 3 || got.Profiles[0].ID != "b" || got.Profiles[1].ID != "a" {
		t.Fatalf("default public profile order did not keep current first then recent: %#v", got.Profiles)
	}
}

func TestSortPublicProfileStoreMostUsedHTTPKeepsSelection(t *testing.T) {
	a := &app{profiles: sortFixtureStore()}
	before := cloneRouterProfileStore(a.profiles)
	rr := httptest.NewRecorder()
	a.listPublicNodes(rr, httptest.NewRequest("GET", "/api/nodes?sort=most-used", nil))
	if rr.Code != 200 {
		t.Fatalf("most-used status=%d: %s", rr.Code, rr.Body.String())
	}
	var got publicProfileStore
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(got.Profiles))
	for i, profile := range got.Profiles {
		ids[i] = profile.ID
	}
	if !reflect.DeepEqual(ids, []string{"c", "a", "b"}) || got.SelectedID != "b" {
		t.Fatal("Most-used was replaced by current, recent, latency or name ordering", ids, got.SelectedID)
	}
	if !reflect.DeepEqual(a.profiles, before) || a.cmd != nil || a.state.Connected {
		t.Fatal("Changing display order changed the stored selection or started a connection")
	}
}

func TestSortPublicProfileStoreMostUsedResolvesTies(t *testing.T) {
	store := common.RouterProfileStore{SelectedID: "negative", Profiles: []common.RouterProfile{
		{ID: "negative", Name: "Zulu", UseCount: -1},
		{ID: "name-z", Name: "Zulu", UseCount: 4, LastUsedAt: "2026-08-01T05:00:00Z"},
		{ID: "name-a-2", Name: "Alpha", UseCount: 4, LastUsedAt: "2026-08-01T00:00:00-05:00"},
		{ID: "name-a-1", Name: "Alpha", UseCount: 4, LastUsedAt: "2026-08-01T05:00:00Z"},
		{ID: "recent", Name: "Zulu", UseCount: 4, LastUsedAt: "2026-08-02T00:00:00Z"},
		{ID: "invalid", Name: "Invalid", UseCount: 4, LastUsedAt: "invalid"},
		{ID: "zero", Name: "Alpha"},
	}}
	before := cloneRouterProfileStore(store)
	for _, order := range []string{"most-used", "most_used", "usage"} {
		got := sortPublicProfileStore(store, order)
		ids := make([]string, len(got.Profiles))
		for i, profile := range got.Profiles {
			ids[i] = profile.ID
		}
		want := []string{"recent", "name-a-1", "name-a-2", "name-z", "invalid", "zero", "negative"}
		if !reflect.DeepEqual(ids, want) || !reflect.DeepEqual(store, before) || got.SelectedID != store.SelectedID {
			t.Fatal("Most-used ties lost deterministic time/name/ID order or mutated source metadata", order, ids)
		}
	}
}
