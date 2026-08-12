package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyProfileMigration(t *testing.T) {
	var p RouterProfile
	if err := json.Unmarshal([]byte(`{"id":"home","kill_switch":true}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != RouterProfileSchemaVersion { t.Fatalf("schema=%d", p.SchemaVersion) }
	if !p.HomeLANAccess { t.Fatal("legacy profile should preserve historical LAN access") }
	if p.KillSwitchPolicy != "on-connect" { t.Fatalf("kill policy=%q", p.KillSwitchPolicy) }
	if p.StartupMode != "manual" || p.IPv6Mode != "auto" || p.MTUPolicy != "default" {
		t.Fatalf("defaults not migrated: %+v", p)
	}
	if p.DiagnosticsRetentionDays != 7 { t.Fatalf("retention=%d", p.DiagnosticsRetentionDays) }
}

func TestExplicitLANOffRoundTrips(t *testing.T) {
	in := RouterProfile{ID: "home", HomeLANAccess: false}
	b, err := json.Marshal(in)
	if err != nil { t.Fatal(err) }
	if !strings.Contains(string(b), `"home_lan_access":false`) { t.Fatalf("missing explicit LAN policy: %s", b) }
	var out RouterProfile
	if err := json.Unmarshal(b, &out); err != nil { t.Fatal(err) }
	if out.HomeLANAccess { t.Fatalf("LAN-off did not survive round trip: %s", b) }
}

func TestFutureProfileSchemaFailsClosed(t *testing.T) {
	var p RouterProfile
	err := json.Unmarshal([]byte(`{"schema_version":999,"id":"future"}`), &p)
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("expected future-schema rejection, got %v", err)
	}
}

func TestStoreMigrationAndSelection(t *testing.T) {
	var s RouterProfileStore
	if err := json.Unmarshal([]byte(`{"profiles":[{"id":"one","home_lan_access":false}]}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != RouterProfileStoreVersion { t.Fatalf("store schema=%d", s.SchemaVersion) }
	if s.SelectedID != "one" { t.Fatalf("selected=%q", s.SelectedID) }
	if s.Profiles[0].HomeLANAccess { t.Fatal("explicit false changed during migration") }
}

func TestManualMTUValidation(t *testing.T) {
	p := RouterProfile{MTUPolicy: "manual", ManualMTU: 100}
	if err := NormalizeRouterProfile(&p); err == nil { t.Fatal("expected invalid manual MTU") }
	p = RouterProfile{MTUPolicy: "manual", ManualMTU: 1400}
	if err := NormalizeRouterProfile(&p); err != nil { t.Fatal(err) }
}

func TestMultihopSameNodeRejected(t *testing.T) {
	p := RouterProfile{MultihopEnabled: true, MultihopEntryID: "same", MultihopExitID: "same"}
	if err := NormalizeRouterProfile(&p); err == nil { t.Fatal("expected same-node multihop rejection") }
}
