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
	if p.StartupMode != "smart-auto" || p.IPv6Mode != "on" || p.MTUPolicy != "auto" {
		t.Fatalf("unified defaults not migrated: %+v", p)
	}
	if p.AutoRequireEncrypted || p.AutoRequireObfuscation { t.Fatalf("AUTO requirements must default off: %+v", p) }
	if p.DiagnosticsRetentionDays != 7 { t.Fatalf("retention=%d", p.DiagnosticsRetentionDays) }
}

func TestExplicitUnifiedDefaultsRoundTrip(t *testing.T) {
	in := RouterProfile{ID: "home", StartupMode: "smart-auto", IPv6Mode: "on", MTUPolicy: "auto", AutoRequireEncrypted: true, AutoRequireObfuscation: true}
	b, err := json.Marshal(in)
	if err != nil { t.Fatal(err) }
	var out RouterProfile
	if err := json.Unmarshal(b, &out); err != nil { t.Fatal(err) }
	if out.StartupMode != "smart-auto" || out.IPv6Mode != "on" || out.MTUPolicy != "auto" || !out.AutoRequireEncrypted || !out.AutoRequireObfuscation { t.Fatalf("unified settings lost: %s", b) }
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
	if s.Profiles[0].StartupMode != "smart-auto" || s.Profiles[0].IPv6Mode != "on" || s.Profiles[0].MTUPolicy != "auto" { t.Fatalf("store did not receive unified defaults: %+v", s.Profiles[0]) }
}

func TestManualMTUValidation(t *testing.T) {
	p := RouterProfile{MTUPolicy: "manual", ManualMTU: 100}
	if err := NormalizeRouterProfile(&p); err == nil { t.Fatal("expected invalid manual MTU") }
	p = RouterProfile{MTUPolicy: "manual", ManualMTU: 1400}
	if err := NormalizeRouterProfile(&p); err != nil { t.Fatal(err) }
}

func TestNodeProofIDValidationAndRoundTrip(t *testing.T) {
	valid := strings.Repeat("a1", 32)
	if !ValidNodeProofID(valid) { t.Fatal("valid lowercase SHA-256 node proof id rejected") }
	for _, invalid := range []string{
		"",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("A", 64),
		strings.Repeat("g", 64),
		strings.Repeat("0", 63) + "/",
	} {
		if invalid != "" && ValidNodeProofID(invalid) { t.Fatalf("invalid node proof id accepted: %q", invalid) }
	}
	p := RouterProfile{ID: "node", NodeProofID: "  " + valid + "  "}
	if err := NormalizeRouterProfile(&p); err != nil { t.Fatal(err) }
	if p.NodeProofID != valid { t.Fatalf("node proof id was not normalized: %q", p.NodeProofID) }
	b, err := json.Marshal(p)
	if err != nil { t.Fatal(err) }
	var out RouterProfile
	if err := json.Unmarshal(b, &out); err != nil { t.Fatal(err) }
	if out.NodeProofID != valid { t.Fatalf("node proof id did not survive round trip: %q", out.NodeProofID) }
}

func TestMalformedNodeProofIDFailsClosed(t *testing.T) {
	for _, raw := range []string{
		`{"id":"node","node_proof_id":"abc"}`,
		`{"id":"node","node_proof_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"id":"node","node_proof_id":"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"}`,
	} {
		var p RouterProfile
		if err := json.Unmarshal([]byte(raw), &p); err == nil || !strings.Contains(err.Error(), "invalid node proof id") {
			t.Fatalf("expected malformed node proof rejection, got %v for %s", err, raw)
		}
	}
}

func TestMultihopRequiresCompleteDistinctNodes(t *testing.T) {
	for _, p := range []RouterProfile{
		{MultihopEnabled: true},
		{MultihopEnabled: true, MultihopEntryID: "entry"},
		{MultihopEnabled: true, MultihopExitID: "exit"},
	} {
		if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "requires both") {
			t.Fatalf("expected incomplete multihop rejection, got %v for %+v", err, p)
		}
	}
	p := RouterProfile{MultihopEnabled: true, MultihopEntryID: "same", MultihopExitID: "same"}
	if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "different") { t.Fatalf("expected same-node rejection, got %v", err) }
	p = RouterProfile{MultihopEnabled: true, MultihopEntryID: " entry ", MultihopExitID: " exit "}
	if err := NormalizeRouterProfile(&p); err != nil { t.Fatal(err) }
	if p.MultihopEntryID != "entry" || p.MultihopExitID != "exit" { t.Fatalf("multihop IDs were not normalized: %+v", p) }
}

func TestDAITALikeRateIsExplicitlyBounded(t *testing.T) {
	for _, rate := range []int{DAITALikeMinRateKbps, 96, DAITALikeMaxRateKbps} {
		p := RouterProfile{ID: "home", DAITARateKbps: rate}
		if err := NormalizeRouterProfile(&p); err != nil { t.Fatalf("valid DAITA-like rate %d rejected: %v", rate, err) }
	}
	for _, rate := range []int{1, DAITALikeMinRateKbps - 1, DAITALikeMaxRateKbps + 1, 1000000} {
		p := RouterProfile{ID: "home", DAITARateKbps: rate}
		if err := NormalizeRouterProfile(&p); err == nil || !strings.Contains(err.Error(), "DAITA-like rate") {
			t.Fatalf("out-of-bound DAITA-like rate %d was accepted: %v", rate, err)
		}
	}
}
