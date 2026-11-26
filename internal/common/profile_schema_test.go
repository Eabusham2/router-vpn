package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileStoreMigrationAndExplicitSettingsRoundTrip(t *testing.T) {
	var store RouterProfileStore
	if err := json.Unmarshal([]byte(`{"profiles":[{"id":"home","kill_switch":true},{"id":"away","home_lan_access":false}]}`), &store); err != nil {
		t.Fatal(err)
	}
	p := &store.Profiles[0]
	if store.SchemaVersion != RouterProfileStoreVersion || store.SelectedID != "home" ||
		p.SchemaVersion != RouterProfileSchemaVersion || !p.HomeLANAccess ||
		p.KillSwitchPolicy != "on-connect" || p.StartupMode != "smart-auto" ||
		p.IPv6Mode != "on" || p.MTUPolicy != "auto" || store.Profiles[1].HomeLANAccess {
		t.Fatalf("legacy selection/defaults changed: %+v", store)
	}
	p.HomeLANAccess = false
	p.AutoRequireEncrypted, p.AutoRequireObfuscation = true, true
	p.NodeProofID = strings.Repeat("a1", 32)
	raw, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	var restored RouterProfileStore
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	got := restored.Profiles[0]
	if restored.SelectedID != "home" || got.HomeLANAccess || !got.AutoRequireEncrypted ||
		!got.AutoRequireObfuscation || got.NodeProofID != p.NodeProofID {
		t.Fatal("explicit settings or node identity did not survive storage")
	}
}

func TestProfileSchemaAndRouteAdmissionFailClosed(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":999,"id":"future"}`,
		`{"id":"node","node_proof_id":"not-a-proof"}`,
	} {
		var p RouterProfile
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			t.Fatal("unsupported schema or identity accepted")
		}
	}
	nodes := []MultihopNodeSelection{
		{ID: "entry", Mode: "awg2-fast"}, {ID: "middle", Mode: "wg"}, {ID: "exit", Mode: "awg2-strong"},
	}
	p := RouterProfile{NodeKind: "router-vpn", MultihopExecution: "local", MultihopNodes: nodes}
	if !PairedPacketLocalMultihopSelection(nodes) || validateRouterProfileNodeChain(&p) != nil {
		t.Fatal("complete original Local packet route rejected")
	}
	p.MultihopExecution = "server"
	if validateRouterProfileNodeChain(&p) == nil {
		t.Fatal("Local-only packet route acquired Server authority")
	}
	nodes[2].ID = nodes[0].ID
	if PairedPacketLocalMultihopSelection(nodes) {
		t.Fatal("duplicate selected peer accepted")
	}
	p = RouterProfile{MTUPolicy: "manual", ManualMTU: 100}
	if err := NormalizeRouterProfile(&p); err == nil {
		t.Fatal("invalid manual MTU accepted")
	}
}
