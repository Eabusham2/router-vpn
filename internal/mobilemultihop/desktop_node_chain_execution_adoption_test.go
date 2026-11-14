package mobilemultihop

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopNodeChainExecutionAdoptionReconstructsExactParentProjection(t *testing.T) {
	for _, target := range []string{"windows", "linux", "darwin"} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(target+"/"+execution, func(t *testing.T) {
				selected := execution
				if selected == "auto" {
					selected = "local"
				}
				child, ready, transfer := desktopExecutionReadyFixture(t, target, execution, selected)
				// Independent parent/child parsing is expected. The projection must
				// retain the parent's exact physical pointer, not the child's copy.
				parent, err := ParseDesktopNodeChainExecutionPreparation(child.preparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				record, err := NewDesktopNodeChainExecutionAdoptionRecord(child, ready.Identity, transfer)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				projection, identity, err := ParseDesktopNodeChainExecutionAdoptionRecord(raw, parent, transfer)
				if err != nil || identity != ready.Identity || projection.Config() != child.Config() || projection.Source() != child.Source() {
					t.Fatal("parent did not recover the actual adopted graph", err)
				}
				physical, _ := projection.DesktopPhysicalPolicy()
				original, _ := parent.DesktopPhysicalPolicy()
				foreign, _ := child.DesktopPhysicalPolicy()
				if physical != original || physical == foreign {
					t.Fatal("adoption replaced original parent physical authority")
				}
				heartbeat, _ := CanonicalDesktopNodeChainExecutionReadyRecord(ready, child, transfer)
				if _, err := ParseDesktopNodeChainExecutionAdoptedReadyRecord(heartbeat, projection, identity, transfer); err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"engine", "network"} {
					changed := ready
					if field == "engine" {
						changed.Identity.EngineID = "replacement-box"
					} else {
						changed.Identity.NetworkID = "replacement-network"
					}
					raw, err := CanonicalDesktopNodeChainExecutionReadyRecord(changed, child, transfer)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := ParseDesktopNodeChainExecutionAdoptedReadyRecord(raw, projection, identity, transfer); err == nil {
						t.Fatal("heartbeat replaced pinned native adoption", field)
					}
				}
				// A mutable returned record must not alias the sealed policy.
				record.Request.Users[0].Password = "changed"
				if child.validateCapture() != nil {
					t.Fatal("receipt leaked mutable original request")
				}
			})
		}
	}
}

func TestDesktopNodeChainExecutionAdoptionRejectsForeignOrAlteredHandoff(t *testing.T) {
	p, ready, transfer := desktopExecutionReadyFixture(t, "linux", "auto", "local")
	original, err := NewDesktopNodeChainExecutionAdoptionRecord(p, ready.Identity, transfer)
	if err != nil {
		t.Fatal(err)
	}
	faults := map[string]func(*DesktopNodeChainExecutionAdoptionRecord){
		"schema":             func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Schema++ },
		"kind":               func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Kind = "routervpn-node-chain-ready-v1" },
		"preparation-source": func(r *DesktopNodeChainExecutionAdoptionRecord) { r.PreparationSourceSHA256 = r.Identity.SourceSHA256 },
		"preparation-config": func(r *DesktopNodeChainExecutionAdoptionRecord) { r.PreparationConfigSHA256 = r.Identity.ConfigSHA256 },
		"physical-source":    func(r *DesktopNodeChainExecutionAdoptionRecord) { r.PhysicalSourceSHA256 = strings.Repeat("e", 64) },
		"transfer":           func(r *DesktopNodeChainExecutionAdoptionRecord) { r.TransferSHA256 = strings.Repeat("e", 64) },
		"session":            func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Identity.SessionID = strings.Repeat("e", 32) },
		"engine":             func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Identity.EngineID = "" },
		"network":            func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Identity.NetworkID = "" },
		"source":             func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Identity.SourceSHA256 = r.PreparationSourceSHA256 },
		"config":             func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Identity.ConfigSHA256 = r.PreparationConfigSHA256 },
		"listener":           func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Request.Port++ },
		"credential": func(r *DesktopNodeChainExecutionAdoptionRecord) {
			r.Request.Users[0].Password = strings.Repeat("e", 48)
		},
		"descriptor": func(r *DesktopNodeChainExecutionAdoptionRecord) { r.Server.DNSPolicySHA256 = strings.Repeat("e", 64) },
		"range":      func(r *DesktopNodeChainExecutionAdoptionRecord) { r.LastPort = 65536 },
	}
	raw, _ := json.Marshal(original)
	for name, mutate := range faults {
		t.Run(name, func(t *testing.T) {
			var r DesktopNodeChainExecutionAdoptionRecord
			if json.Unmarshal(raw, &r) != nil {
				t.Fatal("fixture")
			}
			mutate(&r)
			changed, _ := json.Marshal(r)
			if _, _, err := ParseDesktopNodeChainExecutionAdoptionRecord(changed, p.preparation, transfer); err == nil {
				t.Fatal("altered adoption accepted")
			}
		})
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), '\n'), append([]byte(`{"schema":1,`), raw[1:]...), append([]byte(`{"extra":true,`), raw[1:]...), []byte(strings.Repeat(" ", DesktopNodeChainExecutionAdoptionRecordLimit+1))} {
		if _, _, err := ParseDesktopNodeChainExecutionAdoptionRecord(bad, p.preparation, transfer); err == nil {
			t.Fatal("noncanonical adoption accepted")
		}
	}
	generic, err := NewNodeChainExecutionPreparation(p.preparation.LocalSource(), "auto")
	if err != nil {
		t.Fatal(err)
	}
	_, replacement, _ := desktopExecutionProjection(t, desktopExecutionSource(t, "auto", "https", true), "linux", strings.Repeat("e", 32), 0)
	for _, prep := range []*NodeChainExecutionPreparation{nil, generic, replacement} {
		if _, _, err := ParseDesktopNodeChainExecutionAdoptionRecord(raw, prep, transfer); err == nil {
			t.Fatal("foreign parent accepted original adoption")
		}
	}
}
