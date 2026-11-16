package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func desktopSOCKSExecutionFixture(t *testing.T, mode, authentication, target, execution string) (*DesktopNodeChainSOCKSPolicy, *NodeChainExecutionPreparation, NodeChainExecutionSource) {
	t.Helper()
	source, _, request := socksExecutionFixture(t, mode, authentication, execution)
	policy, err := NewDesktopNodeChainSOCKSPolicy(source, strings.Repeat("c", 32), target, 0)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewDesktopNodeChainSOCKSExecutionPreparation(policy, execution)
	if err != nil {
		t.Fatal("typed desktop preparation", err)
	}
	return policy, prep, request
}

func TestDesktopSOCKSExecutionOriginalPhysicalAndTransition(t *testing.T) {
	for ti, target := range []string{"linux", "windows", "darwin"} {
		for ai, authentication := range []string{"password", "none"} {
			for ei, setting := range []string{"server", "auto"} {
				mode := []string{"wg", "awg2-fast", "awg2-strong"}[(ti+ai+ei)%3]
				t.Run(target+"/"+mode+"/"+authentication+"/"+setting, func(t *testing.T) {
					original, prep, requested := desktopSOCKSExecutionFixture(t, mode, authentication, target, setting)
					physical, err := prep.SOCKSDesktopPhysicalPolicy()
					if err != nil {
						t.Fatal(err)
					}
					retained, err := physical.OriginalDesktopSOCKSPolicy()
					if err != nil || retained != original {
						t.Fatal("desktop original policy replaced", err)
					}
					native, err := prep.OriginalSOCKSSource()
					if err != nil || native != original.native || prep.local.socksSource != native || prep.local.nodes[0] != original.original.pair.nodes[0] || prep.local.nodes[2] != original.original.pair.nodes[1] {
						t.Fatal("original source or paired member replaced", err)
					}
					config, meta, capture, err := ReadDesktopPhysicalPolicy(physical)
					_, _, previous, priorErr := original.PhysicalReadValidated()
					if err != nil || priorErr != nil || config != prep.Config() || meta.Kind != "node-chain-socks-execution" || meta.TargetOS != target || meta.SessionID != original.inputs.sessionID || meta.SourceSHA256 != original.metadata.SourceSHA256 || meta.ConfigSHA256 != prep.ConfigSHA256() || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != SelectorTag || !reflect.DeepEqual(capture.PhysicalRoots, previous.PhysicalRoots) || !reflect.DeepEqual(capture.PrivateDestinations, previous.PrivateDestinations) || capture.ConfiguredMTU != previous.ConfiguredMTU {
						t.Fatal("execution changed original physical roots, DNS or MTU", err, priorErr)
					}
					execution, err := NewNodeChainSOCKSExecutionPolicy(prep, startJSON(t, requested))
					if err != nil {
						t.Fatal("typed desktop policy", err)
					}
					projection, err := prep.BindExecution(execution)
					if err != nil {
						t.Fatal("desktop transition", err)
					}
					adopted, err := projection.SOCKSDesktopPhysicalPolicy()
					if err != nil || adopted != physical {
						t.Fatal("transition changed original physical authority", err)
					}
					before, after := externalTestRead(t, prep.Config()), externalTestRead(t, projection.Config())
					if before["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || after["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || !reflect.DeepEqual(before["services"], after["services"]) {
						t.Fatal("transition opened gate or replaced physical service")
					}
					for _, proof := range native.metadata.Proofs {
						if !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, after, proof.Tag)) {
							t.Fatal("transition replaced original member", proof.Position)
						}
					}
					middle, final := externalTestFind(t, after, native.metadata.Proofs[1].Tag), externalTestFind(t, after, native.metadata.Proofs[2].Tag)
					if middle["type"] != "socks" || middle["udp_over_tcp"] != nil || final["udp_over_tcp"] != nil || final["detour"] != native.metadata.Proofs[1].Tag {
						t.Fatal("desktop replaced actual SOCKS association with CONNECT/UoT")
					}
					for _, parser := range []func(string) (*NodeChainExecutionPreparation, error){ParseNodeChainExecutionPreparation, ParseNodeChainSOCKSExecutionPreparation, ParseDesktopNodeChainCONNECTExecutionPreparation} {
						if _, err := parser(prep.Source()); err == nil {
							t.Fatal("another family adopted desktop SOCKS preparation")
						}
					}
					if _, err := prep.CONNECTDesktopPhysicalPolicy(); err == nil {
						t.Fatal("SOCKS borrowed CONNECT physical authority")
					}
					replayed, err := ParseDesktopNodeChainSOCKSExecutionPreparation(prep.Source())
					if err != nil || replayed.Source() != prep.Source() || replayed.Config() != prep.Config() || replayed.socks.source == prep.socks.source || replayed.socks.desktop.original == original {
						t.Fatal("fresh desktop parser changed source or borrowed original owner", err)
					}
					if _, err := replayed.BindExecution(execution); err == nil {
						t.Fatal("equal-content preparation borrowed original execution")
					}
				})
			}
		}
	}
}

func TestDesktopSOCKSExecutionOriginalReadRefusesReplacements(t *testing.T) {
	for _, fault := range []string{"original", "nil-preparation", "equal-preparation", "copied-preparation", "copied-physical", "copied-binding", "source", "policy", "capture"} {
		t.Run(fault, func(t *testing.T) {
			original, prep, _ := desktopSOCKSExecutionFixture(t, "wg", "password", "linux", "auto")
			physical, err := prep.SOCKSDesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			requested := prep
			switch fault {
			case "nil-preparation":
				requested = nil
			case "equal-preparation":
				requested, err = NewDesktopNodeChainSOCKSExecutionPreparation(original, "auto")
				if err != nil || requested.Source() != prep.Source() {
					t.Fatal("fixture lost independent identical preparation", err)
				}
			case "copied-preparation":
				copy := *prep
				requested = &copy
			case "copied-physical":
				copy := *physical
				physical = &copy
			case "copied-binding":
				copy := *prep.socks.desktop
				prep.socks.desktop = &copy
			case "source":
				original.original.sourceJSON += " "
			case "policy":
				original.inputs.restoredMTU = 1300
			case "capture":
				physical.owner.capture.ConfiguredMTU = 1300
			}
			owner, meta, err := physical.ReadOriginalValidated(requested)
			if fault != "original" {
				if err == nil || owner != nil || !reflect.DeepEqual(meta, DesktopNodeChainMetadata{}) {
					t.Fatal("SOCKS physical source read lent altered or replaced authority", fault, err)
				}
				return
			}
			if err != nil || owner != original || meta.SourceSHA256 != original.metadata.SourceSHA256 {
				t.Fatal("lost exact desktop original", err)
			}
			meta.Prefixes[0].ProfileID = "caller-replacement"
			meta.Roots[0].Tag = "caller-replacement"
			_, again, err := physical.ReadOriginalValidated(prep)
			if err != nil || !reflect.DeepEqual(again, original.metadata.DesktopNodeChainMetadata) {
				t.Fatal("mutable returned metadata changed original owner", err)
			}
		})
	}
}

func TestDesktopSOCKSExecutionRefusesSerializedDerivation(t *testing.T) {
	_, prep, _ := desktopSOCKSExecutionFixture(t, "awg2-strong", "password", "windows", "server")
	for _, fault := range []string{"source", "target", "session", "mtu", "physical-digest", "config-digest", "roots", "foreign-family", "extra-field", "canonical"} {
		t.Run(fault, func(t *testing.T) {
			value := startObject(t, prep.Source())
			metadata := value["desktop_socks"].(map[string]any)
			switch fault {
			case "source":
				value["local_source"] = value["local_source"].(string) + " "
			case "target":
				metadata["target_os"] = "linux"
			case "session":
				metadata["session_id"] = strings.Repeat("d", 32)
			case "mtu":
				metadata["restored_mtu"] = float64(1280)
			case "physical-digest":
				metadata["source_sha256"] = strings.Repeat("d", 64)
			case "config-digest":
				metadata["config_sha256"] = strings.Repeat("d", 64)
			case "roots":
				metadata["roots"] = []any{}
			case "foreign-family":
				value["desktop_connect"] = metadata
			case "extra-field":
				value["config"] = prep.Config()
			}
			input := startJSON(t, value)
			if fault == "canonical" {
				input = prep.Source() + "\n"
			}
			if _, err := ParseDesktopNodeChainSOCKSExecutionPreparation(input); err == nil {
				t.Fatal("serialized fields replaced original derivation", fault)
			}
		})
	}
	long, err := NewNodeChainSOCKSSource(startJSON(t, nodeChainSOCKSPrefixFixture(t, 2, "wg", "", "password")))
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewDesktopNodeChainSOCKSPolicy(long, strings.Repeat("b", 32), "linux", 0)
	if err != nil {
		t.Fatal("longer Local source fixture", err)
	}
	if _, err := NewDesktopNodeChainSOCKSExecutionPreparation(local, "server"); err == nil {
		t.Fatal("desktop execution silently widened the admitted SOCKS trio")
	}
}

func TestDesktopSOCKSExecutionExactPhysicalAnalysis(t *testing.T) {
	original, prep, _ := desktopSOCKSExecutionFixture(t, "awg2-fast", "password", "darwin", "auto")
	d := prep.socks.desktop
	tag := prep.ProofInventory()[0].Tag
	baseline := externalTestRead(t, original.native.config)
	baseline["route"].(map[string]any)["final"] = d.native.metadata.Proofs[2].Tag
	if _, err := d.physicalEgress(startJSON(t, baseline), tag); err != nil {
		t.Fatal("original captured physical analysis", err)
	}
	for _, fault := range []string{"root", "wrapper", "service", "direct-proxy", "extra-root", "foreign-entry"} {
		t.Run(fault, func(t *testing.T) {
			graph := externalTestRead(t, startJSON(t, baseline))
			entry := tag
			switch fault {
			case "root":
				root := d.metadata.Roots[0]
				for _, raw := range graph[root.Family].([]any) {
					row := raw.(map[string]any)
					if row["tag"] == root.Tag {
						row["detour"] = "foreign"
					}
				}
			case "wrapper":
				externalTestFind(t, graph, DesktopNodePhysicalTag)["session_id"] = strings.Repeat("f", 32)
			case "service":
				graph["services"].([]any)[0].(map[string]any)["source_sha256"] = strings.Repeat("f", 64)
			case "direct-proxy":
				delete(externalTestFind(t, graph, d.native.metadata.Proofs[1].Tag), "detour")
			case "extra-root":
				graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": DesktopNodePhysicalTag})
			case "foreign-entry":
				entry = d.native.metadata.Proofs[2].Tag
			}
			if _, err := d.physicalEgress(startJSON(t, graph), entry); err == nil {
				t.Fatal("changed physical owner accepted", fault)
			}
		})
	}
}
