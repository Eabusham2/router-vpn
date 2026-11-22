package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func multipleImportedExecutionFixture(t *testing.T, layout nodeChainImportedLayout, mode, layer, execution, target string) (*NodeChain, *NodeChainExecutionPreparation, NodeChainExecutionSource) {
	t.Helper()
	server, original, capture := multipleImportedServerFixture(t, layout, mode, layer)
	var err error
	if target != "" {
		original, err = ProjectNodeChain(original, target, 1280)
		if err != nil {
			t.Fatal(err)
		}
	}
	prep, err := NewNodeChainMultipleImportedExecutionPreparation(original, execution)
	if err != nil {
		t.Fatal("typed original preparation", err)
	}
	request := capture.Request.Clone()
	closure, err := nodeMultihopPredecessor(original.nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	addresses := closure.final["address"].([]any)
	prefix, err := netip.ParsePrefix(addresses[0].(string))
	if err != nil {
		t.Fatal(err)
	}
	request.Peer = prefix.Addr().String()
	request.Port = 32003
	return original, prep, NodeChainExecutionSource{Schema: 6, Execution: execution, LocalSource: original.sourceJSON, Server: server.Descriptor(), Request: request, FirstPort: 32000, LastPort: 32007}
}

func TestNodeChainMultipleImportedExecutionOriginalWG(t *testing.T) {
	testMultipleImportedExecutionOriginal(t, "wg")
}
func TestNodeChainMultipleImportedExecutionOriginalFast(t *testing.T) {
	testMultipleImportedExecutionOriginal(t, "awg2-fast")
}
func TestNodeChainMultipleImportedExecutionOriginalStrong(t *testing.T) {
	testMultipleImportedExecutionOriginal(t, "awg2-strong")
}
func testMultipleImportedExecutionOriginal(t *testing.T, mode string) {
	for index, layout := range multipleImportedServerLayouts {
		for _, execution := range []string{"server", "auto"} {
			t.Run(layout.name+"/"+execution, func(t *testing.T) {
				layer := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[index%3]
				original, prep, source := multipleImportedExecutionFixture(t, layout, mode, layer, execution, "")
				retained, err := prep.OriginalMultipleImportedSource()
				if err != nil || retained != original || !prep.RequiresMultipleImportedExecutionObserver() {
					t.Fatal("original pointer replaced", err)
				}
				replay, err := ParseNodeChainMultipleImportedExecutionPreparation(prep.Source())
				if err != nil || replay.Config() != prep.Config() || replay.local == original {
					t.Fatal("sealed independent replay", err)
				}
				policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
				if err != nil {
					t.Fatal("original typed policy", err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal("same-owner projection", err)
				}
				if _, err := replay.BindExecution(policy); err == nil {
					t.Fatal("equal-content owner borrowed")
				}
				before, after := externalTestRead(t, original.Config()), externalTestRead(t, projection.Config())
				for _, proof := range original.ProofInventory() {
					if !reflect.DeepEqual(externalTestFind(t, before, proof.Tag), externalTestFind(t, after, proof.Tag)) {
						t.Fatal("original transport replaced", proof.Position)
					}
				}
				if after["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
					t.Fatal("application gate bypass")
				}
				physical, err := projection.PhysicalEgress()
				expected, _ := original.PhysicalEgress()
				if err != nil || !reflect.DeepEqual(physical, expected) {
					t.Fatal("physical authority changed", err)
				}
				for _, selected := range []string{"local", "server"} {
					captured, ipv6, err := projection.ImportedPublicMeasurementCaptures(selected)
					originals, originalV6, _ := original.PublicMeasurementCaptures()
					if err != nil || len(captured) != len(layout.positions) || ipv6 != originalV6 {
						t.Fatal("plural inventory", err)
					}
					proofs, err := projection.ProofInventory(selected)
					if err != nil {
						t.Fatal(err)
					}
					for i, c := range captured {
						if c.Position != originals[i].Position || c.SourceSHA256 != originals[i].SourceSHA256 || c.Tag != proofs[c.Position].Tag || selected == "server" && c.Tag == originals[i].Tag {
							t.Fatal("public position/source/tag changed")
						}
					}
					captured[0].Tag = "foreign"
					again, _, err := projection.ImportedPublicMeasurementCaptures(selected)
					if err != nil || again[0].Tag == "foreign" {
						t.Fatal("mutable public receipt escaped")
					}
					dns, err := projection.DNSCapture(selected)
					if err != nil || dns.DNS.ResolverTag != original.dns.ResolverTag || dns.DNS.FinalTag != SelectorTag || dns.SelectedTag != proofs[len(proofs)-1].Tag {
						t.Fatal("selected DNS", err)
					}
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedExecutionSealedMobile(t *testing.T) {
	for _, target := range []string{"ios", "android"} {
		for _, execution := range []string{"server", "auto"} {
			t.Run(target+"/"+execution, func(t *testing.T) {
				original, prep, source := multipleImportedExecutionFixture(t, multipleImportedServerLayouts[2], "wg", "", execution, target)
				snapshot := original.importedNodes.localSeal
				if !snapshot.matches(original) || snapshot.projection.TargetOS != target {
					t.Fatal("mobile source retained the pre-projection seal")
				}
				original.importedNodes.localSeal = nil
				if original.captureSeal() != snapshot.seal || original.seal != snapshot.seal {
					t.Fatal("original projected bytes and capture seal differ")
				}
				original.importedNodes.localSeal = snapshot
				launch, err := original.LaunchInput()
				if err != nil || launch != prep.source.MultipleImportedLocalLaunch {
					t.Fatal("sealed original launch dropped", err)
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal([]byte(prep.Source()), &fields) != nil || len(fields) != 4 {
					t.Fatal("mobile source shape")
				}
				replay, err := ParseNodeChainMultipleImportedExecutionPreparation(prep.Source())
				if err != nil || replay.local.projection != original.projection || replay.Config() != prep.Config() {
					t.Fatal("mobile projection lost", err)
				}
				policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := prep.BindExecution(policy); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedExecutionSourceRefusals(t *testing.T) {
	_, prep, _ := multipleImportedExecutionFixture(t, multipleImportedServerLayouts[2], "wg", "", "auto", "ios")
	cases := map[string]func(map[string]any){
		"schema": func(v map[string]any) { v["schema"] = 1 }, "execution": func(v map[string]any) { v["execution"] = "local" },
		"source": func(v map[string]any) { v["local_source"] = v["local_source"].(string) + " " }, "missing-launch": func(v map[string]any) { delete(v, "multiple_imported_local_launch") },
		"empty-launch": func(v map[string]any) { v["multiple_imported_local_launch"] = "" }, "raw-source-launch": func(v map[string]any) { v["multiple_imported_local_launch"] = v["local_source"] },
		"empty-openvpn": func(v map[string]any) { v["openvpn_local_launch"] = "" }, "foreign-openvpn": func(v map[string]any) { v["openvpn_local_launch"] = v["multiple_imported_local_launch"] },
		"null-desktop": func(v map[string]any) { v["desktop"] = nil }, "empty-last": func(v map[string]any) { v["desktop_last"] = "" },
		"desktop-multiple": func(v map[string]any) { v["desktop_multiple_imported"] = map[string]any{} }, "unknown": func(v map[string]any) { v["extra"] = true },
		"launch-mtu": func(v map[string]any) {
			x := externalTestRead(t, v["multiple_imported_local_launch"].(string))
			x["restored_mtu"] = 1400
			v["multiple_imported_local_launch"] = startJSON(t, x)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := externalTestRead(t, prep.Source())
			mutate(v)
			if _, err := ParseNodeChainMultipleImportedExecutionPreparation(multipleImportedPreparationFixtureJSON(t, v)); err == nil {
				t.Fatal("altered/cross-family source admitted")
			}
		})
	}
}

func TestNodeChainMultipleImportedExecutionLegacyClosed(t *testing.T) {
	original, prep, source := multipleImportedExecutionFixture(t, multipleImportedServerLayouts[0], "wg", "", "auto", "")
	cases := map[string]func() error{
		"generic-prep":   func() error { _, e := NewNodeChainExecutionPreparation(original.sourceJSON, "auto"); return e },
		"generic-parser": func() error { _, e := ParseNodeChainExecutionPreparation(prep.Source()); return e },
		"openvpn-parser": func() error { _, e := ParseNodeChainOpenVPNExecutionPreparation(prep.Source()); return e },
		"generic-policy": func() error { _, e := NewNodeChainExecutionPolicy(startJSON(t, source)); return e },
		"generic-launch": func() error {
			p, e := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
			if e != nil {
				return e
			}
			_, e = p.LaunchInput()
			return e
		},
		"singleton-capture": func() error {
			p, e := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
			if e != nil {
				return e
			}
			v, e := prep.BindExecution(p)
			if e != nil {
				return e
			}
			_, _, e = v.ImportedPublicMeasurementCapture("local")
			return e
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if f() == nil {
				t.Fatal("legacy constructor widened")
			}
		})
	}
}

func TestNodeChainMultipleImportedExecutionDescriptorRefusals(t *testing.T) {
	cases := map[string]func(*NodeChainExecutionSource){
		"missing-public": func(s *NodeChainExecutionSource) {
			s.Server.Members = append(s.Server.Members[:1], s.Server.Members[2:]...)
		},
		"reordered": func(s *NodeChainExecutionSource) {
			s.Server.Members[0], s.Server.Members[2] = s.Server.Members[2], s.Server.Members[0]
		},
		"source-substitute":    func(s *NodeChainExecutionSource) { s.Server.Members[0].SourceSHA256 = strings.Repeat("a", 64) },
		"public-IP":            func(s *NodeChainExecutionSource) { s.Server.Members[0].ExpectedPublicIP = "198.51.100.99" },
		"public-private-proof": func(s *NodeChainExecutionSource) { s.Server.Members[0].NodeID = strings.Repeat("b", 64) },
		"packet-key": func(s *NodeChainExecutionSource) {
			s.Request.LocalPacketPublicKeys[0] = s.Server.Members[1].ServerPublicKey
		},
		"packet-position": func(s *NodeChainExecutionSource) { s.Request.LocalPacketPositions[1] = 1 },
		"DNS":             func(s *NodeChainExecutionSource) { s.Server.DNSPolicySHA256 = strings.Repeat("c", 64) },
		"front-port":      func(s *NodeChainExecutionSource) { s.Request.Port = 1 }, "source-bytes": func(s *NodeChainExecutionSource) { s.LocalSource += " " },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, p, s := multipleImportedExecutionFixture(t, multipleImportedServerLayouts[2], "wg", "", "auto", "")
			mutate(&s)
			if d, e := s.Server.Digest(); e == nil {
				s.Request.DescriptorSHA256 = d
				s.Request.DNSPolicySHA256 = s.Server.DNSPolicySHA256
			}
			if _, e := NewNodeChainMultipleImportedExecutionPolicy(p, startJSON(t, s)); e == nil {
				t.Fatal("foreign or incomplete original inventory admitted")
			}
		})
	}
}

type multipleImportedExecutionObserverTest struct {
	source *NodeChain
	err    error
	after  func()
	calls  int
}

func (e *multipleImportedExecutionObserverTest) ObserveMultipleImportedExecutionContext(ctx context.Context, original *NodeChain) error {
	e.calls++
	if original != e.source {
		return errors.New("foreign original source")
	}
	if e.after != nil {
		e.after()
	}
	return e.err
}
func TestNodeChainMultipleImportedExecutionOriginalOwners(t *testing.T) {
	cases := map[string]func(*NodeChainExecutionPreparation){
		"binding-copy":  func(p *NodeChainExecutionPreparation) { c := *p.multiple; p.multiple = &c },
		"source-copy":   func(p *NodeChainExecutionPreparation) { c := *p.local; p.local = &c },
		"registry-copy": func(p *NodeChainExecutionPreparation) { c := *p.local.importedNodes; p.local.importedNodes = &c },
		"member-copy": func(p *NodeChainExecutionPreparation) {
			c := *p.local.importedNodes.members[1]
			p.local.importedNodes.members[1] = &c
		},
		"policy-copy": func(p *NodeChainExecutionPreparation) {
			m := p.local.importedSSMemberAt(1)
			c := *m.policy
			m.policy = &c
		},
		"launch":      func(p *NodeChainExecutionPreparation) { p.source.MultipleImportedLocalLaunch += " " },
		"source-seal": func(p *NodeChainExecutionPreparation) { p.local.seal = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			original, p, _ := multipleImportedExecutionFixture(t, multipleImportedServerLayouts[2], "wg", "", "auto", "")
			e := &multipleImportedExecutionObserverTest{source: original}
			if err := p.observeMultipleImportedExecutionContext(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			e.after = func() { mutate(p) }
			if err := p.observeMultipleImportedExecutionContext(context.Background(), e); err == nil {
				t.Fatal("owner substitution survived observation")
			}
		})
	}
}

// Keep the enclosing canonical order so known-field faults cannot pass merely
// because map marshaling reordered the preparation. Preserve explicit omitted
// fields (including empty/null values) as actual present cross-family inputs.
func multipleImportedPreparationFixtureJSON(t *testing.T, fields map[string]any) string {
	t.Helper()
	raw := startJSON(t, fields)
	var typed NodeChainExecutionPreparationSource
	if json.Unmarshal([]byte(raw), &typed) != nil {
		t.Fatal("fixture source")
	}
	canonical := startJSON(t, typed)
	var present map[string]json.RawMessage
	if json.Unmarshal([]byte(canonical), &present) != nil {
		t.Fatal("fixture canonical source")
	}
	for key, value := range fields {
		if _, ok := present[key]; ok {
			continue
		}
		k, _ := json.Marshal(key)
		v, _ := json.Marshal(value)
		canonical = strings.TrimSuffix(canonical, "}") + "," + string(k) + ":" + string(v) + "}"
	}
	return canonical
}

func TestNodeChainMultipleImportedExecutionNativeFixtures(t *testing.T) {
	for _, layout := range multipleImportedServerLayouts {
		t.Run(layout.name, func(t *testing.T) {
			server, original, _ := multipleImportedServerFixture(t, layout, "wg", "")
			launch, err := original.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			if dir := os.Getenv("ROUTERVPN_MULTIPLE_IMPORTED_EXECUTION_NATIVE_FIXTURES"); dir != "" {
				data, err := json.Marshal(struct {
					Local  string `json:"local"`
					Server string `json:"server"`
				}{launch, server.Source()})
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, layout.name+".json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// Each saved digest must be identical to fresh canonical serialization. A
// changed scalar, item, nested value or owner still reaches the original checks.
func TestNodeChainMultipleImportedExecutionOriginalSealInputs(t *testing.T) {
	for _, field := range []string{"source", "config", "setting", "discovery", "dns", "physical", "local-json", "local-proof", "local-dns", "local-physical", "local-projection", "registry-input", "member-input", "member-selection", "policy-capture", "policy-config", "policy-owner"} {
		t.Run(field, func(t *testing.T) {
			original, p, _ := multipleImportedExecutionFixture(t, multipleImportedServerLayouts[1], "wg", "", "auto", "")
			b, r := p.multiple, original.importedNodes
			member := r.members[1]
			if b.originalSeal == nil || r.localSeal == nil || r.inputSeal == nil || member.multipleSeal == nil || !member.multipleSeal.matches(member) {
				t.Fatal("original selection was not frozen")
			}
			initialPrep, initialLocal, initialRegistry := p.captureSeal(), original.captureSeal(), r.captureSeal()
			prepSnapshot, localSnapshot, registrySnapshot := b.originalSeal, r.localSeal, r.inputSeal
			b.originalSeal, r.localSeal, r.inputSeal = nil, nil, nil
			if p.captureSeal() != initialPrep || original.captureSeal() != initialLocal || r.captureSeal() != initialRegistry {
				t.Fatal("saved digest disagrees with original canonical bytes")
			}
			b.originalSeal, r.localSeal, r.inputSeal = prepSnapshot, localSnapshot, registrySnapshot
			switch field {
			case "source":
				p.sourceJSON += " "
			case "config":
				p.config += " "
			case "setting":
				p.source.Execution = "server"
			case "discovery":
				p.discovery.Token += "x"
			case "dns":
				p.dns.DNS.ResolverTag += "x"
			case "physical":
				p.physical[0].Port++
			case "local-json":
				original.sourceJSON += " "
			case "local-proof":
				original.proofs[1].SourceSHA256 = original.proofs[0].SourceSHA256
			case "local-dns":
				original.dns.ResolverTag += "x"
			case "local-physical":
				original.physical[0].Port++
			case "local-projection":
				original.projection.RestoredMTU++
			case "registry-input":
				r.inputs[1] += " "
			case "member-input":
				member.input += " "
			case "member-selection":
				member.selection.Profile["id"] = "changed-original"
			case "policy-capture":
				member.policy.capture.ExpectedPublicIP = "198.51.100.233"
			case "policy-config":
				member.policy.config += " "
			case "policy-owner":
				clone := *member.policy
				member.policy = &clone
			}
			if p.validateCapture() == nil {
				t.Fatal("changed original accepted", field)
			}
			derivedPrep, derivedLocal, derivedRegistry := p.captureSeal(), original.captureSeal(), r.captureSeal()
			b.originalSeal, r.localSeal, r.inputSeal = nil, nil, nil
			if p.captureSeal() != derivedPrep || original.captureSeal() != derivedLocal || r.captureSeal() != derivedRegistry {
				t.Fatal("changed digest diverged from full canonical bytes")
			}
			member.multipleSeal = nil
			if p.validateCapture() == nil {
				t.Fatal("test did not change the original full validation")
			}
		})
	}
}
