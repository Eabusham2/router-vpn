package mobilemultihop

import (
	"encoding/json"
	"router-vpn/internal/routechoice"
	"strings"
	"testing"
	"time"
)

func desktopOpenVPNExecutionReadyFixture(t *testing.T, target, setting, selected string, count int) (*NodeChainExecutionProjection, DesktopNodeChainOpenVPNExecutionReadyRecord, string) {
	t.Helper()
	_, prep, source := desktopOpenVPNExecutionFixture(t, count-2, "wg", "tcp", "", target, setting, 0)
	policy, err := NewNodeChainOpenVPNExecutionPolicy(prep, startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	p, err := prep.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	physical, _ := p.OpenVPNDesktopPhysicalPolicy()
	_, meta, capture, err := physical.PhysicalReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := p.ProofInventory(selected)
	if err != nil {
		t.Fatal(err)
	}
	choice := routechoice.Candidate{Execution: routechoice.Execution(selected), Transport: "ordered-node-chain", EntryID: proofs[0].ProfileID, ExitID: proofs[len(proofs)-1].ProfileID}
	score, err := routechoice.Score(choice, 2*time.Millisecond, 4*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	progress := NodeChainExecutionProgress{NodeChainProgress: NodeChainProgress{Stage: "selected", Complete: true, Ready: true, Execution: selected, DNSProven: true, PublicProven: true}, Comparison: routechoice.Result{Target: Targets[0], Winner: &choice, Final: &score}}
	for _, proof := range proofs {
		row := NodeChainPrefixProgress{Position: proof.Position, ProfileID: proof.ProfileID, ResponseMS: 1.5, Proven: true}
		if proof.Position == len(proofs)-2 {
			row.Kind, row.Label = "public-path", nodeChainOpenVPNExecutionPublicLabel
		}
		progress.Prefixes = append(progress.Prefixes, row)
	}
	transfer := strings.Repeat("c", 64)
	name := "router-vpn"
	if target == "darwin" {
		name = "utun9"
	}
	return p, DesktopNodeChainOpenVPNExecutionReadyRecord{Schema: 1, Kind: "routervpn-node-chain-openvpn-execution-ready-v1", SourceSHA256: meta.SourceSHA256, PreparationSourceSHA256: prep.SourceSHA256(), PreparationConfigSHA256: prep.ConfigSHA256(), TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, Identity: NodeChainIdentity{EngineID: "original-box", SessionID: meta.SessionID, NetworkID: "original-network", SourceSHA256: p.SourceSHA256(), ConfigSHA256: p.ConfigSHA256()}, SelectionEpoch: 3, Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 9, MTU: 1280, ObservedAt: time.Now().UnixMilli(), Progress: progress}, transfer
}
func TestDesktopOpenVPNExecutionCanonicalRecords(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, selected := range []string{"local", "server"} {
			t.Run(target+"-"+selected, func(t *testing.T) {
				p, r, transfer := desktopOpenVPNExecutionReadyFixture(t, target, "auto", selected, 3)
				adoption, err := NewDesktopNodeChainOpenVPNExecutionAdoptionRecord(p, r.Identity, transfer)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(adoption)
				q, id, err := ParseDesktopNodeChainOpenVPNExecutionAdoptionRecord(raw, p.preparation, transfer)
				if err != nil || id != r.Identity || q.preparation != p.preparation || q.Config() != p.Config() {
					t.Fatal("adoption lost original construction", err)
				}
				if _, _, err = ParseDesktopNodeChainExecutionAdoptionRecord(raw, p.preparation, transfer); err == nil {
					t.Fatal("generic adoption opened")
				}
				ready, err := CanonicalDesktopNodeChainOpenVPNExecutionReadyRecord(r, p, transfer)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ParseDesktopNodeChainOpenVPNExecutionAdoptedReadyRecord(ready, q, id, transfer); err != nil {
					t.Fatal(err)
				}
				if _, err = ParseDesktopNodeChainExecutionReadyRecord(ready, p, transfer); err == nil {
					t.Fatal("generic heartbeat opened")
				}
				for _, fault := range []string{"transfer", "identity", "noncanonical", "kind", "dns", "epoch", "proof", "score", "public-kind", "public-label", "private-public", "private-label", "missing-middle", "source", "construction", "mtu"} {
					t.Run(fault, func(t *testing.T) {
						changed := append([]byte(nil), ready...)
						identity := id
						token := transfer
						var x DesktopNodeChainOpenVPNExecutionReadyRecord
						json.Unmarshal(changed, &x)
						switch fault {
						case "transfer":
							token = strings.Repeat("d", 64)
						case "identity":
							identity.EngineID = "foreign"
						case "noncanonical":
							changed = append(changed, '\n')
						case "kind":
							x.Kind = "routervpn-node-chain-execution-ready-v1"
						case "dns":
							x.DNSConfigSHA256 = strings.Repeat("d", 64)
						case "epoch":
							x.SelectionEpoch = 0
						case "proof":
							x.Progress.Prefixes[1].Proven = false
						case "score":
							x.Progress.Comparison.Final.ScoreMS = nil
						case "public-kind":
							x.Progress.Prefixes[len(x.Progress.Prefixes)-2].Kind = "private-node"
						case "public-label":
							x.Progress.Prefixes[len(x.Progress.Prefixes)-2].Label = ""
						case "private-public":
							x.Progress.Prefixes[0].Kind = "public-path"
						case "private-label":
							x.Progress.Prefixes[0].Label = nodeChainOpenVPNExecutionPublicLabel
						case "missing-middle":
							x.Progress.Prefixes = x.Progress.Prefixes[:len(x.Progress.Prefixes)-1]
						case "source":
							x.Identity.SourceSHA256 = strings.Repeat("d", 64)
						case "construction":
							x.PreparationSourceSHA256 = strings.Repeat("d", 64)
						case "mtu":
							x.MTU = 9000
						}
						if fault != "noncanonical" {
							changed, _ = json.Marshal(x)
						}
						if _, err := ParseDesktopNodeChainOpenVPNExecutionAdoptedReadyRecord(changed, q, identity, token); err == nil {
							t.Fatal("foreign or incomplete selected receipt accepted")
						}
					})
				}
			})
		}
	}
}

func TestDesktopOpenVPNExecutionMaximumRecords(t *testing.T) {
	for _, selected := range []string{"local", "server"} {
		t.Run(selected, func(t *testing.T) {
			p, r, transfer := desktopOpenVPNExecutionReadyFixture(t, "linux", "auto", selected, 8)
			raw, err := CanonicalDesktopNodeChainOpenVPNExecutionReadyRecord(r, p, transfer)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Progress.Prefixes) != 8 || r.Progress.Prefixes[6].Kind != "public-path" {
				t.Fatal("complete original prefix omitted")
			}
			if _, err = ParseDesktopNodeChainOpenVPNExecutionReadyRecord(raw, p, transfer); err != nil {
				t.Fatal(err)
			}
			adoption, err := NewDesktopNodeChainOpenVPNExecutionAdoptionRecord(p, r.Identity, transfer)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(adoption)
			q, id, err := ParseDesktopNodeChainOpenVPNExecutionAdoptionRecord(encoded, p.preparation, transfer)
			if err != nil || q.preparation != p.preparation || id != r.Identity {
				t.Fatal("original prefix adoption replaced", err)
			}
			for _, parser := range []func([]byte, *NodeChainExecutionPreparation, string) (*NodeChainExecutionProjection, NodeChainIdentity, error){ParseDesktopNodeChainSOCKSExecutionAdoptionRecord, ParseDesktopNodeChainCONNECTExecutionAdoptionRecord} {
				if _, _, err := parser(encoded, p.preparation, transfer); err == nil {
					t.Fatal("foreign family accepted OpenVPN adoption")
				}
			}
			// The fresh read keeps the original owner checks even though each
			// public getter no longer repeats the same complete validation.
			for _, fault := range []string{"source", "native", "physical", "original", "projection", "dns"} {
				t.Run("owner-"+fault, func(t *testing.T) {
					owner := p.preparation.openvpn.desktop
					var restore func()
					switch fault {
					case "source":
						original := owner.source.sourceJSON
						owner.source.sourceJSON += " "
						restore = func() { owner.source.sourceJSON = original }
					case "native":
						original := owner.native.config
						owner.native.config += " "
						restore = func() { owner.native.config = original }
					case "physical":
						original := owner.physical
						copy := *original
						owner.physical = &copy
						restore = func() { owner.physical = original }
					case "original":
						original := owner.original
						copy := *original
						owner.original = &copy
						restore = func() { owner.original = original }
					case "projection":
						original := p.config
						p.config += " "
						restore = func() { p.config = original }
					case "dns":
						original := owner.capture.SelectedDNS.Detour
						owner.capture.SelectedDNS.Detour = "foreign"
						restore = func() { owner.capture.SelectedDNS.Detour = original }
					}
					defer restore()
					if _, err := p.readOpenVPNDesktopReadyCapture(selected); err == nil || r.Validate(p, transfer) == nil {
						t.Fatal("fresh OpenVPN heartbeat accepted changed original owner", fault)
					}
					if _, _, _, _, _, _, err := owner.physical.ReadExecutionValidated(p.preparation); fault != "projection" && err == nil {
						t.Fatal("fresh OpenVPN physical read accepted changed original owner", fault)
					}
					restore()
					if r.Validate(p, transfer) != nil {
						t.Fatal("original OpenVPN heartbeat could not retry")
					}
				})
			}
			t.Run("copied-output", func(t *testing.T) {
				owner := p.preparation.openvpn.desktop
				original, source, metadata, config, physical, capture, err := owner.physical.ReadExecutionValidated(p.preparation)
				if err != nil || original != owner.original || source != owner.source || config != p.preparation.Config() || physical.ConfigSHA256 != p.preparation.ConfigSHA256() {
					t.Fatal("combined OpenVPN read replaced original construction", err)
				}
				metadata.Prefixes[0].ProfileID = "foreign"
				metadata.Roots[0].Tag = "foreign"
				capture.SelectedDNS.Detour = "foreign"
				read, err := p.readOpenVPNDesktopReadyCapture(selected)
				if err != nil {
					t.Fatal(err)
				}
				read.proofs[0].ProfileID = "foreign"
				read.physical.SelectedDNS.Detour = "foreign"
				if r.Validate(p, transfer) != nil {
					t.Fatal("OpenVPN read leaked mutable proof or physical capture")
				}
			})
			for _, fault := range []string{"server-source", "server-key", "transfer", "kind", "noncanonical"} {
				t.Run(fault, func(t *testing.T) {
					var x DesktopNodeChainOpenVPNExecutionAdoptionRecord
					if err := json.Unmarshal(encoded, &x); err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "server-source":
						x.Server.Members[len(x.Server.Members)-2].SourceSHA256 = strings.Repeat("d", 64)
					case "server-key":
						x.Request.Users[0].Password = strings.Repeat("x", 32)
					case "transfer":
						x.TransferSHA256 = strings.Repeat("d", 64)
					case "kind":
						x.Kind = "routervpn-node-chain-execution-adoption-v1"
					}
					changed, _ := json.Marshal(x)
					if fault == "noncanonical" {
						changed = append(changed, '\n')
					}
					if _, _, err := ParseDesktopNodeChainOpenVPNExecutionAdoptionRecord(changed, p.preparation, transfer); err == nil {
						t.Fatal("changed original source accepted")
					}
				})
			}
		})
	}
}
