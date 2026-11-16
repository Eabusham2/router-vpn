package mobilemultihop

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/routechoice"
)

func desktopExecutionReadyFixture(t *testing.T, target, execution, selected string) (*NodeChainExecutionProjection, DesktopNodeChainExecutionReadyRecord, string) {
	t.Helper()
	source := desktopExecutionSource(t, execution, "https", true)
	_, prep, p := desktopExecutionProjection(t, source, target, desktopNodeTestSession, 0)
	physical, err := p.DesktopPhysicalPolicy()
	if err != nil {
		t.Fatal(err)
	}
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
		progress.Prefixes = append(progress.Prefixes, NodeChainPrefixProgress{Position: proof.Position, ProfileID: proof.ProfileID, ResponseMS: 1.5, Proven: true})
	}
	transfer := strings.Repeat("c", 64)
	name := "router-vpn"
	if target == "darwin" {
		name = "utun9"
	}
	return p, DesktopNodeChainExecutionReadyRecord{Schema: 1, Kind: "routervpn-node-chain-execution-ready-v1", SourceSHA256: meta.SourceSHA256, PreparationSourceSHA256: prep.SourceSHA256(), PreparationConfigSHA256: prep.ConfigSHA256(), TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, Identity: NodeChainIdentity{EngineID: "original-box", SessionID: meta.SessionID, NetworkID: "original-network", SourceSHA256: p.SourceSHA256(), ConfigSHA256: p.ConfigSHA256()}, SelectionEpoch: 3, Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 9, MTU: 1280, ObservedAt: time.Now().UnixMilli(), Progress: progress}, transfer
}

func TestDesktopNodeChainExecutionReadyBindsActualProjection(t *testing.T) {
	for _, target := range []string{"windows", "linux", "darwin"} {
		for _, execution := range []string{"server", "auto"} {
			selected := execution
			if selected == "auto" {
				selected = "local"
			}
			t.Run(target+"/"+execution, func(t *testing.T) {
				p, r, transfer := desktopExecutionReadyFixture(t, target, execution, selected)
				raw, err := CanonicalDesktopNodeChainExecutionReadyRecord(r, p, transfer)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ParseDesktopNodeChainExecutionReadyRecord(raw, p, transfer); err != nil {
					t.Fatal(err)
				}
				if _, err = ParseDesktopNodeChainExecutionReadyRecord(append(raw, '\n'), p, transfer); err == nil {
					t.Fatal("noncanonical source accepted")
				}
				if _, err = ParseDesktopNodeChainExecutionReadyRecord(raw, p, strings.Repeat("d", 64)); err == nil {
					t.Fatal("foreign protection accepted")
				}
				original, _ := p.preparation.DesktopPhysicalPolicy()
				local, _ := original.OriginalDesktopPolicy()
				if _, err = ParseDesktopNodeChainReadyRecord(raw, local, transfer); err == nil {
					t.Fatal("execution heartbeat borrowed Local authority")
				}
			})
		}
	}
}

func TestDesktopNodeChainExecutionReadyRejectsChangedCapture(t *testing.T) {
	p, original, transfer := desktopExecutionReadyFixture(t, "linux", "server", "server")
	faults := map[string]func(*DesktopNodeChainExecutionReadyRecord){
		"kind":                func(r *DesktopNodeChainExecutionReadyRecord) { r.Kind = "routervpn-node-chain-ready-v1" },
		"physical":            func(r *DesktopNodeChainExecutionReadyRecord) { r.SourceSHA256 = strings.Repeat("d", 64) },
		"preparation":         func(r *DesktopNodeChainExecutionReadyRecord) { r.PreparationSourceSHA256 = r.Identity.SourceSHA256 },
		"construction-config": func(r *DesktopNodeChainExecutionReadyRecord) { r.PreparationConfigSHA256 = r.Identity.ConfigSHA256 },
		"source":              func(r *DesktopNodeChainExecutionReadyRecord) { r.Identity.SourceSHA256 = r.PreparationSourceSHA256 },
		"config":              func(r *DesktopNodeChainExecutionReadyRecord) { r.Identity.ConfigSHA256 = r.PreparationConfigSHA256 },
		"session":             func(r *DesktopNodeChainExecutionReadyRecord) { r.Identity.SessionID = "foreign" },
		"engine":              func(r *DesktopNodeChainExecutionReadyRecord) { r.Identity.EngineID = "" },
		"network":             func(r *DesktopNodeChainExecutionReadyRecord) { r.Identity.NetworkID = "" },
		"epoch":               func(r *DesktopNodeChainExecutionReadyRecord) { r.SelectionEpoch = 0 },
		"reader":              func(r *DesktopNodeChainExecutionReadyRecord) { r.Reader = 0 },
		"generation":          func(r *DesktopNodeChainExecutionReadyRecord) { r.Generation = 0 },
		"interface":           func(r *DesktopNodeChainExecutionReadyRecord) { r.InterfaceName = "utun9" },
		"index":               func(r *DesktopNodeChainExecutionReadyRecord) { r.InterfaceIndex = 0 },
		"mtu":                 func(r *DesktopNodeChainExecutionReadyRecord) { r.MTU = 9000 },
		"dns":                 func(r *DesktopNodeChainExecutionReadyRecord) { r.DNSConfigSHA256 = strings.Repeat("d", 64) },
		"unready":             func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Ready = false },
		"local-fallback":      func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Execution = "local" },
		"missing-prefix":      func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Prefixes = r.Progress.Prefixes[:1] },
		"foreign-prefix":      func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Prefixes[1].ProfileID = "foreign" },
		"unproved-prefix":     func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Prefixes[1].Proven = false },
		"nonfinite-prefix":    func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Prefixes[1].ResponseMS = math.NaN() },
		"false-kind":          func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Prefixes[1].Kind = "public-path" },
		"target":              func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Comparison.Target = "127.0.0.1" },
		"winner":              func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Comparison.Winner.ExitID = "foreign" },
		"unscored":            func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Comparison.Final.ScoreMS = nil },
		"false-score":         func(r *DesktopNodeChainExecutionReadyRecord) { *r.Progress.Comparison.Final.ScoreMS = 1 },
		"ineligible":          func(r *DesktopNodeChainExecutionReadyRecord) { r.Progress.Comparison.Final.Eligible = false },
	}
	raw, _ := json.Marshal(original)
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			var r DesktopNodeChainExecutionReadyRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			fault(&r)
			if r.Validate(p, transfer) == nil {
				t.Fatal("changed original capture accepted")
			}
		})
	}
}

func TestDesktopNodeChainExecutionReadyFreshCaptureRetainsOriginalGuards(t *testing.T) {
	for _, selected := range []string{"local", "server"} {
		t.Run(selected, func(t *testing.T) {
			p, record, transfer := desktopExecutionReadyFixture(t, "linux", "auto", selected)
			observation, err := p.readDesktopReadyCapture(selected)
			physical, physicalErr := p.DesktopPhysicalPolicy()
			_, meta, capture, captureErr := physical.PhysicalReadValidated()
			plan, planErr := p.MTUPlan()
			proofs, proofsErr := p.ProofInventory(selected)
			dns, dnsErr := p.DNSCapture(selected)
			if err != nil || physicalErr != nil || captureErr != nil || planErr != nil || proofsErr != nil || dnsErr != nil ||
				!reflect.DeepEqual(observation, desktopNodeChainExecutionReadyCapture{meta, capture, plan, proofs, dns}) {
				t.Fatal("fresh heartbeat read changed original physical, MTU, positional proof or selected DNS", err)
			}
			observation.proofs[0].ProfileID = "caller-replacement"
			observation.physical.PhysicalRoots[0].Tag = "caller-replacement"
			if err := record.Validate(p, transfer); err != nil {
				t.Fatal("fresh read exposed original mutable data", err)
			}
			faults := map[string]func() func(){
				"local-source": func() func() {
					old := p.policy.local.sourceJSON
					p.policy.local.sourceJSON += " "
					return func() { p.policy.local.sourceJSON = old }
				},
				"original-source": func() func() {
					old := p.preparation.desktop.original.sourceJSON
					p.preparation.desktop.original.sourceJSON += " "
					return func() { p.preparation.desktop.original.sourceJSON = old }
				},
				"derived-chain": func() func() {
					old := p.preparation.desktop.chain.sourceJSON
					p.preparation.desktop.chain.sourceJSON += " "
					return func() { p.preparation.desktop.chain.sourceJSON = old }
				},
				"physical-source": func() func() {
					old := physical.metadata.SourceSHA256
					physical.metadata.SourceSHA256 = strings.Repeat("e", 64)
					return func() { physical.metadata.SourceSHA256 = old }
				},
				"foreign-preparation-physical": func() func() {
					copy := *physical
					preparation := *p.preparation
					copy.preparation, preparation.desktopPhysical = &preparation, &copy
					p.preparation.desktopPhysical = &copy
					return func() { p.preparation.desktopPhysical = physical }
				},
				"server-proof": func() func() {
					old := p.policy.serverProofs[1].ProfileID
					p.policy.serverProofs[1].ProfileID = "replacement"
					return func() { p.policy.serverProofs[1].ProfileID = old }
				},
				"selected-dns": func() func() {
					old := p.policy.dns.ResolverSHA256
					p.policy.dns.ResolverSHA256 = strings.Repeat("e", 64)
					return func() { p.policy.dns.ResolverSHA256 = old }
				},
				"adopted-config": func() func() {
					old := p.config
					p.config += " "
					return func() { p.config = old }
				},
				"resealed-tun-transition": func() func() {
					old, seal := p.transition.TUNTag, p.seal
					p.transition.TUNTag = "replacement"
					p.seal = p.captureSeal()
					return func() { p.transition.TUNTag, p.seal = old, seal }
				},
			}
			for name, mutate := range faults {
				t.Run(name, func(t *testing.T) {
					restore := mutate()
					defer restore()
					if err := record.Validate(p, transfer); err == nil {
						t.Fatal("earlier valid heartbeat read lent authority to changed original state")
					}
				})
			}
			if err := record.Validate(p, transfer); err != nil {
				t.Fatal("restored original source no longer validates", err)
			}
		})
	}
}
