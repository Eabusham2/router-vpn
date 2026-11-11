package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopNodeChainReadyRequiresCompletePhysicalAndProofIdentity(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			policy := desktopChainPolicy(t, desktopChainFixture(t, 3, "", nil), target, 0)
			_, meta, capture, err := policy.ReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			transfer := strings.Repeat("a", 64)
			name := "router-vpn"
			if target == "darwin" {
				name = "utun7"
			}
			record := DesktopNodeChainReadyRecord{Schema: 1, Kind: "routervpn-node-chain-ready-v1",
				SourceSHA256: meta.SourceSHA256, TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256,
				Identity: NodeChainIdentity{EngineID: "original-native-engine", SessionID: meta.SessionID,
					NetworkID: "original-network", SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256},
				Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 17, MTU: capture.ConfiguredMTU, ObservedAt: 1234}
			raw, err := CanonicalDesktopNodeChainReadyRecord(record, policy, transfer)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseDesktopNodeChainReadyRecord(raw, policy, transfer)
			if err != nil || parsed != record {
				t.Fatal("exact chain heartbeat lost identity", err)
			}
			for name, change := range map[string]func(*DesktopNodeChainReadyRecord){
				"schema":     func(r *DesktopNodeChainReadyRecord) { r.Schema++ },
				"family":     func(r *DesktopNodeChainReadyRecord) { r.Kind = "routervpn-node-ready-v1" },
				"physical":   func(r *DesktopNodeChainReadyRecord) { r.SourceSHA256 = meta.OriginalSourceSHA256 },
				"transfer":   func(r *DesktopNodeChainReadyRecord) { r.TransferSHA256 = strings.Repeat("b", 64) },
				"dns":        func(r *DesktopNodeChainReadyRecord) { r.DNSConfigSHA256 = strings.Repeat("b", 64) },
				"engine":     func(r *DesktopNodeChainReadyRecord) { r.Identity.EngineID = "" },
				"session":    func(r *DesktopNodeChainReadyRecord) { r.Identity.SessionID = strings.Repeat("b", 32) },
				"network":    func(r *DesktopNodeChainReadyRecord) { r.Identity.NetworkID = "\noriginal-network" },
				"order":      func(r *DesktopNodeChainReadyRecord) { r.Identity.SourceSHA256 = meta.SourceSHA256 },
				"config":     func(r *DesktopNodeChainReadyRecord) { r.Identity.ConfigSHA256 = strings.Repeat("b", 64) },
				"generation": func(r *DesktopNodeChainReadyRecord) { r.Generation = 0 },
				"reader":     func(r *DesktopNodeChainReadyRecord) { r.Reader = 0 },
				"interface":  func(r *DesktopNodeChainReadyRecord) { r.InterfaceName = "foreign-tun" },
				"index":      func(r *DesktopNodeChainReadyRecord) { r.InterfaceIndex = 0 },
				"mtu-low":    func(r *DesktopNodeChainReadyRecord) { r.MTU = 1279 },
				"mtu-prefix": func(r *DesktopNodeChainReadyRecord) {
					plan, _ := policy.NodeChain().MTUPlan()
					r.MTU = plan.Ceiling + 1
				},
				"time": func(r *DesktopNodeChainReadyRecord) { r.ObservedAt = 0 },
			} {
				t.Run(name, func(t *testing.T) {
					altered := record
					change(&altered)
					if altered.Validate(policy, transfer) == nil {
						t.Fatal("altered chain heartbeat accepted")
					}
				})
			}
			for name, altered := range map[string][]byte{
				"newline":       append(append([]byte(nil), raw...), '\n'),
				"unknown":       bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unused":true`), 1),
				"duplicate":     bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
				"identity-null": bytes.Replace(raw, []byte(`"engine_id":"original-native-engine"`), []byte(`"engine_id":null`), 1),
			} {
				t.Run(name, func(t *testing.T) {
					if _, err := ParseDesktopNodeChainReadyRecord(altered, policy, transfer); err == nil {
						t.Fatal("noncanonical chain heartbeat accepted")
					}
				})
			}
			// MTU replacement preserves the sealed executable source. The caller
			// must additionally match these observed values to its original owner.
			replaced := record
			replaced.Reader++
			replaced.Generation++
			replaced.InterfaceIndex++
			if target == "darwin" {
				replaced.InterfaceName = "utun8"
			}
			replaced.MTU = 1280
			replaced.ObservedAt++
			replacement, err := CanonicalDesktopNodeChainReadyRecord(replaced, policy, transfer)
			if err != nil || bytes.Equal(raw, replacement) || replaced.Identity != record.Identity {
				t.Fatal("MTU reader changed sealed source identity", err)
			}
			var object map[string]any
			if json.Unmarshal(raw, &object) != nil || len(object) != 12 {
				t.Fatal("heartbeat shape drifted")
			}
		})
	}
}

func desktopChainReadyTargetFixture(t *testing.T, chain *NodeChain, target string) (*DesktopNodeChainPolicy, DesktopNodeChainReadyRecord, string) {
	t.Helper()
	policy := desktopChainPolicy(t, chain, target, 0)
	_, meta, capture, err := policy.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	name := "router-vpn"
	if target == "darwin" {
		name = "utun7"
	}
	transfer := strings.Repeat("a", 64)
	record := DesktopNodeChainReadyRecord{Schema: 1, Kind: "routervpn-node-chain-ready-v1",
		SourceSHA256: meta.SourceSHA256, TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256,
		Identity: NodeChainIdentity{EngineID: "original-native-engine", SessionID: meta.SessionID,
			NetworkID: "original-network", SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256},
		Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 17, MTU: capture.ConfiguredMTU, ObservedAt: 1234}
	if err := record.Validate(policy, transfer); err != nil {
		t.Fatal("target fixture lacks an actual validated original policy", err)
	}
	return policy, record, transfer
}

func TestDesktopNodeChainReadyInterfaceNamesFollowCapturedTarget(t *testing.T) {
	chain := desktopChainFixture(t, 3, "", nil)
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			policy, record, transfer := desktopChainReadyTargetFixture(t, chain, target)
			accepted := []string{"router-vpn"}
			if target == "darwin" {
				accepted = []string{"utun0", "utun7", "utun1024"}
			}
			for _, name := range accepted {
				t.Run("accepted-"+name, func(t *testing.T) {
					selected := record
					selected.InterfaceName = name
					raw, err := CanonicalDesktopNodeChainReadyRecord(selected, policy, transfer)
					if err != nil {
						t.Fatal("original target lost its native interface shape", err)
					}
					got, err := ParseDesktopNodeChainReadyRecord(raw, policy, transfer)
					if err != nil || got != selected {
						t.Fatal("native interface observation changed during canonical replay", err)
					}
				})
			}
			rejected := []struct{ name, value string }{
				{"empty", ""}, {"pair-alias", "router-vpn-multihop"},
				{"physical", "en0"}, {"loopback", "lo0"}, {"tun-alias", "tun0"},
				{"missing-unit", "utun"}, {"negative-unit", "utun-1"}, {"signed-unit", "utun+1"},
				{"wrong-case", "UTUN7"}, {"mixed-case", "uTun7"}, {"extra-prefix", "xutun7"},
				{"extra-suffix", "utun7x"}, {"slash", "utun/7"}, {"colon", "utun7:1"},
				{"space-prefix", " utun7"}, {"space-suffix", "utun7 "}, {"newline", "utun7\n"},
				{"nul", "utun7\x00"}, {"unicode-unit", "utun٧"}, {"fullwidth-unit", "utun７"},
			}
			if target == "darwin" {
				rejected = append(rejected, struct{ name, value string }{"fixed-alias", "router-vpn"})
			} else {
				rejected = append(rejected,
					struct{ name, value string }{"darwin-zero", "utun0"},
					struct{ name, value string }{"darwin-allocated", "utun7"})
			}
			for _, test := range rejected {
				t.Run("rejected-"+test.name, func(t *testing.T) {
					changed := record
					changed.InterfaceName = test.value
					if changed.Validate(policy, transfer) == nil {
						t.Fatal("foreign or malformed interface acquired original target authority")
					}
					// Bypass the canonical writer only to exercise the real decoder's
					// rejection of a well-formed JSON record with a wrong native name.
					raw, err := json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := ParseDesktopNodeChainReadyRecord(raw, policy, transfer); err == nil {
						t.Fatal("canonical replay admitted another target's native interface")
					}
				})
			}
		})
	}
}

func TestDesktopNodeChainReadyRejectsSubstitutedTargetAuthority(t *testing.T) {
	chain := desktopChainFixture(t, 3, "", nil)
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			policy, original, transfer := desktopChainReadyTargetFixture(t, chain, target)
			for _, other := range []string{"linux", "windows", "darwin"} {
				if other == target {
					continue
				}
				t.Run("foreign-"+other, func(t *testing.T) {
					foreign, template, _ := desktopChainReadyTargetFixture(t, chain, other)
					changed := original
					changed.InterfaceName = template.InterfaceName
					if changed.Validate(foreign, transfer) == nil {
						t.Fatal("another target replayed the original source with a new interface alias")
					}
				})
			}
			t.Run("nil-policy", func(t *testing.T) {
				if original.Validate(nil, transfer) == nil {
					t.Fatal("unowned interface record acquired native target authority")
				}
			})
			t.Run("metadata-target", func(t *testing.T) {
				changed := *policy
				changed.metadata.TargetOS = "darwin"
				if target == "darwin" {
					changed.metadata.TargetOS = "linux"
				}
				changed.seal = changed.currentSeal()
				copied := original
				copied.InterfaceName = "utun7"
				if changed.metadata.TargetOS == "linux" {
					copied.InterfaceName = "router-vpn"
				}
				if copied.Validate(&changed, transfer) == nil {
					t.Fatal("resealed target metadata replaced the original constructor")
				}
			})
			t.Run("input-target", func(t *testing.T) {
				changed := *policy
				changed.inputs.targetOS = "darwin"
				if target == "darwin" {
					changed.inputs.targetOS = "linux"
				}
				if original.Validate(&changed, transfer) == nil {
					t.Fatal("changed derivation target retained the original readiness authority")
				}
			})
		})
	}
	for _, target := range []string{"", "Darwin", "darwin/arm64", "macos", "macOS", "ios", "android", "freebsd"} {
		t.Run("unsupported-"+target, func(t *testing.T) {
			if desktopNodeChainReadyInterface(target, "router-vpn") || desktopNodeChainReadyInterface(target, "utun7") {
				t.Fatal("unknown target acquired interface readiness")
			}
			if _, err := NewDesktopNodeChainPolicy(chain, desktopNodeTestSession, target, 0); err == nil {
				t.Fatal("unsupported target acquired an original native constructor")
			}
		})
	}
}
