package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopNodeChainReadyRequiresCompletePhysicalAndProofIdentity(t *testing.T) {
	for _, target := range []string{"linux", "windows"} {
		t.Run(target, func(t *testing.T) {
			policy := desktopChainPolicy(t, desktopChainFixture(t, 3, "", nil), target, 0)
			_, meta, capture, err := policy.ReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			transfer := strings.Repeat("a", 64)
			record := DesktopNodeChainReadyRecord{Schema: 1, Kind: "routervpn-node-chain-ready-v1",
				SourceSHA256: meta.SourceSHA256, TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256,
				Identity: NodeChainIdentity{EngineID: "original-native-engine", SessionID: meta.SessionID,
					NetworkID: "original-network", SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256},
				Generation: 1, Reader: 1, InterfaceName: "router-vpn", InterfaceIndex: 17, MTU: capture.ConfiguredMTU, ObservedAt: 1234}
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
