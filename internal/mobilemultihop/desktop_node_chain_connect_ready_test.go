package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func desktopCONNECTReadyFixture(t *testing.T, target string) (*DesktopNodeChainCONNECTPolicy, DesktopNodeChainCONNECTReadyRecord, string) {
	t.Helper()
	_, policy := desktopCONNECTPolicyFixture(t, "wg", "", target, 0)
	_, meta, capture, err := policy.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	name := "router-vpn"
	if target == "darwin" {
		name = "utun73"
	}
	transfer := strings.Repeat("e", 64)
	record := DesktopNodeChainCONNECTReadyRecord{Schema: 1, Kind: "routervpn-node-chain-connect-ready-v1", SourceSHA256: meta.SourceSHA256,
		TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256,
		Identity:   NodeChainIdentity{EngineID: "original-box", SessionID: meta.SessionID, NetworkID: "original-network", SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256},
		Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 73, MTU: 1280, ObservedAt: time.Now().UnixMilli()}
	return policy, record, transfer
}

func TestDesktopNodeChainCONNECTReadyUsesOriginalPolicy(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			policy, record, transfer := desktopCONNECTReadyFixture(t, target)
			raw, err := CanonicalDesktopNodeChainCONNECTReadyRecord(record, policy, transfer)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseDesktopNodeChainCONNECTReadyRecord(raw, policy, transfer)
			if err != nil || parsed != record {
				t.Fatal("typed Ready lost original complete observation", err)
			}
			again, err := json.Marshal(parsed)
			if err != nil || !bytes.Equal(raw, again) {
				t.Fatal("typed Ready changed canonical bytes", err)
			}
			for _, private := range []string{"private-proxy-secret", "ordered-private-token", "password", "original_source"} {
				if bytes.Contains(raw, []byte(private)) {
					t.Fatal("typed Ready exposed private source")
				}
			}
		})
	}
}

func TestDesktopNodeChainCONNECTReadyRejectsForeignObservation(t *testing.T) {
	for _, fault := range []string{"kind", "schema", "source", "transfer", "dns", "engine", "network", "session", "original-source", "config", "generation", "reader", "interface", "index", "low-mtu", "high-mtu", "time", "unknown", "whitespace", "null", "nil-policy"} {
		t.Run(fault, func(t *testing.T) {
			policy, record, transfer := desktopCONNECTReadyFixture(t, "linux")
			switch fault {
			case "kind":
				record.Kind = "routervpn-node-chain-ready-v1"
			case "schema":
				record.Schema = 2
			case "source":
				record.SourceSHA256 = record.Identity.SourceSHA256
			case "transfer":
				record.TransferSHA256 = strings.Repeat("f", 64)
			case "dns":
				record.DNSConfigSHA256 = strings.Repeat("d", 64)
			case "engine":
				record.Identity.EngineID = ""
			case "network":
				record.Identity.NetworkID = ""
			case "session":
				record.Identity.SessionID = strings.Repeat("b", 32)
			case "original-source":
				record.Identity.SourceSHA256 = record.SourceSHA256
			case "config":
				record.Identity.ConfigSHA256 = strings.Repeat("c", 64)
			case "generation":
				record.Generation = 0
			case "reader":
				record.Reader = 0
			case "interface":
				record.InterfaceName = "utun73"
			case "index":
				record.InterfaceIndex = 0
			case "low-mtu":
				record.MTU = 1279
			case "high-mtu":
				record.MTU = 9001
			case "time":
				record.ObservedAt = 0
			case "nil-policy":
				policy = nil
			}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "unknown":
				raw = append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"foreign":true}`)...)
			case "whitespace":
				raw = append(raw, '\n')
			case "null":
				raw = []byte("null")
			}
			if _, err := ParseDesktopNodeChainCONNECTReadyRecord(raw, policy, transfer); err == nil {
				t.Fatal("typed Ready admitted a foreign or noncanonical observation")
			}
		})
	}
}
