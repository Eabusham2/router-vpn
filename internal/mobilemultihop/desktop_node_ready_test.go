package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func desktopNodeReadyFixture(t *testing.T, restored int) (*DesktopNodePolicy, string, DesktopNodeReadyRecord) {
	t.Helper()
	policy, err := NewDesktopNodePolicyWithMTU(desktopNodeFixture(t, "wg", ""), desktopNodeTestSession, "windows", restored)
	if err != nil {
		t.Fatal(err)
	}
	meta := policy.Metadata()
	capture, err := policy.Capture()
	if err != nil {
		t.Fatal(err)
	}
	mtu := capture.ConfiguredMTU
	if restored != 0 {
		mtu = restored
	}
	transfer := strings.Repeat("a", 64)
	return policy, transfer, DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: transfer,
		DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "router-vpn", InterfaceIndex: 771, MTU: mtu, ProvedAt: 1793366400123, DNSMilliseconds: 1.25}
}

func TestDesktopNodeReadyRecordBindsExactCapturedPolicy(t *testing.T) {
	for _, mtu := range []int{0, 1392} {
		policy, transfer, record := desktopNodeReadyFixture(t, mtu)
		raw, err := CanonicalDesktopNodeReadyRecord(record, policy, transfer)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := ParseDesktopNodeReadyRecord(raw, policy, transfer)
		if err != nil || !reflect.DeepEqual(actual, record) {
			t.Fatal("exact native readiness record did not round-trip", err)
		}
		for name, mutate := range map[string]func(*DesktopNodeReadyRecord){
			"schema": func(r *DesktopNodeReadyRecord) { r.Schema++ }, "kind": func(r *DesktopNodeReadyRecord) { r.Kind += "-other" },
			"session":      func(r *DesktopNodeReadyRecord) { r.SessionID = strings.Repeat("f", 32) },
			"source":       func(r *DesktopNodeReadyRecord) { r.SourceSHA256 = strings.Repeat("f", 64) },
			"config":       func(r *DesktopNodeReadyRecord) { r.ConfigSHA256 = strings.Repeat("f", 64) },
			"transfer":     func(r *DesktopNodeReadyRecord) { r.TransferSHA256 = strings.Repeat("f", 64) },
			"dns":          func(r *DesktopNodeReadyRecord) { r.DNSConfigSHA256 = strings.Repeat("f", 64) },
			"tun":          func(r *DesktopNodeReadyRecord) { r.InterfaceName += "-other" },
			"index":        func(r *DesktopNodeReadyRecord) { r.InterfaceIndex = 0 },
			"mtu":          func(r *DesktopNodeReadyRecord) { r.MTU++ },
			"timestamp":    func(r *DesktopNodeReadyRecord) { r.ProvedAt = 0 },
			"timing-zero":  func(r *DesktopNodeReadyRecord) { r.DNSMilliseconds = 0 },
			"timing-bound": func(r *DesktopNodeReadyRecord) { r.DNSMilliseconds = 5000.1 },
		} {
			t.Run(name, func(t *testing.T) {
				changed := record
				mutate(&changed)
				if _, err := CanonicalDesktopNodeReadyRecord(changed, policy, transfer); err == nil {
					t.Fatal("readiness accepted a substituted captured field", name)
				}
			})
		}
	}
}

func TestDesktopNodeReadyRecordRejectsAmbiguousEncoding(t *testing.T) {
	policy, transfer, record := desktopNodeReadyFixture(t, 1392)
	raw, err := CanonicalDesktopNodeReadyRecord(record, policy, transfer)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	variants := map[string][]byte{
		"whitespace": append(append([]byte(nil), raw...), '\n'),
		"duplicate":  []byte(strings.TrimSuffix(string(raw), "}") + `,"schema":1}`),
		"unknown":    []byte(strings.TrimSuffix(string(raw), "}") + `,"success":true}`),
		"null":       []byte(strings.Replace(string(raw), `"schema":1`, `"schema":null`, 1)),
		"overflow":   []byte(strings.Replace(string(raw), `"interface_index":771`, `"interface_index":4294967296`, 1)),
		"oversize":   []byte(strings.Repeat(" ", DesktopNodeReadyRecordLimit+1)),
	}
	for key := range object {
		copy := map[string]any{}
		for name, value := range object {
			if name != key {
				copy[name] = value
			}
		}
		variants["missing-"+key], _ = json.Marshal(copy)
	}
	for name, value := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDesktopNodeReadyRecord(value, policy, transfer); err == nil {
				t.Fatal("noncanonical native readiness was admitted", name)
			}
		})
	}
}
