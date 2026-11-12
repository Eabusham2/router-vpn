package mobilemultihop

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func desktopDarwinChainDNSReady(t *testing.T, target string, restored int) (*DesktopNodeChainPolicy, string, DesktopNodeReadyRecord) {
	t.Helper()
	policy := desktopChainPolicy(t, desktopChainFixture(t, 3, "", nil), target, restored)
	_, meta, capture, err := policy.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	mtu := capture.ConfiguredMTU
	if restored != 0 {
		mtu = restored
	}
	transfer := strings.Repeat("a", 64)
	return policy, transfer, DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1",
		SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256,
		TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256,
		InterfaceName: "utun771", InterfaceIndex: 771, MTU: mtu, ProvedAt: 1793366400123, DNSMilliseconds: 1.25}
}
func TestDesktopNodeReadyDarwinRequiresExactOrderedPolicy(t *testing.T) {
	for _, restored := range []int{0, 1400} {
		name := "configured"
		if restored != 0 {
			name = "restored"
		}
		t.Run(name, func(t *testing.T) {
			policy, transfer, record := desktopDarwinChainDNSReady(t, "darwin", restored)
			raw, err := CanonicalDesktopNodeReadyRecord(record, policy, transfer)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := ParseDesktopNodeReadyRecord(raw, policy, transfer)
			if err != nil || actual != record {
				t.Fatal("Darwin ordered selected-DNS receipt lost original policy", err)
			}
		})
	}
	t.Run("ordinary-policy", func(t *testing.T) {
		policy, transfer, record := desktopNodeReadyFixtureFor(t, 1392, "darwin")
		record.InterfaceName = "utun771"
		if record.Validate(policy, transfer) == nil {
			t.Fatal("ordinary Darwin policy acquired ordered selected-DNS readiness")
		}
	})
	for _, target := range []string{"windows", "linux"} {
		t.Run(target+"-utun", func(t *testing.T) {
			policy, transfer, record := desktopDarwinChainDNSReady(t, target, 0)
			if record.Validate(policy, transfer) == nil {
				t.Fatal("foreign target adopted Darwin interface shape")
			}
		})
	}
}
func TestDesktopNodeReadyDarwinPreservesOriginalDNSAndTUN(t *testing.T) {
	policy, transfer, record := desktopDarwinChainDNSReady(t, "darwin", 1400)
	for name, change := range map[string]func(*DesktopNodeReadyRecord){
		"schema":       func(r *DesktopNodeReadyRecord) { r.Schema++ },
		"kind":         func(r *DesktopNodeReadyRecord) { r.Kind = "routervpn-node-chain-ready-v1" },
		"session":      func(r *DesktopNodeReadyRecord) { r.SessionID = strings.Repeat("f", 32) },
		"source":       func(r *DesktopNodeReadyRecord) { r.SourceSHA256 = strings.Repeat("f", 64) },
		"config":       func(r *DesktopNodeReadyRecord) { r.ConfigSHA256 = strings.Repeat("f", 64) },
		"transfer":     func(r *DesktopNodeReadyRecord) { r.TransferSHA256 = strings.Repeat("f", 64) },
		"dns":          func(r *DesktopNodeReadyRecord) { r.DNSConfigSHA256 = strings.Repeat("f", 64) },
		"index":        func(r *DesktopNodeReadyRecord) { r.InterfaceIndex = 0 },
		"mtu":          func(r *DesktopNodeReadyRecord) { r.MTU++ },
		"time":         func(r *DesktopNodeReadyRecord) { r.ProvedAt = 0 },
		"query":        func(r *DesktopNodeReadyRecord) { r.DNSMilliseconds = 0 },
		"bound":        func(r *DesktopNodeReadyRecord) { r.DNSMilliseconds = 5000.1 },
		"nan":          func(r *DesktopNodeReadyRecord) { r.DNSMilliseconds = math.NaN() },
		"infinite":     func(r *DesktopNodeReadyRecord) { r.DNSMilliseconds = math.Inf(1) },
		"cover-count":  func(r *DesktopNodeReadyRecord) { r.CoverServices = 1 },
		"cover-digest": func(r *DesktopNodeReadyRecord) { r.CoverSHA256 = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := record
			change(&changed)
			if changed.Validate(policy, transfer) == nil {
				t.Fatal("Darwin selected-DNS readiness substituted an original field")
			}
		})
	}

	raw, err := CanonicalDesktopNodeReadyRecord(record, policy, transfer)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{append(append([]byte(nil), raw...), '\n'),
		[]byte(strings.TrimSuffix(string(raw), "}") + `,"schema":1}`),
		[]byte(strings.TrimSuffix(string(raw), "}") + `,"foreign":true}`)} {
		if _, err := ParseDesktopNodeReadyRecord(changed, policy, transfer); err == nil {
			t.Fatal("Darwin readiness admitted noncanonical source")
		}
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	for missing := range object {
		copy := map[string]any{}
		for key, value := range object {
			if key != missing {
				copy[key] = value
			}
		}
		raw, _ := json.Marshal(copy)
		if _, err := ParseDesktopNodeReadyRecord(raw, policy, transfer); err == nil {
			t.Fatal("Darwin readiness omitted original field", missing)
		}
	}
}

func TestDesktopNodeReadyDarwinRejectsForeignInterface(t *testing.T) {
	policy, transfer, record := desktopDarwinChainDNSReady(t, "darwin", 1400)
	for label, name := range map[string]string{"empty": "", "fixed": "router-vpn", "missing-unit": "utun",
		"negative": "utun-1", "plus": "utun+1", "suffix": "utun1x", "unicode": "utun１", "case": "Utun1", "newline": "utun1\n"} {
		t.Run(label, func(t *testing.T) {
			changed := record
			changed.InterfaceName = name
			if changed.Validate(policy, transfer) == nil {
				t.Fatal("Darwin selected-DNS readiness accepted a foreign interface")
			}
		})
	}
}
