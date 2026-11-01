package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func desktopNodeCoverFixture(t *testing.T, enabled bool, rate int) *DesktopNodePolicy {
	t.Helper()
	files, profile, start := nodeProfileFixture(t, "shadowsocks", "")
	profile["kill_switch_policy"], profile["ipv6_mode"] = "on-connect", "on"
	profile["daita_enabled"], profile["daita_rate_kbps"], profile["daita_host"] = enabled, rate, "10.77.0.1"
	original, err := NewNodeProfile("shadowsocks", files, startJSON(t, profile), start, "")
	if err != nil {
		t.Fatal(err)
	}
	return desktopNodePlan(t, original, desktopNodeTestSession, "linux")
}

func TestDesktopNodeCoverPolicyRetainsExactBoundedSource(t *testing.T) {
	for _, rate := range []int{32, 64, 192} {
		policy := desktopNodeCoverFixture(t, true, rate)
		options, digest, err := policy.CoverPolicy()
		if err != nil || len(options) != 1 || !proofID.MatchString(digest) || options[0].Tag != "routervpn-cover-exit" ||
			options[0].Options.NodeID != policy.Metadata().NodeID || options[0].Options.API != "http://10.77.0.1:8787" ||
			options[0].Options.Sink != "10.77.0.1" || options[0].Options.RateKbps != rate || options[0].Options.ProofTag != "proxy" || options[0].Options.PacketTag != "proxy" {
			t.Fatal("cover did not retain its complete paired private native policy", err, options)
		}
		before := append([]DesktopNodeCoverService(nil), options...)
		options[0].Options.NodeID = strings.Repeat("b", 64)
		options[0].Options.RateKbps = 193
		again, same, err := policy.CoverPolicy()
		if err != nil || same != digest || !reflect.DeepEqual(again, before) {
			t.Fatal("returned cover options mutated a retained native source", err)
		}
		other := desktopNodeCoverFixture(t, true, map[bool]int{true: 64, false: 32}[rate == 32])
		_, different, err := other.CoverPolicy()
		if err != nil || different == digest {
			t.Fatal("another bounded rate reused the captured service digest", err)
		}
	}
	off := desktopNodeCoverFixture(t, false, 64)
	options, digest, err := off.CoverPolicy()
	if err != nil || len(options) != 0 || digest != "" {
		t.Fatal("disabled native cover acquired a requested worker", err)
	}
	for _, changed := range []*DesktopNodePolicy{nil, {}, {config: off.Config(), metadata: off.Metadata()}} {
		if _, _, err := changed.CoverPolicy(); err == nil {
			t.Fatal("unconstructed cover policy acquired source authority")
		}
	}
}

func TestDesktopNodeLinuxReadinessRequiresCapturedCoverActivation(t *testing.T) {
	policy := desktopNodeCoverFixture(t, true, 64)
	meta := policy.Metadata()
	capture, err := policy.Capture()
	if err != nil {
		t.Fatal(err)
	}
	options, digest, err := policy.CoverPolicy()
	if err != nil {
		t.Fatal(err)
	}
	transfer := strings.Repeat("a", 64)
	record := DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: transfer,
		DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "router-vpn", InterfaceIndex: 771,
		MTU: capture.ConfiguredMTU, ProvedAt: 1793366400123, DNSMilliseconds: 1.25, CoverServices: len(options), CoverSHA256: digest}
	raw, err := CanonicalDesktopNodeReadyRecord(record, policy, transfer)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseDesktopNodeReadyRecord(raw, policy, transfer); err != nil || parsed != record {
		t.Fatal("actual cover readiness lost its sealed source binding", err)
	}
	for _, fault := range []string{"missing", "wrong-count", "wrong-policy", "disabled-policy", "windows-policy", "tampered-source"} {
		t.Run(fault, func(t *testing.T) {
			changed, selected := record, policy
			switch fault {
			case "missing":
				changed.CoverServices, changed.CoverSHA256 = 0, ""
			case "wrong-count":
				changed.CoverServices++
			case "wrong-policy":
				changed.CoverSHA256 = strings.Repeat("b", 64)
			case "disabled-policy":
				selected = desktopNodeCoverFixture(t, false, 64)
			case "windows-policy":
				selected = desktopNodePlan(t, policy.OriginalProfile(), meta.SessionID, "windows")
			case "tampered-source":
				copy := *policy
				copy.config = strings.Replace(copy.config, `"rate_kbps":64`, `"rate_kbps":192`, 1)
				selected = &copy
			}
			encoded, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseDesktopNodeReadyRecord(encoded, selected, transfer); err == nil {
				t.Fatal("readiness adopted absent, stale or foreign cover proof")
			}
		})
	}
}
