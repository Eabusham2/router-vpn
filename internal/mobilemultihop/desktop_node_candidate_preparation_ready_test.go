package mobilemultihop

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func desktopCandidateReadyFixture(t *testing.T, target string) (*DesktopNodeCandidatePreparationPolicy, string, DesktopNodeCandidatePreparationReadyRecord) {
	t.Helper()
	p := desktopCandidatePreparationFixture(t, "wg", target, 1, 0, nil)
	m := p.Metadata()
	name := "router-vpn"
	if target == "darwin" {
		name = "utun13"
	}
	transfer := strings.Repeat("a", 64)
	r := DesktopNodeCandidatePreparationReadyRecord{Schema: 1, Kind: "routervpn-node-candidate-prefix-ready-v1",
		SourceSHA256: m.SourceSHA256, CaptureSHA256: m.CaptureSHA256, TransferSHA256: transfer,
		Identity:   NodeChainIdentity{EngineID: "original-box", SessionID: m.SessionID, SourceSHA256: m.SourceSHA256, ConfigSHA256: m.ConfigSHA256, NetworkID: "original-network"},
		Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 772, MTU: 1280, ObservedAt: 1793366400123, Prepared: true}
	for _, proof := range m.Prefixes {
		r.Prefixes = append(r.Prefixes, NodeChainPrefixProgress{Position: proof.Position, ProfileID: proof.ProfileID, ResponseMS: 1.25, Proven: true})
	}
	return p, transfer, r
}

func TestDesktopNodeCandidatePreparationReadyExactClosedPrefix(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			p, transfer, original := desktopCandidateReadyFixture(t, target)
			raw, err := CanonicalDesktopNodeCandidatePreparationReadyRecord(original, p, transfer)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseDesktopNodeCandidatePreparationReadyRecord(raw, p, transfer)
			if err != nil || !reflect.DeepEqual(parsed, original) {
				t.Fatal("original private prefix heartbeat did not round-trip", err)
			}
			if _, err := ParseDesktopNodeReadyRecord(raw, p, transfer); err == nil {
				t.Fatal("prefix heartbeat upgraded into ordinary DNS readiness")
			}
			full := desktopChainPolicy(t, p.original.original, target, 0)
			if _, err := ParseDesktopNodeChainReadyRecord(raw, full, transfer); err == nil {
				t.Fatal("prefix heartbeat upgraded into complete-chain readiness")
			}
		})
	}
}

func TestDesktopNodeCandidatePreparationReadyRejectsChangedCapture(t *testing.T) {
	p, transfer, original := desktopCandidateReadyFixture(t, "linux")
	for name, mutate := range map[string]func(*DesktopNodeCandidatePreparationReadyRecord){
		"schema":        func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Schema++ },
		"ordinary-kind": func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Kind = "routervpn-node-ready-v1" },
		"source":        func(r *DesktopNodeCandidatePreparationReadyRecord) { r.SourceSHA256 = strings.Repeat("f", 64) },
		"catalog":       func(r *DesktopNodeCandidatePreparationReadyRecord) { r.CaptureSHA256 = strings.Repeat("f", 64) },
		"transfer":      func(r *DesktopNodeCandidatePreparationReadyRecord) { r.TransferSHA256 = strings.Repeat("f", 64) },
		"session":       func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Identity.SessionID = strings.Repeat("f", 32) },
		"full-source": func(r *DesktopNodeCandidatePreparationReadyRecord) {
			r.Identity.SourceSHA256 = p.Metadata().OriginalSourceSHA256
		},
		"config":          func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Identity.ConfigSHA256 = strings.Repeat("f", 64) },
		"engine":          func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Identity.EngineID = "" },
		"network":         func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Identity.NetworkID = "" },
		"generation":      func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Generation = 0 },
		"reader":          func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Reader = 0 },
		"interface":       func(r *DesktopNodeCandidatePreparationReadyRecord) { r.InterfaceName = "utun13" },
		"index":           func(r *DesktopNodeCandidatePreparationReadyRecord) { r.InterfaceIndex = 0 },
		"mtu-small":       func(r *DesktopNodeCandidatePreparationReadyRecord) { r.MTU = 1279 },
		"mtu-ceiling":     func(r *DesktopNodeCandidatePreparationReadyRecord) { r.MTU = 9000 },
		"time":            func(r *DesktopNodeCandidatePreparationReadyRecord) { r.ObservedAt = 0 },
		"unprepared":      func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prepared = false },
		"application":     func(r *DesktopNodeCandidatePreparationReadyRecord) { r.ApplicationOpen = true },
		"dns":             func(r *DesktopNodeCandidatePreparationReadyRecord) { r.DNSOpen = true },
		"missing-prefix":  func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prefixes = r.Prefixes[:1] },
		"extra-prefix":    func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prefixes = append(r.Prefixes, r.Prefixes[1]) },
		"prefix-order":    func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prefixes[0].Position = 1 },
		"prefix-owner":    func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prefixes[0].ProfileID = "foreign" },
		"unproved-prefix": func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prefixes[0].Proven = false },
		"zero-proof":      func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prefixes[0].ResponseMS = 0 },
		"nan-proof":       func(r *DesktopNodeCandidatePreparationReadyRecord) { r.Prefixes[0].ResponseMS = math.NaN() },
	} {
		t.Run(name, func(t *testing.T) {
			r := original
			r.Prefixes = append([]NodeChainPrefixProgress(nil), original.Prefixes...)
			mutate(&r)
			if r.Validate(p, transfer) == nil {
				t.Fatal("changed prefix receipt retained native authority")
			}
		})
	}
}

func TestDesktopNodeCandidatePreparationReadyRejectsAmbiguousEncoding(t *testing.T) {
	p, transfer, original := desktopCandidateReadyFixture(t, "linux")
	raw, err := CanonicalDesktopNodeCandidatePreparationReadyRecord(original, p, transfer)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture lost original receipt")
	}
	for _, field := range []string{"application_open", "dns_open", "prepared", "prefixes", "capture_sha256"} {
		for _, mutation := range []string{"missing", "null"} {
			t.Run(field+"/"+mutation, func(t *testing.T) {
				copy := make(map[string]json.RawMessage, len(fields))
				for key, value := range fields {
					copy[key] = value
				}
				if mutation == "missing" {
					delete(copy, field)
				} else {
					copy[field] = json.RawMessage("null")
				}
				changed, _ := json.Marshal(copy)
				if _, err := ParseDesktopNodeCandidatePreparationReadyRecord(changed, p, transfer); err == nil {
					t.Fatal("incomplete prefix receipt admitted")
				}
			})
		}
	}
	for _, changed := range [][]byte{append(append([]byte{}, raw...), '\n'), []byte(strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1)), []byte(strings.Replace(string(raw), `"schema":1`, `"schema":1,"connected":true`, 1))} {
		if _, err := ParseDesktopNodeCandidatePreparationReadyRecord(changed, p, transfer); err == nil {
			t.Fatal("noncanonical or foreign prefix receipt admitted")
		}
	}
}
