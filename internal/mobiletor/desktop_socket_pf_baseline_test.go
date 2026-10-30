package mobiletor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func desktopPFBaselineFixture() DesktopDarwinPFBaselineRequest {
	return DesktopDarwinPFBaselineRequest{Schema: 1, Action: "replace", SessionID: strings.Repeat("a", 32),
		SourceSHA256: strings.Repeat("b", 64), Expected: []DesktopDarwinPFBaselineProof{{}}}
}

func TestDesktopPFBaselinePreservesExistingPythonPolicy(t *testing.T) {
	// These digests were captured by executing the unchanged shipping Python
	// renderer before factoring the Go policy. They protect the prior active,
	// inactive, LAN and non-LAN byte contracts, independent of this compiler.
	for _, test := range []struct {
		active, lan bool
		digest      string
	}{
		{false, false, "f63029eba40fdc5cacefebf54448916186a7c97fe0a9e4541f8cf3232de155b5"},
		{false, true, "663133034edb874ace4efe760aa18a4539906299a2b96a7aa44c49da167892f5"},
		{true, false, "145a36662f6ce2f1e9408d642d046d1e425ebb7423eccfb7537ba471d853b528"},
		{true, true, "bdbd3cd5d98afe1bc7024a22228f3f4f60f470d4122ba8dc9ca4994cdf561862"},
	} {
		session, source := "", ""
		if test.active {
			session, source = strings.Repeat("a", 32), strings.Repeat("b", 64)
		}
		rules := desktopPFOwnedBaseline(session, source, test.lan, "")
		if desktopPFDigest([]byte(rules)) != test.digest {
			t.Fatal("shared baseline changed the prior Python policy bytes", test.active, test.lan)
		}
		if _, err := desktopPFCompileFilters(rules); err != nil {
			t.Fatal("existing baseline no longer compiles through the finite native filter grammar", err)
		}
		if strings.Contains(rules, "anchor ") != test.active || strings.Contains(rules, "pass out quick") ||
			!strings.Contains(rules, "block drop out quick all ! tagged ") {
			t.Fatal("baseline changed its captured-dispatch or fail-closed order")
		}
	}
}

func TestDesktopPFBaselineRecordExactRoundTrip(t *testing.T) {
	for _, request := range []DesktopDarwinPFBaselineRequest{
		desktopPFBaselineFixture(),
		{Schema: 1, Action: "replace", HomeLANAccess: true, Expected: []DesktopDarwinPFBaselineProof{{Present: true, RulesSHA256: strings.Repeat("c", 64)}}},
		{Schema: 1, Action: "clear", Expected: []DesktopDarwinPFBaselineProof{{}, {Present: true, RulesSHA256: strings.Repeat("d", 64)}}},
	} {
		raw, err := EncodeDesktopDarwinPFBaselineRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseDesktopDarwinPFBaselineRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		again, err := EncodeDesktopDarwinPFBaselineRequest(parsed)
		if err != nil || !bytes.Equal(raw, again) {
			t.Fatal("baseline transition lost its exact canonical source", err)
		}
		for _, proof := range request.Expected {
			if !parsed.accepts(proof) {
				t.Fatal("baseline rejected its retained preimage or ambiguous installed target")
			}
		}
		if parsed.accepts(DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("e", 64)}) {
			t.Fatal("baseline accepted a replacement owner's kernel proof")
		}
	}
}

func TestDesktopPFBaselineRecordRejectsAmbiguousAuthority(t *testing.T) {
	for name, mutate := range map[string]func(*DesktopDarwinPFBaselineRequest){
		"schema":              func(r *DesktopDarwinPFBaselineRequest) { r.Schema = 2 },
		"operation":           func(r *DesktopDarwinPFBaselineRequest) { r.Action = "flush" },
		"missing-expectation": func(r *DesktopDarwinPFBaselineRequest) { r.Expected = nil },
		"too-many-possible-owners": func(r *DesktopDarwinPFBaselineRequest) {
			r.Expected = append(r.Expected, DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("c", 64)}, DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("d", 64)})
		},
		"duplicate-expectation":   func(r *DesktopDarwinPFBaselineRequest) { r.Expected = append(r.Expected, r.Expected[0]) },
		"absence-with-digest":     func(r *DesktopDarwinPFBaselineRequest) { r.Expected[0].RulesSHA256 = strings.Repeat("c", 64) },
		"presence-without-digest": func(r *DesktopDarwinPFBaselineRequest) { r.Expected[0].Present = true },
		"noncanonical-digest": func(r *DesktopDarwinPFBaselineRequest) {
			r.Expected[0] = DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("A", 64)}
		},
		"missing-session":          func(r *DesktopDarwinPFBaselineRequest) { r.SessionID = "" },
		"missing-source":           func(r *DesktopDarwinPFBaselineRequest) { r.SourceSHA256 = "" },
		"noncanonical-session":     func(r *DesktopDarwinPFBaselineRequest) { r.SessionID = strings.Repeat("A", 32) },
		"clear-with-active-source": func(r *DesktopDarwinPFBaselineRequest) { r.Action = "clear" },
		"clear-with-LAN-policy": func(r *DesktopDarwinPFBaselineRequest) {
			r.Action, r.SessionID, r.SourceSHA256, r.HomeLANAccess = "clear", "", "", true
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := desktopPFBaselineFixture()
			mutate(&request)
			if _, err := EncodeDesktopDarwinPFBaselineRequest(request); err == nil {
				t.Fatal("baseline accepted incomplete, broad or borrowed transition authority")
			}
			raw, _ := json.Marshal(request)
			if _, err := ParseDesktopDarwinPFBaselineRequest(raw); err == nil {
				t.Fatal("baseline parser accepted a malformed encoded transition")
			}
		})
	}
}

func TestDesktopPFBaselineRecordRejectsMalformedJSON(t *testing.T) {
	raw, err := EncodeDesktopDarwinPFBaselineRequest(desktopPFBaselineFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{
		"", string(raw) + "\n", string(raw) + "{}", string(raw)[:len(raw)-1],
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"anchor":"com.apple/foreign"`, 1),
		strings.Replace(string(raw), `"home_lan_access":false,`, "", 1),
		strings.Replace(string(raw), `"home_lan_access":false`, `"home_lan_access":null`, 1),
		strings.Replace(string(raw), `"home_lan_access":false`, `"home_lan_access":0`, 1),
		strings.Replace(string(raw), `"present":false`, `"present":false,"present":false`, 1),
		strings.Replace(string(raw), `"rules_sha256":""`, `"rules_sha256":null`, 1),
		strings.Repeat(" ", DesktopDarwinPFBaselineLimit+1),
	} {
		if _, err := ParseDesktopDarwinPFBaselineRequest([]byte(malformed)); err == nil {
			t.Fatal("baseline parser admitted an ambiguous or noncanonical private frame")
		}
	}
}
