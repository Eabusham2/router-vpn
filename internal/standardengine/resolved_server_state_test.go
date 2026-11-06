package standardengine

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func resolvedServerStateFixture() (ResolvedPolicy, ResolvedServerRow) {
	policy := resolvedDNSSECPolicyFixture()
	policy.Manager.DNSSEC = "allow-downgrade"
	text, _ := resolvedServerText(*policy.Manager.CurrentDNS)
	row := ResolvedServerRow{Server: text, Type: "system", VerifiedFeatureLevel: "n/a", PossibleFeatureLevel: "UDP+EDNS0", DNSSECMode: "allow-downgrade", DNSSECSupported: false, PacketRRSIGMissing: true}
	return policy, row
}
func resolvedServerEnvelope(rows ...ResolvedServerRow) []byte {
	body, _ := json.Marshal(map[string]any{"parameters": map[string]any{"dump": rows}})
	return body
}
func TestResolvedServerStateExactSelectedDecision(t *testing.T) {
	p, row := resolvedServerStateFixture()
	state, err := SelectResolvedServerState(resolvedServerEnvelope(row), p, "vpn.example", 0)
	if err != nil || !state.AllowsCurrentIncompatibility() {
		t.Fatal(err, state)
	}
	raw, err := state.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeResolvedServerState(raw, p, "vpn.example", 0); err != nil {
		t.Fatal(err)
	}
	capture := strings.Repeat("a", 64)
	frame, err := BuildResolvedServerStateFrame(capture, 19, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeResolvedServerStateFrame(frame, capture, 19, p, "vpn.example", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeResolvedServerStateFrame(frame, capture, 18, p, "vpn.example", 0); err == nil {
		t.Fatal("server-state response replayed into another original query")
	}
}
func TestResolvedServerStateRejectsChangedAuthority(t *testing.T) {
	p, row := resolvedServerStateFixture()
	for name, mutate := range map[string]func(*ResolvedServerRow){"address": func(r *ResolvedServerRow) { r.Server = "198.51.100.53:5353#dns.example" }, "port": func(r *ResolvedServerRow) { r.Server = "192.0.2.53:53#dns.example" }, "sni": func(r *ResolvedServerRow) { r.Server = "192.0.2.53:5353#foreign.example" }, "scope": func(r *ResolvedServerRow) { r.Type = "fallback" }, "mode": func(r *ResolvedServerRow) { r.DNSSECMode = "no" }, "inconsistent-support": func(r *ResolvedServerRow) { r.DNSSECSupported = true }, "unknown-feature": func(r *ResolvedServerRow) { r.PossibleFeatureLevel = "future-unknown" }} {
		t.Run(name, func(t *testing.T) {
			copy := row
			mutate(&copy)
			if _, err := SelectResolvedServerState(resolvedServerEnvelope(copy), p, "vpn.example", 0); err == nil {
				t.Fatal("changed selected server observation admitted")
			}
		})
	}
	if _, err := SelectResolvedServerState(resolvedServerEnvelope(row, row), p, "vpn.example", 0); err == nil {
		t.Fatal("duplicate original selected server admitted")
	}
	missing := bytes.Replace(resolvedServerEnvelope(row), []byte(`"PacketDoOff":false,`), nil, 1)
	if bytes.Equal(missing, resolvedServerEnvelope(row)) {
		missing = bytes.Replace(missing, []byte(`,"PacketDoOff":false`), nil, 1)
	}
	if _, err := SelectResolvedServerState(missing, p, "vpn.example", 0); err == nil {
		t.Fatal("incomplete server observation admitted")
	}
	duplicate := bytes.Replace(resolvedServerEnvelope(row), []byte(`"DNSSECSupported":false`), []byte(`"DNSSECSupported":true,"DNSSECSupported":false`), 1)
	if _, err := SelectResolvedServerState(duplicate, p, "vpn.example", 0); err == nil {
		t.Fatal("duplicate monitor field admitted")
	}
	for _, field := range []string{"DNSSECSupported", "ReceivedUDPFragmentMax", "FailedUDPAttempts", "FailedTCPAttempts", "PacketTruncated", "PacketBadOpt", "PacketRRSIGMissing", "PacketInvalid", "PacketDoOff"} {
		var fields map[string]any
		encoded, _ := json.Marshal(row)
		_ = json.Unmarshal(encoded, &fields)
		fields[field] = nil
		raw, _ := json.Marshal(map[string]any{"parameters": map[string]any{"dump": []any{fields}}})
		if _, err := SelectResolvedServerState(raw, p, "vpn.example", 0); err == nil {
			t.Fatal("null monitor scalar admitted", field)
		}
	}
}
func TestResolvedServerStateSupportDecision(t *testing.T) {
	p, row := resolvedServerStateFixture()
	for _, scenario := range []string{"supported", "bad-opt", "missing-rrsig", "do-off", "tcp-two", "tcp-three", "strict"} {
		t.Run(scenario, func(t *testing.T) {
			r := row
			r.PacketRRSIGMissing = false
			r.DNSSECSupported = true
			policy := p
			switch scenario {
			case "bad-opt":
				r.PacketBadOpt = true
				r.DNSSECSupported = false
			case "missing-rrsig":
				r.PacketRRSIGMissing = true
				r.DNSSECSupported = false
			case "do-off":
				r.PacketDoOff = true
				r.DNSSECSupported = false
			case "tcp-two":
				r.FailedTCPAttempts = 2
			case "tcp-three":
				r.FailedTCPAttempts = 3
				r.DNSSECSupported = false
			case "strict":
				policy.Manager.DNSSEC = "yes"
				r.DNSSECMode = "yes"
				r.PacketBadOpt = true
			}
			state, err := SelectResolvedServerState(resolvedServerEnvelope(r), policy, "vpn.example", 0)
			if err != nil {
				t.Fatal(err)
			}
			want := scenario == "bad-opt" || scenario == "missing-rrsig" || scenario == "do-off" || scenario == "tcp-three"
			if state.AllowsCurrentIncompatibility() != want {
				t.Fatal("original support decision changed", scenario)
			}
		})
	}
}
func TestResolvedServerStateNativeTupleFormatting(t *testing.T) {
	for _, test := range []struct {
		s    ResolvedDNS
		want string
	}{{ResolvedDNS{7, "192.0.2.53", 0, ""}, "192.0.2.53"}, {ResolvedDNS{7, "2001:db8::53", 853, "tls.example"}, "[2001:db8::53]:853#tls.example"}, {ResolvedDNS{7, "fe80::53", 0, ""}, "fe80::53%7"}, {ResolvedDNS{7, "fe80::53", 853, "tls.example"}, "[fe80::53]:853%7#tls.example"}} {
		got, err := resolvedServerText(test.s)
		if err != nil || got != test.want {
			t.Fatal(got, err, test.want)
		}
	}
}
