package mobilemultihop

import (
	"encoding/json"
	"strings"
	"testing"
)

func amneziaFixture() (string, string) {
	raw, id := wireGuardFixture()
	params := "Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n"
	return strings.Replace(raw, "[Peer]", params+"[Peer]", 1), id
}
func TestAmneziaParserPreservesEveryParameter(t *testing.T) {
	text, id := amneziaFixture()
	encoded, err := CompileAmneziaProfile(text, id)
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]json.RawMessage
	_ = json.Unmarshal([]byte(encoded), &profile)
	runtime, err := AmneziaRuntimeConfig(string(profile["endpoint"]))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"jc=3\n", "jmin=40\n", "jmax=900\n", "s1=56\n", "s2=48\n", "s3=24\n", "s4=32\n", "h1=10000000-19999999\n", "h4=40000000-49999999\n", "persistent_keepalive_interval=25\n", "allowed_ip=::/0\n"} {
		if !strings.Contains(runtime.UAPI, field) {
			t.Fatalf("dropped %s", field)
		}
	}
	if runtime.MTU != 1420 || runtime.Remote.String() != "192.0.2.1:51820" || len(runtime.Addresses) != 2 {
		t.Fatal("native fields lost")
	}
	// AWG and WG have different server keys; durable identity is verified after
	// encryption starts, not incorrectly equated with the AWG peer key hash.
	if _, err = CompileAmneziaProfile(text, strings.Repeat("f", 64)); err != nil {
		t.Fatal(err)
	}
}
func TestAmneziaParserRejectsDroppedOrAmbiguousPolicy(t *testing.T) {
	text, id := amneziaFixture()
	for name, raw := range map[string]string{
		"missing": strings.Replace(text, "S4=32\n", "", 1), "duplicate": text + "[Interface]\nJc=3\n",
		"peer-parameter": text + "S4=32\n", "noise-budget": strings.Replace(text, "Jc=3", "Jc=999999", 1),
		"reversed-noise": strings.Replace(text, "Jmin=40", "Jmin=1000", 1), "header-overlap": strings.Replace(text, "H2=20000000-29999999", "H2=10000000-19999999", 1),
		"plain-wireguard": strings.Replace(text, "H1=10000000-19999999", "H1=1", 1), "unowned-field": strings.Replace(text, "[Peer]", "PostUp=arbitrary-command\n[Peer]", 1),
		"unsupported-extension": strings.Replace(text, "[Peer]", "I1=<r 100>\n[Peer]", 1), "newlines": text + "\x00",
		"second-peer": text + "[Peer]\n", "listener": strings.Replace(text, "[Peer]", "ListenPort=5000\n[Peer]", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileAmneziaProfile(raw, id); err == nil {
				t.Fatal("accepted invalid AWG policy")
			}
		})
	}
	encoded, _ := CompileAmneziaProfile(text, id)
	var p map[string]any
	_ = json.Unmarshal([]byte(encoded), &p)
	ep := p["endpoint"].(map[string]any)
	for _, field := range []string{"fwmark", "bind_interface", "profile_text", "pre_up"} {
		ep[field] = "unowned"
		raw, _ := json.Marshal(ep)
		if _, err := AmneziaRuntimeConfig(string(raw)); err == nil {
			t.Fatal("unowned native field accepted", field)
		}
		delete(ep, field)
	}
	if _, err := AmneziaRuntimeConfig(`{"amnezia":{},"amnezia":{}}`); err == nil {
		t.Fatal("duplicate fields accepted")
	}
}
