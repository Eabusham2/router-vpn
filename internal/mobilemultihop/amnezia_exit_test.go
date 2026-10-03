package mobilemultihop

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func awgExitGraph(t *testing.T, mode, execution string) (string, string) {
	t.Helper()
	text, id := amneziaFixture()
	compiled, err := AmneziaExitConfig(text, id)
	if err != nil {
		t.Fatal(err)
	}
	var awg, graph map[string]any
	json.Unmarshal([]byte(compiled), &awg)
	original, meta := fixture(t, execution)
	json.Unmarshal([]byte(original), &graph)
	end := awg["endpoints"].([]any)[0].(map[string]any)
	end["detour"] = "entry-wg"
	graph["endpoints"] = append(graph["endpoints"].([]any), end)
	graph["outbounds"] = []any{}
	graph["inbounds"] = awg["inbounds"]
	graph["endpoints"].([]any)[0].(map[string]any)["mtu"] = 1420
	var m Metadata
	json.Unmarshal([]byte(meta), &m)
	m.ExitMode = mode
	a, _ := json.Marshal(graph)
	b, _ := json.Marshal(m)
	return string(a), string(b)
}
func TestNativeAmneziaExitPlanAndExactProtocol(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		for _, execution := range []string{"local", "server", "auto"} {
			graph, meta := awgExitGraph(t, mode, execution)
			c, err := New(graph, meta)
			if err != nil {
				t.Fatal(mode, execution, err)
			}
			var original, result map[string]any
			json.Unmarshal([]byte(graph), &original)
			json.Unmarshal([]byte(c.Config()), &result)
			source := original["endpoints"].([]any)[1].(map[string]any)
			source["tag"] = LocalTag
			want, _ := json.Marshal(source)
			got, _ := json.Marshal(result["endpoints"].([]any)[1])
			if string(want) != string(got) {
				t.Fatal("AWG exit credentials/padding changed")
			}
			key, _ := base64.StdEncoding.DecodeString(source["private_key"].(string))
			private, _ := ecdh.X25519().NewPrivateKey(key)
			if c.localPublicKey != base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) || c.proposal.ExitMode != mode {
				t.Fatal("missing independent AWG client identity")
			}
			dnsA, _ := json.Marshal(original["dns"])
			dnsB, _ := json.Marshal(result["dns"])
			if string(dnsA) != string(dnsB) {
				t.Fatal("exit DNS changed")
			}
			out := result["outbounds"].([]any)
			if out[0].(map[string]any)["detour"] != "entry-wg" || out[1].(map[string]any)["type"] != "selector" {
				t.Fatal("unowned server relay")
			}
			if _, err := New(graph, strings.Replace(meta, mode, "wg", 1)); err == nil {
				t.Fatal("AWG relabeled ordinary WireGuard")
			}
		}
	}
	graph, meta := awgExitGraph(t, "awg2-fast", "auto")
	var p map[string]any
	json.Unmarshal([]byte(graph), &p)
	end := p["endpoints"].([]any)[1].(map[string]any)
	delete(end["amnezia"].(map[string]any), "s4")
	raw, _ := json.Marshal(p)
	if _, err := New(string(raw), meta); err == nil {
		t.Fatal("missing AWG exit parameter accepted")
	}
}
func TestNativeAmneziaExitMTUIncludesS4(t *testing.T) {
	graph, _ := awgExitGraph(t, "awg2-strong", "auto")
	for _, tc := range []struct {
		host  string
		limit int
	}{{"192.0.2.1", 1328}, {"2001:db8::1", 1296}} {
		cfg := strings.ReplaceAll(graph, "192.0.2.1", tc.host)
		encoded, err := ApplyMTUPolicy(cfg, `{"entry":{},"exit":{}}`)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		json.Unmarshal([]byte(encoded), &result)
		exit := result["endpoints"].([]any)[1].(map[string]any)
		if exit["mtu"] != float64(tc.limit) || exit["amnezia"].(map[string]any)["s4"] != "32" {
			t.Fatal("native padding envelope ignored", encoded)
		}
		if _, err = ApplyMTUPolicy(cfg, `{"entry":{},"exit":{"mtu_policy":"fixed","manual_mtu":1340}}`); err == nil {
			t.Fatal("fixed MTU silently clamped for AWG exit")
		}
	}
	cfg := strings.Replace(graph, `"s4":"32"`, `"s4":"1280"`, 1)
	if _, err := ApplyMTUPolicy(cfg, `{"entry":{},"exit":{}}`); err == nil {
		t.Fatal("uncarriable AWG packet accepted")
	}
}

func TestAmneziaAutoComparisonRequiresIndependentPairedServerKey(t *testing.T) {
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		for _, variant := range []string{"missing", "same", "different"} {
			graph, meta := awgExitGraph(t, mode, "auto")
			c, err := New(graph, meta)
			if err != nil {
				t.Fatal(err)
			}
			e := makeEngine(t)
			e.exitMode = mode
			switch variant {
			case "same":
				e.clientPublic = c.localPublicKey
			case "different":
				e.clientPublic = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32)))
			}
			if err = c.Run(context.Background(), e); err != nil {
				t.Fatal(mode, variant, err)
			}
			want := LocalTag
			if variant == "different" {
				want = ServerTag
			}
			if e.Selected() != want {
				t.Fatal("invalid AWG server comparison eligibility", variant, c.ProgressJSON())
			}
			if err = c.Close(); err != nil || e.lease != nil || e.secretLeak || len(e.errors) != 0 {
				t.Fatal("AWG lease ownership cleanup", err, e.errors)
			}
		}
	}
}
