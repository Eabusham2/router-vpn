package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func exitFixtureProfile(t *testing.T, mode string, change func(map[string]any)) string {
	t.Helper()
	profile, _ := xrayEntryFixture(t, mode)
	var files map[string]string
	if e := json.Unmarshal([]byte(profile), &files); e != nil {
		t.Fatal(e)
	}
	raw, e := base64.StdEncoding.DecodeString(files["sing-box.json"])
	if e != nil {
		t.Fatal(e)
	}
	var wrapper map[string]any
	if e = json.Unmarshal(raw, &wrapper); e != nil {
		t.Fatal(e)
	}
	if change != nil {
		change(wrapper)
	}
	raw, e = json.Marshal(wrapper)
	if e != nil {
		t.Fatal(e)
	}
	files["sing-box.json"] = base64.StdEncoding.EncodeToString(raw)
	encoded, e := json.Marshal(files)
	if e != nil {
		t.Fatal(e)
	}
	return string(encoded)
}
func exitNative(t *testing.T, mode string) map[string]any {
	t.Helper()
	profile := exitFixtureProfile(t, mode, nil)
	text, e := CompileXrayExit(profile, mode)
	if e != nil {
		t.Fatal(e)
	}
	var graph map[string]any
	if e = json.Unmarshal([]byte(text), &graph); e != nil {
		t.Fatal(e)
	}
	for _, v := range graph["outbounds"].([]any) {
		o := v.(map[string]any)
		if o["type"] == "routervpn-xray" {
			return o
		}
	}
	t.Fatal("compiled native exit is missing")
	return nil
}
func TestXrayExitKeepsProtocolAndEverySelectedDNSTransport(t *testing.T) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, transport := range []string{"udp", "tcp", "tls", "https", "h3"} {
			t.Run(mode+"/"+transport, func(t *testing.T) {
				resolver := map[string]any{"type": transport, "tag": "selected-dns", "server": "192.168.50.133", "server_port": 5353, "detour": "owned-exit"}
				if transport == "tls" || transport == "https" || transport == "h3" {
					resolver["tls"] = map[string]any{"enabled": true, "server_name": "adguard.example.test"}
				}
				if transport == "https" || transport == "h3" {
					resolver["path"] = "/private-resolver"
				}
				source := exitFixtureProfile(t, mode, func(g map[string]any) {
					g["outbounds"].([]any)[0].(map[string]any)["tag"] = "owned-exit"
					g["route"].(map[string]any)["final"] = "owned-exit"
					g["dns"] = map[string]any{"servers": []any{resolver}, "final": "selected-dns"}
				})
				text, e := CompileXrayExit(source, mode)
				if e != nil {
					t.Fatal(e)
				}
				var graph map[string]any
				json.Unmarshal([]byte(text), &graph)
				var assets map[string]string
				json.Unmarshal([]byte(source), &assets)
				raw, _ := base64.StdEncoding.DecodeString(assets["xray.json"])
				out := graph["outbounds"].([]any)[0].(map[string]any)
				if out["type"] != "routervpn-xray" || out["mode"] != mode || out["tag"] != "proxy" || out["config_json"] != string(raw) || len(out) != 4 {
					t.Fatal("exit authentication, protocol or owner changed")
				}
				if len(graph["inbounds"].([]any)) != 1 || graph["endpoints"] != nil {
					t.Fatal("extra VPN owner introduced")
				}
				got := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				want := map[string]any{}
				for k, v := range resolver {
					want[k] = v
				}
				want["detour"] = "proxy"
				a, _ := json.Marshal(got)
				b, _ := json.Marshal(want)
				if string(a) != string(b) {
					t.Fatal("selected resolver, transport, port or TLS changed")
				}
				if graph["route"].(map[string]any)["final"] != "proxy" {
					t.Fatal("exit path not final")
				}
				// Re-importing an already native graph is exact and does not add a helper.
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(text))
				again, _ := json.Marshal(assets)
				repeated, e := CompileXrayExit(string(again), mode)
				if e != nil || repeated != text {
					t.Fatal("non-idempotent native exit composition", e)
				}
			})
		}
	}
}
func TestXrayExitRejectsMalformedOrBypassedDNS(t *testing.T) {
	for _, dns := range []any{nil, "system", true, map[string]any{}, map[string]any{"servers": "bad"}, map[string]any{"servers": []any{map[string]any{"type": "udp", "server": "192.168.50.133", "detour": "direct"}}}} {
		source := exitFixtureProfile(t, "reality-vision", func(g map[string]any) { g["dns"] = dns })
		if _, e := CompileXrayExit(source, "reality-vision"); e == nil {
			t.Fatal("malformed/bypassed DNS silently replaced")
		}
	}
	source := exitFixtureProfile(t, "reality-xhttp", nil)
	var files map[string]string
	json.Unmarshal([]byte(source), &files)
	delete(files, "sing-box.json")
	raw, _ := json.Marshal(files)
	result, e := CompileXrayExit(string(raw), "reality-xhttp")
	if e != nil {
		t.Fatal(e)
	}
	var graph map[string]any
	json.Unmarshal([]byte(result), &graph)
	if graph["dns"] != nil {
		t.Fatal("legacy XHTTP invents a public resolver instead of awaiting captured host policy")
	}
	if graph["outbounds"].([]any)[0].(map[string]any)["tag"] != "proxy" {
		t.Fatal("legacy raw XHTTP exit not owned")
	}
	for _, mode := range []string{"split", "max", "direct", "tor"} {
		if _, e = CompileXrayExit(source, mode); e == nil {
			t.Fatal("unsupported graph collapsed into one native exit")
		}
	}
}
func TestXrayExitUsesActualRetainedLocalServerAutoSelection(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = previous }()
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				config, metadata := fixture(t, execution)
				var graph map[string]any
				json.Unmarshal([]byte(config), &graph)
				out := exitNative(t, mode)
				out["detour"] = "entry-wg"
				graph["outbounds"] = []any{out}
				var meta Metadata
				json.Unmarshal([]byte(metadata), &meta)
				meta.ExitMode = mode
				raw, _ := json.Marshal(graph)
				data, _ := json.Marshal(meta)
				ctrl, e := New(string(raw), string(data))
				if e != nil {
					t.Fatal(e)
				}
				engine := makeEngine(t)
				engine.exitMode = mode
				if e = ctrl.Run(context.Background(), engine); e != nil {
					t.Fatal(e)
				}
				if !ctrl.Healthy() {
					t.Fatal("native exit did not retain verified engine")
				}
				var result map[string]any
				json.Unmarshal([]byte(ctrl.Config()), &result)
				local := result["outbounds"].([]any)[0].(map[string]any)
				copy := map[string]any{}
				for k, v := range out {
					copy[k] = v
				}
				copy["tag"] = LocalTag
				if !reflect.DeepEqual(copy, local) {
					t.Fatal("local exit credential/protocol changed during comparison")
				}
				if e = ctrl.Close(); e != nil {
					t.Fatal(e)
				}
				if engine.lease != nil || engine.secretLeak || len(engine.errors) != 0 {
					t.Fatal("native exit retained another session's lease or leaked credentials")
				}
				for _, fault := range []string{"label", "bypass", "extra", "manager", "auth"} {
					changed := map[string]any{}
					for k, v := range out {
						changed[k] = v
					}
					switch fault {
					case "label":
						changed["mode"] = "max"
					case "bypass":
						changed["detour"] = "direct"
					case "extra":
						changed["bind_interface"] = "wan"
					case "auth":
						changed["config_json"] = `{"secret":"must-not-leak"}`
					}
					graph["outbounds"] = []any{changed}
					if fault == "manager" {
						graph["endpoints"] = append(graph["endpoints"].([]any), changed)
						graph["outbounds"] = []any{}
					}
					raw, _ = json.Marshal(graph)
					_, e = New(string(raw), string(data))
					if e == nil || strings.Contains(e.Error(), "must-not-leak") {
						t.Fatal("forged native exit accepted or echoed private source", fault)
					}
					if fault == "manager" {
						graph["endpoints"] = graph["endpoints"].([]any)[:1]
					}
				}
			})
		}
	}
}
