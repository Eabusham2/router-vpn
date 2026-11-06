package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func TestDesktopWindowsExternalRouterLocalPolicy(t *testing.T) {
	original := desktopExternalRouterServerFixture(t, "local", true)
	policy, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "windows")
	if err != nil {
		t.Fatal(err)
	}
	before, after := externalTestRead(t, original.Config()), externalTestRead(t, policy.Config())
	for _, tag := range []string{LocalTag, ServerTag, ExternalFinalTag} {
		if !reflect.DeepEqual(externalTestFind(t, before, tag), externalTestFind(t, after, tag)) {
			t.Fatal("candidate changed", tag)
		}
	}
	if externalTestFind(t, after, ExternalFinalTag)["default"] != LocalTag {
		t.Fatal("Local choice replaced")
	}
	if !reflect.DeepEqual(before["dns"], after["dns"]) {
		t.Fatal("selected DNS changed")
	}
	root := externalTestFind(t, after, externalEntryTag)
	if root["detour"] != DesktopExternalPhysicalTag {
		t.Fatal("original WG root bypassed")
	}
	delete(root, "detour")
	if !reflect.DeepEqual(root, externalTestFind(t, before, externalEntryTag)) {
		t.Fatal("paired assets replaced")
	}
	for _, os := range []string{"darwin", "linux"} {
		if _, err := NewDesktopExternalPolicy(original, strings.Repeat("b", 32), os); err == nil {
			t.Fatal("unproved platform accepted", os)
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"selector-server": func(g map[string]any) { externalTestFind(t, g, ExternalFinalTag)["default"] = ServerTag },
		"local-bypass":    func(g map[string]any) { delete(externalTestFind(t, g, LocalTag), "detour") },
		"relay-password":  func(g map[string]any) { externalTestFind(t, g, ServerTag)["password"] = "foreign" },
		"extra-root": func(g map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": "foreign"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := desktopExternalRouterServerFixture(t, "local", true)
			g := externalTestRead(t, p.Config())
			mutate(g)
			p.config = externalTestJSON(t, g)
			if _, err := NewDesktopExternalPolicy(p, strings.Repeat("c", 32), "windows"); err == nil {
				t.Fatal("changed Local graph accepted")
			}
		})
	}
}

func TestDesktopWindowsExternalRouterLocalCaptureIsExplicit(t *testing.T) {
	original := desktopExternalRouterServerFixture(t, "local", true)
	capture := externalTestRead(t, externalTestJSON(t, original.capture))
	graph, _ := externalTestFixture(t, "shadowsocks", "")
	source := externalTestJSON(t, graph)
	delete(capture, "execution")
	raw := externalTestJSON(t, capture)
	ordinary, err := PrepareExternalExecutionCapture(source, raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if externalTestRead(t, ordinary)["execution"] != nil {
		t.Fatal("ordinary Local acquired implicit paired controller")
	}
	first, err := PrepareExternalPairedExecutionCapture(source, raw, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareExternalPairedExecutionCapture(source, raw, "")
	if err != nil {
		t.Fatal(err)
	}
	a, b := externalTestRead(t, first), externalTestRead(t, second)
	if reflect.DeepEqual(a["execution"], b["execution"]) {
		t.Fatal("fresh explicit capture reused relay proposal")
	}
	for _, key := range []string{"profile", "entry", "predecessor_config"} {
		if !reflect.DeepEqual(a[key], capture[key]) {
			t.Fatal("capture changed original source", key)
		}
	}
	if _, err := PrepareExternalPairedExecutionCapture(source, raw, "server"); err == nil {
		t.Fatal("restoration replaced explicit Local")
	}
	if _, err := PrepareExternalPairedExecutionCapture(source, first, ""); err == nil {
		t.Fatal("execution recaptured")
	}
	capture["profile"].(map[string]any)["multihop_execution"] = "auto"
	if _, err := PrepareExternalPairedExecutionCapture(source, externalTestJSON(t, capture), ""); err == nil {
		t.Fatal("Compare admitted before native proof")
	}
}
