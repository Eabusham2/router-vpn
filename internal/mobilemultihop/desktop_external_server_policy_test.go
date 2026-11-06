package mobilemultihop

import (
	"reflect"
	"strings"
	"testing"
)

func desktopExternalRouterServerFixture(t *testing.T, execution string, paired ...bool) *ExternalPolicy {
	t.Helper()
	_, raw := externalExecutionFixture(t, execution)
	graph, _ := externalTestFixture(t, "shadowsocks", "")
	source := externalTestJSON(t, graph)
	capture := externalTestRead(t, raw)
	predecessor, entry := externalPredecessorFixture(t, "wg", "", false)
	entry["id"] = "saved-entry"
	capture["entry"], capture["entry_tag"], capture["predecessor_config"] = entry, externalEntryTag, predecessor
	profile := capture["profile"].(map[string]any)
	profile["multihop_entry_mode"], profile["kill_switch_policy"] = "wg", "always"
	prepare := PrepareExternalExecutionCapture
	if len(paired) != 0 && paired[0] {
		prepare = PrepareExternalPairedExecutionCapture
	}
	prepared, err := prepare(source, externalTestJSON(t, capture), "")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewExternalPolicy(source, prepared)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestDesktopWindowsExternalRouterServerPolicy(t *testing.T) {
	for _, execution := range []string{"server", "auto", "local"} {
		t.Run(execution, func(t *testing.T) {
			original := desktopExternalRouterServerFixture(t, execution)
			policy, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "windows")
			if execution == "local" {
				if err == nil {
					t.Fatal("unsupported selection admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			before, after := externalTestRead(t, original.Config()), externalTestRead(t, policy.Config())
			for _, tag := range []string{LocalTag, ServerTag, ExternalFinalTag} {
				if !reflect.DeepEqual(externalTestFind(t, before, tag), externalTestFind(t, after, tag)) {
					t.Fatal("authenticated candidate or selector changed", tag)
				}
			}
			root := externalTestFind(t, after, externalEntryTag)
			if root["detour"] != DesktopExternalPhysicalTag || policy.Metadata().RootType != "wireguard" {
				t.Fatal("paired root lost original lower")
			}
			delete(root, "detour")
			if !reflect.DeepEqual(root, externalTestFind(t, before, externalEntryTag)) {
				t.Fatal("paired assets changed")
			}
			if !reflect.DeepEqual(before["dns"], after["dns"]) {
				t.Fatal("selected DNS changed")
			}
		})
	}
}

func TestDesktopWindowsExternalRouterServerRejectsChangedCapture(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"selector-local": func(g map[string]any) { externalTestFind(t, g, ExternalFinalTag)["default"] = LocalTag },
		"selector-extra": func(g map[string]any) { externalTestFind(t, g, ExternalFinalTag)["outbounds"] = []any{ServerTag} },
		"relay-password": func(g map[string]any) { externalTestFind(t, g, ServerTag)["password"] = "other-session" },
		"relay-port":     func(g map[string]any) { externalTestFind(t, g, ServerTag)["server_port"] = float64(26272) },
		"relay-bypass":   func(g map[string]any) { delete(externalTestFind(t, g, ServerTag), "detour") },
		"local-bypass":   func(g map[string]any) { delete(externalTestFind(t, g, LocalTag), "detour") },
		"root-key": func(g map[string]any) {
			externalTestFind(t, g, externalEntryTag)["private_key"] = strings.Repeat("a", 44)
		},
		"extra-root": func(g map[string]any) {
			g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": "foreign"})
		},
		"selected-dns": func(g map[string]any) { g["dns"].(map[string]any)["final"] = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			original := desktopExternalRouterServerFixture(t, "server")
			graph := externalTestRead(t, original.Config())
			mutate(graph)
			original.config = externalTestJSON(t, graph)
			if _, err := NewDesktopExternalPolicy(original, strings.Repeat("b", 32), "windows"); err == nil {
				t.Fatal("changed original compiled authority accepted")
			}
		})
	}
	for _, target := range []string{"linux", "darwin"} {
		t.Run(target, func(t *testing.T) {
			if _, err := NewDesktopExternalPolicy(desktopExternalRouterServerFixture(t, "server"), strings.Repeat("b", 32), target); err == nil {
				t.Fatal("unproved platform broadened")
			}
		})
	}
}
