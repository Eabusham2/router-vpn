package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDesktopWindowsExternalRouterComparePolicy(t *testing.T) {
	original := desktopExternalRouterServerFixture(t, "auto", true)
	policy, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), "windows")
	if err != nil {
		t.Fatal(err)
	}
	before, after := externalTestRead(t, original.Config()), externalTestRead(t, policy.Config())
	for _, tag := range []string{LocalTag, ServerTag, ExternalFinalTag} {
		if !reflect.DeepEqual(externalTestFind(t, before, tag), externalTestFind(t, after, tag)) {
			t.Fatal("authenticated Compare row changed", tag)
		}
	}
	if externalTestFind(t, after, ExternalFinalTag)["default"] != LocalTag {
		t.Fatal("Compare default ceased to be captured Local candidate")
	}
	if !reflect.DeepEqual(before["dns"], after["dns"]) {
		t.Fatal("selected DNS changed")
	}
	for _, target := range []string{"linux", "darwin"} {
		if _, err := NewDesktopExternalPolicy(original, strings.Repeat("a", 32), target); err == nil {
			t.Fatal("Compare broadened another OS", target)
		}
	}
	for _, field := range []string{"selection", "entry", "lease", "row"} {
		t.Run(field, func(t *testing.T) {
			changed := desktopExternalRouterServerFixture(t, "auto", true)
			switch field {
			case "selection":
				changed.capture.Profile["multihop_execution"] = "local"
			case "entry":
				changed.capture.Entry["node_proof_id"] = strings.Repeat("f", 64)
			case "lease":
				changed.capture.Execution.Request.Password = "other-session"
			case "row":
				graph := externalTestRead(t, changed.Config())
				externalTestFind(t, graph, ExternalFinalTag)["default"] = ServerTag
				changed.config = externalTestJSON(t, graph)
			}
			if _, err := NewDesktopExternalPolicy(changed, strings.Repeat("b", 32), "windows"); err == nil {
				t.Fatal("replacement Compare authority accepted")
			}
		})
	}
	// A restored winner remains a new execution proposal under the original
	// saved auto source; the controller receives a fixed choice, not auto again.
	graph, _ := externalTestFixture(t, "shadowsocks", "")
	source := externalTestJSON(t, graph)
	raw, _ := json.Marshal(original.capture)
	saved := externalTestRead(t, string(raw))
	delete(saved, "execution")
	for _, winner := range []string{"local", "server"} {
		t.Run("restore-"+winner, func(t *testing.T) {
			prepared, err := PrepareExternalPairedExecutionCapture(source, externalTestJSON(t, saved), winner)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := NewExternalPolicy(source, prepared)
			if err != nil {
				t.Fatal(err)
			}
			derived, err := NewDesktopExternalPolicy(restored, strings.Repeat("c", 32), "windows")
			if err != nil {
				t.Fatal(err)
			}
			if restored.capture.Profile["multihop_execution"] != "auto" || restored.capture.Execution.Selection != winner || restored.capture.Execution.Request.SessionID == original.capture.Execution.Request.SessionID {
				t.Fatal("restore replaced saved auto or reused lease")
			}
			want := LocalTag
			if winner == "server" {
				want = ServerTag
			}
			if externalTestFind(t, externalTestRead(t, derived.Config()), ExternalFinalTag)["default"] != want {
				t.Fatal("restore reran Compare")
			}
		})
	}
}
