package mobilemultihop

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDesktopPredecessorUsesTheCompleteNodeValidator(t *testing.T) {
	count := 0
	for _, mode := range predecessorFamilies {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				files, profile, start := nodeProfileFixture(t, mode, layer)
				raw := startJSON(t, profile)
				node, err := NewNodeProfile(mode, files, raw, start, "")
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateNodePredecessor(mode, raw, node.Config()); err != nil {
					t.Fatal("complete compiled entry was rejected", err)
				}
				count++
				wrongMode := "wg"
				if mode == wrongMode {
					wrongMode = "shadowsocks"
				}
				if err := ValidateNodePredecessor(wrongMode, raw, node.Config()); err == nil {
					t.Fatal("a different saved mode acquired this compiled graph")
				}
				for _, fault := range []string{"extra-tun", "direct-final", "dns-bypass", "node-kind", "unknown-mode"} {
					graph := startObject(t, node.Config())
					p := startObject(t, raw)
					selected := mode
					switch fault {
					case "extra-tun":
						graph["inbounds"] = append(graph["inbounds"].([]any), graph["inbounds"].([]any)[0])
					case "direct-final":
						graph["route"].(map[string]any)["final"] = "direct"
						graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": "direct"})
					case "dns-bypass":
						graph["dns"].(map[string]any)["final"] = "ambient"
					case "node-kind":
						p["node_kind"] = "external"
					case "unknown-mode":
						selected = "tor-bridge"
					}
					config, _ := json.Marshal(graph)
					if err := ValidateNodePredecessor(selected, startJSON(t, p), string(config)); err == nil {
						t.Fatal("incomplete or substituted predecessor accepted", fault)
					}
				}
			})
		}
	}
	if count != 57 {
		t.Fatal("complete 19-mode and three-layer predecessor matrix did not run", count)
	}
	if ValidateNodePredecessor("wg", "{}", "") == nil || ValidateNodePredecessor("wg", strings.Repeat(" ", 256<<10)+"{}", "{}") == nil {
		t.Fatal("empty or unbounded predecessor entered validation")
	}
}
