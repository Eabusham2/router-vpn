package mobilemultihop

import "testing"

func TestExternalWireGuardCapturedKeepalive(t *testing.T) {
	for _, role := range []string{"entry", "exit"} {
		for _, original := range []any{nil, 0, 25, 65535} {
			for _, changed := range []any{nil, 0, 24, 25, 65535, -1, 65536, 1.5, "25", true} {
				graph, capture := externalTestFixture(t, "wireguard", "wireguard")
				index, field := 0, "entry"
				if role == "exit" {
					index, field = 1, "profile"
				}
				peer := graph["endpoints"].([]any)[index].(map[string]any)["peers"].([]any)[0].(map[string]any)
				source := capture[field].(map[string]any)["external"].(map[string]any)["wireguard"].(map[string]any)
				if original != nil {
					source["persistent_keepalive_interval"] = original
				}
				if changed != nil {
					peer["persistent_keepalive_interval"] = changed
				}
				want := original == changed || (original == nil || original == 0) && (changed == nil || changed == 0)
				_, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, capture))
				if (err == nil) != want {
					t.Fatalf("%s keepalive captured=%v native=%v accepted=%v: %v", role, original, changed, err == nil, err)
				}
			}
		}
	}
}
