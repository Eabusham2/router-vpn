package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func appleOpenVPNExecutionFixture(t *testing.T, count int, mode, network, layer string) (NodeChainSource, map[string]any) {
	t.Helper()
	packetCount := count
	if layer != "" {
		// The original longest layered fixture supplies a 4096-byte configured
		// packet budget. Retain those exact assets for shorter layered paths;
		// never turn that saved budget into a live connected-capacity receipt.
		packetCount = 6
	}
	local, plan := nodeChainOpenVPNServerPlanFixture(t, packetCount, mode, network, layer)
	if packetCount != count {
		local.Nodes = append(append([]string(nil), local.Nodes[:count]...), local.Nodes[packetCount:]...)
		local.IdentitySources = append(append([]string(nil), local.IdentitySources[:count]...), local.IdentitySources[packetCount:]...)
		rows := plan["members"].([]any)
		plan["members"] = append(append([]any(nil), rows[:count-1]...), rows[packetCount-1:]...)
	}
	return local, plan
}

// Emit original provider pairs and independently provisioned packet assets for
// the shipping Swift consumers. Fixture generation supplies no connected proof.
func TestEmitAppleOpenVPNExecutionFixtures(t *testing.T) {
	destination := os.Getenv("ROUTER_VPN_APPLE_OPENVPN_FIXTURES")
	if destination == "" {
		t.Skip("the required Apple source gate supplies its private fixture output")
	}
	fixtures := map[string]any{}
	for count := 1; count <= 6; count++ {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "mixed"} {
			for _, network := range []string{"tcp", "udp"} {
				for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					initialMode := mode
					if initialMode == "mixed" {
						initialMode = "wg"
					}
					local, original := appleOpenVPNExecutionFixture(t, count, initialMode, network, layer)
					if mode == "mixed" {
						for position := 0; position < count; position++ {
							selected := []string{"wg", "awg2-fast", "awg2-strong"}[position%3]
							source, plan := appleOpenVPNExecutionFixture(t, count, selected, network, layer)
							local.Nodes[position], local.IdentitySources[position] = source.Nodes[position], source.IdentitySources[position]
							if position == 0 {
								original["entry"] = plan["entry"]
							} else {
								original["members"].([]any)[position-1] = plan["members"].([]any)[position-1]
							}
						}
					}
					policy, err := NewNodeChainOpenVPNServerPlan(startJSON(t, original))
					if err != nil {
						t.Fatal("original independent Server plan", count, mode, network, layer, err)
					}
					chain, err := NewNodeChain(startJSON(t, local))
					if err != nil {
						t.Fatal("original Local packet graph", count, mode, network, layer, err)
					}
					sealed, err := chain.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					bundles := make([]map[string]any, len(local.Nodes))
					references := make([]map[string]string, len(local.Nodes))
					for position, input := range local.Nodes {
						var profile map[string]any
						selectedMode := mode
						if position == count {
							var member nodeChainImportedInput
							if json.Unmarshal([]byte(input), &member) != nil {
								t.Fatal("original provider capture")
							}
							profile = externalTestRead(t, member.Capture)["profile"].(map[string]any)
							bundles[position] = map[string]any{"profiles": map[string]any{}, "routerProfiles": []any{profile}}
							selectedMode = "openvpn"
						} else {
							node, err := ParseNodeLaunchInput(input)
							if err != nil {
								t.Fatal(err)
							}
							bundles[position] = nodeChainServerPlanBundle(t, node, local.IdentitySources[position])
							profile = bundles[position]["routerProfiles"].([]any)[0].(map[string]any)
							selectedMode = node.mode
						}
						id := profile["id"].(string)
						bundles[position]["selectedRouterID"] = id
						references[position] = map[string]string{"id": id, "mode": selectedMode}
					}
					final := bundles[len(bundles)-1]["routerProfiles"].([]any)[0].(map[string]any)
					final["multihop_enabled"], final["multihop_execution"], final["multihop_nodes"] = true, "local", references
					name := layer
					if name == "" {
						name = "off"
					}
					key := fmt.Sprintf("%d/%s/%s/%s", count+2, mode, network, name)
					fixtures[key] = map[string]any{"bundles": bundles, "server_source": policy.Source(), "descriptor": policy.Descriptor(), "original_local_launch": sealed}
				}
			}
		}
	}
	if len(fixtures) != 144 {
		t.Fatal("incomplete original source inventory", len(fixtures))
	}
	encoded, err := json.Marshal(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("emitted 144 original OpenVPN packet/provider/Server source fixtures")
}
