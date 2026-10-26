package mobilemultihop

import (
	"strings"
	"testing"

	"router-vpn/internal/nativecomposite"
)

func TestNodeMultihopCompositeRejectsMissingForeignOrBypassedLanes(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, fault := range []string{"root-detour", "same-lane", "wrong-node", "wrong-mode", "missing-tcp", "missing-udp", "tcp-bypass", "udp-bypass", "weak-udp-trust", "wrong-layer", "foreign-child", "DNS-bypass", "missing-cover"} {
				t.Run(mode+"/"+layer+"/"+fault, func(t *testing.T) {
					entry := multihopNodeFixture(t, "awg2-strong", "aes-256-gcm", "entry")
					exit := multihopNodeFixture(t, mode, layer, "exit")
					graph := startObject(t, exit.config)
					nodes := map[string]map[string]any{}
					for _, raw := range graph["outbounds"].([]any) {
						out := raw.(map[string]any)
						nodes[predecessorText(out, "tag")] = out
					}
					switch fault {
					case "root-detour":
						nodes["proxy"]["detour"] = "entry-wg"
					case "same-lane":
						nodes["proxy"]["udp"] = nodes["proxy"]["tcp"]
					case "wrong-node":
						nodes["proxy"]["node_id"] = strings.Repeat("e", 64)
					case "wrong-mode":
						nodes["proxy"]["mode"] = "not-the-captured-composite"
					case "missing-tcp", "missing-udp":
						tag := nativecomposite.SourcePrefix + strings.TrimPrefix(fault, "missing-")
						values := []any{}
						for _, raw := range graph["outbounds"].([]any) {
							if raw.(map[string]any)["tag"] != tag {
								values = append(values, raw)
							}
						}
						graph["outbounds"] = values
					case "tcp-bypass":
						nodes[nativecomposite.TCPTag]["detour"] = "direct"
					case "udp-bypass":
						nodes[nativecomposite.UDPTag]["detour"] = "direct"
					case "weak-udp-trust":
						nodes[nativecomposite.UDPTag]["tls"].(map[string]any)["insecure"] = true
					case "wrong-layer":
						if layer == "" {
							exit.profile["start_layer"] = "aes-256-gcm"
						} else {
							delete(nodes[nativecomposite.UDPTag], "detour")
						}
					case "foreign-child":
						graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": CompositeExitPrefix + "tcp"})
					case "DNS-bypass":
						graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] = "direct"
					case "missing-cover":
						delete(graph, "services")
					}
					exit.config = startJSON(t, graph)
					if _, err := NodeMultihopConfig(entry, exit); err == nil {
						t.Fatal("incomplete or foreign composite reached a runnable node graph")
					}
				})
			}
		}
	}
}
