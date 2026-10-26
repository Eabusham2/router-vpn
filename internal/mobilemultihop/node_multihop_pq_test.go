package mobilemultihop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
)

func TestNodeMultihopPQIdentityAndRequiredNegotiation(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				exit := multihopNodeFixture(t, mode, layer, "exit")
				original := exit.Config()
				endpoint := startObject(t, original)["endpoints"].([]any)[0].(map[string]any)
				public, _ := base64.StdEncoding.DecodeString(endpoint["pq"].(map[string]any)["public"].(string))
				sum := sha256.Sum256(public)
				identity, err := exit.PQClientIdentity()
				if err != nil || identity != hex.EncodeToString(sum[:]) || exit.Config() != original {
					t.Fatal("captured PQ public fingerprint or private source changed", err)
				}
				for _, fault := range []string{"missing", "empty-secret", "wrong-node", "wrong-mode", "wrong-endpoint", "version", "plain-packet", "layer-bypass"} {
					t.Run(fault, func(t *testing.T) {
						graph := startObject(t, original)
						packet := graph["endpoints"].([]any)[0].(map[string]any)
						switch fault {
						case "missing":
							delete(packet, "pq")
						case "empty-secret":
							packet["pq"].(map[string]any)["secret"] = ""
						case "wrong-node":
							packet["node_id"] = "not-the-captured-node"
						case "wrong-mode":
							packet["mode"] = "wg"
						case "wrong-endpoint":
							packet["pq"].(map[string]any)["endpoint"] = "198.51.100.42:51822"
						case "version":
							packet["pq"].(map[string]any)["version"] = 4
						case "plain-packet":
							packet["type"] = "wireguard"
						case "layer-bypass":
							packet["detour"] = "direct"
						}
						copy := *exit
						copy.config = startJSON(t, graph)
						entry := multihopNodeCapacityFixture(t, "wg", "", "entry", 1500)
						if _, err := NodeMultihopConfig(entry, &copy); err == nil {
							t.Fatal("invalid mandatory PQ transport reached a runnable graph")
						}
					})
				}
			})
		}
	}
}

func TestNodeMultihopPQMTURetainsBasePaddingAndLayerBound(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, capacity := range []int{1420, 1500} {
				for _, fixed := range []int{0, 1280, 1408} {
					t.Run(mode+"/"+layer+"/"+strconv.Itoa(capacity)+"/"+strconv.Itoa(fixed), func(t *testing.T) {
						entry := multihopNodeCapacityFixture(t, "awg2-strong", "", "entry", capacity)
						files, profile, start := multihopNodeSources(t, mode, layer, "exit")
						if fixed != 0 {
							profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(fixed)
						}
						exit, err := NewNodeProfile(mode, files, startJSON(t, profile), start, "")
						if err != nil {
							t.Fatal(err)
						}
						overhead := 60
						if mode == "awg2-pq" {
							overhead += 32
						}
						if layer != "" {
							overhead += 58
						}
						limit := (capacity - overhead) / 16 * 16
						graph, err := NodeMultihopConfig(entry, exit)
						if limit < 1280 || fixed > limit {
							if err == nil {
								t.Fatal("invalid fixed/nested PQ MTU silently accepted")
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						want := limit
						if fixed != 0 {
							want = fixed
						}
						if want > 1420 {
							want = 1420
						}
						for _, raw := range startObject(t, graph)["endpoints"].([]any) {
							endpoint := raw.(map[string]any)
							if endpoint["tag"] == "proxy" && (endpoint["type"] != PQType || endpoint["mode"] != mode || endpoint["mtu"] != float64(want) || endpoint["pq"] == nil) {
								t.Fatal("MTU arithmetic replaced or widened the required PQ owner", endpoint["mtu"], want)
							}
						}
					})
				}
			}
		}
	}
}
