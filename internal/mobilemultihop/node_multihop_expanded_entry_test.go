package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestNodeMultihopEveryCompleteNativeEntryAndExit(t *testing.T) {
	count := 0
	layers := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}
	for _, mode := range NodeMultihopEntryModes() {
		for layerIndex, layer := range layers {
			for exitIndex, exitMode := range NodeMultihopExitModes() {
				t.Run(mode+"/"+layer+"/"+exitMode, func(t *testing.T) {
					capacity := 0
					if mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" || IsPQMode(mode) || MAXMode(mode) {
						capacity = 1500 // Explicit entry payload capacity, not a PMTU claim.
					}
					entry := multihopNodeCapacityFixture(t, mode, layer, "entry", capacity)
					exit := multihopNodeFixture(t, exitMode, layers[(layerIndex+exitIndex)%len(layers)], "exit")
					beforeEntry, beforeExit := entry.Config(), exit.Config()
					owners, err := entry.MultihopEntryOwners()
					if err != nil {
						t.Fatal(err)
					}
					compiled, err := NodeMultihopConfig(entry, exit)
					if err != nil {
						t.Fatal(err)
					}
					if entry.Config() != beforeEntry || exit.Config() != beforeExit {
						t.Fatal("composition rewrote captured input assets")
					}
					graph := startObject(t, compiled)
					ins := graph["inbounds"].([]any)
					if len(ins) != 1 || ins[0].(map[string]any)["type"] != "tun" || graph["route"].(map[string]any)["final"] != "proxy" {
						t.Fatal("expanded entry lost single protected TUN or independent exit")
					}
					mtu := ins[0].(map[string]any)["mtu"].(float64)
					if mtu < 1280 || mtu > 1500 {
						t.Fatal("historical MTU replaced configured path bounds", mtu)
					}
					captured, err := nodeMultihopPredecessor(entry)
					if err != nil {
						t.Fatal(err)
					}
					reverse, dnsReverse := map[string]string{"entry-wg": captured.finalTag}, map[string]string{}
					for original, owner := range captured.nodeOwnerNames("entry-wg") {
						reverse[owner] = original
					}
					for tag := range captured.resolvers {
						dnsReverse[predecessorNamespace("dns", tag)] = tag
					}
					undoResolver := func(value map[string]any) {
						if query, ok := value["domain_resolver"].(map[string]any); ok {
							tag := predecessorText(query, "server")
							if dnsReverse[tag] == "" {
								t.Fatal("entry acquired another node's resolver", tag)
							}
							query["server"] = dnsReverse[tag]
						}
					}
					seen := map[string]bool{}
					for _, family := range []string{"endpoints", "outbounds"} {
						rows, _ := graph[family].([]any)
						for _, raw := range rows {
							actual := predecessorCopy(raw.(map[string]any))
							tag := predecessorText(actual, "tag")
							original := reverse[tag]
							if original == "" {
								continue
							}
							if seen[tag] {
								t.Fatal("entry transport owner duplicated")
							}
							seen[tag] = true
							actual["tag"] = original
							for _, field := range []string{"detour", "tcp", "udp"} {
								if ref, exists := actual[field]; exists {
									name, _ := ref.(string)
									if reverse[name] == "" {
										t.Fatal("entry transport escaped its captured dependency closure")
									}
									actual[field] = reverse[name]
								}
							}
							undoResolver(actual)
							prior := predecessorCopy(captured.nodes[original])
							delete(actual, "mtu")
							delete(prior, "mtu")
							if !reflect.DeepEqual(prior, actual) {
								t.Fatal("entry keys, TLS, protocol parameters or helper dependency changed", family, original)
							}
						}
					}
					if len(seen) != len(owners.Nodes) {
						t.Fatal("complete native entry silently lost an engine")
					}
					seenDNS := map[string]bool{}
					for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
						actual := predecessorCopy(raw.(map[string]any))
						tag := predecessorText(actual, "tag")
						original := dnsReverse[tag]
						if original == "" {
							continue
						}
						seenDNS[tag] = true
						actual["tag"] = original
						if ref, exists := actual["detour"]; exists {
							actual["detour"] = reverse[ref.(string)]
						}
						undoResolver(actual)
						if !reflect.DeepEqual(actual, captured.resolvers[original]) {
							t.Fatal("entry DNS transport, endpoint, bootstrap or lower path changed")
						}
					}
					if len(seenDNS) != len(owners.Resolvers) {
						t.Fatal("entry resolver tree was truncated")
					}
					count++
				})
			}
		}
	}
	if count != len(NodeMultihopEntryModes())*len(layers)*len(NodeMultihopExitModes()) {
		t.Fatal("complete entry/exit matrix did not execute", count)
	}
}
