package mobilemultihop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func maxHopSource(t *testing.T, mode, layer string, exit bool) (string, string) {
	t.Helper()
	host := "10.77.0.1"
	if exit {
		host = "10.88.0.1"
	}
	base, outs, node := compiledMAXBoundary(t, mode, layer, host)
	if exit {
		// Independent structural node/key fixtures, not a physical KEM exchange.
		public := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
		hash := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + public))
		node = hex.EncodeToString(hash[:])
		base["node_id"] = node
		base["private_key"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("v", 32)))
		base["peers"].([]any)[0].(map[string]any)["public_key"] = public
		base["pq"].(map[string]any)["public"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", 128)))
	}
	graph := map[string]any{"endpoints": []any{base}, "outbounds": outs,
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "mtu": 1280, "auto_route": true, "strict_route": true, "address": []string{"172.29.94.1/30", "fd29:94::1/126"}}},
		"route":    map[string]any{"final": "proxy", "rules": []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}},
		"dns":      map[string]any{"servers": []any{map[string]any{"type": "udp", "server": "192.168.50.133", "tag": "adguard", "detour": "proxy"}}, "final": "adguard"}}
	return startJSON(t, graph), node
}

func maxCompositeFixture(t *testing.T, entryMode, exitMode, entryLayer, exitLayer, execution string) (string, string, string, string, string, string) {
	t.Helper()
	e, x := entryMode, exitMode
	if MAXMode(e) {
		e = multihoprelay.MAXBaseMode(e)
	}
	if MAXMode(x) {
		x = multihoprelay.MAXBaseMode(x)
	}
	el, xl := entryLayer, exitLayer
	if MAXMode(entryMode) {
		el = ""
	}
	if MAXMode(exitMode) {
		xl = ""
	}
	var config, metadata, entryStart, exitStart string
	if IsPQMode(x) {
		config, metadata, entryStart, exitStart = pqExitGraph(t, e, x, el, xl, execution, false)
	} else if IsPQMode(e) {
		config, metadata, entryStart, exitStart = pqEntryGraph(t, e, x, el, xl, execution)
	} else {
		config, metadata, entryStart, exitStart = exitLayerFixture(t, e, x, el, xl, execution)
	}
	g, m := startObject(t, config), startObject(t, metadata)
	g["inbounds"].([]any)[0].(map[string]any)["tag"] = "tun-in"
	g["inbounds"].([]any)[0].(map[string]any)["mtu"] = 1280
	entrySource, exitSource := "", ""
	for _, entry := range []bool{true, false} {
		mode, layer, tag, prefix := exitMode, exitLayer, "proxy", "exit"
		if entry {
			mode, layer, tag, prefix = entryMode, entryLayer, "entry-wg", "entry"
		}
		if !MAXMode(mode) {
			continue
		}
		source, node := maxHopSource(t, mode, layer, !entry)
		plain, err := MAXMultihopBase(source, mode, node, layer)
		if err != nil {
			t.Fatal(err)
		}
		base := graphEntry(t, startObject(t, plain), "proxy")
		base["tag"] = tag
		if !entry {
			base["detour"] = "entry-wg"
		}
		found := false
		endpoints := g["endpoints"].([]any)
		for i, raw := range endpoints {
			if raw.(map[string]any)["tag"] == tag {
				endpoints[i] = base
				found = true
			}
		}
		if !found {
			t.Fatal("fixture lost packet slot")
		}
		m[prefix+"_mode"], m[prefix+"_node_id"], m[prefix+"_start_layer"] = mode, node, layer
		if entry {
			entrySource = source
			m["entry_api"] = "http://10.77.0.1:8787"
		} else {
			exitSource = source
			m["exit_api"] = "http://10.88.0.1:8787"
		}
	}
	return startJSON(t, g), startJSON(t, m), entrySource, exitSource, entryStart, exitStart
}

func TestCompleteMAXMultihopRetainsMixedEntryExitGraphs(t *testing.T) {
	modes := []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"}
	layers := [][2]string{{"", ""}, {"aes-256-gcm", "aes-256-gcm+xor-whitening"}, {"aes-256-gcm+xor-whitening", "aes-256-gcm"}}
	count := 0
	for _, entry := range modes {
		for _, exit := range modes {
			if !MAXMode(entry) && !MAXMode(exit) {
				continue
			}
			for _, layer := range layers {
				t.Run(entry+"/"+exit+"/"+layer[0]+"/"+layer[1], func(t *testing.T) {
					input, meta, a, b, al, bl := maxCompositeFixture(t, entry, exit, layer[0], layer[1], "auto")
					g, err := ComposeMAXMultihop(input, meta, a, b)
					if err != nil {
						t.Fatal(err)
					}
					before := startObject(t, g)
					original := startObject(t, input)
					for _, field := range []string{"inbounds", "route", "dns"} {
						if !reflect.DeepEqual(before[field], original[field]) {
							t.Fatal("composition discarded device policy", field)
						}
					}
					if _, err = ComposeMAXMultihop(g, meta, a, b); err == nil {
						t.Fatal("same MAX chain composed twice")
					}
					if c, err := New(input, meta); err == nil {
						c.Close()
						t.Fatal("temporary base counted as complete MAX")
					}
					profiles := `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
					if ProxyEntryMode(entry) {
						profiles = `{"entry":{"mtu_policy":"fixed","manual_mtu":1280},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`
					}
					sized, err := ApplyMTUPolicy(g, profiles)
					if err != nil {
						t.Fatal(err)
					}
					c, err := NewWithStartLayers(sized, meta, al, bl)
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					after := startObject(t, c.Config())
					if c.meta.EntryMode != entry || c.meta.ExitMode != exit || c.candidate("local").Transport != exit {
						t.Fatal("composite modes became base-only labels")
					}
					if MAXMode(exit) && (c.localPQIdentity == "" || c.localPublicKey == "" || c.proposal.ExitMode != exit || c.proposal.ExitStartLayer != layer[1]) {
						t.Fatal("composite exit lost independent lease identities")
					}
					if c.Healthy() {
						t.Fatal("prepared composite graph falsely healthy")
					}
					if graphEntry(t, after, ServerTag)["detour"] != "entry-wg" {
						t.Fatal("server candidate bypassed entry")
					}
					for _, isEntry := range []bool{true, false} {
						mode, rootTag, node, layerMode, via, src := exit, LocalTag, c.meta.ExitNodeID, layer[1], "entry-wg", b
						if isEntry {
							mode, rootTag, node, layerMode, via, src = entry, "entry-wg", c.meta.EntryNodeID, layer[0], "", a
						}
						if !MAXMode(mode) {
							continue
						}
						base := graphEntry(t, after, rootTag)
						tags := maxTags(rootTag, isEntry)
						list := []any{graphEntry(t, after, tags.Middle), graphEntry(t, after, tags.Outer)}
						if layerMode != "" {
							list = append(list, graphEntry(t, after, tags.Start))
						}
						if err = multihoprelay.ValidateMAXChain(base, list, mode, node, layerMode, tags, via); err != nil {
							t.Fatal(err)
						}
						captured := graphEntry(t, startObject(t, src), "proxy")
						for _, field := range []string{"private_key", "peers", "pq", "amnezia", "node_id", "mode"} {
							if !reflect.DeepEqual(base[field], captured[field]) {
								t.Fatal("captured MAX key/peer changed", field)
							}
						}
					}
					count++
				})
			}
		}
	}
	if count != 288 {
		t.Fatal("MAX composition matrix incomplete", count)
	}
}

func TestCompleteMAXCompositionRejectsChangedPlaceholdersAndMissingLayers(t *testing.T) {
	input, meta, a, b, _, _ := maxCompositeFixture(t, "max-tls-wg", "max-quic-awg", "aes-256-gcm", "aes-256-gcm+xor-whitening", "auto")
	for _, fault := range []string{"private-key", "pq-key", "node", "mode", "mtu", "route", "unknown-out", "wrong-source", "missing-source"} {
		t.Run(fault, func(t *testing.T) {
			g := startObject(t, input)
			x, y := a, b
			ep := graphEntry(t, g, "proxy")
			switch fault {
			case "private-key":
				ep["private_key"] = graphEntry(t, g, "entry-wg")["private_key"]
			case "pq-key":
				ep["pq"].(map[string]any)["public"] = "changed"
			case "node":
				ep["node_id"] = strings.Repeat("c", 64)
			case "mode":
				ep["mode"] = "awg2-fast"
			case "mtu":
				ep["mtu"] = float64(1500)
			case "route":
				ep["detour"] = "direct"
			case "unknown-out":
				g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": maxTags("proxy", false).Outer})
			case "wrong-source":
				x, y = y, x
			case "missing-source":
				y = ""
			}
			if _, err := ComposeMAXMultihop(startJSON(t, g), meta, x, y); err == nil {
				t.Fatal("modified MAX input was accepted")
			}
		})
	}
	compiled, err := ComposeMAXMultihop(input, meta, a, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"base-detour", "middle-detour", "exit-egress", "entry-egress", "omitted-layer", "wrong-metadata", "duplicate-tag", "unknown-chain", "private-node"} {
		t.Run(fault, func(t *testing.T) {
			g, m := startObject(t, compiled), startObject(t, meta)
			switch fault {
			case "base-detour":
				graphEntry(t, g, "proxy")["detour"] = "entry-wg"
			case "middle-detour":
				graphEntry(t, g, maxTags("proxy", false).Middle)["detour"] = "entry-wg"
			case "exit-egress":
				delete(graphEntry(t, g, maxTags("proxy", false).Start), "detour")
			case "entry-egress":
				graphEntry(t, g, maxTags("entry-wg", true).Start)["detour"] = "proxy"
			case "omitted-layer":
				m["exit_start_layer"] = ""
			case "wrong-metadata":
				m["entry_mode"] = "wg-pq"
			case "duplicate-tag":
				g["outbounds"] = append(g["outbounds"].([]any), graphEntry(t, g, maxTags("proxy", false).Middle))
			case "unknown-chain":
				g["outbounds"] = append(g["outbounds"].([]any), map[string]any{"type": "direct", "tag": MAXExitPrefix + "bypass"})
			case "private-node":
				m["exit_api"] = "http://10.88.0.99:8787"
			}
			if c, err := New(startJSON(t, g), startJSON(t, m)); err == nil {
				c.Close()
				t.Fatal("unowned chain adopted")
			}
		})
	}
	for _, bad := range []string{"", `{}`, `{"outbounds":null}`, `{"outbounds":[null]}`} {
		if _, err := ApplyMTUPolicy(bad, `{"entry":{},"exit":{}}`); err == nil {
			t.Fatal("malformed MTU graph accepted")
		}
	}
}
