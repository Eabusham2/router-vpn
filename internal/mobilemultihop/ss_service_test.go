package mobilemultihop

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCapturedSSServicePassiveAuthority(t *testing.T) {
	files, p, _ := nodeProfileFixture(t, "shadowsocks", "")
	node := p["node_proof_id"].(string)
	var assets map[string]string
	if err := exactJSON([]byte(files), &assets, 4<<20); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
	graph := externalTestRead(t, string(raw))
	graph["outbounds"].([]any)[0].(map[string]any)["server"] = "node.example.test"
	assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, graph)))
	files = pairedSSServiceFiles(t, externalTestJSON(t, assets), node)
	if err := ValidateCapturedSSService(files, node); err != nil {
		t.Fatal("passive hostname authority rejected", err)
	}
	if _, err := CompileProxyEntry(files, "shadowsocks"); err == nil {
		t.Fatal("passive validation widened physical hostname admission")
	}
	for _, fault := range []string{"missing-node", "foreign-node", "malformed-node", "missing-claim", "unknown-asset", "oversize"} {
		t.Run(fault, func(t *testing.T) {
			source, owner := files, node
			switch fault {
			case "missing-node":
				owner = ""
			case "foreign-node":
				owner = strings.Repeat("b", 64)
			case "malformed-node":
				owner = "not-a-node"
			case "missing-claim":
				source = externalTestJSON(t, assets)
			case "unknown-asset":
				var copy map[string]string
				_ = exactJSON([]byte(files), &copy, 8<<20)
				copy["foreign.json"] = base64.StdEncoding.EncodeToString([]byte("{}"))
				source = externalTestJSON(t, copy)
			case "oversize":
				source = strings.Repeat(" ", 8<<20+1)
			}
			if err := ValidateCapturedSSService(source, owner); err == nil {
				t.Fatal("unowned passive authority accepted")
			}
		})
	}
}

func TestResolvedSSSourceRetainsOriginalProjection(t *testing.T) {
	original := map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "node.example.test", "server_port": 8388, "method": NativeStartLayerMethod, "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))}}, "dns": map[string]any{"final": "home"}}
	for _, fault := range []string{"success", "key", "port", "method", "graph", "hostname", "loopback", "extra-row", "literal-change"} {
		t.Run(fault, func(t *testing.T) {
			raw := externalTestJSON(t, original)
			resolved := externalTestRead(t, raw)
			out := resolved["outbounds"].([]any)[0].(map[string]any)
			out["server"] = "192.0.2.77"
			switch fault {
			case "key":
				out["password"] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
			case "port":
				out["server_port"] = float64(9999)
			case "method":
				out["method"] = "foreign"
			case "graph":
				resolved["dns"] = map[string]any{"final": "foreign"}
			case "hostname":
				out["server"] = "other.example.test"
			case "loopback":
				out["server"] = "127.0.0.1"
			case "extra-row":
				resolved["outbounds"] = append(resolved["outbounds"].([]any), out)
			case "literal-change":
				base := externalTestRead(t, raw)
				base["outbounds"].([]any)[0].(map[string]any)["server"] = "192.0.2.78"
				raw = externalTestJSON(t, base)
			}
			err := ValidateResolvedSSSource(raw, externalTestJSON(t, resolved))
			if (fault == "success") != (err == nil) {
				t.Fatal("resolved source acceptance mismatch", fault, err)
			}
		})
	}
}
