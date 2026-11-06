package mobilemultihop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"router-vpn/internal/nativecomposite"
	"testing"
)

func pairedSSServiceFiles(t *testing.T, files, node string) string {
	t.Helper()
	var assets map[string]string
	if err := exactJSON([]byte(files), &assets, 4<<20); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(assets["sing-box.json"])
	if err != nil {
		t.Fatal(err)
	}
	source := externalTestRead(t, string(raw))["outbounds"].([]any)[0].(map[string]any)
	sha, key := sha256.Sum256(raw), sha256.Sum256([]byte(source["password"].(string)))
	claim := map[string]any{"schema": 1, "node_id": node, "configured_image": nativecomposite.SSServiceImage, "uot_version": 2, "endpoint": source["server"], "port": source["server_port"], "method": source["method"], "key_sha256": hex.EncodeToString(key[:]), "source_sha256": hex.EncodeToString(sha[:])}
	assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, claim)))
	return externalTestJSON(t, assets)
}
func TestPairedSSServiceCompanionOrdinaryGraphs(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong"} {
		layers := []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"}
		if mode == "shadowsocks" {
			layers = append([]string{"off"}, layers...)
		}
		for _, layer := range layers {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				files, profile, start := nodeProfileFixture(t, mode, layer)
				before, err := NewNodeProfile(mode, files, externalTestJSON(t, profile), start, "")
				if err != nil {
					t.Fatal(err)
				}
				if mode == "shadowsocks" {
					old, err := CompileProxyEntry(files, mode)
					if err != nil {
						t.Fatal(err)
					}
					files = pairedSSServiceFiles(t, files, profile["node_proof_id"].(string))
					current, err := CompileProxyEntry(files, mode)
					if err != nil || current != old {
						t.Fatal("service declaration changed ordinary outbound", err)
					}
				} else {
					start = pairedSSServiceFiles(t, start, profile["node_proof_id"].(string))
				}
				after, err := NewNodeProfile(mode, files, externalTestJSON(t, profile), start, "")
				if err != nil || after.Config() != before.Config() || after.Metadata() == before.Metadata() {
					t.Fatal("passive service declaration changed graph or lost source ownership", err)
				}
			})
		}
	}
}
func TestPairedSSServiceCompanionRefusals(t *testing.T) {
	for _, fault := range []string{"node", "node-format", "image", "schema", "version", "endpoint", "port", "method", "key-sha", "source-sha", "raw-whitespace", "extra", "unknown-asset", "malformed"} {
		t.Run(fault, func(t *testing.T) {
			files, profile, start := nodeProfileFixture(t, "shadowsocks", "")
			files = pairedSSServiceFiles(t, files, profile["node_proof_id"].(string))
			var assets map[string]string
			_ = exactJSON([]byte(files), &assets, 4<<20)
			data, _ := base64.StdEncoding.DecodeString(assets[nativecomposite.SSServiceAsset])
			claim := externalTestRead(t, string(data))
			switch fault {
			case "node":
				claim["node_id"] = externalDigest([]byte("foreign"))
			case "node-format":
				claim["node_id"] = "invalid"
			case "image":
				claim["configured_image"] = "foreign:latest"
			case "schema":
				claim["schema"] = float64(2)
			case "version":
				claim["uot_version"] = float64(1)
			case "endpoint":
				claim["endpoint"] = "192.0.2.99"
			case "port":
				claim["port"] = float64(9999)
			case "method":
				claim["method"] = "2022-blake3-chacha20-poly1305"
			case "key-sha":
				claim["key_sha256"] = externalDigest([]byte("foreign"))
			case "source-sha":
				claim["source_sha256"] = externalDigest([]byte("foreign"))
			case "raw-whitespace":
				raw, _ := base64.StdEncoding.DecodeString(assets["sing-box.json"])
				assets["sing-box.json"] = base64.StdEncoding.EncodeToString(append(raw, '\n'))
			case "extra":
				claim["unowned"] = true
			}
			assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(externalTestJSON(t, claim)))
			if fault == "unknown-asset" {
				assets["foreign.json"] = assets[nativecomposite.SSServiceAsset]
				delete(assets, nativecomposite.SSServiceAsset)
			}
			if fault == "malformed" {
				assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte("{"))
			}
			if _, err := NewNodeProfile("shadowsocks", externalTestJSON(t, assets), externalTestJSON(t, profile), start, ""); err == nil {
				t.Fatal("accepted unowned SS service claim")
			}
		})
	}
}
