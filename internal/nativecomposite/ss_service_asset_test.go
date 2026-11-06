package nativecomposite

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestPairedSSServiceCompanionPreservesCompositeLayers(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				node := strings.Repeat("a", 64)
				source, metadata, start := fixture(t, mode, node, layer, "udp")
				before, err := Compile(mode, source, metadata, start)
				if err != nil {
					t.Fatal(err)
				}
				var files map[string]string
				if json.Unmarshal([]byte(start), &files) != nil {
					t.Fatal("fixture")
				}
				raw, _ := base64.StdEncoding.DecodeString(files["sing-box.json"])
				out := parsed(t, string(raw))["outbounds"].([]any)[0].(map[string]any)
				sum, key := sha256.Sum256(raw), sha256.Sum256([]byte(out["password"].(string)))
				claim := map[string]any{"schema": 1, "node_id": node, "configured_image": SSServiceImage, "uot_version": 2, "endpoint": out["server"], "port": out["server_port"], "method": out["method"], "key_sha256": hex.EncodeToString(key[:]), "source_sha256": hex.EncodeToString(sum[:])}
				files[SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(encoded(claim)))
				after, err := Compile(mode, source, metadata, encoded(files))
				if err != nil || after != before {
					t.Fatal("passive declaration changed ordinary composite", err)
				}
				for _, fault := range []string{"node", "key", "source", "version", "unknown"} {
					t.Run(fault, func(t *testing.T) {
						copy := map[string]string{}
						for k, v := range files {
							copy[k] = v
						}
						changed := parsed(t, encoded(claim))
						switch fault {
						case "node":
							changed["node_id"] = strings.Repeat("b", 64)
						case "key":
							changed["key_sha256"] = strings.Repeat("b", 64)
						case "source":
							changed["source_sha256"] = strings.Repeat("b", 64)
						case "version":
							changed["uot_version"] = float64(1)
						}
						copy[SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(encoded(changed)))
						if fault == "unknown" {
							copy["foreign.json"] = copy[SSServiceAsset]
							delete(copy, SSServiceAsset)
						}
						if _, err := Compile(mode, source, metadata, encoded(copy)); err == nil {
							t.Fatal("accepted foreign service declaration")
						}
					})
				}
			})
		}
	}
}
