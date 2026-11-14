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

func TestPairedSSServiceCompanionRetainsExactSS2022Credentials(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			password := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", size)))
			node := strings.Repeat("a", 64)
			validate := func(cipher, secret string) error {
				out := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "203.0.113.20", "server_port": 8388, "method": cipher, "password": secret}
				source := []byte(encoded(map[string]any{"outbounds": []any{out}}))
				sum, key := sha256.Sum256(source), sha256.Sum256([]byte(secret))
				claim := map[string]any{"schema": 1, "node_id": node, "configured_image": SSServiceImage, "uot_version": 2, "endpoint": out["server"], "port": out["server_port"], "method": cipher, "key_sha256": hex.EncodeToString(key[:]), "source_sha256": hex.EncodeToString(sum[:])}
				return ValidateSSServiceCompanion(source, []byte(encoded(claim)), node)
			}
			if err := validate(method, password); err != nil {
				t.Fatal("captured SS2022 method and exact canonical key were rejected", err)
			}
			if err := validate(method, password+":"+password); (err == nil) != (method != "2022-blake3-chacha20-poly1305") {
				t.Fatal("configured receiver changed the cipher's identity-chain rule", err)
			}
			for _, fault := range []string{"short", "long", "newline", "unpadded", "trailing-key", "empty", "oversized", "legacy", "case-alias", "noncanonical-padding"} {
				t.Run(fault, func(t *testing.T) {
					cipher, secret := method, password
					switch fault {
					case "short":
						secret = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", size-1)))
					case "long":
						secret = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", size+1)))
					case "newline":
						secret += "\n"
					case "unpadded":
						secret = strings.TrimRight(secret, "=")
					case "trailing-key":
						secret += ":"
					case "empty":
						secret = ""
					case "oversized":
						secret = strings.Repeat(password+":", 4096/len(password)+1) + password
					case "legacy":
						cipher = "aes-256-gcm"
					case "case-alias":
						cipher = strings.ToUpper(cipher)
					case "noncanonical-padding":
						index := len(strings.TrimRight(secret, "=")) - 1
						const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
						secret = secret[:index] + string(alphabet[strings.IndexByte(alphabet, secret[index])+1]) + secret[index+1:]
					}
					if err := validate(cipher, secret); err == nil {
						t.Fatal("matching hashes authorized an unsupported method or noncanonical credential")
					}
				})
			}
		})
	}
}
