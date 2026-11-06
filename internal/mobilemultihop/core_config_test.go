package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/nativecomposite"
	"strings"
	"testing"
)

type ssServiceGeneratedBundle struct {
	Profiles       map[string]map[string]string `json:"profiles"`
	RouterProfiles []map[string]any             `json:"routerProfiles"`
}

func ssServiceGenerated(t *testing.T, endpoint string) (map[string]string, map[string]any) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	command := exec.Command("python3", "../../server/scripts/ss_service_consumer_fixture.py", "--endpoint", endpoint, "--output", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual private bundle producer: %v %s", err, output)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bundle ssServiceGeneratedBundle
	if json.Unmarshal(data, &bundle) != nil || len(bundle.RouterProfiles) != 1 || len(bundle.Profiles["shadowsocks"][nativecomposite.SSServiceAsset]) == 0 {
		t.Fatal("actual producer lost source or sidecar")
	}
	return bundle.Profiles["shadowsocks"], bundle.RouterProfiles[0]
}
func ssServiceLegacy(assets map[string]string) map[string]string {
	copy := map[string]string{}
	for k, v := range assets {
		if k != nativecomposite.SSServiceAsset {
			copy[k] = v
		}
	}
	return copy
}
func TestSSServiceGeneratedStandaloneAndRestoredSources(t *testing.T) {
	assets, profile := ssServiceGenerated(t, "192.0.2.44")
	files, legacy := startJSON(t, assets), startJSON(t, ssServiceLegacy(assets))
	original, _ := CompileProxyEntry(legacy, "shadowsocks")
	current, err := CompileProxyEntry(files, "shadowsocks")
	if err != nil || current != original || strings.Contains(current, "udp_over_tcp") {
		t.Fatal("configured metadata changed ordinary SS transport", err)
	}
	var restored map[string]string
	if json.Unmarshal([]byte(files), &restored) != nil || startJSON(t, restored) != files {
		t.Fatal("captured restore changed asset bytes")
	}
	for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			p := predecessorCopy(profile)
			p["start_layer"] = layer
			before, err := NewNodeProfile("shadowsocks", legacy, startJSON(t, p), "", "")
			if err != nil {
				t.Fatal(err)
			}
			after, err := NewNodeProfile("shadowsocks", files, startJSON(t, p), "", "")
			if err != nil {
				t.Fatal(err)
			}
			replay, err := NewNodeProfile("shadowsocks", startJSON(t, restored), startJSON(t, p), "", "")
			if err != nil || before.Config() != after.Config() || after.SourceSHA256() != replay.SourceSHA256() {
				t.Fatal("metadata or restored capture changed standalone path", err)
			}
		})
	}
}
func TestSSServiceGeneratedStartLayers(t *testing.T) {
	packets, _ := ssServiceGenerated(t, "192.0.2.1")
	proxies, _ := ssServiceGenerated(t, "192.0.2.44")
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "wg-pq", "awg2-pq", "ss-v2ray", "split", "naive-h2", "naive-h3"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				files, p, _ := nodeProfileFixture(t, mode, layer)
				assets := proxies
				if p["endpoint"] == "192.0.2.1" {
					assets = packets
				}
				plain, with := startJSON(t, ssServiceLegacy(assets)), startJSON(t, assets)
				before, err := NewNodeProfile(mode, files, startJSON(t, p), plain, "")
				if err != nil {
					t.Fatal(err)
				}
				after, err := NewNodeProfile(mode, files, startJSON(t, p), with, "")
				if err != nil {
					t.Fatal(err)
				}
				if before.Config() != after.Config() {
					t.Fatal("configured metadata changed the captured AES source")
				}
			})
		}
	}
}
func TestSSServiceMetadataRefusesForeignSources(t *testing.T) {
	assets, profile := ssServiceGenerated(t, "192.0.2.44")
	raw, _ := base64.StdEncoding.DecodeString(assets[nativecomposite.SSServiceAsset])
	for _, fault := range []string{"node", "endpoint", "port", "method", "key", "source", "schema", "version", "extra", "unknown-asset", "stale-client"} {
		t.Run(fault, func(t *testing.T) {
			copied := map[string]string{}
			for k, v := range assets {
				copied[k] = v
			}
			claim := startObject(t, string(raw))
			switch fault {
			case "node":
				claim["node_id"] = strings.Repeat("f", 64)
			case "endpoint":
				claim["endpoint"] = "192.0.2.55"
			case "port":
				claim["port"] = 8387
			case "method":
				claim["method"] = "aes-256-gcm"
			case "key":
				claim["key_sha256"] = strings.Repeat("a", 64)
			case "source":
				claim["source_sha256"] = strings.Repeat("b", 64)
			case "schema":
				claim["schema"] = true
			case "version":
				claim["uot_version"] = 1
			case "extra":
				claim["ready"] = true
			case "unknown-asset":
				copied["unowned.json"] = base64.StdEncoding.EncodeToString([]byte("{}"))
			case "stale-client":
				b, _ := base64.StdEncoding.DecodeString(copied["sing-box.json"])
				copied["sing-box.json"] = base64.StdEncoding.EncodeToString(append(b, ' '))
			}
			copied[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, claim)))
			if _, err := NewNodeProfile("shadowsocks", startJSON(t, copied), startJSON(t, profile), "", ""); err == nil {
				t.Fatal("foreign sidecar gained node source")
			}
			files, p, _ := nodeProfileFixture(t, "hysteria2", "aes-256-gcm")
			p["node_proof_id"] = profile["node_proof_id"]
			if _, err := NewNodeProfile("hysteria2", files, startJSON(t, p), startJSON(t, copied), ""); err == nil {
				t.Fatal("foreign sidecar gained start source")
			}
		})
	}
	// The published validator rejects unsupported positive declarations;
	// legacy bundles without any declaration retain their original behavior.
	claim := startObject(t, string(raw))
	claim["configured_image"] = "foreign.example/ss:old"
	assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, claim)))
	if _, err := NewNodeProfile("shadowsocks", startJSON(t, assets), startJSON(t, profile), "", ""); err == nil {
		t.Fatal("unsupported positive declaration gained source authority")
	}
}

func TestSSServiceGeneratedPairedStartSources(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, role := range []string{"entry", "exit"} {
			t.Run(role+"/"+layer, func(t *testing.T) {
				var config, metadata string
				endpoint := "192.0.2.77"
				if role == "entry" {
					var entry map[string]any
					config, metadata, _, entry = entryLayerFixture(t, "shadowsocks", layer, "local")
					endpoint = entry["server"].(string)
				} else {
					config, metadata, _, _ = exitLayerFixture(t, "shadowsocks", "shadowsocks", "", layer, "local")
				}
				assets, profile := ssServiceGenerated(t, endpoint)
				meta := startObject(t, metadata)
				meta[role+"_node_id"] = profile["node_proof_id"]
				metadata = startJSON(t, meta)
				oldSource := startJSON(t, EntryStartLayer{Mode: layer, Profile: ssServiceLegacy(assets)})
				source := startJSON(t, EntryStartLayer{Mode: layer, Profile: assets})
				compile := func(value string) (*Controller, error) {
					if role == "entry" {
						return NewWithEntryStartLayer(config, metadata, value)
					}
					return NewWithStartLayers(config, metadata, "", value)
				}
				before, err := compile(oldSource)
				if err != nil {
					t.Fatal(err)
				}
				after, err := compile(source)
				if err != nil {
					t.Fatal(err)
				}
				if ssServicePairedConfig(t, before) != ssServicePairedConfig(t, after) {
					t.Fatal("paired start metadata changed original transport")
				}
				raw, _ := base64.StdEncoding.DecodeString(assets[nativecomposite.SSServiceAsset])
				claim := startObject(t, string(raw))
				claim["node_id"] = strings.Repeat("f", 64)
				assets[nativecomposite.SSServiceAsset] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, claim)))
				if _, err = compile(startJSON(t, EntryStartLayer{Mode: layer, Profile: assets})); err == nil {
					t.Fatal("foreign node sidecar gained paired start authority")
				}
			})
		}
	}
}

// New creates a fresh Server execution lease even when Local is selected. Check
// every lease field against that controller's actual captured owner, then compare
// the complete remaining graph with only those three fresh values standardized.
func ssServicePairedConfig(t *testing.T, c *Controller) string {
	t.Helper()
	graph := startObject(t, c.Config())
	found := 0
	for _, value := range graph["outbounds"].([]any) {
		out := value.(map[string]any)
		if out["tag"] != ServerTag {
			continue
		}
		found++
		if len(out) != 8 || out["type"] != "socks" || out["server"] != c.expected.Host || out["server_port"] != float64(c.expected.Port) || out["version"] != "5" || out["username"] != c.expected.Username || out["password"] != c.expected.Password || out["detour"] != c.meta.EntryTag {
			t.Fatal("fresh Server lease lost exact captured owner")
		}
		out["server_port"] = 26240
		out["username"] = "fresh-owner-username"
		out["password"] = "fresh-owner-password"
	}
	if found != 1 {
		t.Fatal("missing or ambiguous Server lease")
	}
	return startJSON(t, graph)
}
