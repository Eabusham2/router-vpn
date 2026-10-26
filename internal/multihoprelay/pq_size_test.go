package multihoprelay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// These are serialization fixtures with the pinned StaticKem's actual byte
// lengths, not cryptographic peers. The mandatory native PQ graph suite uses
// independently generated genuine keypairs and performs the real exchange.
func pqNativeSizeExit(t *testing.T, mode string) Exit {
	t.Helper()
	exit := pqExit(t, mode)
	pq := exit.Transport["pq"].(map[string]any)
	for _, key := range []struct {
		name string
		size int
		fill byte
	}{{"secret", 13608, 's'}, {"public", 524160, 'p'}, {"peer", 524160, 'r'}} {
		pq[key.name] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{key.fill}, key.size))
	}
	return exit
}

func TestPQRelayCopiesNativeSizedPrivateKeysWithoutChangingOwners(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				exit := pqNativeSizeExit(t, mode)
				if layer != "" {
					exit.StartLayer = &StartLayer{Mode: layer, API: "http://10.88.0.1:8787", Transport: map[string]any{
						"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.2", "server_port": 8388,
						"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'k'}, 32)),
					}}
				}
				before, err := json.Marshal(exit)
				if err != nil || len(before) < 1<<20 {
					t.Fatal("fixture does not exercise real PQ key sizes", err)
				}
				cfg, runtime := config(), &runner{}
				cfg.Exits = []Exit{exit}
				manager, err := New(cfg, req().EntryNodeID, runtime)
				if err != nil {
					t.Fatal("native-sized registry rejected", err)
				}
				t.Cleanup(func() { _ = manager.Close(context.Background()) })
				request := pinnedPQRequest(t, exit)
				request.ExitStartLayer = layer
				owner := netip.MustParseAddr("10.77.0.2")
				if _, err = manager.Create(context.Background(), owner, request); err != nil {
					t.Fatal("native-sized relay rejected", err)
				}
				var graph map[string]any
				if len(runtime.configs) != 1 || json.Unmarshal(runtime.configs[0], &graph) != nil {
					t.Fatal("missing captured relay graph")
				}
				endpoint := graph["endpoints"].([]any)[0].(map[string]any)
				if endpoint["type"] != "routervpn-pq" || endpoint["mode"] != mode || endpoint["node_id"] != exit.NodeID || endpoint["private_key"] != exit.Transport["private_key"] {
					t.Fatal("native endpoint identity changed")
				}
				for _, key := range []string{"secret", "public", "peer"} {
					if endpoint["pq"].(map[string]any)[key] != exit.Transport["pq"].(map[string]any)[key] {
						t.Fatalf("native-sized %s changed", key)
					}
				}
				if layer != "" && (endpoint["pq"].(map[string]any)["endpoint"] != "10.88.0.1:51822" || endpoint["detour"] != ExitStartLayerTag) {
					t.Fatal("Start Layer lost PQ routing ownership")
				}
				if graph["route"].(map[string]any)["final"] != "exit" || graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["detour"] != "exit" {
					t.Fatal("selected policy bypassed the captured endpoint")
				}
				if _, err = manager.Create(context.Background(), owner, request); err != nil || len(runtime.configs) != 1 {
					t.Fatal("renewal lost its captured identity", err)
				}
				endpoint["pq"].(map[string]any)["secret"] = "mutation"
				after, _ := json.Marshal(exit)
				if !bytes.Equal(before, after) {
					t.Fatal("copy mutated the administrator's paired registry")
				}
			})
		}
	}
}

func TestPQPrivateSizeAllowanceRejectsOversizeAndForeignFields(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq"} {
		for _, fault := range []string{"secret", "public", "peer", "config", "envelope", "type", "mode", "unknown-pq", "foreign-endpoint", "ordinary"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				exit := pqNativeSizeExit(t, mode)
				pq := exit.Transport["pq"].(map[string]any)
				switch fault {
				case "secret", "public", "peer":
					pq[fault] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, (2<<20)+1))
				case "config":
					// Each key is within its independent limit, but their JSON is
					// beyond the pre-existing aggregate PQ configuration bound.
					for index, key := range []string{"secret", "public", "peer"} {
						pq[key] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 2<<20))
					}
				case "envelope":
					exit.Transport["tag"] = strings.Repeat("x", 256<<10)
				case "type":
					exit.Transport["type"] = "wireguard"
				case "mode":
					exit.Transport["mode"] = "wg"
				case "unknown-pq":
					pq["command"] = "not-an-owned-key"
				case "foreign-endpoint":
					pq["endpoint"] = "192.0.2.9:51822"
				case "ordinary":
					exit.Mode = "wg"
				}
				cfg, runtime := config(), &runner{}
				cfg.Exits = []Exit{exit}
				if manager, err := New(cfg, req().EntryNodeID, runtime); err == nil {
					_ = manager.Close(context.Background())
					t.Fatal("invalid or oversized private transport accepted")
				}
				if len(runtime.configs) != 0 {
					t.Fatal("rejected material reached a runtime")
				}
			})
		}
	}
}

func TestOrdinaryTransportCopyRetainsItsOriginalLimit(t *testing.T) {
	value := map[string]any{"payload": strings.Repeat("x", (256<<10)-64)}
	copy, err := copyMap(value)
	if err != nil || !reflect.DeepEqual(copy, value) {
		t.Fatal("ordinary bounded copy changed", err)
	}
	value["payload"] = strings.Repeat("x", 256<<10)
	if _, err = copyMap(value); err == nil {
		t.Fatal("ordinary transport acquired the private PQ allowance")
	}
	if _, err = copyMap(pqNativeSizeExit(t, "wg-pq").Transport); err == nil {
		t.Fatal("generic copy granted PQ privileges without validation")
	}
	for _, mode := range []string{"shadowsocks", "hysteria2"} {
		exit := Exit{Mode: mode, DNS: "10.88.0.1", Transport: map[string]any{
			"type": mode, "server": "192.0.2.2", "server_port": 443,
			"method": "aes-256-gcm", "password": strings.Repeat("x", 256<<10),
		}}
		if mode == "hysteria2" {
			delete(exit.Transport, "method")
			exit.Transport["tls"] = map[string]any{"enabled": true}
		}
		if _, err = validateTransport(exit); err == nil {
			t.Fatalf("%s transport limit was widened", mode)
		}
	}
}
