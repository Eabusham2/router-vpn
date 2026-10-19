package mobilemultihop

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobilepq"
	"router-vpn/internal/multihoprelay"
)

type maxRelayProcess struct{ live bool }

func (p *maxRelayProcess) Alive() bool { return p.live }
func (p *maxRelayProcess) Stop(context.Context) error {
	p.live = false
	return nil
}

type maxRelayRunner struct {
	configs [][]byte
	process *maxRelayProcess
}

func (r *maxRelayRunner) Start(_ context.Context, config []byte, _ multihoprelay.Lease) (multihoprelay.Process, error) {
	r.configs = append(r.configs, append([]byte(nil), config...))
	r.process = &maxRelayProcess{live: true}
	return r.process, nil
}

func pairedMAXFixture(t *testing.T, mode, layer string) (multihoprelay.Exit, map[string]any) {
	t.Helper()
	assets, metadata := maxFixture(t, mode)
	return pairedMAXSource(t, mode, layer, assets, metadata)
}

func pairedMAXSource(t *testing.T, mode, layer string, assets map[string]string, metadata string) (multihoprelay.Exit, map[string]any) {
	t.Helper()
	compiled, err := CompileMAXProfile(mode, pqEncoded(assets), metadata)
	if err != nil {
		t.Fatal(err)
	}
	policy := startObject(t, metadata)
	node := policy["node_id"].(string)
	_, base, outputs, err := standaloneMAXGraph(compiled, mode, node, "")
	if err != nil {
		t.Fatal(err)
	}
	paired, err := multihoprelay.PairMAXChain(base, outputs, mode, node, generatedMAXTags())
	if err != nil {
		t.Fatal(err)
	}
	plan := startObject(t, string(paired))
	exit := multihoprelay.Exit{ID: "paired-max", Mode: mode, NodeID: node, DNS: "10.88.0.1", Transport: plan}
	if layer != "" {
		middle := graphEntry(t, startObject(t, compiled), MAXShadowsocksTag)
		exit.StartLayer = &multihoprelay.StartLayer{Mode: layer, API: policy["router_api"].(string), Transport: map[string]any{
			"type": "shadowsocks", "tag": "proxy", "server": policy["endpoint"], "server_port": middle["server_port"], "method": middle["method"], "password": middle["password"],
		}}
	}
	return exit, startObject(t, compiled)
}

// Only the HTTP routing boundary is a test fixture. Discovery, independent-key
// enforcement, acquisition, native graph building and release are all the
// shipping controller and private relay manager, with no fabricated catalog.
func TestCompleteMAXPrivateDiscoveryReachesControllerOnlyWithIndependentKeys(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = previous }()
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, identity := range []string{"independent", "independent-layered", "same-WG", "same-PQ"} {
			t.Run(mode+"/"+identity, func(t *testing.T) {
				layer := ""
				if identity == "independent-layered" {
					layer = "aes-256-gcm+xor-whitening"
				}
				input, metadata, a, b, al, bl := maxCompositeFixture(t, "wg", mode, "", layer, "server")
				composed, err := ComposeMAXMultihop(input, metadata, a, b)
				if err != nil {
					t.Fatal(err)
				}
				sized, err := ApplyMTUPolicy(composed, `{"entry":{"mtu_policy":"fixed","manual_mtu":1500},"exit":{"mtu_policy":"fixed","manual_mtu":1280}}`)
				if err != nil {
					t.Fatal(err)
				}
				controller, err := NewWithStartLayers(sized, metadata, al, bl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = controller.Close() })
				// Pair the same remote node using separate client WG/PQ credentials.
				// The two mutation controls reuse exactly one local key family.
				source, node := maxHopSource(t, mode, "", true)
				_, base, outputs, err := standaloneMAXGraph(source, mode, node, "")
				if err != nil {
					t.Fatal(err)
				}
				if identity != "same-WG" {
					base["private_key"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'r'}, 32))
				}
				if identity != "same-PQ" {
					base["pq"].(map[string]any)["public"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'w'}, 128))
				}
				plan, err := multihoprelay.PairMAXChain(base, outputs, mode, node, generatedMAXTags())
				if err != nil {
					t.Fatal(err)
				}
				exit := multihoprelay.Exit{ID: controller.meta.ExitID, Mode: mode, NodeID: node, DNS: "10.88.0.1", Transport: startObject(t, string(plan))}
				if layer != "" {
					middle := outputs[0].(map[string]any)
					exit.StartLayer = &multihoprelay.StartLayer{Mode: layer, API: controller.meta.ExitAPI, Transport: map[string]any{
						"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.44", "server_port": middle["server_port"], "method": middle["method"], "password": middle["password"],
					}}
				}
				runner, cfg := &maxRelayRunner{}, maxRelayConfiguration(exit)
				cfg.ListenIP = "10.77.0.1"
				manager, err := multihoprelay.New(cfg, controller.meta.EntryNodeID, runner)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = manager.Close(context.Background()) })
				engine := makeEngine(t)
				engine.entryNode, engine.exitNode = controller.meta.EntryNodeID, controller.meta.ExitNodeID
				peer := netip.MustParseAddr("10.77.0.2")
				fallback := engine.handler("entry-wg")
				entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					if request.URL.Path != "/api/multihop/lease" {
						fallback(w, request)
						return
					}
					if request.Header.Get("Authorization") != "Bearer "+controller.meta.EntryToken {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if request.Method == http.MethodGet {
						_ = json.NewEncoder(w).Encode(map[string]any{"node_id": controller.meta.EntryNodeID, "execution": "server", "exits": manager.Available()})
						return
					}
					var lease multihoprelay.Request
					if json.NewDecoder(request.Body).Decode(&lease) != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					switch request.Method {
					case http.MethodPut:
						created, err := manager.Create(request.Context(), peer, lease)
						if err != nil {
							w.WriteHeader(http.StatusConflict)
							return
						}
						_ = json.NewEncoder(w).Encode(created)
					case http.MethodDelete:
						if manager.Delete(request.Context(), peer, lease) != nil {
							w.WriteHeader(http.StatusConflict)
							return
						}
						_ = json.NewEncoder(w).Encode(map[string]any{"node_id": controller.meta.EntryNodeID, "session_id": lease.SessionID, "stopped": true})
					default:
						w.WriteHeader(http.StatusMethodNotAllowed)
					}
				}))
				t.Cleanup(entry.Close)
				engine.servers["entry-wg"] = entry
				err = controller.Run(context.Background(), engine)
				independent := strings.HasPrefix(identity, "independent")
				if independent {
					if err != nil || !controller.Healthy() || engine.Selected() != ServerTag || len(runner.configs) != 1 {
						t.Fatal("actual private MAX catalog failed its retained server strategy", err)
					}
				} else if err == nil || controller.Healthy() || len(runner.configs) != 0 {
					t.Fatal("one reused client key family reached a MAX server process")
				}
				if err = controller.Close(); err != nil || independent && runner.process.live {
					t.Fatal("MAX controller did not confirm its actual private lease teardown", err)
				}
			})
		}
	}
}

func maxRelayConfiguration(exit multihoprelay.Exit) multihoprelay.Config {
	return multihoprelay.Config{ListenIP: "10.99.0.1", FirstPort: 26240, LastPort: 26271, TTLSeconds: 90, Exits: []multihoprelay.Exit{exit}}
}

func maxRelayRequest(exit multihoprelay.Exit) multihoprelay.Request {
	return multihoprelay.Request{SessionID: strings.Repeat("1", 32), EntryNodeID: strings.Repeat("a", 64), ExitID: exit.ID, ExitMode: exit.Mode, ExitStartLayer: multihoprelay.LayerMode(exit.StartLayer)}
}

func TestCompleteMAXPrivateRelaysPreserveBothProofsAndEveryOwnedLayer(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				exit, original := pairedMAXFixture(t, mode, layer)
				before := startJSON(t, exit)
				cfg, request, runner := maxRelayConfiguration(exit), maxRelayRequest(exit), &maxRelayRunner{}
				manager, err := multihoprelay.New(cfg, request.EntryNodeID, runner)
				if err != nil {
					t.Fatal("complete captured MAX pairing rejected", err)
				}
				t.Cleanup(func() { _ = manager.Close(context.Background()) })
				caps := manager.Available()
				if len(caps) != 1 || caps[0]["exit_id"] != exit.ID || caps[0]["exit_mode"] != mode || caps[0]["exit_node_id"] != exit.NodeID || caps[0]["exit_start_layer"] != layer {
					t.Fatal("public catalog lost complete mode or selected layer")
				}
				base := original["endpoints"].([]any)[0].(map[string]any)
				private, err := base64.StdEncoding.Strict().DecodeString(base["private_key"].(string))
				if err != nil {
					t.Fatal(err)
				}
				key, err := ecdh.X25519().NewPrivateKey(private)
				if err != nil || caps[0]["client_public_key"] != base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) {
					t.Fatal("MAX catalog omitted its actual independent base client fingerprint")
				}
				var pq mobilepq.Config
				if err = json.Unmarshal([]byte(startJSON(t, base["pq"])), &pq); err != nil {
					t.Fatal(err)
				}
				identity, err := mobilepq.ClientIdentity(pq)
				pq.Erase()
				if err != nil || identity == "" || caps[0]["pq_client_identity"] != identity {
					t.Fatal("MAX catalog omitted its independent PQ exchange identity")
				}
				encodedCaps := startJSON(t, caps)
				for _, secret := range []string{base["private_key"].(string), base["pq"].(map[string]any)["secret"].(string), "exact-quic-credential"} {
					if strings.Contains(encodedCaps, secret) {
						t.Fatal("public capability catalog exposed captured private source")
					}
				}
				caps[0]["exit_mode"] = "wg-pq"
				if manager.Available()[0]["exit_mode"] != mode {
					t.Fatal("mutable public catalog replaced the frozen chain")
				}
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				peer := netip.MustParseAddr("10.99.0.2")
				if _, err = manager.Create(cancelled, peer, request); !errors.Is(err, context.Canceled) || len(runner.configs) != 0 {
					t.Fatal("cancelled MAX request started a process")
				}
				for _, change := range []string{"mode", "layer"} {
					wrong := request
					if change == "mode" {
						wrong.ExitMode = multihoprelay.MAXBaseMode(mode)
					} else if layer == "" {
						wrong.ExitStartLayer = "aes-256-gcm"
					} else {
						wrong.ExitStartLayer = ""
					}
					if _, err = manager.Create(context.Background(), peer, wrong); !errors.Is(err, multihoprelay.ErrUnavailable) || len(runner.configs) != 0 {
						t.Fatal("a base-only or different encryption request adopted the MAX pairing")
					}
				}
				// New owns a complete copy, including nested keys and optional AES.
				exit.Transport["endpoint"].(map[string]any)["private_key"] = "private-must-not-echo"
				if exit.StartLayer != nil {
					exit.StartLayer.Transport["password"] = "private-must-not-echo"
				}
				lease, err := manager.Create(context.Background(), peer, request)
				if err != nil || len(runner.configs) != 1 || lease.ExitMode != mode || lease.ExitStartLayer != layer {
					t.Fatal("frozen MAX pairing failed to start the exact private lease", err)
				}
				graph := startObject(t, string(runner.configs[0]))
				endpoints, outputs := graph["endpoints"].([]any), graph["outbounds"].([]any)
				if len(endpoints) != 1 || len(outputs) != 2+boolCount(layer != "") {
					t.Fatal("MAX relay collapsed or duplicated a required encryption owner")
				}
				actual := endpoints[0].(map[string]any)
				if err = multihoprelay.ValidateMAXChain(actual, outputs, mode, lease.ExitNodeID, layer, multihoprelay.MAXRelayTags(), ""); err != nil {
					t.Fatal("private relay did not build the complete native chain", err)
				}
				for _, key := range []string{"type", "mode", "node_id", "private_key", "pq", "peers", "address", "mtu", "amnezia"} {
					if !reflect.DeepEqual(actual[key], base[key]) {
						t.Fatal("paired MAX base or independent key material changed", key)
					}
				}
				inbounds := graph["inbounds"].([]any)
				inbound := inbounds[0].(map[string]any)
				if len(inbounds) != 1 || inbound["type"] != "socks" || inbound["listen"] != cfg.ListenIP || inbound["users"] == nil {
					t.Fatal("MAX relay created a TUN or an unauthenticated listener")
				}
				route := graph["route"].(map[string]any)
				rule := route["rules"].([]any)[0].(map[string]any)
				if route["final"] != "exit" || rule["action"] != "reject" || rule["invert"] != true || rule["source_ip_cidr"].([]any)[0] != "10.99.0.2/32" {
					t.Fatal("MAX lost the authenticated peer's exact route boundary")
				}
				dns := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["detour"] != "exit" || dns["server"] != "10.88.0.1" {
					t.Fatal("DNS bypassed the complete MAX base")
				}
				first := append([]byte(nil), runner.configs[0]...)
				if _, err = manager.Create(context.Background(), peer, request); err != nil || len(runner.configs) != 1 || !bytes.Equal(first, runner.configs[0]) {
					t.Fatal("lease renewal recreated or changed the captured MAX engine", err)
				}
				wrong := request
				wrong.SessionID = strings.Repeat("2", 32)
				if err = manager.Delete(context.Background(), peer, wrong); !errors.Is(err, multihoprelay.ErrOwnership) || !runner.process.live {
					t.Fatal("foreign session stopped the owned MAX chain")
				}
				if err = manager.Delete(context.Background(), peer, request); err != nil || runner.process.live {
					t.Fatal("owned MAX teardown was not confirmed", err)
				}
				if strings.Contains(string(first), "private-must-not-echo") || !strings.Contains(before, base["private_key"].(string)) {
					t.Fatal("frozen source was replaced by a later caller mutation")
				}
			})
		}
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestCompleteMAXPrivateRelaysRejectPartialAndForeignChainsBeforeStarting(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, fault := range []string{"node", "mode", "missing-PQ", "wrong-PQ-route", "bare-base", "missing-middle", "missing-outer", "extra-output", "foreign-detour", "outer-direct", "extra-plan-field", "pre-layered", "foreign-AES", "wrong-AES-key", "wrong-private-API", "invalid-UTF8", "cyclic-plan"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				exit, _ := pairedMAXFixture(t, mode, "aes-256-gcm")
				base := exit.Transport["endpoint"].(map[string]any)
				outputs := exit.Transport["outbounds"].([]any)
				switch fault {
				case "node":
					exit.NodeID = strings.Repeat("b", 64)
				case "mode":
					exit.Mode = multihoprelay.MAXBaseMode(mode)
				case "missing-PQ":
					delete(base, "pq")
				case "wrong-PQ-route":
					base["pq"].(map[string]any)["endpoint"] = "192.0.2.99:51822"
				case "bare-base":
					delete(base, "detour")
				case "missing-middle":
					exit.Transport["outbounds"] = outputs[1:]
				case "missing-outer":
					exit.Transport["outbounds"] = outputs[:1]
				case "extra-output":
					exit.Transport["outbounds"] = append(outputs, map[string]any{"type": "direct", "tag": "fallback"})
				case "foreign-detour":
					outputs[0].(map[string]any)["detour"] = "direct"
				case "outer-direct":
					outputs[1].(map[string]any)["type"] = "direct"
				case "extra-plan-field":
					exit.Transport["route"] = map[string]any{"final": "direct"}
				case "pre-layered":
					outputs[1].(map[string]any)["detour"] = multihoprelay.MAXRelayTags().Start
				case "foreign-AES":
					exit.StartLayer.Transport["server"] = "192.0.2.99"
				case "wrong-AES-key":
					exit.StartLayer.Transport["password"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'z'}, 32))
				case "wrong-private-API":
					exit.StartLayer.API = "http://10.254.99.1:8787"
				case "invalid-UTF8":
					if strings.HasPrefix(mode, "max-quic-") {
						outputs[1].(map[string]any)["password"] = string([]byte{'p', 0xff})
					} else {
						exit.Transport[string([]byte{'p', 0xff})] = "invalid"
					}
				case "cyclic-plan":
					exit.Transport["outbounds"] = []any{exit.Transport}
				}
				runner := &maxRelayRunner{}
				if _, err := multihoprelay.New(maxRelayConfiguration(exit), strings.Repeat("a", 64), runner); err == nil || len(runner.configs) != 0 {
					t.Fatal("invalid MAX source reached a private listener")
				}
			})
		}
	}
}
