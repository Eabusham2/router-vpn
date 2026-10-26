package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativecomposite"
)

// These are the actual imported helper/wrapper shapes, with independent TCP
// authentication and trusted HY2 UDP. No generic SOCKS stand-in reaches the
// native composite compiler or runtime checks.
func nativeMultihopCompositeExitAssets(t *testing.T, exit common.RouterProfile, mode string) map[string][]byte {
	t.Helper()
	certificate, _ := nativeMultihopTrafficCertificate(t)
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		t.Fatal("composite fixture lost its exact certificate")
	}
	helperPort, helperName := 1090, "xray.json"
	xrayMode := "reality-vision"
	if mode == "max" {
		xrayMode = "reality-pq-vision"
	}
	assets := nativeMultihopProxyExitAssets(t, exit, xrayMode)
	helper := assets["xray.json"]
	if mode == "ss-v2ray" {
		helperPort, helperName = 1092, "sslocal.json"
		helper, _ = json.Marshal(map[string]any{
			"server": exit.Endpoint, "server_port": 10443, "password": testWGKey('s'),
			"method": "2022-blake3-aes-256-gcm", "local_address": "127.0.0.1", "local_port": helperPort,
			"mode": "tcp_only", "plugin": "v2ray-plugin",
			"plugin_opts": "tls;host=exit-certificate.example;path=/captured-composite;certRaw=" + base64.StdEncoding.EncodeToString(block.Bytes),
		})
	}
	graph := map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true, "mtu": 1280}},
		"outbounds": []any{
			map[string]any{"type": "socks", "tag": "tcp-stack", "server": "127.0.0.1", "server_port": helperPort, "version": "5"},
			map[string]any{"type": "hysteria2", "tag": "udp-stack", "server": exit.Endpoint, "server_port": 8443, "password": "captured-composite-udp", "obfs": map[string]any{"type": "salamander", "password": "captured-composite-mask"}, "tls": map[string]any{"enabled": true, "server_name": "exit-certificate.example", "certificate_path": "cert.pem"}},
		},
		"route": map[string]any{"final": "tcp-stack", "rules": []any{
			map[string]any{"protocol": "dns", "action": "hijack-dns"},
			map[string]any{"network": "tcp", "action": "route", "outbound": "tcp-stack"},
			map[string]any{"network": "udp", "action": "route", "outbound": "udp-stack"},
		}},
		"dns": map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "captured-home", "server": exit.AdGuardIPv4, "detour": "tcp-stack"}}, "final": "captured-home"},
	}
	body, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"sing-box.json": body, helperName: helper, "cert.pem": []byte(certificate)}
}

func TestNativeMultihopCompositeServerRetainsPoliciesAndRemovesExactExitClosure(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				root, selection := nativeMultihopCapturedFixture(t, "awg2-strong", layer)
				selection.ExitMode = mode
				selection.Exit.DNSMode, selection.Exit.DNSProtocol, selection.Exit.DNSHost, selection.Exit.DNSPort = "custom", "https", "resolver.example", 8443
				selection.Exit.DNSServerName, selection.Exit.DNSPath = "owned-certificate.example", "/captured-dns"
				selection.Exit.MTUPolicy, selection.Exit.ManualMTU = "manual", 1392
				selection, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				original := selection.Native.configs[mode]
				local := retainedGraph(t, []byte(original))
				_, descriptor := executionFixture()
				descriptor.Lease.ExitMode = mode
				if layer != "off" {
					descriptor.Lease.ExitStartLayer = layer
				}
				compiled, err := compileDesktopExecutionConfig([]byte(original), descriptor, selection)
				if err != nil {
					t.Fatal(err)
				}
				server := retainedGraph(t, compiled)
				for _, field := range []string{"endpoints", "inbounds", "services", "dns"} {
					if !reflect.DeepEqual(local[field], server[field]) {
						t.Fatal("Server replaced entry, selected DNS/bootstrap, MTU or protection", field)
					}
				}
				// Server lease control has always used the entry endpoint rather
				// than the Local path's private SOCKS helper. No ordinary traffic
				// or protection rule may be moved along with that one proof lane.
				wantRoute := local["route"].(map[string]any)
				proofRules := 0
				for _, raw := range wantRoute["rules"].([]any) {
					rule := raw.(map[string]any)
					if in, _ := rule["inbound"].([]any); len(in) == 1 && in[0] == "multihop-entry-proof" {
						rule["outbound"] = "entry-wg"
						proofRules++
					}
				}
				if proofRules != 1 || !reflect.DeepEqual(wantRoute, server["route"]) {
					t.Fatal("Server changed routes beyond its exact entry control lane")
				}
				found, entryLayer := 0, false
				for _, raw := range server["outbounds"].([]any) {
					out := raw.(map[string]any)
					tag, _ := out["tag"].(string)
					if strings.HasPrefix(tag, mobilemultihop.CompositeExitPrefix) || strings.HasPrefix(tag, nativecomposite.SourcePrefix) || out["type"] == nativecomposite.Type {
						t.Fatal("dormant local composite exit retained after lease adoption")
					}
					if tag == "proxy" {
						found++
						if out["type"] != "socks" || out["password"] != descriptor.Lease.Password || out["detour"] != "entry-wg" {
							t.Fatal("Server lost the authenticated captured lease")
						}
					} else if strings.HasPrefix(tag, "external-entry-node-") && (out["type"] == "shadowsocks" || out["type"] == "routervpn-aes-xor") {
						entryLayer = true
					}
				}
				if found != 1 || entryLayer != (layer != "off") || selection.Native.configs[mode] != original || selection.Native.validate(selection) != nil {
					t.Fatal("Server altered the source capture, entry layer, or unique final owner")
				}
			})
		}
	}
}

func TestNativeMultihopCompositeServerRejectsUnownedChildClosure(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, fault := range []string{"missing-tcp", "missing-udp", "missing-start", "root-detour", "tcp-bypass", "udp-bypass", "start-bypass", "same-lane", "node", "duplicate-child", "extra-child", "UDP-trust"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				root, selection := nativeMultihopCapturedFixture(t, "wg", "aes-256-gcm")
				selection.ExitMode = mode
				selection, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
				if err != nil {
					t.Fatal(err)
				}
				graph := retainedGraph(t, []byte(selection.Native.configs[mode]))
				prefix := mobilemultihop.CompositeExitPrefix
				nodes := map[string]map[string]any{}
				for _, raw := range graph["outbounds"].([]any) {
					out := raw.(map[string]any)
					nodes[out["tag"].(string)] = out
				}
				switch fault {
				case "missing-tcp", "missing-udp", "missing-start":
					retained := []any{}
					for _, raw := range graph["outbounds"].([]any) {
						if raw.(map[string]any)["tag"] != prefix+strings.TrimPrefix(fault, "missing-") {
							retained = append(retained, raw)
						}
					}
					graph["outbounds"] = retained
				case "root-detour":
					nodes["proxy"]["detour"] = "entry-wg"
				case "tcp-bypass":
					nodes[prefix+"tcp"]["detour"] = "entry-wg"
				case "udp-bypass":
					nodes[prefix+"udp"]["detour"] = "entry-wg"
				case "start-bypass":
					delete(nodes[prefix+"start"], "detour")
				case "same-lane":
					nodes["proxy"]["udp"] = nodes["proxy"]["tcp"]
				case "node":
					nodes["proxy"]["node_id"] = selection.Entry.NodeProofID
				case "duplicate-child":
					graph["outbounds"] = append(graph["outbounds"].([]any), nodes[prefix+"udp"])
				case "extra-child":
					graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": prefix + "foreign"})
				case "UDP-trust":
					nodes[prefix+"udp"]["tls"].(map[string]any)["insecure"] = true
				}
				mutated, _ := json.Marshal(graph)
				// Exercise the Server compiler's own closure validation as well
				// as the separately tested byte-identity guard around this capture.
				selection.Native.configs[mode] = string(mutated)
				_, descriptor := executionFixture()
				descriptor.Lease.ExitMode, descriptor.Lease.ExitStartLayer = mode, "aes-256-gcm"
				if _, err := compileDesktopExecutionConfig(mutated, descriptor, selection); err == nil {
					t.Fatal("Server discarded an unowned or incomplete child graph")
				}
			})
		}
	}
}

func TestNativeMultihopCompositeHostnameFreezesBothLanesBeforeLookup(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		t.Run(mode, func(t *testing.T) {
			_, selection := nativeMultihopCapturedFixture(t, "wg", "off")
			profile := selection.Exit
			profile.Endpoint = "captured-node.example"
			assets := nativeMultihopCompositeExitAssets(t, profile, mode)
			original := encodeDesktopNodeAssets(assets)
			calls := 0
			compiled, endpoint, err := compileDesktopNode(context.Background(), profile, mode, assets, nil, func(_ context.Context, host string) ([]netip.Addr, error) {
				calls++
				if host != profile.Endpoint {
					t.Fatal("unowned hostname bootstrap")
				}
				return []netip.Addr{netip.MustParseAddr("198.51.100.19")}, nil
			})
			if err != nil || calls != 1 || endpoint != "198.51.100.19" || original != encodeDesktopNodeAssets(assets) {
				t.Fatal("composite bootstrap changed source or missed a physical lane", err, calls)
			}
			graph := retainedGraph(t, []byte(compiled.Config()))
			plan, err := nativecomposite.Extract(graph, mode, profile.NodeProofID, "", "proxy", nativecomposite.SourcePrefix, "")
			if err != nil || plan["udp"].(map[string]any)["server"] != endpoint {
				t.Fatal("UDP lane missed exact captured endpoint", err)
			}
			if mode == "ss-v2ray" {
				tcp := plan["tcp"].(map[string]any)
				var originalHelper map[string]any
				_ = json.Unmarshal(assets["sslocal.json"], &originalHelper)
				if tcp["server"] != endpoint || tcp["plugin_opts"] != originalHelper["plugin_opts"] || tcp["password"] != originalHelper["password"] {
					t.Fatal("SIP003 freeze changed trust, path or credentials")
				}
			}
		})
	}
}

func TestNativeMultihopCompositeRestoreAndDNSRetainExactProvedPath(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, execution := range []string{"local", "server"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				f := newRetainedMultihopModeFixture(t, execution, mode)
				t.Setenv("HOMEVPN_ROOT", f.launch.root)
				manifest := filepath.Join(f.launch.root, "runtime", "native", "NATIVE-RUNTIME.json")
				if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
				f.a.profiles.Profiles[2].EffectiveMTU = 9000
				snapshot := speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(f.a.profiles), State: f.a.state, Runtime: f.a.cmd}
				plan, err := f.a.speedLabCaptureRestorePlan(snapshot)
				if err != nil || plan.multihop == nil || plan.multihop.Native != f.selection.Native || plan.multihop.restoreMTU != 1360 || plan.request.Execution != execution || plan.multihop.Control.MultihopExecution != "auto" || plan.multihop.ExitMode != mode {
					t.Fatal("composite restore lost its proved Local/Server choice or adopted historical MTU", err)
				}
				observation := observedConnection{Profile: f.selection.Exit, RouterID: f.selection.Exit.ID, Connected: true, Phase: "connected"}
				calls := 0
				lookup := func(context.Context, string) ([]string, error) { calls++; return []string{"192.0.2.1"}, nil }
				proof := proveSelectedDNSWithLookup(context.Background(), f.a, observation, mode, lookup)
				if proof.Status != "passed" || calls != 1 || proof.Host != f.selection.Exit.AdGuardIPv4 {
					t.Fatal("composite selected DNS did not use its captured owner", proof, calls)
				}
				observation.Profile.DNSMode, observation.Profile.DNSProtocol, observation.Profile.DNSHost, observation.Profile.DNSPort = "custom", "udp", "1.1.1.1", 53
				if proof = proveSelectedDNSWithLookup(context.Background(), f.a, observation, mode, lookup); proof.Status != "failed" || calls != 1 {
					t.Fatal("foreign resolver reached composite DNS lookup", proof, calls)
				}
				nativeMultihopOwners.Delete(f.a)
				if _, err := f.a.speedLabCaptureRestorePlan(snapshot); err == nil {
					t.Fatal("retired composite owner reached restore")
				}
			})
		}
	}
}
