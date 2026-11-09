//go:build go1.25

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

var desktopImportedNaiveH3Kinds = []string{"socks5", "shadowsocks", "hysteria2", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"}

// Use the actual protected parent preparation. Its Windows controller/kernel
// boundary is modeled by the existing fixture; this does not prove a real WFP
// session or grant the legacy fixed-tuple path a negotiated SOCKS UDP relay.
func desktopImportedNaiveH3Fixture(t *testing.T, kind, first, last string) *desktopImportedOwnedFixture {
	t.Helper()
	protocol := kind
	if strings.HasPrefix(kind, "openvpn-") {
		protocol = "openvpn"
	}
	return newDesktopImportedOwnedFixture(t, protocol, "naive-h3", "always", func(selected *multihopSelection) {
		if protocol == "openvpn" {
			entry := desktopImportedOpenVPNProfileFixture(t, strings.TrimPrefix(kind, "openvpn-"))
			entry.ID, entry.Name = selected.Entry.ID, selected.Entry.Name
			selected.Entry = entry
		}
		selected.Entry.StartLayer, selected.Exit.StartLayer = first, last
		if first != "off" {
			selected.Entry.External.StartLayer = &common.ExternalStartLayer{Mode: first, API: "http://10.93.0.1:8787",
				Transport: map[string]any{"type": "shadowsocks", "tag": "saved-layer", "server": selected.Entry.Endpoint,
					"server_port": float64(8389), "method": "2022-blake3-aes-256-gcm", "password": testWGKey('l')}}
		}
		selected.Exit.DNSMode, selected.Exit.DNSProtocol = "home", ""
		selected.Exit.DNSHost, selected.Exit.DNSPort = "", 0
		// The shared external fixture explicitly disables entry IPv6. This
		// producer requests it at both ends; the compiler must still preserve
		// the stricter policy when either captured profile disables it.
		selected.Entry.IPv6Mode = "on"
		selected.Exit.IPv6Mode, selected.Exit.EffectiveMTU = "on", 0
	})
}

func TestDesktopImportedNaiveH3CapturedGraphs(t *testing.T) {
	for _, kind := range desktopImportedNaiveH3Kinds {
		for _, first := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					f := desktopImportedNaiveH3Fixture(t, kind, first, last)
					before := mustImportedJSON(t, f.a.profiles)
					policy := f.launch.ownedNode.imported.policy
					original := policy.OriginalController()
					config, meta, capture, err := policy.ReadValidated()
					if err != nil || original == nil || config != string(f.launch.config) || original.Healthy() ||
						meta.TargetOS != "windows" || meta.ExitMode != "naive-h3" || meta.EntryID != f.selection.Entry.ID || meta.ExitID != f.selection.Exit.ID ||
						meta.ExitNodeID != f.selection.Exit.NodeProofID || meta.IPv6Mode != "on" ||
						meta.SOCKSUDPAssociationRequired != (kind == "socks5" && first == "off") ||
						!capture.UDPAvailable || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Physical {
						t.Fatal("desktop H3 changed its original source, protected carrier, identity or Home UDP policy", err)
					}
					graph := retainedGraph(t, []byte(config))
					final := desktopImportedGraphNode(t, graph, mobilemultihop.LocalTag)
					if final["type"] != "naive" || final["quic"] != true || final["username"] == "" || final["password"] == "" ||
						!reflect.DeepEqual(final["udp_over_tcp"], map[string]any{"enabled": true, "version": float64(2)}) {
						t.Fatal("desktop H3 substituted the original authenticated native QUIC transport")
					}
					originalGraph := retainedGraph(t, []byte(original.Config()))
					if !reflect.DeepEqual(final, desktopImportedGraphNode(t, originalGraph, mobilemultihop.LocalTag)) {
						t.Fatal("protected desktop preparation changed final credentials, TLS or independent layer")
					}
					servers := graph["dns"].(map[string]any)["servers"].([]any)
					if len(servers) != 2 {
						t.Fatal("desktop H3 lost its selected and bootstrap DNS pair")
					}
					selected, bootstrap := servers[0].(map[string]any), servers[1].(map[string]any)
					if selected["type"] != "udp" || selected["server"] != f.selection.Exit.AdGuardIPv4 || selected["detour"] != "proxy" ||
						bootstrap["type"] != "udp" || bootstrap["server"] != selected["server"] ||
						!reflect.DeepEqual(graph["dns"], originalGraph["dns"]) {
						t.Fatal("desktop H3 rewrote original Home AdGuard or its separate bootstrap")
					}
					for _, tuple := range f.launch.nodePhysicalEgress {
						if tuple.Host != f.selection.Entry.Endpoint || tuple.Host == f.selection.Exit.Endpoint ||
							meta.SOCKSUDPAssociationRequired && tuple.Network != "tcp" {
							t.Fatal("desktop H3 invented a physical final or static SOCKS relay exception", tuple)
						}
					}
					if len(f.launch.nodePhysicalEgress) == 0 || f.selection.Native.validate(f.selection) != nil {
						t.Fatal("desktop H3 lost its original captured physical roots")
					}
					restoredSelection := f.selection
					restoredSelection.restoreMTU = 1280
					restored, err := prepareDesktopOwnedImportedLaunchWith(f.operation, f.a, restoredSelection, f.readNetwork)
					if err != nil {
						t.Fatal("captured H3 restoration failed", err)
					}
					defer func() {
						if err := restored.ownedNode.closeImportedConstructor(); err != nil {
							t.Error("restored H3 constructor did not close its original owner", err)
						}
					}()
					if restored.ownedNode.imported.policy.Metadata().RestoredMTU != 1280 ||
						!reflect.DeepEqual(restored.nodePhysicalEgress, f.launch.nodePhysicalEgress) ||
						string(before) != string(mustImportedJSON(t, f.a.profiles)) {
						t.Fatal("desktop H3 restoration replaced captured policy, physical roots or saved state")
					}
					// Portable parser evidence retains the original sealed graph.
					// The actual Windows package separately parses the protected
					// launch projection, including its inert owned SOCKS constructor.
					// Neither parser result binds or starts a physical network owner.
					for variable, raw := range map[string]string{
						"ROUTERVPN_DESKTOP_IMPORTED_NAIVE_H3_FIXTURES":           original.Config(),
						"ROUTERVPN_DESKTOP_IMPORTED_NAIVE_H3_PROTECTED_FIXTURES": config,
					} {
						if directory := os.Getenv(variable); directory != "" {
							if err := os.WriteFile(filepath.Join(directory, kind+"--naive-h3--"+first+"--"+last+".json"), []byte(raw), 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
				})
			}
		}
	}
}

func TestDesktopImportedNaiveH3OriginalParentDispatch(t *testing.T) {
	for _, kind := range desktopImportedNaiveH3Kinds {
		t.Run(kind, func(t *testing.T) {
			f := desktopImportedNaiveH3Fixture(t, kind, "off", "off")
			f.stage(t)
			f.publish(t)
			if err := startDesktopOwnedImportedLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			if f.starts != 1 || f.a.state.Connected || f.launch.command.Process != nil ||
				f.a.desktopOwnedNodeCurrentContext(f.operation, f.launch, true) != nil {
				t.Fatal("H3 changed the original modeled parent dispatch or invented a live proof")
			}
			if _, err := f.a.readDesktopOwnedNodeReadyContext(f.operation, f.launch, false); err != nil {
				t.Fatal("H3 readiness lost its original imported source", err)
			}
		})
	}
}

func TestDesktopImportedNaiveH3RefusesCONNECTBeforeCapture(t *testing.T) {
	for _, kind := range []string{"http-connect", "https-connect"} {
		t.Run(kind, func(t *testing.T) {
			root, selected := desktopImportedFixture(t, kind, "naive-h3")
			before := mustImportedJSON(t, selected)
			q := multihopConnectRequest{EntryMode: kind, ExitMode: "naive-h3", Execution: "local"}
			if _, err := resolveDesktopImportedSelection(selected.Control, selected.Entry, selected.Exit, q); err == nil {
				t.Fatal("desktop H3 advertised a stream-only imported carrier")
			}
			if captured, err := captureNativeMultihopSelection(context.Background(), root, selected, []string{"naive-h3"}, nil); err == nil || captured.Native != nil {
				t.Fatal("desktop H3 granted a CONNECT source or physical owner")
			}
			if string(before) != string(mustImportedJSON(t, selected)) {
				t.Fatal("refused H3 changed the selected CONNECT profile")
			}
		})
	}
}

func TestDesktopImportedNaiveH3RejectsChangedAuthority(t *testing.T) {
	for _, fault := range []string{"h2", "missing-password", "uot-v1", "insecure-tls", "foreign-detour"} {
		t.Run(fault, func(t *testing.T) {
			f := desktopImportedNaiveH3Fixture(t, "socks5", "off", "off")
			path := filepath.Join(f.launch.root, "generated", f.selection.Exit.ID, "naive-h3", "sing-box.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			graph := retainedGraph(t, raw)
			final := graph["outbounds"].([]any)[0].(map[string]any)
			switch fault {
			case "h2":
				final["quic"] = false
			case "missing-password":
				delete(final, "password")
			case "uot-v1":
				final["udp_over_tcp"].(map[string]any)["version"] = float64(1)
			case "insecure-tls":
				final["tls"].(map[string]any)["insecure"] = true
			case "foreign-detour":
				final["detour"] = "direct"
			}
			changed, _ := json.Marshal(graph)
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := captureDesktopImportedMultihopWithHost(f.operation, f.launch.root, f.selection, []string{"naive-h3"}, nil, f.selection.Native.importedHost); err == nil {
				t.Fatal("protected desktop H3 borrowed changed or malformed native authority", fault)
			}
		})
	}
}
