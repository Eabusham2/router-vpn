package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Complete generated asset shapes exercise the real private reader/compiler.
// Synthetic KEM bytes here are structural fixtures; the separate mandatory
// native traffic group uses genuine pinned-Rust keys and authenticated rekey.
func nativeMultihopMAXAssets(t *testing.T, exit common.RouterProfile, mode string) map[string][]byte {
	t.Helper()
	files := nativeEntryMAXAssets(t, exit, mode)
	peer := testWGKey('r')
	if strings.HasSuffix(mode, "-awg") {
		peer = testWGKey('w')
	}
	for name, raw := range files {
		if strings.HasSuffix(name, ".conf") || name == "rosenpass.env" || name == "rosenpass.toml" {
			text := strings.ReplaceAll(string(raw), testWGKey('q'), peer)
			if strings.HasSuffix(name, ".conf") {
				text = strings.NewReplacer("10.77.", "10.88.", "10.78.", "10.88.").Replace(text)
				text = strings.Replace(text, "[Interface]\n", "[Interface]\nMTU = 1420\n", 1)
			}
			files[name] = []byte(text)
		}
	}
	return files
}

func TestNativeMAXDesktopCaptureServerClosureAndRetainedPolicy(t *testing.T) {
	for _, entryMode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "max-tls-wg", "max-quic-awg"} {
		for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
			for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(entryMode+"/"+mode+"/"+layer, func(t *testing.T) {
					root, selection := nativeEntryMultihopFixture(t, entryMode, layer)
					selection.ExitMode = mode
					selection, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
					if err != nil {
						t.Fatal(err)
					}
					if selection.Native.localPacketPublic[mode] == "" || selection.Native.localPQIdentity[mode] == "" {
						t.Fatal("complete MAX did not capture both independent public identities")
					}
					original := selection.Native.configs[mode]
					local, err := compileRetainedNativeMultihopLaunch(selection, nil)
					if err != nil {
						t.Fatal(err)
					}
					_, descriptor := executionFixture()
					descriptor.Lease.ExitMode, descriptor.Lease.ExitStartLayer = mode, layer
					if layer == "off" {
						descriptor.Lease.ExitStartLayer = ""
					}
					server, err := compileRetainedNativeMultihopLaunch(selection, &descriptor)
					if err != nil {
						t.Fatal(err)
					}
					before, after := retainedGraph(t, local.config), retainedGraph(t, server.config)
					removed, err := nativeMAXExitOwners(before, selection)
					if err != nil || len(removed) != 2+boolInt(layer != "off") {
						t.Fatal("Local lost an owned mandatory or selected MAX layer", err)
					}
					_, entryBefore, err := nativeMultihopEntrySnapshot(before, selection.Native.entryOwners)
					if err != nil {
						t.Fatal(err)
					}
					_, entryAfter, err := nativeMultihopEntrySnapshot(after, selection.Native.entryOwners)
					if err != nil || !bytes.Equal(entryBefore, entryAfter) {
						t.Fatal("Server changed the exact captured entry, resolver or proof closure", err)
					}
					for _, field := range []string{"dns", "inbounds", "services"} {
						if !reflect.DeepEqual(before[field], after[field]) {
							t.Fatal("Server changed selected DNS, protected TUN or proof owners", field)
						}
					}
					for _, family := range []string{"endpoints", "outbounds"} {
						for _, raw := range after[family].([]any) {
							value := raw.(map[string]any)
							tag, _ := value["tag"].(string)
							if removed[tag] || family == "endpoints" && tag == "proxy" {
								t.Fatal("Server retained a competing Local packet or helper owner", tag)
							}
							if tag == "proxy" && (value["type"] != "socks" || value["detour"] != "entry-wg" || value["password"] != descriptor.Lease.Password) {
								t.Fatal("Server lost the authenticated owned lease")
							}
						}
					}
					selection.restoreMTU = 1360
					restored, err := compileRetainedNativeMultihopLaunch(selection, &descriptor)
					if err != nil || selection.Native.configs[mode] != original {
						t.Fatal("restoration rewrote the complete captured source", err)
					}
					restoredGraph := retainedGraph(t, restored.config)
					for field, value := range after {
						if field != "inbounds" && !reflect.DeepEqual(value, restoredGraph[field]) {
							t.Fatal("live TUN restore changed a MAX transport, credential, DNS or owner", field)
						}
					}
					meta := retainedGraph(t, restored.metadata)
					if meta["execution"] != "server" || meta["exit_mode"] != mode || meta["entry_mode"] != entryMode || meta["graph_source_sha256"] != selection.Native.source {
						t.Fatal("restored receipt changed captured execution or source")
					}
					if binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"); binary != "" && entryMode == "wg" {
						for _, launch := range []*desktopNodeLaunch{local, server} {
							directory := t.TempDir()
							path := filepath.Join(directory, "complete-max.json")
							if err := os.WriteFile(path, launch.config, 0600); err != nil {
								t.Fatal(err)
							}
							command := exec.Command(binary, "check", "-D", directory, "-c", path)
							command.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
							if output, err := command.CombinedOutput(); err != nil {
								t.Fatal("complete native parser rejected exact captured MAX graph", err, string(output))
							}
						}
					}
				})
			}
		}
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestNativeMAXDesktopRejectsIncompleteOrForeignClosure(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		root, selection := nativeMultihopCapturedFixture(t, "wg", "aes-256-gcm+xor-whitening")
		selection.ExitMode = mode
		selection, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, descriptor := executionFixture()
		descriptor.Lease.ExitMode, descriptor.Lease.ExitStartLayer = mode, selection.Exit.StartLayer
		for _, fault := range []string{"missing-base", "base-mode", "missing-middle", "middle-key", "outer-bypass", "missing-layer", "foreign-child", "duplicate-child"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				graph := retainedGraph(t, []byte(selection.Native.configs[mode]))
				switch fault {
				case "missing-base", "base-mode":
					for index, raw := range graph["endpoints"].([]any) {
						value := raw.(map[string]any)
						if value["tag"] == "proxy" {
							if fault == "missing-base" {
								graph["endpoints"] = append(graph["endpoints"].([]any)[:index], graph["endpoints"].([]any)[index+1:]...)
							} else {
								value["mode"] = "wg"
							}
							break
						}
					}
				default:
					outputs := graph["outbounds"].([]any)
					for index, raw := range outputs {
						value := raw.(map[string]any)
						tag, _ := value["tag"].(string)
						if fault == "missing-middle" && tag == mobilemultihop.MAXExitPrefix+"ss" || fault == "missing-layer" && tag == mobilemultihop.MAXExitPrefix+"start" {
							graph["outbounds"] = append(outputs[:index], outputs[index+1:]...)
							break
						}
						if fault == "middle-key" && tag == mobilemultihop.MAXExitPrefix+"ss" {
							value["password"] = "invalid"
						}
						if fault == "outer-bypass" && tag == mobilemultihop.MAXExitPrefix+"outer" {
							value["detour"] = "entry-wg"
						}
						if fault == "duplicate-child" && tag == mobilemultihop.MAXExitPrefix+"ss" {
							graph["outbounds"] = append(outputs, value)
							break
						}
					}
					if fault == "foreign-child" {
						graph["outbounds"] = append(outputs, map[string]any{"type": "direct", "tag": mobilemultihop.MAXExitPrefix + "foreign"})
					}
				}
				body, _ := json.Marshal(graph)
				broken := selection
				capture := *selection.Native
				capture.configs = map[string]string{mode: string(body)}
				broken.Native = &capture
				if _, err := compileDesktopExecutionConfig(body, descriptor, broken); err == nil {
					t.Fatal("Server silently removed or accepted an invalid captured MAX closure", fault)
				}
			})
		}
	}
}

// The Server controls must exercise the same independent identity, renewal,
// Compare reacquisition and retained ownership cases as ordinary packet exits.
func TestNativeMAXDesktopIndependentServerPinsAndProvedRestore(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		t.Run(mode, func(t *testing.T) {
			nativeMultihopPacketServerPeerGuard(t, mode)
			nativeMultihopPacketRestoreRetainsProvedServerPeerAndExecution(t, mode)
			nativeMultihopPacketRestoreRejectsRetiredLeaseIdentity(t, mode)
			nativeMultihopPacketUsesOwnedDNSInsteadOfKernelShortcut(t, mode)
		})
	}
}

func TestNativeMAXDesktopServerMovesOnlyItsCapturedResolverEdges(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		root, selection := nativeMultihopCapturedFixture(t, "awg2-strong", "aes-256-gcm+xor-whitening")
		selection.ExitMode = mode
		selection, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
		if err != nil {
			t.Fatal(err)
		}
		graph := retainedGraph(t, []byte(selection.Native.configs[mode]))
		servers := graph["dns"].(map[string]any)["servers"].([]any)
		for _, child := range []string{"ss", "outer", "start"} {
			servers = append(servers, map[string]any{"type": "tls", "tag": "captured-resolver-" + child, "server": "10.88.0.53", "server_port": float64(853), "detour": mobilemultihop.MAXExitPrefix + child, "tls": map[string]any{"enabled": true, "server_name": "captured-resolver.example"}})
		}
		graph["dns"].(map[string]any)["servers"] = servers
		body, _ := json.Marshal(graph)
		selection.Native.configs[mode] = string(body)
		_, descriptor := executionFixture()
		descriptor.Lease.ExitMode, descriptor.Lease.ExitStartLayer = mode, selection.Exit.StartLayer
		encoded, err := compileDesktopExecutionConfig(body, descriptor, selection)
		if err != nil {
			t.Fatal(err)
		}
		got := retainedGraph(t, encoded)["dns"].(map[string]any)["servers"].([]any)
		if len(got) != len(servers) {
			t.Fatal("Server changed the captured resolver inventory")
		}
		for index, raw := range servers {
			want := raw.(map[string]any)
			if tag, _ := want["tag"].(string); strings.HasPrefix(tag, "captured-resolver-") {
				want["detour"] = "proxy"
			}
			if !reflect.DeepEqual(got[index], want) {
				t.Fatal("Server changed an unowned resolver field or retained a deleted exit edge", mode, index)
			}
		}
	}
}
