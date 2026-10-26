package main

import (
	"bytes"
	"context"
	"encoding/base64"
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

// Complete import shapes enter the shipping desktop reader/compiler. KEM
// bytes in this structural matrix are synthetic; the independent native PQ
// traffic gate uses genuine pinned-Rust keys and proves negotiation/rekey.
func nativeEntryMultihopFixture(t *testing.T, mode, layer string) (string, multihopSelection) {
	t.Helper()
	root, selected := nativeMultihopCapturedFixture(t, "wg", "off")
	selected.Entry.StartLayer, selected.Exit.StartLayer = layer, layer
	selected.EntryMode, selected.Base = mode, desktopExternalEntryBase(mode)
	var files map[string][]byte
	switch {
	case mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong":
		_, files = viaEntryBaseFixture(t, mode)
	case mobilemultihop.IsPQMode(mode):
		base := "wg"
		if mode == "awg2-pq" {
			base = "awg2-strong"
		}
		_, packet := viaEntryBaseFixture(t, base)
		files = nativeMultihopPQAssets(t, mode, packet, testWGKey('q'))
	case mobilemultihop.MAXMode(mode):
		files = nativeEntryMAXAssets(t, selected.Entry, mode)
	case mobilemultihop.CompositeMode(mode):
		files = nativeMultihopCompositeExitAssets(t, selected.Entry, mode)
	case mode == "shadowsocks":
		var err error
		files, err = readDesktopNodeAssets(root, selected.Entry.ID, mode)
		if err != nil {
			t.Fatal(err)
		}
	case mode == "hysteria2":
		var err error
		files, err = readDesktopNodeAssets(root, selected.Exit.ID, mode)
		if err != nil {
			t.Fatal(err)
		}
		files["sing-box.json"] = bytes.ReplaceAll(files["sing-box.json"], []byte(selected.Exit.Endpoint), []byte(selected.Entry.Endpoint))
	default:
		files = nativeMultihopProxyExitAssets(t, selected.Entry, mode)
	}
	dir := filepath.Join(root, "generated", selected.Entry.ID, mode)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" || mobilemultihop.IsPQMode(mode) || mobilemultihop.MAXMode(mode) {
		selected.Entry.MTUPolicy, selected.Entry.ManualMTU = "manual", 1500
	}
	selected.Control = cloneRouterProfile(selected.Entry)
	selected.Control.MultihopEntryMode = mode
	return root, selected
}

func nativeEntryMAXAssets(t *testing.T, entry common.RouterProfile, mode string) map[string][]byte {
	t.Helper()
	base, pqMode, name, compat, tool, port := "wg", "wg-pq", "wg.conf", "wg-socks.conf", "wg", 51820
	if strings.HasSuffix(mode, "-awg") {
		base, pqMode, name, compat, tool, port = "awg2-strong", "awg2-pq", "awg.conf", "awg-socks.conf", "awg", 585
	}
	_, packet := viaEntryBaseFixture(t, base)
	files := nativeMultihopPQAssets(t, pqMode, packet, testWGKey('q'))
	lines := strings.Split(string(files[name]), "\n")
	for i, line := range lines {
		key, _, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "endpoint") {
			lines[i] = "Endpoint = 127.0.0.1:51830"
		}
	}
	files[name] = []byte(strings.Join(lines, "\n"))
	files[compat] = append([]byte(nil), files[name]...)
	pqHost := "10.77.0.1"
	if pqMode == "awg2-pq" {
		pqHost = "10.78.0.1"
	}
	files["rosenpass.toml"] = bytes.ReplaceAll(files["rosenpass.toml"], []byte("captured-router.example"), []byte(pqHost))
	ss := map[string]any{"type": "shadowsocks", "tag": "ss-hop", "server": "127.0.0.1", "server_port": 8388, "method": mobilemultihop.NativeStartLayerMethod, "password": testWGKey('s'), "detour": "outer"}
	var outer map[string]any
	engine, layers := "sing-box", "rosenpass-pq>base>shadowsocks2022>hysteria2-quic"
	if strings.HasPrefix(mode, "max-tls-") {
		engine, layers = "xray", "rosenpass-pq>base>shadowsocks2022>xray-vless-pq-reality-xhttp-finalmask"
		xray := nativeMultihopProxyExitAssets(t, entry, "reality-xhttp")
		files["outer-xray.json"] = xray["xray.json"]
		outer = map[string]any{"type": "socks", "tag": "outer", "server": "127.0.0.1", "server_port": 1090, "version": "5"}
	} else {
		cert, _ := nativeMultihopTrafficCertificate(t)
		files["cert.pem"] = []byte(cert)
		outer = map[string]any{"type": "hysteria2", "tag": "outer", "server": entry.Endpoint, "server_port": 8443, "password": "captured-max-quic-password", "tls": map[string]any{"enabled": true, "server_name": "exit-certificate.example", "certificate_path": "cert.pem"}}
	}
	middle := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "direct", "tag": "base-relay", "listen": "127.0.0.1", "listen_port": 51830, "network": "udp", "override_address": "127.0.0.1", "override_port": port}}, "outbounds": []any{outer, ss}, "route": map[string]any{"final": "ss-hop"}}
	files["middle-sing-box.json"], _ = json.Marshal(middle)
	files["chain.env"] = []byte("CHAIN_READY=1\nOUTER_ENGINE=" + engine + "\nCHAIN_LAYERS=" + layers + "\nLOCAL_RELAY_PORT=51830\nPQ_BASE=1\n")
	if !bytes.Contains(files["rosenpass.env"], []byte("ROSENPASS_TOOL="+tool)) {
		t.Fatal("MAX fixture substituted the packet family")
	}
	return files
}

func TestNativeEntryMultihopLocalServerCaptureMatrix(t *testing.T) {
	count := 0
	exits := mobilemultihop.NodeMultihopExitModes()
	for entryIndex, mode := range mobilemultihop.NodeMultihopEntryModes() {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(mode+"/"+layer, func(t *testing.T) {
				root, selected := nativeEntryMultihopFixture(t, mode, layer)
				selected, err := captureNativeMultihopSelection(context.Background(), root, selected, exits, nil)
				if err != nil || selected.Native == nil || len(selected.Native.configs) != len(exits) {
					if selected.Native != nil {
						t.Fatal("entry could not retain the complete exit catalog", selected.Native.failures, err)
					}
					t.Fatal(err)
				}
				if selected.EntryMode != mode || selected.Native.entryMode != mode || selected.Base != desktopExternalEntryBase(mode) {
					t.Fatal("capture changed the raw entry family")
				}
				if mobilemultihop.MAXMode(mode) {
					for _, asset := range selected.Native.assets {
						if asset.id == selected.Entry.ID && asset.mode == "shadowsocks" {
							t.Fatal("complete MAX captured an unrelated additional Start Layer")
						}
					}
				}
				for exitIndex, exitMode := range exits {
					selected.ExitMode = exitMode
					local, err := compileRetainedNativeMultihopLaunch(selected, nil)
					if err != nil {
						t.Fatal(err)
					}
					_, descriptor := executionFixture()
					descriptor.Lease.ExitMode = exitMode
					if layer != "off" {
						descriptor.Lease.ExitStartLayer = layer
					}
					server, err := compileRetainedNativeMultihopLaunch(selected, &descriptor)
					if err != nil {
						t.Fatal(mode, exitMode, err)
					}
					before := retainedGraph(t, local.config)
					after := retainedGraph(t, server.config)
					_, beforeEntry, err := nativeMultihopEntrySnapshot(before, selected.Native.entryOwners)
					if err != nil {
						t.Fatal(err)
					}
					_, afterEntry, err := nativeMultihopEntrySnapshot(after, selected.Native.entryOwners)
					if err != nil || !bytes.Equal(beforeEntry, afterEntry) {
						t.Fatal("Server replaced an entry engine/resolver/performance owner", err)
					}
					clear(beforeEntry)
					clear(afterEntry)
					for _, field := range []string{"inbounds", "services"} {
						if !reflect.DeepEqual(before[field], after[field]) {
							t.Fatal("Server changed protected interface/MTU or cover policy", field)
						}
					}
					for _, launch := range []*desktopNodeLaunch{local, server} {
						meta := retainedGraph(t, launch.metadata)
						if meta["entry_mode"] != mode || meta["base"] != desktopExternalEntryBase(mode) || meta["graph_source_sha256"] != selected.Native.source || launch.endpoint != selected.Entry.Endpoint {
							t.Fatal("native receipt or physical whitelist lost captured entry identity")
						}
						// Every entry/layer and every exit family reaches the real
						// parser without duplicating the full Cartesian process matrix.
						if binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"); binary != "" && exitIndex == entryIndex%len(exits) {
							dir := t.TempDir()
							path := filepath.Join(dir, "native-entry.json")
							if err := os.WriteFile(path, launch.config, 0600); err != nil {
								t.Fatal(err)
							}
							command := exec.Command(binary, "check", "-c", path, "-D", dir)
							command.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
							if output, err := command.CombinedOutput(); err != nil {
								t.Fatal("actual native parser rejected expanded entry", mode, exitMode, err, string(output))
							}
						}
					}
					count += 2
				}
			})
		}
	}
	if count != 2*3*len(mobilemultihop.NodeMultihopEntryModes())*len(exits) {
		t.Fatal("missing captured Local/Server entry composition", count)
	}
}

// Keep an independent reference to the credential form used by ordinary SS
// entry and the real traffic harness; this must remain a canonical AES key.
func nativeEntryTrafficAESKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}
