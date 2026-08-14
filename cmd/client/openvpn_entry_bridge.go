package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"router-vpn/internal/common"
)

const openVPNEntrySOCKSPort = 1100

// writeOpenVPNEntryBridge creates a loopback-only SOCKS bridge whose traffic is
// forced through the linked Router VPN entry WireGuard endpoint. OpenVPN then
// dials its external TCP server through this local SOCKS listener. The bridge
// does not install an OS default route and therefore cannot compete with the
// final OpenVPN TUN for route ownership.
func writeOpenVPNEntryBridge(root, runtimeDir string, entry common.RouterProfile) (string, error) {
	if entry.ID == "" { return "", errors.New("OpenVPN hop requires a linked Router VPN entry") }
	entryDir, err := nativeGeneratedDir(root, entry.ID, "wg")
	if err != nil { return "", err }
	wg, err := parseNativeWG(filepath.Join(entryDir, "wg.conf"))
	if err != nil { return "", err }

	// The endpoint object is already the same pinned/native sing-box WireGuard
	// shape used by Windows/macOS multihop. A direct outbound detoured through
	// that endpoint gives the local SOCKS listener a single controlled egress.
	cfg := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "openvpn-entry-socks",
			"listen": "127.0.0.1", "listen_port": openVPNEntrySOCKSPort,
		}},
		"endpoints": []any{nativeWGEndpoint(wg)},
		"outbounds": []any{map[string]any{
			"type": "direct", "tag": "entry-egress", "detour": "entry-wg",
		}},
		"route": map[string]any{"final": "entry-egress", "auto_detect_interface": true},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil { return "", err }
	if len(raw) > 1<<20 { return "", errors.New("OpenVPN entry bridge config exceeds safety limit") }
	path := filepath.Join(runtimeDir, "entry-bridge.json")
	if err = os.WriteFile(path, append(raw, '\n'), 0o600); err != nil { return "", err }
	if err = os.Chmod(path, 0o600); err != nil { return "", err }
	return path, nil
}

func newOpenVPNRuntimeDir(root string) (string, error) {
	base := filepath.Join(root, "run", "openvpn-standard-exit")
	if err := os.MkdirAll(base, 0o700); err != nil { return "", err }
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil { return "", err }
	dir := filepath.Join(base, hex.EncodeToString(nonce))
	if err := os.Mkdir(dir, 0o700); err != nil { return "", err }
	return dir, nil
}
