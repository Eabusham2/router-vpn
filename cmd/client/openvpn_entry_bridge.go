package main

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"router-vpn/internal/common"
)

const openVPNEntrySOCKSPort = 1100

// writeOpenVPNEntryBridge creates a loopback-only SOCKS bridge whose traffic is
// forced through either a linked Router VPN WireGuard entry or a supported
// external standard entry. OpenVPN then dials its external TCP server through
// this local SOCKS listener. The bridge never owns the OS default route, so it
// cannot compete with the final OpenVPN TUN.
func writeOpenVPNEntryBridge(root, runtimeDir string, entry common.RouterProfile) (string, error) {
	if entry.ID == "" {
		return "", errors.New("OpenVPN hop requires a linked entry node")
	}
	if err := ensurePrivateRuntimeDirectory(runtimeDir); err != nil {
		return "", err
	}
	var cfg map[string]any
	if entry.NodeKind == "external" {
		externalEntry, err := standardExitFromExternalProfile(entry)
		if err != nil {
			return "", err
		}
		if externalEntry.Protocol == "openvpn" {
			return "", errors.New("external OpenVPN cannot currently be used as the entry to another OpenVPN/default-route hop")
		}
		cfg, err = externalEntryBridgeConfig(externalEntry, openVPNEntrySOCKSPort)
		if err != nil {
			return "", err
		}
	} else {
		entryDir, err := nativeGeneratedDir(root, entry.ID, "wg")
		if err != nil {
			return "", err
		}
		wg, err := parseNativeWG(filepath.Join(entryDir, "wg.conf"))
		if err != nil {
			return "", err
		}

		// The endpoint object is the same pinned/native sing-box WireGuard shape
		// used by Windows/macOS multihop. A direct outbound detoured through that
		// endpoint gives the local SOCKS listener a single controlled egress.
		cfg = map[string]any{
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
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	if len(raw) > 1<<20 {
		return "", errors.New("OpenVPN entry bridge config exceeds safety limit")
	}
	path := filepath.Join(runtimeDir, "entry-bridge.json")
	if err = writePrivateRuntimeFile(path, append(raw, '\n')); err != nil {
		return "", err
	}
	return path, nil
}

func newOpenVPNRuntimeDir(root string) (string, error) {
	return newPrivateRuntimeDir(root, "openvpn-standard-exit")
}
