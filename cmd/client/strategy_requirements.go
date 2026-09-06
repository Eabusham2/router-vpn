package main

import (
	"fmt"
	"strings"

	"router-vpn/internal/common"
)

// modeMeetsAutoRequirements is intentionally used only by AUTO/SMART AUTO.
// Manual logical modes and CUSTOM remain explicit user choices and are not
// silently rewritten by these convenience filters.
func modeMeetsAutoRequirements(mode common.Mode, profile common.RouterProfile) (bool, string) {
	startLayer, err := common.NormalizeStartLayerMode(profile.StartLayer)
	if err != nil {
		return false, fmt.Sprintf("%s filtered: invalid Start Layer preference: %v", mode.ID, err)
	}
	if startLayer != common.StartLayerOff && !common.StartLayerSupportsRawMode(mode.ID) {
		return false, fmt.Sprintf("%s filtered: Start Layer %s is enabled and this runtime has no proved AES pre-tunnel composition path", mode.ID, startLayer)
	}
	if profile.AutoRequireEncrypted && !modeHasEncryptedTransport(mode) {
		return false, fmt.Sprintf("%s filtered: Require encrypted is enabled and this runtime has no recognized encrypted tunnel/transport layer", mode.ID)
	}
	if profile.AutoRequireObfuscation && !modeHasObfuscation(mode) {
		return false, fmt.Sprintf("%s filtered: Require obfuscation is enabled and this runtime has no recognized camouflage/obfuscation layer", mode.ID)
	}
	return true, ""
}

func normalizedModeLayers(mode common.Mode) map[string]bool {
	out := make(map[string]bool, len(mode.Layers))
	for _, raw := range mode.Layers {
		if value := strings.ToLower(strings.TrimSpace(raw)); value != "" {
			out[value] = true
		}
	}
	return out
}

func modeHasEncryptedTransport(mode common.Mode) bool {
	layers := normalizedModeLayers(mode)
	for _, value := range []string{
		"wireguard", "amneziawg", "amneziawg2", "shadowsocks2022",
		"reality", "hysteria2", "tls", "https", "xtls-vision",
		"naive", "vless-pq", "rosenpass-pq",
	} {
		if layers[value] {
			return true
		}
	}
	return false
}

func modeHasObfuscation(mode common.Mode) bool {
	layers := normalizedModeLayers(mode)
	for _, value := range []string{
		"light-obfuscation", "strong-obfuscation", "reality", "salamander",
		"v2ray-plugin", "websocket", "utls-chrome", "finalmask", "xhttp",
		"naive", "https", "protocol-split",
	} {
		if layers[value] {
			return true
		}
	}
	return false
}
