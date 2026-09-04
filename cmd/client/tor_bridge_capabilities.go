package main

import (
	"runtime"
	"strings"
)

type torBridgeTransportCapability struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Implemented      bool   `json:"implemented"`
	Supported        bool   `json:"supported"`
	StrictKillSwitch bool   `json:"strict_kill_switch"`
	Helper           string `json:"helper,omitempty"`
	Description      string `json:"description"`
	Reason           string `json:"reason,omitempty"`
}

func torBridgeTransportCapabilities() []torBridgeTransportCapability {
	rows := []torBridgeTransportCapability{
		{ID: "obfs4", Name: "obfs4", Implemented: true, StrictKillSwitch: true, Description: "Obfuscates Tor bridge traffic into random-looking traffic and resists active probing; one literal obfs4 bridge can use Router VPN's strict pre-tunnel kill switch."},
		{ID: "meek_lite", Name: "meek", Implemented: true, Description: "Carries Tor through HTTPS/domain-fronting style infrastructure so blocking it can create collateral damage; dynamic CDN egress is not yet compatible with Router VPN's endpoint-only strict kill switch."},
		{ID: "snowflake", Name: "Snowflake", Implemented: true, Description: "Uses a broker plus short-lived volunteer WebRTC proxies so censors cannot rely on one stable bridge address; its dynamic broker/STUN/WebRTC egress requires Kill Switch Off until process-scoped firewall ownership is implemented."},
		{ID: "webtunnel", Name: "WebTunnel", Implemented: true, Description: "Makes Tor bridge traffic resemble ordinary HTTPS web traffic; Router VPN keeps strict kill switch unavailable because the PT's web bootstrap can differ from one static endpoint exception."},
		{ID: "custom", Name: "Auto / Custom Tor bridges", Implemented: true, Description: "Accepts one or more validated Tor-issued obfs4, meek, Snowflake, or WebTunnel bridge lines and can mix recognized families; arbitrary torrc directives, executable paths, and unknown PTs are rejected."},
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		for i := range rows {
			rows[i].Reason = "full-device Tor pluggable-transport runtime is currently implemented on Linux/macOS only"
		}
		return rows
	}
	if _, err := safeExecutable("tor"); err != nil {
		for i := range rows { rows[i].Reason = "tor is required for the real Tor circuit runtime" }
		return rows
	}
	if _, err := safeExecutable("sing-box"); err != nil {
		for i := range rows { rows[i].Reason = "sing-box is required for the full-device Tor TUN" }
		return rows
	}
	lyrebird, lyrebirdErr := safeExecutable("lyrebird")
	legacy, legacyErr := safeExecutable("obfs4proxy")
	for i := range rows {
		switch rows[i].ID {
		case "obfs4", "meek_lite":
			if lyrebirdErr == nil {
				rows[i].Supported, rows[i].Helper = true, lyrebird
			} else if legacyErr == nil {
				rows[i].Supported, rows[i].Helper = true, legacy
			} else {
				rows[i].Reason = "Lyrebird is preferred; compatible legacy obfs4proxy is not installed"
			}
		case "snowflake", "webtunnel", "custom":
			if lyrebirdErr == nil {
				rows[i].Supported, rows[i].Helper = true, lyrebird
			} else {
				rows[i].Reason = "Lyrebird is required for this Tor circumvention transport"
			}
		}
		rows[i].Helper = strings.TrimSpace(rows[i].Helper)
	}
	return rows
}
