package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"

	"router-vpn/internal/common"
)

type torBridgeTransportCapability struct {
	ID                          string `json:"id"`
	Name                        string `json:"name"`
	Implemented                 bool   `json:"implemented"`
	Supported                   bool   `json:"supported"`
	StrictKillSwitch            bool   `json:"strict_kill_switch"`
	StrictRouterEntryKillSwitch bool   `json:"strict_router_entry_kill_switch"`
	Helper                      string `json:"helper,omitempty"`
	Description                 string `json:"description"`
	Reason                      string `json:"reason,omitempty"`
}

func torBridgeTransportCapabilities() []torBridgeTransportCapability {
	rows := []torBridgeTransportCapability{
		{ID: "obfs4", Name: "obfs4", Implemented: true, StrictKillSwitch: true, StrictRouterEntryKillSwitch: true, Description: "Obfuscates Tor bridge traffic into random-looking traffic and resists active probing; one literal obfs4 bridge supports strict Direct protection, and a captured Local Router entry also protects multiple bridges."},
		{ID: "meek_lite", Name: "meek", Implemented: true, StrictRouterEntryKillSwitch: true, Description: "Carries Tor through HTTPS/domain-fronting. Strict protection requires a captured Local Router entry; its HTTPS and DNS use that proved entry. Direct dynamic egress still requires Kill Switch Off."},
		{ID: "snowflake", Name: "Snowflake", Implemented: true, StrictRouterEntryKillSwitch: true, Description: "Uses a broker and short-lived WebRTC proxies. Strict protection requires a captured Local Router entry for broker HTTPS, DNS, STUN and WebRTC traffic. Direct dynamic egress still requires Kill Switch Off."},
		{ID: "webtunnel", Name: "WebTunnel", Implemented: true, StrictRouterEntryKillSwitch: true, Description: "Makes Tor traffic resemble ordinary HTTPS. Strict protection requires a captured Local Router entry for its HTTPS and DNS; Direct dynamic egress still requires Kill Switch Off."},
		{ID: "custom", Name: "Auto / Custom Tor bridges", Implemented: true, StrictRouterEntryKillSwitch: true, Description: "Accepts validated obfs4, meek, Snowflake and WebTunnel bridge lines, including mixed families. Strict protection requires a captured Local Router entry unless the selection is one fixed obfs4 bridge; arbitrary torrc directives and executables are rejected."},
	}

	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	cap := torBridgeRuntimeCapabilityForRoot(root)
	if !cap.Supported {
		for i := range rows {
			rows[i].Reason = cap.Reason
		}
		return rows
	}
	for i := range rows {
		rows[i].Supported = true
		rows[i].Helper = "Router VPN native transport owner"
	}
	return rows
}

// The packaged native owner implements the complete accepted transport set.
// The saved profile still needs exact grammar and policy validation.
func torBridgeProfileRuntimeCapability(profile common.RouterProfile) standardExitCapability {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	cap := torBridgeRuntimeCapabilityForRoot(root)
	if !cap.Supported {
		return cap
	}
	if _, _, _, _, err := torBridgeProfile(profile); err != nil {
		cap.Supported = false
		cap.Reason = "saved Tor bridge profile is invalid: " + err.Error()
	}
	return cap
}

func (a *app) torBridgeCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	cap := torBridgeRuntimeCapabilityForRoot(root)
	helperExecution := "native helpers"
	if runtime.GOOS == "windows" {
		var err error
		helperExecution, err = windowsTorHostCompatibility()
		if err != nil {
			helperExecution = "unavailable"
		}
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                              true,
		"protocol":                        "tor-bridge",
		"platform":                        runtime.GOOS,
		"helper_execution":                helperExecution,
		"implemented":                     cap.Implemented,
		"supported":                       cap.Supported,
		"reason":                          cap.Reason,
		"direct_full_device":              cap.Supported,
		"upstream_hop":                    cap.Supported,
		"router_vpn_entry_hop":            cap.Supported,
		"router_entry_strict_kill_switch": cap.Supported,
		"router_vpn_entry_modes":          a.externalRouterEntryModes(),
		"external_entry_hop":              false,
		"local_execution":                 cap.Supported,
		"server_execution":                false,
		"compare_execution":               false,
		"dynamic_exit":                    true,
		"transports":                      torBridgeTransportCapabilities(),
		"truth":                           "the pluggable transport evades censorship; Tor's proved ntor-v3 circuit is the encrypted final path",
	})
}
