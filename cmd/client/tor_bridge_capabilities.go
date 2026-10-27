package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"

	"router-vpn/internal/common"
)

type torBridgeTransportCapability struct {
	ID                            string `json:"id"`
	Name                          string `json:"name"`
	Implemented                   bool   `json:"implemented"`
	Supported                     bool   `json:"supported"`
	StrictKillSwitch              bool   `json:"strict_kill_switch"`
	StrictRouterEntryKillSwitch   bool   `json:"strict_router_entry_kill_switch"`
	StrictExternalEntryKillSwitch bool   `json:"strict_external_entry_kill_switch"`
	Helper                        string `json:"helper,omitempty"`
	Description                   string `json:"description"`
	Reason                        string `json:"reason,omitempty"`
}

func torBridgeTransportCapabilities() []torBridgeTransportCapability {
	rows := []torBridgeTransportCapability{
		{ID: "tor", Name: "Plain Tor", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Uses ordinary Tor guard relays through the captured native TCP owner. Local supports Direct with Kill Switch Off or a proved Router/ordinary entry with strict protection. Server requires a paired private Router."},
		{ID: "obfs4", Name: "obfs4", Implemented: true, StrictKillSwitch: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Obfuscates Tor bridge traffic and resists active probing. One literal bridge supports strict Direct protection. Multiple bridges can use a proved Router entry or a Local ordinary entry with its exact captured physical sockets."},
		{ID: "meek_lite", Name: "meek", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Carries Tor through HTTPS/domain-fronting. Strict protection uses the proved Router or Local ordinary entry for HTTPS and DNS. Direct dynamic egress requires Kill Switch Off."},
		{ID: "snowflake", Name: "Snowflake", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Uses a broker and short-lived WebRTC proxies. Strict protection carries HTTPS, DNS, STUN and WebRTC through a proved entry with bounded native UDP. Local SOCKS5 and HTTP CONNECT entries cannot provide that UDP authority. Direct dynamic egress requires Kill Switch Off."},
		{ID: "webtunnel", Name: "WebTunnel", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Makes Tor traffic resemble ordinary HTTPS. Strict protection uses the proved Router or Local ordinary entry for HTTPS and DNS. Direct dynamic egress requires Kill Switch Off."},
		{ID: "custom", Name: "Auto / Custom Tor bridges", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Accepts validated obfs4, meek, Snowflake and WebTunnel bridge lines, including mixed families. Strict protection requires an entry whose captured graph carries every selected transport, unless the selection is one fixed obfs4 bridge. Server execution requires a paired private Router."},
	}

	cap := torBridgeRuntimeCapability()
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
	cap := torBridgeRuntimeCapabilityForExecution(root, profile.MultihopExecution)
	if profile.External != nil && desktopTorProtocol(profile.External.Protocol) {
		cap.Protocol = profile.External.Protocol
	}
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
	server := torBridgeRuntimeCapabilityForExecution(root, "server")
	available, reason := cap.Supported || server.Supported, cap.Reason
	if available {
		reason = ""
	}
	helperExecution := "native helpers"
	if runtime.GOOS == "windows" {
		var err error
		helperExecution, err = windowsTorHostCompatibility()
		if err != nil {
			helperExecution = "unavailable"
			if server.Supported {
				helperExecution = "native Server execution"
			}
		}
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                                  true,
		"protocol":                            "tor-bridge",
		"protocols":                           []string{"tor", "tor-bridge"},
		"platform":                            runtime.GOOS,
		"helper_execution":                    helperExecution,
		"implemented":                         cap.Implemented,
		"supported":                           available,
		"reason":                              reason,
		"direct_full_device":                  cap.Supported,
		"upstream_hop":                        available,
		"router_vpn_entry_hop":                available,
		"router_entry_strict_kill_switch":     available,
		"profile_update_source_preconditions": true,
		"router_vpn_entry_modes":              a.externalRouterEntryModes(),
		"external_entry_hop":                  cap.Supported,
		"external_entry_strict_kill_switch":   cap.Supported,
		"local_execution":                     cap.Supported,
		"server_execution":                    server.Supported,
		"server_execution_reason":             server.Reason,
		"server_requires_paired_source":       true,
		"compare_execution":                   false,
		"dynamic_exit":                        true,
		"transports":                          torBridgeTransportCapabilities(),
		"truth":                               "the pluggable transport evades censorship; Tor's proved ntor-v3 circuit is the encrypted final path",
	})
}
