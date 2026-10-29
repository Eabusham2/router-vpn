package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

type torBridgeTransportCapability struct {
	ID                            string `json:"id"`
	Name                          string `json:"name"`
	Implemented                   bool   `json:"implemented"`
	Supported                     bool   `json:"supported"`
	StrictKillSwitch              bool   `json:"strict_kill_switch"`
	StrictDynamicDirectKillSwitch bool   `json:"strict_dynamic_direct_kill_switch"`
	StrictRouterEntryKillSwitch   bool   `json:"strict_router_entry_kill_switch"`
	StrictExternalEntryKillSwitch bool   `json:"strict_external_entry_kill_switch"`
	Helper                        string `json:"helper,omitempty"`
	Description                   string `json:"description"`
	Reason                        string `json:"reason,omitempty"`
}

func torBridgeTransportCapabilities() []torBridgeTransportCapability {
	rows := []torBridgeTransportCapability{
		{ID: "tor", Name: "Plain Tor", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Uses ordinary Tor guard relays through the captured native TCP owner. Local supports Direct with Kill Switch Off or a proved Router/ordinary entry with strict protection. Server requires a paired private Router."},
		{ID: "obfs4", Name: "obfs4", Implemented: true, StrictKillSwitch: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Obfuscates Tor bridge traffic and resists active probing. One to eight literal obfs4 bridges support strict Direct protection using only their captured TCP sockets. A proved Router or Local ordinary entry can carry the same bridge set."},
		{ID: "meek_lite", Name: "meek", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Carries Tor through HTTPS/domain-fronting. Strict protection uses the proved Router or Local ordinary entry for HTTPS and DNS. Direct dynamic egress requires Kill Switch Off."},
		{ID: "snowflake", Name: "Snowflake", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Uses a broker and short-lived WebRTC proxies. Strict protection carries HTTPS, DNS, STUN and WebRTC through a proved entry with bounded native UDP. Local SOCKS5 and HTTP CONNECT entries cannot provide that UDP authority. Direct dynamic egress requires Kill Switch Off."},
		{ID: "webtunnel", Name: "WebTunnel", Implemented: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Makes Tor traffic resemble ordinary HTTPS. Strict protection uses the proved Router or Local ordinary entry for HTTPS and DNS. Direct dynamic egress requires Kill Switch Off."},
		{ID: "custom", Name: "Auto / Custom Tor bridges", Implemented: true, StrictKillSwitch: true, StrictRouterEntryKillSwitch: true, StrictExternalEntryKillSwitch: true, Description: "Accepts validated obfs4, meek, Snowflake and WebTunnel bridge lines, including mixed families. Direct strict protection requires every selected bridge to be literal obfs4, with one to eight lines. Dynamic families require an eligible captured entry; Server requires a paired private Router."},
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
		if runtime.GOOS == "linux" {
			rows[i].StrictDynamicDirectKillSwitch = true
			text := rows[i].Description
			text = strings.ReplaceAll(text, "Direct dynamic egress requires Kill Switch Off.", "Direct strict protection is available through the Linux native runtime, including selected bootstrap DNS.")
			text = strings.ReplaceAll(text, "Local supports Direct with Kill Switch Off or a proved Router/ordinary entry with strict protection.", "Local supports strict protection for Direct or a proved Router/ordinary entry.")
			text = strings.ReplaceAll(text, "Direct strict protection requires every selected bridge to be literal obfs4, with one to eight lines. Dynamic families require an eligible captured entry;", "Direct strict protection supports all accepted bridge families through the Linux native runtime;")
			rows[i].Description = text
		}
	}
	return rows
}

// The packaged native owner implements the complete accepted transport set.
// The saved profile still needs exact grammar and policy validation.
func torBridgeProfileRuntimeCapability(profile common.RouterProfile) standardExitCapability {
	root := filepath.Clean(getenv("HOMEVPN_ROOT", "/opt/router-vpn-client"))
	cap := torBridgeRuntimeCapabilityForExecution(root, profile.MultihopExecution)
	if profile.MultihopExecution == "auto" {
		local := torBridgeRuntimeCapabilityForExecution(root, "local")
		server := torBridgeRuntimeCapabilityForExecution(root, "server")
		cap = local
		// A missing candidate receives no score. A valid other candidate may
		// still win after the same final two-probe recheck.
		if !cap.Supported && server.Supported {
			cap = server
		}
	}
	if profile.External != nil && desktopTorProtocol(profile.External.Protocol) {
		cap.Protocol = profile.External.Protocol
	}
	if !cap.Supported {
		return cap
	}
	if _, _, _, _, err := torBridgeProfile(profile); err != nil {
		cap.Supported = false
		cap.Reason = "saved Tor bridge profile is invalid: " + err.Error()
		return cap
	}
	if source, err := json.Marshal(profile); err != nil {
		cap.Supported, cap.Reason = false, "saved Tor profile cannot be captured"
	} else if err = mobiletor.ValidateDesktopBridgeProfileForOS(string(source), runtime.GOOS); err != nil {
		cap.Supported, cap.Reason = false, "saved Tor policy is invalid: "+err.Error()
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
		"direct_dynamic_strict_kill_switch":   cap.Supported && runtime.GOOS == "linux",
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
		"compare_execution":                   available,
		"compare_requires_paired_source":      true,
		"last_node_measurement":               "tor-last-relay-http",
		"external_measurement":                "same-captured-endpoint-http",
		"dynamic_exit":                        true,
		"transports":                          torBridgeTransportCapabilities(),
		"truth":                               "the pluggable transport evades censorship; Tor's proved ntor-v3 circuit is the encrypted final path",
	})
}
