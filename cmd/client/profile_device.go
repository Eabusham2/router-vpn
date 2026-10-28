package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// Imported nodes share device policy without acquiring the Router-only base,
// Start Layer or forwarding fields from a disabled settings form. Tor
// cover traffic has a separate captured capability and atomic preference pair.
type profileDeviceSettings struct {
	ProfileID             string `json:"profile_id"`
	ProfileToken          string `json:"profile_token"`
	NodeKind              string `json:"node_kind"`
	Protocol              string `json:"protocol"`
	DevicePolicySupported bool   `json:"device_policy_supported"`
	DevicePolicyReason    string `json:"device_policy_reason"`
	HomeLANAccess         bool   `json:"home_lan_access"`
	KillSwitchPolicy      string `json:"kill_switch_policy"`
	IPv6Mode              string `json:"ipv6_mode"`
	MTUPolicy             string `json:"mtu_policy"`
	ManualMTU             int    `json:"manual_mtu"`
	JumboTUN              bool   `json:"jumbo_tun"`
	JumboTUNSupported     bool   `json:"jumbo_tun_supported"`
	DAITAEnabled          bool   `json:"daita_enabled"`
	DAITARateKbps         int    `json:"daita_rate_kbps"`
	TorCoverSupported     bool   `json:"tor_cover_supported"`
	TorCoverNote          string `json:"tor_cover_note"`
	EffectiveMTU          int    `json:"effective_mtu"`
	MTUSource             string `json:"mtu_source"`
	StartupMode           string `json:"startup_mode"`
	AutoConnect           bool   `json:"auto_connect"`
	Note                  string `json:"note"`
}

type profileDeviceRequest struct {
	ProfileID        string  `json:"profile_id"`
	ProfileToken     string  `json:"profile_token"`
	HomeLANAccess    *bool   `json:"home_lan_access"`
	KillSwitchPolicy *string `json:"kill_switch_policy"`
	IPv6Mode         *string `json:"ipv6_mode"`
	MTUPolicy        *string `json:"mtu_policy"`
	ManualMTU        *int    `json:"manual_mtu"`
	JumboTUN         *bool   `json:"jumbo_tun,omitempty"`
	DAITAEnabled     *bool   `json:"daita_enabled,omitempty"`
	DAITARateKbps    *int    `json:"daita_rate_kbps,omitempty"`
	StartupMode      *string `json:"startup_mode,omitempty"`
	AutoConnect      *bool   `json:"auto_connect,omitempty"`
}

func profileDeviceSettingsToken(profile, entry common.RouterProfile) string {
	// Historical readback may finish while an idle editor is open. It is not
	// the requested MTU policy and must neither invalidate nor be overwritten
	// by a device edit. All actual source, credentials and entry policy remain
	// bound by the exact private-source projection.
	profile.EffectiveMTU, entry.EffectiveMTU = 0, 0
	sum := sha256.Sum256([]byte(profileStartupSettingsToken(profile) + ":" + profileStartupSettingsToken(entry)))
	return hex.EncodeToString(sum[:])
}

func externalDevicePolicySupport(profile common.RouterProfile) (bool, string) {
	if profile.NodeKind != "external" || profile.External == nil {
		return false, "Common external device settings require the complete imported node."
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return false, "Common external device settings require the native Windows, macOS or Linux runtime."
	}
	if desktopExternalNativeProtocol(profile.External.Protocol) {
		return true, ""
	}
	if desktopTorProtocol(profile.External.Protocol) {
		// Entry settings belong to the same owned native Tor graph. The
		// idle form preserves the saved choice; Connect still captures its full
		// native predecessor and authenticates it before any PT can start.
		switch {
		case profile.MultihopEnabled && (!validProfileID(profile.MultihopEntryID) || profile.MultihopEntryID == profile.ID ||
			profile.MultihopExitID != profile.ID || desktopTorExecution(profile.MultihopExecution) == "" && profile.MultihopExecution != "auto" ||
			profile.MultihopEntryMode != "" && !mobilemultihop.NodeMultihopEntryMode(profile.MultihopEntryMode) && !desktopExternalNativeProtocol(profile.MultihopEntryMode)):
			return false, "Tor entry device settings require the exact saved Local, Server or Compare entry, exit and native mode."
		case !profile.MultihopEnabled && desktopTorExecution(profile.MultihopExecution) != "local":
			return false, "Direct Tor device settings require Local execution."
		default:
			return true, ""
		}
	}
	return false, "This external protocol does not yet apply the common device settings through an owned native desktop runtime."
}

func externalDevicePolicySupportForPath(profile, entry common.RouterProfile) (bool, string) {
	if supported, reason := externalDevicePolicySupport(profile); !supported {
		return supported, reason
	}
	if desktopTorProtocol(profile.External.Protocol) && profile.MultihopEnabled {
		if entry.ID != profile.MultihopEntryID {
			return false, "Tor entry device settings require the same linked node; reopen Settings after relinking it."
		}
		if (profile.MultihopExecution == "server" || profile.MultihopExecution == "auto") && (entry.External != nil || entry.NodeKind != "" && entry.NodeKind != "router-vpn") {
			return false, "Tor Server and Compare device settings require the captured private Router entry."
		}
		if _, err := desktopTorEntryMode(profile, entry, "", ""); err != nil {
			return false, err.Error()
		}
	}
	return true, ""
}

func profileDeviceJumboSupported(profile common.RouterProfile) bool {
	supported, _ := externalDevicePolicySupport(profile)
	return supported && profile.External != nil && desktopTorProtocol(profile.External.Protocol)
}

func profileDeviceTorCoverSelection(profile common.RouterProfile) bool {
	if profile.External == nil || !desktopTorProtocol(profile.External.Protocol) {
		return false
	}
	execution := desktopTorExecution(profile.MultihopExecution)
	return execution == "local" || (execution == "server" || profile.MultihopExecution == "auto") && profile.MultihopEnabled
}

func profileDeviceTorCoverSupported(profile, entry common.RouterProfile) bool {
	if !profileDeviceTorCoverSelection(profile) {
		return false
	}
	supported, _ := externalDevicePolicySupportForPath(profile, entry)
	return supported
}

func writeProfileDeviceSettings(w http.ResponseWriter, profile, entry common.RouterProfile) {
	protocol := ""
	if profile.External != nil {
		protocol = profile.External.Protocol
	}
	supported, reason := externalDevicePolicySupportForPath(profile, entry)
	kill := strings.ToLower(strings.TrimSpace(profile.KillSwitchPolicy))
	if kill == "" {
		kill = "off"
		if profile.KillSwitch {
			kill = "on-connect"
		}
	}
	ipv6 := strings.ToLower(strings.TrimSpace(profile.IPv6Mode))
	if ipv6 == "" {
		ipv6 = "on"
	}
	mtu := strings.ToLower(strings.TrimSpace(profile.MTUPolicy))
	if mtu == "" {
		mtu = "auto"
	} else if mtu == "fixed" {
		mtu = "manual"
	}
	manual := profile.ManualMTU
	if mtu == "auto" || mtu == "default" {
		manual = 0
	}
	startup := strings.ToLower(strings.TrimSpace(profile.StartupMode))
	if startup == "" {
		startup = "smart-auto"
	}
	note := "Save while disconnected. Fixed MTU is a requested interface value, not a measured path result. Effective MTU is historical; use Retest on the connected path. This edit preserves independent entry policy, DNS, credentials and graph selection."
	if desktopTorProtocol(protocol) {
		note = "Save while disconnected. Tor Auto starts with a 1280-byte virtual interface, then compares HTTPS response time and download/upload performance at tested MTUs. Retest repeats those measurements with fresh Tor and DNS proof; Cancel waits for the previous interface value to be restored. Default keeps 1280; Fixed applies your interface value. Interface readback is not a UDP path-MTU measurement. DNS, credentials and graph selection are preserved."
		if profile.JumboTUN {
			note = "Save while disconnected. Tor Jumbo configures a 9000-byte virtual interface; it does not force 9000-byte packets onto the underlying network. Auto and Retest do not change that interface while Jumbo is selected. Fixed MTU must also be 9000. The saved Auto or Default preference is retained for when Jumbo is turned off. DNS, credentials and graph selection are preserved."
		}
	}
	coverSupported := profileDeviceTorCoverSupported(profile, entry)
	coverNote := "Outgoing Tor cover traffic requires a captured Local path or a private Router Server path. Saved cover preferences are preserved while unavailable."
	if coverSupported {
		if profile.MultihopExecution == "auto" {
			coverNote = "Outgoing Tor cover traffic runs on each measured candidate and the retained winner. It is not bidirectional DAITA. Budget: 32–192 kbit/s; 0 keeps the native default of 192. Both Local and Server require selected DNS and a fresh cover receipt; Compare preserves this exact preference."
		} else if desktopTorExecution(profile.MultihopExecution) == "server" {
			coverNote = "Outgoing Tor cover traffic adds bounded relay cells from the selected server. It is not bidirectional DAITA. Budget: 32–192 kbit/s; 0 keeps the native default of 192. Saving is a preference; the authenticated server source and fresh cover receipt must still be proved on Connect."
		} else {
			coverNote = "Outgoing Tor cover traffic adds bounded relay cells from this device. It is not bidirectional DAITA. Budget: 32–192 kbit/s; 0 keeps the native default of 192. Saving is a preference; the captured path, selected DNS and fresh cover receipt must still be proved on Connect and renewed while connected."
		}
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(profileDeviceSettings{
		ProfileID: profile.ID, ProfileToken: profileDeviceSettingsToken(profile, entry),
		NodeKind: profile.NodeKind, Protocol: protocol,
		DevicePolicySupported: supported, DevicePolicyReason: reason,
		HomeLANAccess: profile.HomeLANAccess, KillSwitchPolicy: kill,
		IPv6Mode: ipv6, MTUPolicy: mtu, ManualMTU: manual,
		JumboTUN: profile.JumboTUN, JumboTUNSupported: supported && profileDeviceJumboSupported(profile),
		DAITAEnabled: profile.DAITAEnabled, DAITARateKbps: profile.DAITARateKbps,
		TorCoverSupported: coverSupported, TorCoverNote: coverNote,
		EffectiveMTU: profile.EffectiveMTU, MTUSource: profile.EffectiveMTUSource,
		StartupMode: startup, AutoConnect: profile.AutoConnect,
		Note: note,
	})
}

func applyProfileDeviceSettings(profile common.RouterProfile, request profileDeviceRequest) (common.RouterProfile, error) {
	if request.HomeLANAccess == nil || request.KillSwitchPolicy == nil || request.IPv6Mode == nil ||
		request.MTUPolicy == nil || request.ManualMTU == nil {
		return profile, errors.New("home_lan_access, kill_switch_policy, ipv6_mode, mtu_policy and manual_mtu are all required")
	}
	updated := cloneRouterProfile(profile)
	updated.HomeLANAccess = *request.HomeLANAccess
	updated.KillSwitchPolicy = strings.ToLower(strings.TrimSpace(*request.KillSwitchPolicy))
	switch updated.KillSwitchPolicy {
	case "off", "on-connect", "always":
		updated.KillSwitch = updated.KillSwitchPolicy != "off"
	default:
		return profile, errors.New("kill_switch_policy must be off, on-connect, or always")
	}
	updated.IPv6Mode = strings.ToLower(strings.TrimSpace(*request.IPv6Mode))
	switch updated.IPv6Mode {
	case "on", "auto", "off":
	default:
		return profile, errors.New("ipv6_mode must be on, auto, or off")
	}
	updated.MTUPolicy = strings.ToLower(strings.TrimSpace(*request.MTUPolicy))
	updated.ManualMTU = *request.ManualMTU
	if request.JumboTUN != nil {
		if !profileDeviceJumboSupported(profile) {
			return profile, errors.New("this captured device editor cannot change Jumbo for the selected native path")
		}
		updated.JumboTUN = *request.JumboTUN
	}
	if (request.DAITAEnabled == nil) != (request.DAITARateKbps == nil) {
		return profile, errors.New("daita_enabled and daita_rate_kbps must be supplied together")
	}
	if request.DAITAEnabled != nil {
		rate := *request.DAITARateKbps
		if rate != 0 && (rate < mobiletor.PaddingMinRateKbps || rate > mobiletor.PaddingMaxRateKbps) {
			return profile, errors.New("outgoing Tor cover budget must be 0 or 32..192 kbit/s")
		}
		changed := *request.DAITAEnabled != profile.DAITAEnabled || rate != profile.DAITARateKbps
		if changed && !profileDeviceTorCoverSelection(profile) {
			return profile, errors.New("this captured device editor can change outgoing Tor cover traffic only for a saved Local or private Router Server path")
		}
		updated.DAITAEnabled, updated.DAITARateKbps = *request.DAITAEnabled, rate
	}
	switch updated.MTUPolicy {
	case "auto", "default":
		if updated.ManualMTU != 0 {
			return profile, errors.New("Auto or Default MTU requires manual_mtu 0")
		}
	case "manual":
		if updated.ManualMTU < 1280 || updated.ManualMTU > 9000 {
			return profile, errors.New("native Fixed MTU must be 1280..9000")
		}
	default:
		return profile, errors.New("mtu_policy must be auto, default, or manual")
	}
	// Full Settings can save an explicitly edited startup pair atomically.
	// Narrow common-policy editors omit both and retain the saved preference.
	if (request.StartupMode == nil) != (request.AutoConnect == nil) {
		return profile, errors.New("startup_mode and auto_connect must be supplied together")
	}
	if request.StartupMode != nil {
		updated.StartupMode = strings.ToLower(strings.TrimSpace(*request.StartupMode))
		updated.AutoConnect = *request.AutoConnect
		switch updated.StartupMode {
		case "manual", "auto", "smart-auto", "last":
		default:
			return profile, errors.New("startup_mode must be manual, auto, smart-auto, or last")
		}
		if updated.AutoConnect && updated.StartupMode == "manual" {
			return profile, errors.New("Manual startup must remain disconnected")
		}
	}
	if err := validateExternalDeviceSettings(updated); err != nil {
		return profile, err
	}
	return updated, nil
}

// Validate with the exact native transport/device/MTU parser, without choosing
// DNS, looking up a hostname, launching an engine or granting runtime readiness.
func validateExternalDeviceSettings(profile common.RouterProfile) error {
	if supported, reason := externalDevicePolicySupport(profile); !supported {
		return errors.New(reason)
	}
	if desktopTorProtocol(profile.External.Protocol) {
		if profile.MultihopExecution == "auto" {
			// An idle Compare preference must validate both concrete policies.
			// It never enters a native compiler or becomes a claimed winner.
			for _, execution := range []string{"local", "server"} {
				candidate := cloneRouterProfile(profile)
				candidate.MultihopExecution = execution
				if err := validateExternalDeviceSettings(candidate); err != nil {
					return err
				}
			}
			return nil
		}
		// Pass the exact runtime preferences and private owners to the shipping
		// Tor parser. Idle Home may remain unresolved; this never grants a
		// runnable resolver, modifies bridge credentials, or reuses MTU history.
		// Display/measurement floats are deliberately outside this projection.
		captured := common.RouterProfile{
			ID: profile.ID, NodeKind: profile.NodeKind, External: profile.External,
			NodeProofID: profile.NodeProofID, RouterAPI: profile.RouterAPI, APIToken: profile.APIToken,
			StartLayer: profile.StartLayer, HomeLANAccess: profile.HomeLANAccess, HomeLANCIDRs: profile.HomeLANCIDRs,
			KillSwitch: profile.KillSwitch, KillSwitchPolicy: profile.KillSwitchPolicy, IPv6Mode: profile.IPv6Mode,
			MTUPolicy: profile.MTUPolicy, ManualMTU: profile.ManualMTU, JumboTUN: profile.JumboTUN,
			DNSMode: profile.DNSMode, DNSProtocol: profile.DNSProtocol, DNSHost: profile.DNSHost,
			DNSPort: profile.DNSPort, DNSServerName: profile.DNSServerName, DNSPath: profile.DNSPath,
			MultihopEnabled: profile.MultihopEnabled, MultihopEntryID: profile.MultihopEntryID,
			MultihopExitID: profile.MultihopExitID, MultihopEntryMode: profile.MultihopEntryMode,
			MultihopExecution: profile.MultihopExecution,
			DAITAEnabled:      profile.DAITAEnabled, DAITARateKbps: profile.DAITARateKbps,
			DAITAHost: profile.DAITAHost, DAITAPort: profile.DAITAPort,
		}
		source, err := desktopTorRuntimePolicyJSON(captured)
		if err != nil {
			return errors.New("could not capture Tor device policy")
		}
		return mobiletor.ValidateDesktopBridgeProfile(string(source))
	}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		return err
	}
	endpoint, outbound, err := directStandardExitRuntimeParts(exit)
	if err != nil {
		return err
	}
	endpoints, outbounds := []any{}, []any{}
	if endpoint != nil {
		endpoints = append(endpoints, endpoint)
	}
	if outbound != nil {
		outbounds = append(outbounds, outbound)
	}
	graph := map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in",
			"address": []any{"172.29.91.1/30", "fd29:91::1/126"}, "mtu": 1280,
			"auto_route": true, "strict_route": true, "stack": "system"}},
		"endpoints": endpoints, "outbounds": outbounds,
		"route": map[string]any{"final": "custom-exit", "auto_detect_interface": true},
	}
	// Only runtime policy is needed by the idle parser. Historical/display
	// floats cannot prevent a policy correction, and no normalization of the
	// captured credentials or saved policy is persisted.
	type wireProfile common.RouterProfile
	captured := common.RouterProfile{
		ID: profile.ID, NodeKind: profile.NodeKind, External: profile.External,
		StartLayer: profile.StartLayer, HomeLANAccess: profile.HomeLANAccess,
		HomeLANCIDRs: profile.HomeLANCIDRs, IPv6Mode: profile.IPv6Mode,
		MTUPolicy: profile.MTUPolicy, ManualMTU: profile.ManualMTU,
		MultihopExecution: profile.MultihopExecution,
	}
	source, err := json.Marshal(graph)
	if err != nil {
		return errors.New("could not capture native device transport")
	}
	capture, err := json.Marshal(map[string]any{
		"schema": 1, "exit_id": profile.ID, "protocol": profile.External.Protocol,
		"expected_public_ip": profile.External.ExpectedPublicIP, "profile": wireProfile(captured),
	})
	if err != nil {
		return errors.New("could not capture external device policy")
	}
	return mobilemultihop.ValidateExternalTransport(string(source), string(capture))
}

// Idle intent retains the exact linked transport, not a proof of runtime
// readiness. Strict ordinary paths still need the independently compiled
// physical projection and live typed entry proof at connection time.
func validateExternalDeviceSettingsForPath(profile, entry common.RouterProfile) error {
	if supported, reason := externalDevicePolicySupportForPath(profile, entry); !supported {
		return errors.New(reason)
	}
	if desktopTorProtocol(profile.External.Protocol) && profile.MultihopEnabled && entry.External != nil {
		kill := profile.KillSwitchPolicy
		if kill == "" {
			kill = "off"
			if profile.KillSwitch {
				kill = "on-connect"
			}
		}
		if kill != "off" {
			if err := validateExternalDeviceSettings(entry); err != nil {
				return err
			}
			plan, err := desktopTorTransportPlan(profile)
			if err != nil {
				return err
			}
			for _, bridge := range plan.Bridges {
				if bridge.Transport == "snowflake" && (entry.External.Protocol == "socks5" || entry.External.Protocol == "http-connect" || entry.External.Protocol == "https-connect") {
					return errors.New("protected Snowflake requires a predecessor with bounded native UDP; SOCKS5 and HTTP CONNECT cannot supply that physical authority")
				}
			}
		}
	}
	return validateExternalDeviceSettings(profile)
}

func (a *app) profileDeviceSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		release, err := a.beginMutationOperation(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		defer release()
	}
	a.mu.Lock()
	profile, entry, ok := a.dnsPolicySelectionLocked()
	a.mu.Unlock()
	if !ok || !externalDNSProfile(profile) {
		http.Error(w, "select an imported external node for common device settings", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		writeProfileDeviceSettings(w, profile, entry)
		return
	}
	var request profileDeviceRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	fields, objectErr := applexray.Object(raw)
	if err != nil || objectErr != nil {
		http.Error(w, "device settings require one unambiguous JSON object", http.StatusBadRequest)
		return
	}
	if value, present := fields["jumbo_tun"]; present {
		if _, valid := value.(bool); !valid {
			http.Error(w, "jumbo_tun must be a boolean when supplied", http.StatusBadRequest)
			return
		}
	}
	if value, present := fields["daita_enabled"]; present {
		if _, valid := value.(bool); !valid {
			http.Error(w, "daita_enabled must be a boolean when supplied", http.StatusBadRequest)
			return
		}
	}
	if value, present := fields["daita_rate_kbps"]; present {
		number, valid := value.(json.Number)
		if !valid {
			http.Error(w, "daita_rate_kbps must be a whole number when supplied", http.StatusBadRequest)
			return
		}
		if _, err := number.Int64(); err != nil {
			http.Error(w, "daita_rate_kbps must be a whole number when supplied", http.StatusBadRequest)
			return
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid device settings", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "one device settings object is required", http.StatusBadRequest)
		return
	}
	token := profileDeviceSettingsToken(profile, entry)
	if request.ProfileID != profile.ID || request.ProfileToken == "" || request.ProfileToken != token {
		http.Error(w, "selected node, entry or policy changed; reopen Settings", http.StatusConflict)
		return
	}
	if supported, reason := externalDevicePolicySupportForPath(profile, entry); !supported {
		http.Error(w, reason, http.StatusUnprocessableEntity)
		return
	}
	validated, err := applyProfileDeviceSettings(profile, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateExternalDeviceSettingsForPath(validated, entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	current, currentEntry, exists := a.dnsPolicySelectionLocked()
	if !exists || current.ID != profile.ID || profileDeviceSettingsToken(current, currentEntry) != token ||
		a.closing || r.Context().Err() != nil || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "node, entry or connection changed; reopen Settings when disconnected", http.StatusConflict)
		return
	}
	updated := cloneRouterProfile(current)
	updated.HomeLANAccess = validated.HomeLANAccess
	updated.KillSwitchPolicy, updated.KillSwitch = validated.KillSwitchPolicy, validated.KillSwitch
	updated.IPv6Mode = validated.IPv6Mode
	updated.MTUPolicy, updated.ManualMTU = validated.MTUPolicy, validated.ManualMTU
	updated.JumboTUN = validated.JumboTUN
	if request.DAITAEnabled != nil {
		updated.DAITAEnabled, updated.DAITARateKbps = validated.DAITAEnabled, validated.DAITARateKbps
	}
	if request.StartupMode != nil {
		updated.StartupMode, updated.AutoConnect = validated.StartupMode, validated.AutoConnect
	}
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != current.ID {
			continue
		}
		a.profiles.Profiles[i] = updated
		err = a.persistProfilesLocked()
		if err != nil {
			a.profiles.Profiles[i] = current
		}
		break
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, "could not save device settings", http.StatusInternalServerError)
		return
	}
	cancelPendingStartupPolicy(a)
	writeProfileDeviceSettings(w, updated, currentEntry)
}
