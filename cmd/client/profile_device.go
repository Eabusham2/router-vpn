package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// Imported nodes share device policy without acquiring the Router-only base,
// Start Layer, forwarding or padding fields from a disabled settings form.
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
	if profile.External.Protocol == "tor-bridge" {
		// The native Tor owner now applies these device settings. It does not
		// yet own a Router predecessor, Jumbo selection or padding runtime.
		// Keep those saved requests intact and expose the specific missing path.
		switch {
		case profile.MultihopEnabled:
			return false, "Tor common device settings for Router-entry graphs require the captured desktop predecessor runtime, which is not yet implemented."
		case profile.JumboTUN:
			return false, "Tor common device settings cannot discard saved Jumbo mode; its desktop runtime is not yet implemented."
		case profile.DAITAEnabled:
			return false, "Tor common device settings cannot discard saved padding; its desktop runtime is not yet implemented."
		default:
			return true, ""
		}
	}
	return false, "This external protocol does not yet apply the common device settings through an owned native desktop runtime."
}

func writeProfileDeviceSettings(w http.ResponseWriter, profile, entry common.RouterProfile) {
	protocol := ""
	if profile.External != nil {
		protocol = profile.External.Protocol
	}
	supported, reason := externalDevicePolicySupport(profile)
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
	if protocol == "tor-bridge" {
		note = "Save while disconnected. Tor Auto and Default currently use a 1280-byte virtual interface; Fixed changes the interface value only. Interface readback and historical MTU are not fresh path measurements. Tor MTU optimization and Retest are not yet implemented. DNS, credentials and graph selection are preserved."
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(profileDeviceSettings{
		ProfileID: profile.ID, ProfileToken: profileDeviceSettingsToken(profile, entry),
		NodeKind: profile.NodeKind, Protocol: protocol,
		DevicePolicySupported: supported, DevicePolicyReason: reason,
		HomeLANAccess: profile.HomeLANAccess, KillSwitchPolicy: kill,
		IPv6Mode: ipv6, MTUPolicy: mtu, ManualMTU: manual,
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
	if profile.External.Protocol == "tor-bridge" {
		// Pass the exact runtime preferences and private owners to the shipping
		// Tor parser. Idle Home may remain unresolved; this never grants a
		// runnable resolver, modifies bridge credentials, or reuses MTU history.
		// Display/measurement floats are deliberately outside this projection.
		type wireProfile common.RouterProfile
		captured := common.RouterProfile{
			ID: profile.ID, NodeKind: profile.NodeKind, External: profile.External,
			NodeProofID: profile.NodeProofID, RouterAPI: profile.RouterAPI, APIToken: profile.APIToken,
			StartLayer: profile.StartLayer, HomeLANAccess: profile.HomeLANAccess, HomeLANCIDRs: profile.HomeLANCIDRs,
			KillSwitch: profile.KillSwitch, KillSwitchPolicy: profile.KillSwitchPolicy, IPv6Mode: profile.IPv6Mode,
			MTUPolicy: profile.MTUPolicy, ManualMTU: profile.ManualMTU,
			DNSMode: profile.DNSMode, DNSProtocol: profile.DNSProtocol, DNSHost: profile.DNSHost,
			DNSPort: profile.DNSPort, DNSServerName: profile.DNSServerName, DNSPath: profile.DNSPath,
		}
		source, err := json.Marshal(wireProfile(captured))
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
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
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
	if supported, reason := externalDevicePolicySupport(profile); !supported {
		http.Error(w, reason, http.StatusUnprocessableEntity)
		return
	}
	validated, err := applyProfileDeviceSettings(profile, request)
	if err != nil {
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
