package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

type profileSettingsRequest struct {
	HomeLANAccess    *bool   `json:"home_lan_access,omitempty"`
	KillSwitchPolicy *string `json:"kill_switch_policy,omitempty"`
	IPv6Mode         *string `json:"ipv6_mode,omitempty"`
	StartupMode      *string `json:"startup_mode,omitempty"`
	AutoConnect      *bool   `json:"auto_connect,omitempty"`
	BaseTunnel       *string `json:"base_tunnel,omitempty"`
	BaseFallback     *bool   `json:"base_fallback,omitempty"`
	MTUPolicy        *string `json:"mtu_policy,omitempty"`
	ManualMTU        *int    `json:"manual_mtu,omitempty"`
	DAITAEnabled     *bool   `json:"daita_enabled,omitempty"`
	JumboTUN         *bool   `json:"jumbo_tun,omitempty"`
	SocksEnabled     *bool   `json:"socks_enabled,omitempty"`
}

type profileSettingsResponse struct {
	HomeLANAccess     bool   `json:"home_lan_access"`
	KillSwitchPolicy  string `json:"kill_switch_policy"`
	IPv6Mode          string `json:"ipv6_mode"`
	StartupMode       string `json:"startup_mode"`
	AutoConnect       bool   `json:"auto_connect"`
	BaseTunnel        string `json:"base_tunnel"`
	BaseFallback      bool   `json:"base_fallback"`
	MTUPolicy         string `json:"mtu_policy"`
	ManualMTU         int    `json:"manual_mtu,omitempty"`
	EffectiveMTU      int    `json:"effective_mtu,omitempty"`
	EffectiveMTUSource string `json:"effective_mtu_source,omitempty"`
	DAITAEnabled      bool   `json:"daita_enabled"`
	JumboTUN          bool   `json:"jumbo_tun"`
	SocksEnabled      bool   `json:"socks_enabled"`
	Note              string `json:"note"`
}

func registerProfileSettingsRoute(h *http.ServeMux, a *app) {
	a.mu.Lock()
	if p, ok := a.profileByIDLocked(a.profiles.SelectedID); ok && !a.state.Connected {
		a.syncProfileOptionStateLocked(p)
	}
	a.mu.Unlock()
	h.HandleFunc("/api/profile/settings", a.profileSettings)
}

func (a *app) syncProfileOptionStateLocked(p common.RouterProfile) {
	a.state.DAITA = p.DAITAEnabled
	a.state.Jumbo = p.JumboTUN
	a.state.Socks = p.SocksEnabled
}

func (a *app) profileSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	selected := a.profiles.SelectedID
	profile, ok := a.profileByIDLocked(selected)
	busy := a.state.Connected || a.state.Phase == "starting" || a.state.Phase == "checking" || strings.HasPrefix(a.state.Phase, "auto:")
	if ok && !busy { a.syncProfileOptionStateLocked(profile) }
	a.mu.Unlock()
	if !ok {
		http.Error(w, "add and select your home router first", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(strings.TrimSpace(profile.NodeKind), "external") || profile.External != nil {
		http.Error(w, "Router VPN profile settings apply only to Router VPN home nodes; external exits own their protocol settings", http.StatusConflict)
		return
	}
	if r.Method == http.MethodGet {
		writeProfileSettings(w, profile)
		return
	}
	if busy {
		http.Error(w, "disconnect before changing Router VPN profile settings so the next tunnel starts from one coherent policy", http.StatusConflict)
		return
	}
	var request profileSettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	updated, err := applyProfileSettings(profile, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if a.state.Connected || a.state.Phase == "starting" || a.state.Phase == "checking" || strings.HasPrefix(a.state.Phase, "auto:") {
		a.mu.Unlock()
		http.Error(w, "disconnect before changing Router VPN profile settings", http.StatusConflict)
		return
	}
	found := false
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == selected {
			a.profiles.Profiles[i] = updated
			found = true
			break
		}
	}
	if !found {
		a.mu.Unlock()
		http.Error(w, "selected router disappeared", http.StatusConflict)
		return
	}
	a.syncProfileOptionStateLocked(updated)
	err = a.persistProfilesLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeProfileSettings(w, updated)
}

func applyProfileSettings(profile common.RouterProfile, q profileSettingsRequest) (common.RouterProfile, error) {
	updated := profile
	if q.HomeLANAccess != nil { updated.HomeLANAccess = *q.HomeLANAccess }
	if q.KillSwitchPolicy != nil { updated.KillSwitchPolicy = strings.ToLower(strings.TrimSpace(*q.KillSwitchPolicy)); updated.KillSwitch = updated.KillSwitchPolicy != "off" }
	if q.IPv6Mode != nil { updated.IPv6Mode = strings.ToLower(strings.TrimSpace(*q.IPv6Mode)) }
	if q.StartupMode != nil { updated.StartupMode = strings.ToLower(strings.TrimSpace(*q.StartupMode)) }
	if q.AutoConnect != nil { updated.AutoConnect = *q.AutoConnect }
	if q.BaseTunnel != nil {
		value := strings.ToLower(strings.TrimSpace(*q.BaseTunnel))
		switch value { case "auto", "wg", "awg": updated.BaseTunnel = value; default: return profile, errors.New("base_tunnel must be auto, wg, or awg") }
	}
	if q.BaseFallback != nil { updated.BaseFallback = *q.BaseFallback }
	if q.MTUPolicy != nil { updated.MTUPolicy = strings.ToLower(strings.TrimSpace(*q.MTUPolicy)) }
	if q.ManualMTU != nil { updated.ManualMTU = *q.ManualMTU }
	if q.DAITAEnabled != nil { updated.DAITAEnabled = *q.DAITAEnabled }
	if q.JumboTUN != nil { updated.JumboTUN = *q.JumboTUN }
	if q.SocksEnabled != nil { updated.SocksEnabled = *q.SocksEnabled }
	if err := common.NormalizeRouterProfile(&updated); err != nil { return profile, err }
	return updated, nil
}

func writeProfileSettings(w http.ResponseWriter, p common.RouterProfile) {
	response := profileSettingsResponse{
		HomeLANAccess: p.HomeLANAccess, KillSwitchPolicy: p.KillSwitchPolicy,
		IPv6Mode: p.IPv6Mode, StartupMode: p.StartupMode, AutoConnect: p.AutoConnect,
		BaseTunnel: p.BaseTunnel, BaseFallback: p.BaseFallback,
		MTUPolicy: p.MTUPolicy, ManualMTU: p.ManualMTU,
		EffectiveMTU: p.EffectiveMTU, EffectiveMTUSource: p.EffectiveMTUSource,
		DAITAEnabled: p.DAITAEnabled, JumboTUN: p.JumboTUN, SocksEnabled: p.SocksEnabled,
		Note: "Settings are stored only on the selected Router VPN profile. Disconnect before editing; saved settings apply on the next tunnel start and are not runtime proof by themselves.",
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}
