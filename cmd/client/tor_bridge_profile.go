package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

type torBridgeProfileCreateRequest struct {
	Name             string   `json:"name"`
	Transport        string   `json:"transport"`
	Bridges          []string `json:"bridges"`
	SocksPort        int      `json:"socks_port,omitempty"`
	KillSwitchPolicy string   `json:"kill_switch_policy,omitempty"`
	DNSMode          string   `json:"dns_mode,omitempty"`
	DNSProtocol      string   `json:"dns_protocol,omitempty"`
	DNSHost          string   `json:"dns_host,omitempty"`
	DNSPort          int      `json:"dns_port,omitempty"`
	DNSServerName    string   `json:"dns_server_name,omitempty"`
	DNSPath          string   `json:"dns_path,omitempty"`
}

func safeTorProfileName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("Tor bridge profile name is required")
	}
	if len(value) > 96 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("Tor bridge profile name is oversized or contains a control character")
	}
	return value, nil
}

func torBridgeProfileFromCreate(q torBridgeProfileCreateRequest) (common.RouterProfile, string, error) {
	name, err := safeTorProfileName(q.Name)
	if err != nil {
		return common.RouterProfile{}, "", err
	}
	profile := common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            newID(),
		Name:          name,
		NodeKind:      "external",
		StartupMode:   "manual",
		IPv6Mode:      "on",
		MTUPolicy:     "auto",
		DNSMode:       strings.TrimSpace(q.DNSMode),
		DNSProtocol:   strings.TrimSpace(q.DNSProtocol),
		DNSHost:       strings.TrimSpace(q.DNSHost),
		DNSPort:       q.DNSPort,
		DNSServerName: strings.TrimSpace(q.DNSServerName),
		DNSPath:       strings.TrimSpace(q.DNSPath),
		External: &common.ExternalNodeConfig{
			Protocol: "tor-bridge",
			TorBridge: &common.ExternalTorBridgeConfig{
				Transport: strings.TrimSpace(q.Transport),
				Bridges:   append([]string(nil), q.Bridges...),
				SocksPort: q.SocksPort,
			},
		},
	}
	if profile.DNSMode == "" {
		profile.DNSMode = "rescue"
		profile.DNSProtocol = "https"
		profile.DNSHost = "1.1.1.1"
		profile.DNSPort = 443
		profile.DNSServerName = "cloudflare-dns.com"
		profile.DNSPath = "/dns-query"
	}
	// First normalize the bridge set with kill switch disabled so the builder
	// can decide whether the selected PT graph has one exact pre-tunnel endpoint.
	profile.KillSwitchPolicy = "off"
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		return common.RouterProfile{}, "", err
	}
	cfg := profile.External.TorBridge
	strictLiteralObfs4 := cfg != nil && cfg.Transport == "obfs4" && len(cfg.Bridges) == 1
	requestedPolicy := strings.ToLower(strings.TrimSpace(q.KillSwitchPolicy))
	if requestedPolicy == "" {
		if strictLiteralObfs4 {
			requestedPolicy = "on-connect"
		} else {
			requestedPolicy = "off"
		}
	}
	if requestedPolicy != "off" && !strictLiteralObfs4 {
		return common.RouterProfile{}, "", errors.New("meek/Snowflake/WebTunnel/custom or multi-bridge Tor profiles require kill_switch_policy=off until their dynamic bootstrap egress can be scoped safely")
	}
	profile.KillSwitchPolicy = requestedPolicy
	profile.KillSwitch = requestedPolicy != "off"
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		return common.RouterProfile{}, "", err
	}
	if _, err := standardExitFromExternalProfile(profile); err != nil {
		return common.RouterProfile{}, "", err
	}
	if _, err := externalRuntimePolicy(profile); err != nil {
		return common.RouterProfile{}, "", err
	}
	warning := ""
	if !strictLiteralObfs4 {
		warning = "This Tor circumvention profile uses dynamic or multiple bootstrap endpoints, so strict pre-tunnel kill switch is unavailable and the profile is stored with Kill Switch Off."
	}
	return profile, warning, nil
}

func (a *app) torBridgeProfileCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q torBridgeProfileCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&q); err != nil {
		http.Error(w, "invalid Tor bridge profile request", http.StatusBadRequest)
		return
	}
	profile, warning, err := torBridgeProfileFromCreate(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()

	a.mu.Lock()
	defer a.mu.Unlock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		http.Error(w, "disconnect before adding a Tor bridge profile", http.StatusConflict)
		return
	}
	previousStore := cloneRouterProfileStore(a.profiles)
	previousRouterID := a.state.RouterID
	a.profiles.Profiles = append(a.profiles.Profiles, profile)
	a.profiles.SelectedID = profile.ID
	a.state.RouterID = profile.ID
	if err := a.persistProfilesLocked(); err != nil {
		a.rollbackProfilesLocked(previousStore)
		a.state.RouterID = previousRouterID
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"profile": publicProfileFor(profile),
		"warning": warning,
	})
}
