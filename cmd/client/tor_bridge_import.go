package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

type torBridgeImportRequest struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name,omitempty"`
	Transport        string   `json:"transport,omitempty"`
	Bridges          []string `json:"bridges"`
	SocksPort        int      `json:"socks_port,omitempty"`
	KillSwitchPolicy string   `json:"kill_switch_policy,omitempty"`
	DNSMode          string   `json:"dns_mode,omitempty"`
	DNSProtocol      string   `json:"dns_protocol,omitempty"`
	DNSHost          string   `json:"dns_host,omitempty"`
	DNSPort          int      `json:"dns_port,omitempty"`
	DNSServerName    string   `json:"dns_server_name,omitempty"`
	DNSPath          string   `json:"dns_path,omitempty"`
	Location         string   `json:"location,omitempty"`
	Latitude         float64  `json:"latitude,omitempty"`
	Longitude        float64  `json:"longitude,omitempty"`
}

type torBridgeUpdateIntent struct {
	Name      bool
	Transport bool
	SocksPort bool
	DNS       bool
	Location  bool
}

func torBridgeUpdateIntentFor(q torBridgeImportRequest) torBridgeUpdateIntent {
	return torBridgeUpdateIntent{
		Name:      strings.TrimSpace(q.Name) != "",
		Transport: strings.TrimSpace(q.Transport) != "",
		SocksPort: q.SocksPort != 0,
		DNS: strings.TrimSpace(q.DNSMode) != "" || strings.TrimSpace(q.DNSProtocol) != "" || strings.TrimSpace(q.DNSHost) != "" || q.DNSPort != 0 || strings.TrimSpace(q.DNSServerName) != "" || strings.TrimSpace(q.DNSPath) != "",
		Location: strings.TrimSpace(q.Location) != "" || q.Latitude != 0 || q.Longitude != 0,
	}
}

func (a *app) torBridgeImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q torBridgeImportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&q); err != nil {
		http.Error(w, "invalid Tor bridge form", http.StatusBadRequest)
		return
	}
	updateIntent := torBridgeUpdateIntentFor(q)
	q.Transport = strings.TrimSpace(q.Transport)
	if q.Transport == "" {
		q.Transport = "obfs4"
	}
	q.Name = strings.TrimSpace(q.Name)
	if q.Name == "" {
		q.Name = "Tor " + strings.ReplaceAll(q.Transport, "_", " ")
	}
	if len(q.Name) > 120 || strings.ContainsAny(q.Name, "\r\n\x00") {
		http.Error(w, "Tor profile name is unsafe or too long", http.StatusBadRequest)
		return
	}
	if len(q.Bridges) < 1 || len(q.Bridges) > 8 {
		http.Error(w, "paste between one and eight Tor bridge lines", http.StatusBadRequest)
		return
	}
	for i := range q.Bridges {
		q.Bridges[i] = strings.TrimSpace(q.Bridges[i])
		if q.Bridges[i] == "" {
			http.Error(w, "Tor bridge lines cannot be blank", http.StatusBadRequest)
			return
		}
	}
	requestedKill := strings.ToLower(strings.TrimSpace(q.KillSwitchPolicy))
	if requestedKill != "" && requestedKill != "off" && requestedKill != "on-connect" && requestedKill != "always" {
		http.Error(w, "Tor kill switch policy must be off, on-connect, or always", http.StatusBadRequest)
		return
	}

	profile := common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            strings.TrimSpace(q.ID),
		Name:          q.Name,
		NodeKind:      "external",
		External: &common.ExternalNodeConfig{Protocol: "tor-bridge", TorBridge: &common.ExternalTorBridgeConfig{
			Transport: q.Transport,
			Bridges:   append([]string(nil), q.Bridges...),
			SocksPort: q.SocksPort,
		}},
		KillSwitchPolicy: "off",
		IPv6Mode:         "on",
		MTUPolicy:        "auto",
		StartupMode:      "manual",
		DNSMode:          strings.TrimSpace(q.DNSMode),
		DNSProtocol:      strings.TrimSpace(q.DNSProtocol),
		DNSHost:          strings.TrimSpace(q.DNSHost),
		DNSPort:          q.DNSPort,
		DNSServerName:    strings.TrimSpace(q.DNSServerName),
		DNSPath:          strings.TrimSpace(q.DNSPath),
		Location:         strings.TrimSpace(q.Location),
		Latitude:         q.Latitude,
		Longitude:        q.Longitude,
	}
	if profile.DNSMode == "" {
		profile.DNSMode = "rescue"
		profile.DNSProtocol = "https"
		profile.DNSHost = "1.1.1.1"
		profile.DNSPort = 443
		profile.DNSServerName = "cloudflare-dns.com"
		profile.DNSPath = "/dns-query"
	}
	// Normalize with kill switch disabled first so the canonical PT parser can
	// decide whether this graph owns one exact literal obfs4 bootstrap endpoint.
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		http.Error(w, "invalid Tor bridge profile: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := profile.External.TorBridge
	strictLiteralObfs4 := cfg != nil && cfg.Transport == "obfs4" && len(cfg.Bridges) == 1
	if requestedKill == "" {
		if strictLiteralObfs4 {
			requestedKill = "on-connect"
		} else {
			requestedKill = "off"
		}
	}
	if requestedKill != "off" && !strictLiteralObfs4 {
		http.Error(w, "meek/Snowflake/WebTunnel/custom or multi-bridge Tor profiles require kill_switch_policy=off until their dynamic bootstrap egress can be scoped safely", http.StatusBadRequest)
		return
	}
	profile.KillSwitchPolicy = requestedKill
	profile.KillSwitch = requestedKill != "off"
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		http.Error(w, "invalid Tor bridge profile: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Re-run both dataplane translation and policy validation before the private
	// store is touched. This prevents a saved node from looking ready when its
	// DNS/kill-switch/runtime policy would fail only at Connect time.
	if _, err := standardExitFromExternalProfile(profile); err != nil {
		http.Error(w, "Tor bridge profile is not runnable: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := externalRuntimePolicy(profile); err != nil {
		http.Error(w, "Tor bridge policy is not runnable: "+err.Error(), http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(profile.ID) != "" {
		handled, err := a.updateExistingTorBridgeProfile(r, &profile, updateIntent)
		if err != nil {
			status := http.StatusConflict
			if errors.Is(err, errInvalidTorBridgeUpdateID) {
				status = http.StatusBadRequest
			}
			http.Error(w, err.Error(), status)
			return
		}
		if handled {
			w.Header().Set("content-type", "application/json")
			w.Header().Set("cache-control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "updated": true, "profile": publicProfileFor(profile)})
			return
		}
	}

	body, err := json.Marshal(profile)
	if err != nil {
		http.Error(w, "could not encode Tor bridge profile", http.StatusInternalServerError)
		return
	}
	internal, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://127.0.0.1/api/external-profile/import", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "could not stage Tor bridge profile", http.StatusInternalServerError)
		return
	}
	capture := &captureResponseWriter{}
	a.externalProfileImport(capture, internal)
	status := capture.status
	if status == 0 {
		status = http.StatusOK
	}
	if status >= 400 {
		message := strings.TrimSpace(capture.body.String())
		if message == "" {
			message = http.StatusText(status)
		}
		http.Error(w, message, status)
		return
	}
	if capture.body.Len() == 0 {
		http.Error(w, errors.New("Tor bridge importer returned no result").Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(capture.body.Bytes())
}

var errInvalidTorBridgeUpdateID = errors.New("Tor bridge update requires a valid profile id")

func preserveTorBridgeEditSettings(existing common.RouterProfile, next common.RouterProfile, intent torBridgeUpdateIntent) common.RouterProfile {
	if !intent.Name {
		next.Name = existing.Name
	}
	if next.External != nil && next.External.TorBridge != nil && existing.External != nil && existing.External.TorBridge != nil {
		if !intent.Transport {
			next.External.TorBridge.Transport = existing.External.TorBridge.Transport
		}
		if !intent.SocksPort {
			next.External.TorBridge.SocksPort = existing.External.TorBridge.SocksPort
		}
	}
	if !intent.DNS {
		next.DNSMode = existing.DNSMode
		next.DNSProtocol = existing.DNSProtocol
		next.DNSHost = existing.DNSHost
		next.DNSPort = existing.DNSPort
		next.DNSServerName = existing.DNSServerName
		next.DNSPath = existing.DNSPath
	}
	if !intent.Location {
		next.Location = existing.Location
		next.Latitude = existing.Latitude
		next.Longitude = existing.Longitude
	}
	// These are ordinary user preferences outside the Tor bridge/PT form. A
	// bridge edit must not silently reset them to builder defaults.
	next.HomeLANAccess = existing.HomeLANAccess
	next.HomeLANCIDRs = append([]string(nil), existing.HomeLANCIDRs...)
	next.IPv6Mode = existing.IPv6Mode
	next.StartupMode = existing.StartupMode
	next.AutoConnect = existing.AutoConnect
	next.AutoRequireEncrypted = existing.AutoRequireEncrypted
	next.AutoRequireObfuscation = existing.AutoRequireObfuscation
	next.DAITAEnabled = existing.DAITAEnabled
	next.JumboTUN = existing.JumboTUN
	next.SocksEnabled = existing.SocksEnabled
	next.MTUPolicy = existing.MTUPolicy
	next.ManualMTU = existing.ManualMTU
	next.DiagnosticsEnabled = existing.DiagnosticsEnabled
	next.DiagnosticsRetentionDays = existing.DiagnosticsRetentionDays
	next.ShareDiagnostics = existing.ShareDiagnostics
	next.TelemetryEnabled = existing.TelemetryEnabled
	next.PathProbeURL = existing.PathProbeURL
	return next
}

// updateExistingTorBridgeProfile handles only an explicit update of an already
// stored Tor node. The generic external importer remains append-only: it must
// never silently replace another external node merely because an ID collided.
// A safe ID that is not present returns handled=false so the historical import
// behavior (create while retaining that stable ID) is preserved.
func (a *app) updateExistingTorBridgeProfile(r *http.Request, profile *common.RouterProfile, intent torBridgeUpdateIntent) (bool, error) {
	if profile == nil {
		return false, errInvalidTorBridgeUpdateID
	}
	profile.ID = strings.TrimSpace(profile.ID)
	if !validProfileID(profile.ID) {
		return false, errInvalidTorBridgeUpdateID
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		return false, guardErr
	}
	defer release()

	a.mu.Lock()
	defer a.mu.Unlock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		return false, errors.New("disconnect before updating a Tor bridge node")
	}
	index := -1
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == profile.ID {
			index = i
			break
		}
	}
	if index < 0 {
		return false, nil
	}
	existing := a.profiles.Profiles[index]
	if existing.NodeKind != "external" || existing.External == nil || strings.ToLower(strings.TrimSpace(existing.External.Protocol)) != "tor-bridge" {
		return false, errors.New("profile id belongs to a non-Tor node; refusing replacement")
	}

	merged := preserveTorBridgeEditSettings(existing, *profile, intent)
	if err := common.NormalizeRouterProfile(&merged); err != nil {
		return false, errors.New("updated Tor bridge profile is invalid: " + err.Error())
	}
	if _, err := standardExitFromExternalProfile(merged); err != nil {
		return false, errors.New("updated Tor bridge profile is not runnable: " + err.Error())
	}
	policy, err := externalRuntimePolicy(merged)
	if err != nil {
		return false, errors.New("updated Tor bridge policy is not runnable: " + err.Error())
	}
	merged = policy

	previousStore := cloneRouterProfileStore(a.profiles)
	// Usage metadata describes this stable node identity and is safe to retain.
	// Public exit, durable latency/DNS benchmarks, and effective-MTU measurement
	// deliberately stay cleared: changing bridge/PT policy invalidates them.
	merged.UseCount = existing.UseCount
	merged.LastUsedAt = existing.LastUsedAt
	a.profiles.Profiles[index] = merged
	if err := a.persistProfilesLocked(); err != nil {
		a.rollbackProfilesLocked(previousStore)
		return false, err
	}
	*profile = merged
	return true, nil
}
