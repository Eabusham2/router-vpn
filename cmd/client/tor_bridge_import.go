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
	q.Transport = strings.TrimSpace(q.Transport)
	if q.Transport == "" { q.Transport = "obfs4" }
	q.Name = strings.TrimSpace(q.Name)
	if q.Name == "" { q.Name = "Tor " + strings.ReplaceAll(q.Transport, "_", " ") }
	if len(q.Name) > 120 { http.Error(w, "Tor profile name is too long", http.StatusBadRequest); return }
	if len(q.Bridges) < 1 || len(q.Bridges) > 8 {
		http.Error(w, "paste between one and eight Tor bridge lines", http.StatusBadRequest)
		return
	}
	for i := range q.Bridges {
		q.Bridges[i] = strings.TrimSpace(q.Bridges[i])
		if q.Bridges[i] == "" { http.Error(w, "Tor bridge lines cannot be blank", http.StatusBadRequest); return }
	}
	kill := strings.ToLower(strings.TrimSpace(q.KillSwitchPolicy))
	if kill == "" { kill = "off" }
	if kill != "off" && kill != "on-connect" && kill != "always" {
		http.Error(w, "Tor kill switch policy must be off, on-connect, or always", http.StatusBadRequest)
		return
	}

	profile := common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID: strings.TrimSpace(q.ID), Name: q.Name, NodeKind: "external",
		External: &common.ExternalNodeConfig{Protocol: "tor-bridge", TorBridge: &common.ExternalTorBridgeConfig{
			Transport: q.Transport, Bridges: append([]string(nil), q.Bridges...), SocksPort: q.SocksPort,
		}},
		KillSwitchPolicy: kill, IPv6Mode: "on", MTUPolicy: "auto", StartupMode: "manual",
		DNSMode: strings.TrimSpace(q.DNSMode), DNSProtocol: strings.TrimSpace(q.DNSProtocol), DNSHost: strings.TrimSpace(q.DNSHost),
		DNSPort: q.DNSPort, DNSServerName: strings.TrimSpace(q.DNSServerName), DNSPath: strings.TrimSpace(q.DNSPath),
		Location: strings.TrimSpace(q.Location), Latitude: q.Latitude, Longitude: q.Longitude,
	}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		http.Error(w, "invalid Tor bridge profile: "+err.Error(), http.StatusBadRequest)
		return
	}
	body, err := json.Marshal(profile)
	if err != nil { http.Error(w, "could not encode Tor bridge profile", http.StatusInternalServerError); return }
	internal, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://127.0.0.1/api/external-profile/import", bytes.NewReader(body))
	if err != nil { http.Error(w, "could not stage Tor bridge profile", http.StatusInternalServerError); return }
	capture := &captureResponseWriter{}
	a.externalProfileImport(capture, internal)
	status := capture.status
	if status == 0 { status = http.StatusOK }
	if status >= 400 {
		message := strings.TrimSpace(capture.body.String())
		if message == "" { message = http.StatusText(status) }
		http.Error(w, message, status)
		return
	}
	if capture.body.Len() == 0 { http.Error(w, errors.New("Tor bridge importer returned no result").Error(), http.StatusInternalServerError); return }
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(capture.body.Bytes())
}
