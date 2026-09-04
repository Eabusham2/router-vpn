package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"router-vpn/internal/common"
)

// externalProfileCreateRequest is the native-UI-safe creation surface for the
// common external node families. It deliberately does not expose executable
// paths, arbitrary sing-box JSON, torrc directives, or OpenVPN text. Those
// richer imports keep their dedicated hardened import paths.
type externalProfileCreateRequest struct {
	Name             string   `json:"name"`
	Protocol         string   `json:"protocol"`
	ExpectedPublicIP string   `json:"expected_public_ip"`
	Server           string   `json:"server"`
	Port             int      `json:"port"`
	Username         string   `json:"username,omitempty"`
	Password         string   `json:"password,omitempty"`
	Method           string   `json:"method,omitempty"`
	Secret           string   `json:"secret,omitempty"`
	TLSServerName    string   `json:"tls_server_name,omitempty"`
	WGPrivateKey     string   `json:"wg_private_key,omitempty"`
	WGAddresses      []string `json:"wg_addresses,omitempty"`
	WGPeerPublicKey  string   `json:"wg_peer_public_key,omitempty"`
	WGPresharedKey   string   `json:"wg_preshared_key,omitempty"`
	WGAllowedIPs     []string `json:"wg_allowed_ips,omitempty"`
	WGDNS            []string `json:"wg_dns,omitempty"`
	WGMTU            int      `json:"wg_mtu,omitempty"`
}

func externalProfileFromCreateRequest(q externalProfileCreateRequest) (common.RouterProfile, error) {
	q.Name = strings.TrimSpace(q.Name)
	if q.Name == "" {
		q.Name = "Custom Node"
	}
	if len(q.Name) > 120 || strings.ContainsAny(q.Name, "\r\n\x00") {
		return common.RouterProfile{}, errors.New("external node name is unsafe or too long")
	}
	protocol := normalizeStandardExitProtocol(q.Protocol)
	p := common.RouterProfile{
		ID:       newID(),
		Name:     q.Name,
		NodeKind: "external",
		External: &common.ExternalNodeConfig{Protocol: protocol, ExpectedPublicIP: strings.TrimSpace(q.ExpectedPublicIP)},
	}

	// The typed maker promises that a saved profile is runnable, not merely
	// syntactically representable. Normalize the server before persistence using
	// the same direct-IP/hostname contract used by the standard-exit runtime.
	// This rejects URL/path/query/userinfo/whitespace injection early instead of
	// storing a node that will only fail later at Connect.
	var host string
	if protocol != "openvpn" && protocol != "tor-bridge" {
		var err error
		host, err = normalizeEndpoint(q.Server)
		if err != nil {
			return common.RouterProfile{}, errors.New(protocol + " node server: " + err.Error())
		}
	}

	switch protocol {
	case "wireguard":
		if q.Port < 1 || q.Port > 65535 {
			return common.RouterProfile{}, errors.New("WireGuard node requires a valid port")
		}
		p.External.WireGuard = &common.ExternalWireGuardConfig{
			PrivateKey:    q.WGPrivateKey,
			Addresses:     append([]string(nil), q.WGAddresses...),
			PeerPublicKey: q.WGPeerPublicKey,
			PresharedKey:  q.WGPresharedKey,
			Endpoint:      net.JoinHostPort(host, strconv.Itoa(q.Port)),
			AllowedIPs:    append([]string(nil), q.WGAllowedIPs...),
			DNS:           append([]string(nil), q.WGDNS...),
			MTU:           q.WGMTU,
		}
	case "socks5":
		p.External.SOCKS5 = &common.ExternalSOCKS5Config{Host: host, Port: q.Port, Username: q.Username, Password: q.Password}
	case "http-connect":
		if strings.TrimSpace(q.TLSServerName) != "" {
			return common.RouterProfile{}, errors.New("plain HTTP CONNECT cannot specify a TLS server name; choose https-connect instead")
		}
		p.External.HTTPConnect = &common.ExternalHTTPConnectConfig{Host: host, Port: q.Port, Username: q.Username, Password: q.Password}
	case "https-connect":
		p.External.HTTPSConnect = &common.ExternalHTTPConnectConfig{Host: host, Port: q.Port, Username: q.Username, Password: q.Password, TLSServerName: q.TLSServerName}
	case "shadowsocks":
		p.External.Shadowsocks = &common.ExternalShadowsocksConfig{Server: host, Port: q.Port, Method: q.Method, Password: q.Secret}
	case "hysteria2":
		p.External.Hysteria2 = &common.ExternalHysteria2Config{Server: host, Port: q.Port, Password: q.Secret, TLSServerName: q.TLSServerName}
	case "openvpn":
		return common.RouterProfile{}, errors.New("OpenVPN uses the hardened config import path; the typed node maker does not accept raw OpenVPN text")
	case "tor-bridge":
		return common.RouterProfile{}, errors.New("Tor bridges use the dedicated censorship-circumvention builder")
	default:
		return common.RouterProfile{}, errors.New("unsupported external node protocol")
	}
	if err := common.NormalizeRouterProfile(&p); err != nil {
		return common.RouterProfile{}, err
	}
	return p, nil
}

func registerExternalProfileCreateRoute(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/external-profile/create", a.externalProfileCreate)
}

func (a *app) externalProfileCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	release, err := a.beginMutationOperation(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer release()
	var q externalProfileCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&q); err != nil {
		http.Error(w, "bad external node request", http.StatusBadRequest)
		return
	}
	p, err := externalProfileFromCreateRequest(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	previousStore := cloneRouterProfileStore(a.profiles)
	previousState := a.state
	a.profiles.Profiles = append(a.profiles.Profiles, p)
	a.profiles.SelectedID = p.ID
	a.state.RouterID = p.ID
	err = a.persistProfilesLocked()
	if err != nil {
		a.rollbackProfilesLocked(previousStore)
		a.state = previousState
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": publicProfileFor(p)})
}
