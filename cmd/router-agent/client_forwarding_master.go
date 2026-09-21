package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const clientForwardingMasterPath = "/api/forwarding/master"
const clientForwardingMasterMaxResponse = 64 * 1024

// registerClientForwardingMasterRoute exposes one narrowly scoped server-owned
// control to authenticated tunnel peers. The Setup Center admin token never
// crosses the router-agent boundary and no generic admin proxy is exposed.
func registerClientForwardingMasterRoute(h *http.ServeMux, s *server) {
	h.HandleFunc(clientForwardingMasterPath, s.clientForwardingMaster)
}

func validatedAdminMutationBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultAdminMutationListen
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", errors.New("admin mutation address is invalid")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("admin mutation address must remain loopback-only")
	}
	if port == "" {
		return "", errors.New("admin mutation port is missing")
	}
	return "http://" + net.JoinHostPort(ip.String(), port), nil
}

func loadAdminMutationToken() (string, error) {
	path := getenv("ROUTER_VPN_ADMIN_TOKEN_FILE", "/etc/router-vpn/setup-center.token")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if len(token) < 32 {
		return "", errors.New("admin mutation token is unavailable")
	}
	return token, nil
}

func (s *server) clientForwardingMaster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
		return
	}
	peer, err := s.authorized(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var requested *bool
	if r.Method == http.MethodPut {
		value, err := decodeForwardingMasterRequest(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			http.Error(w, "body must be exactly {\"enabled\":true|false}", http.StatusBadRequest)
			return
		}
		requested = &value
	}

	base, err := validatedAdminMutationBase(getenv("ROUTER_VPN_ADMIN_MUTATION_LISTEN", defaultAdminMutationListen))
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	adminToken, err := loadAdminMutationToken()
	if err != nil {
		http.Error(w, "forwarding administration is unavailable", http.StatusServiceUnavailable)
		return
	}
	endpoint, err := url.Parse(base + "/api/admin/settings")
	if err != nil || endpoint.Scheme != "http" {
		http.Error(w, "forwarding administration target is invalid", http.StatusServiceUnavailable)
		return
	}

	method := http.MethodGet
	var payload io.Reader
	if requested != nil {
		method = http.MethodPut
		body, _ := json.Marshal(map[string]bool{"forwarding_master": *requested})
		payload = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(r.Context(), method, endpoint.String(), payload)
	if err != nil {
		http.Error(w, "forwarding administration request failed", http.StatusServiceUnavailable)
		return
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	request.Header.Set("Accept", "application/json")
	if requested != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   4 * time.Second,
		Transport: transport,
		// A redirect must never turn this narrowly scoped loopback operation
		// into an arbitrary request carrying the Setup Center admin token.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		http.Error(w, "forwarding administration is unavailable", http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, clientForwardingMasterMaxResponse+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) > clientForwardingMasterMaxResponse {
		http.Error(w, "forwarding administration response is invalid", http.StatusBadGateway)
		return
	}
	if response.StatusCode/100 != 2 {
		http.Error(w, fmt.Sprintf("forwarding administration returned HTTP %d", response.StatusCode), http.StatusBadGateway)
		return
	}
	var admin struct {
		OK       bool `json:"ok"`
		Settings struct {
			ForwardingMaster *bool `json:"forwarding_master"`
		} `json:"settings"`
	}
	if json.Unmarshal(body, &admin) != nil || !admin.OK || admin.Settings.ForwardingMaster == nil {
		http.Error(w, "forwarding administration response could not be verified", http.StatusBadGateway)
		return
	}
	if requested != nil && subtle.ConstantTimeByteEq(boolByte(*admin.Settings.ForwardingMaster), boolByte(*requested)) != 1 {
		http.Error(w, "forwarding master did not reach the requested state", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"enabled": *admin.Settings.ForwardingMaster,
		"peer":    peer.String(),
		"proof":   "authenticated tunnel-peer request proxied server-side to loopback forwarding policy",
	})
}

// Decode exactly one boolean member. Decoding straight into a struct accepts
// duplicate keys and an unread second JSON value, neither of which is a
// verifiable master-control command. Consume EOF before any admin mutation.
func decodeForwardingMasterRequest(body io.Reader) (bool, error) {
	dec := json.NewDecoder(body)
	invalid := errors.New("invalid forwarding master command")
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return false, invalid
	}
	if token, err := dec.Token(); err != nil || token != "enabled" {
		return false, invalid
	}
	var enabled *bool
	if err := dec.Decode(&enabled); err != nil || enabled == nil {
		return false, invalid
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return false, invalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return false, invalid
	}
	return *enabled, nil
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}
