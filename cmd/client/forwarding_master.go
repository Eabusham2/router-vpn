package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const desktopForwardingMasterPath = "/api/forwarding/master"
const desktopForwardingMasterMaxResponse = 64 * 1024

type desktopForwardingMasterReply struct {
	OK      bool   `json:"ok"`
	Enabled bool   `json:"enabled"`
	Peer    string `json:"peer,omitempty"`
	Proof   string `json:"proof,omitempty"`
}

func registerForwardingMasterRoute(h *http.ServeMux, a *app) {
	h.HandleFunc(desktopForwardingMasterPath, a.forwardingMaster)
}

func (a *app) forwardingMaster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
		return
	}

	release, guardErr := a.beginNodeBoundOperation()
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()

	profile, st, err := activeLatencyTarget(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if !st.Connected || strings.EqualFold(strings.TrimSpace(profile.NodeKind), "external") || profile.External != nil {
		http.Error(w, "connect a Router VPN home-node path before changing forwarding master", http.StatusConflict)
		return
	}
	base, err := validatedPrivateRouterAPI(profile.RouterAPI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	token := strings.TrimSpace(profile.APIToken)
	if token == "" {
		http.Error(w, "active Router VPN node has no private router-agent token", http.StatusConflict)
		return
	}

	var requested *bool
	if r.Method == http.MethodPut {
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil || body.Enabled == nil {
			http.Error(w, "body must be {\"enabled\":true|false}", http.StatusBadRequest)
			return
		}
		requested = body.Enabled
	}

	method := http.MethodGet
	var payload io.Reader
	if requested != nil {
		method = http.MethodPut
		raw, _ := json.Marshal(map[string]bool{"enabled": *requested})
		payload = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(r.Context(), method, base+desktopForwardingMasterPath, payload)
	if err != nil {
		http.Error(w, "could not create forwarding-master request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if requested != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("forwarding-master redirects are not allowed")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "active private router-agent forwarding request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, desktopForwardingMasterMaxResponse+1))
	if err != nil || len(body) > desktopForwardingMasterMaxResponse {
		http.Error(w, "forwarding-master response is invalid", http.StatusBadGateway)
		return
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 512 {
			msg = msg[:512]
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		http.Error(w, fmt.Sprintf("private router-agent returned HTTP %d: %s", resp.StatusCode, msg), http.StatusBadGateway)
		return
	}
	var remote desktopForwardingMasterReply
	if err := json.Unmarshal(body, &remote); err != nil || !remote.OK {
		http.Error(w, "forwarding-master response could not be verified", http.StatusBadGateway)
		return
	}
	if requested != nil && remote.Enabled != *requested {
		http.Error(w, "forwarding master did not reach the requested state", http.StatusBadGateway)
		return
	}

	// Re-check that the active graph did not change while the mutation was in flight.
	after, afterState, err := activeLatencyTarget(a)
	if err != nil || !afterState.Connected || after.ID != profile.ID || afterState.Mode != st.Mode || afterState.RuntimeMode != st.RuntimeMode || afterState.Base != st.Base {
		http.Error(w, "active Router VPN graph changed while forwarding master was being verified", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"enabled":   remote.Enabled,
		"router_id": profile.ID,
		"name":      profile.Name,
		"proof":     "active desktop Router VPN graph -> authenticated private router-agent forwarding master; Setup Center admin token remains server-side",
	})
}

func validatedPrivateRouterAPI(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("active Router VPN node has no private router API")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("active Router VPN private router API is invalid")
	}
	host := strings.TrimSpace(u.Hostname())
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return "", errors.New("active Router VPN router API must be a literal private/local IP")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("active Router VPN router API must not contain a path")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
