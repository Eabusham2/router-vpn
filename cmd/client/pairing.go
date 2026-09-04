package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxPairingBundle = 32 << 20

type pairProfileRequest struct {
	Host string `json:"host"`
	Code string `json:"code"`
}

type captureResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *captureResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *captureResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *captureResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}

func registerPairingRoute(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/profile/pair", a.pairProfileBundle)
	// Node-data routes intentionally share this registration point because all
	// desktop native shells call it exactly once through registerDesktopMultihopRoutes.
	// Router VPN bundle import remains /api/profile/import; external schema-v3
	// profiles use the separate validated path so no WG identity file is faked.
	h.HandleFunc("/api/external-profile/import", a.externalProfileImport)
	registerExternalProfileCreateRoute(h, a)
}

// pairProfileBundle redeems the Setup Center's short-lived LAN code and then
// runs the returned bundle through the exact same hardened import handler used
// by file/manual imports. The client never accepts a public pairing endpoint,
// follows redirects, or trusts a DNS name that resolves partly to public space.
func (a *app) pairProfileBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var q pairProfileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&q); err != nil {
		http.Error(w, "bad pairing request", http.StatusBadRequest)
		return
	}
	host, err := normalizePairingHost(q.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(q.Code)
	if len(code) != 6 {
		http.Error(w, "pairing code must be exactly 6 digits", http.StatusBadRequest)
		return
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			http.Error(w, "pairing code must be exactly 6 digits", http.StatusBadRequest)
			return
		}
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(resolved) == 0 {
		http.Error(w, "pairing host did not resolve on the local network", http.StatusBadRequest)
		return
	}
	for _, candidate := range resolved {
		if !pairingPrivateIP(candidate.IP) {
			http.Error(w, "pairing host resolved outside private/local address space", http.StatusBadRequest)
			return
		}
	}
	pinned := resolved[0].IP.String()

	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(pinned, "8786"))
	}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("pairing redirects are not allowed") }}
	payload, _ := json.Marshal(map[string]string{"code": code})
	endpoint := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, "8786"), Path: "/api/pairing/redeem"}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "could not create pairing request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "LAN pairing failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxPairingBundle+1))
	if readErr != nil {
		http.Error(w, "could not read paired bundle", http.StatusBadGateway)
		return
	}
	if len(body) > maxPairingBundle {
		http.Error(w, "paired bundle is larger than 32 MiB", http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			message = "pairing code is invalid, expired, already used, or the Setup Center rejected the LAN source"
		}
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		http.Error(w, message, resp.StatusCode)
		return
	}

	importReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://127.0.0.1/api/profile/import", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "could not stage paired bundle", http.StatusInternalServerError)
		return
	}
	capture := &captureResponseWriter{}
	a.importProfileBundle(capture, withInternalMutationContext(importReq))
	status := capture.status
	if status == 0 {
		status = http.StatusOK
	}
	if status >= 400 {
		http.Error(w, strings.TrimSpace(capture.body.String()), status)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(capture.body.Bytes())
}

func normalizePairingHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.Trim(host, "/")
	if host == "" || strings.ContainsAny(host, "/?#@") {
		return "", fmt.Errorf("enter only the AI Board LAN IP or hostname")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if strings.Count(host, ":") == 1 {
		return "", fmt.Errorf("do not include a port; Router VPN pairing uses private port 8786")
	}
	return host, nil
}

func pairingPrivateIP(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}
