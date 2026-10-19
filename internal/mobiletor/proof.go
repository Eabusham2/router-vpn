package mobiletor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const ProofURL = "https://check.torproject.org/api/ip"

type Proof struct {
	SessionID string    `json:"session_id"`
	IP        string    `json:"ip"`
	IsTor     bool      `json:"is_tor"`
	CheckedAt time.Time `json:"checked_at"`
}

type DialContext func(context.Context, string, string) (net.Conn, error)

// Prove must receive the captured final outbound's dialer after the real device
// TUN is up. No default transport, environment proxy or static expected-exit IP
// can substitute for the dynamic Tor circuit-exit proof.
func Prove(ctx context.Context, sessionID string, dial DialContext) (Proof, error) {
	if sessionID == "" || len(sessionID) > 512 || strings.ContainsAny(sessionID, "\x00\r\n") || dial == nil {
		return Proof{}, errors.New("dynamic Tor proof requires its frozen VPN session and final outbound")
	}
	transport := &http.Transport{DialContext: dial, DisableKeepAlives: true, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Tor exit proof redirect rejected") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ProofURL, nil)
	if err != nil {
		return Proof{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(req)
	if err != nil {
		return Proof{}, errors.New("dynamic Tor exit proof request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Proof{}, errors.New("dynamic Tor exit proof returned a non-success status")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(data) > 4096 {
		return Proof{}, errors.New("dynamic Tor exit proof response is invalid or oversized")
	}
	address, err := parseProof(data)
	if err != nil {
		return Proof{}, err
	}
	if err := ctx.Err(); err != nil {
		return Proof{}, err
	}
	return Proof{SessionID: sessionID, IP: address, IsTor: true, CheckedAt: time.Now().UTC()}, nil
}

func parseProof(data []byte) (string, error) {
	failure := errors.New("dynamic Tor exit proof did not establish a public Tor exit")
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", failure
	}
	seen := map[string]bool{}
	var isTor bool
	var address string
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return "", failure
		}
		seen[key] = true
		switch key {
		case "IsTor":
			err = decoder.Decode(&isTor)
		case "IP":
			err = decoder.Decode(&address)
		default:
			return "", failure
		}
		if err != nil {
			return "", failure
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return "", failure
	}
	if _, err = decoder.Token(); err != io.EOF {
		return "", failure
	}
	ip := net.ParseIP(address)
	if len(seen) != 2 || !isTor || ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "", failure
	}
	return ip.String(), nil
}
