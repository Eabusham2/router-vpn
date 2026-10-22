package mobiletor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ProofURL = "https://check.torproject.org/api/ip"

type Proof struct {
	SessionID string    `json:"session_id"`
	IP        string    `json:"ip"`
	IsTor     bool      `json:"is_tor"`
	DNSProven bool      `json:"dns_proven,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

type DialContext func(context.Context, string, string) (net.Conn, error)

// Prove must receive the captured final outbound's dialer after the real device
// TUN is up. No default transport, environment proxy or static expected-exit IP
// can substitute for the dynamic Tor circuit-exit proof.
func Prove(ctx context.Context, sessionID string, dial DialContext) (Proof, error) {
	return proveWithRoots(ctx, sessionID, dial, nil)
}

// One fixed HTTPS origin needs no asynchronous Transport. Synchronous TLS and
// HTTP keep every physical Read/Write in this proof worker; the joined close
// callback retains even a lower Close that returns before its Read unwinds.
// The private roots argument is used only by the real TLS fixture. Public
// callers always validate check.torproject.org against the platform roots.
func proveWithRoots(parent context.Context, sessionID string, dial DialContext, roots *x509.CertPool) (proof Proof, failure error) {
	if parent == nil || sessionID == "" || len(sessionID) > 512 || strings.ContainsAny(sessionID, "\x00\r\n") || dial == nil {
		return Proof{}, errors.New("dynamic Tor proof requires its frozen VPN session and final outbound")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return Proof{}, errors.New("dynamic Tor exit proof was canceled")
	}
	raw, err := dial(ctx, "tcp", "check.torproject.org:443")
	if err != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return Proof{}, errors.New("dynamic Tor exit proof request failed")
	}
	var closeOnce sync.Once
	var closeErr error
	closed := make(chan struct{})
	closeOwned := func() { closeOnce.Do(func() { closeErr = raw.Close(); close(closed) }) }
	stop := context.AfterFunc(ctx, closeOwned)
	defer func() {
		if !stop() {
			<-closed
		}
		closeOwned()
		if ctx.Err() != nil || closeErr != nil && !errors.Is(closeErr, net.ErrClosed) && !errors.Is(closeErr, io.ErrClosedPipe) {
			proof = Proof{}
			failure = errors.New("dynamic Tor exit proof did not finish cleanly")
		}
	}()
	deadline, _ := ctx.Deadline()
	phaseDeadline := func() time.Time {
		phase := time.Now().Add(15 * time.Second)
		if deadline.Before(phase) {
			return deadline
		}
		return phase
	}
	if ctx.Err() != nil || raw.SetDeadline(phaseDeadline()) != nil {
		return Proof{}, errors.New("dynamic Tor exit proof was canceled")
	}
	connection := tls.Client(raw, &tls.Config{ServerName: "check.torproject.org", RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	// Handshake has no internal context callback: our joined cancellation
	// callback and actual raw deadlines own its complete synchronous lifetime.
	if connection.Handshake() != nil || ctx.Err() != nil {
		return Proof{}, errors.New("dynamic Tor exit proof TLS verification failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ProofURL, nil)
	if err != nil {
		return Proof{}, errors.New("dynamic Tor exit proof request is invalid")
	}
	req.Close = true
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-store")
	if raw.SetDeadline(phaseDeadline()) != nil || req.Write(connection) != nil {
		return Proof{}, errors.New("dynamic Tor exit proof request failed")
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(connection, 16385)), req)
	if err != nil {
		return Proof{}, errors.New("dynamic Tor exit proof response is invalid")
	}
	defer func() { closeOwned(); _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return Proof{}, errors.New("dynamic Tor exit proof returned a non-success status")
	}
	if raw.SetDeadline(deadline) != nil {
		return Proof{}, errors.New("dynamic Tor exit proof was canceled")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(data) > 4096 {
		return Proof{}, errors.New("dynamic Tor exit proof response is invalid or oversized")
	}
	address, err := parseProof(data)
	if err != nil {
		return Proof{}, err
	}
	if ctx.Err() != nil {
		return Proof{}, errors.New("dynamic Tor exit proof was canceled")
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
