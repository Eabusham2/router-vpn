package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"

	"router-vpn/internal/multihoprelay"
)

const multihopTorLeasePath = "/api/multihop/tor/lease"

// Source discovery and leases require both an authenticated actual tunnel peer
// and an admitted native Tor runner. The catalog contains immutable references,
// never private bridge material, arbitrary native configuration or traffic proof.
func (s *server) multihopTorLease(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip, err := s.authorized(r)
	if err != nil {
		http.Error(w, "authenticated tunnel peer required", http.StatusForbidden)
		return
	}
	if s.relay == nil {
		http.Error(w, "native Tor relay is unavailable", http.StatusServiceUnavailable)
		return
	}
	peer, err := netip.ParseAddr(ip.String())
	if err != nil || r.URL.RawQuery != "" {
		http.Error(w, "invalid Tor lease request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		challenge, sources, err := s.relay.TorAvailable(peer)
		if err != nil {
			http.Error(w, "native Tor relay is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"node_id": s.cfg.NodeID, "challenge": challenge, "sources": sources})
		return
	}
	request, nonce, err := decodeTorRelayRequest(http.MaxBytesReader(w, r.Body, 4096), r.Method == http.MethodPost)
	if err != nil {
		http.Error(w, "invalid Tor lease request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodPut:
		var lease multihoprelay.TorLease
		lease, err = s.relay.CreateTor(ctx, peer, request)
		if err == nil {
			_ = json.NewEncoder(w).Encode(lease)
			return
		}
	case http.MethodPost:
		var status multihoprelay.TorLeaseStatus
		status, err = s.relay.TorStatus(ctx, peer, request, nonce)
		if err == nil {
			_ = json.NewEncoder(w).Encode(status)
			return
		}
	case http.MethodDelete:
		err = s.relay.DeleteTor(ctx, peer, request)
		if err == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": s.cfg.NodeID, "session_id": request.SessionID, "stopped": true})
			return
		}
	}
	status := http.StatusBadGateway
	if errors.Is(err, multihoprelay.ErrOwnership) {
		status = http.StatusForbidden
	} else if errors.Is(err, multihoprelay.ErrBusy) {
		status = http.StatusConflict
	} else if errors.Is(err, multihoprelay.ErrUnavailable) {
		status = http.StatusServiceUnavailable
	}
	// Do not reflect imported bridge material, native paths or worker errors.
	http.Error(w, http.StatusText(status), status)
}

func decodeTorRelayRequest(body io.Reader, status bool) (multihoprelay.TorRequest, string, error) {
	bad := errors.New("expected one exact Tor lease request")
	var request multihoprelay.TorRequest
	d := json.NewDecoder(body)
	open, err := d.Token()
	if err != nil || open != json.Delim('{') {
		return request, "", bad
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for d.More() {
		raw, err := d.Token()
		key, ok := raw.(string)
		if err != nil || !ok || seen[key] {
			return request, "", bad
		}
		seen[key] = true
		if key == "listen_port" {
			if d.Decode(&request.Port) != nil || request.Port < 26240 || request.Port > 26271 {
				return request, "", bad
			}
			continue
		}
		if key == "acquire_expires_at" {
			if d.Decode(&request.AcquireExpiresAt) != nil || request.AcquireExpiresAt <= 0 {
				return request, "", bad
			}
			continue
		}
		switch key {
		case "session_id", "entry_node_id", "exit_id", "exit_mode", "source_sha256", "dns_policy_sha256", "epoch", "peer", "listener_username", "listener_password":
		case "status_nonce":
			if !status {
				return request, "", bad
			}
		default:
			return request, "", bad
		}
		var value *string
		if d.Decode(&value) != nil || value == nil || len(*value) == 0 || len(*value) > 128 {
			return request, "", bad
		}
		values[key] = *value
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return request, "", bad
	}
	if _, err := d.Token(); err != io.EOF {
		return request, "", bad
	}
	for _, key := range []string{"session_id", "entry_node_id", "exit_id", "exit_mode", "source_sha256", "dns_policy_sha256", "epoch", "peer"} {
		if values[key] == "" {
			return request, "", bad
		}
	}
	if seen["listen_port"] != seen["listener_username"] || seen["listen_port"] != seen["listener_password"] || status != seen["status_nonce"] ||
		!seen["acquire_expires_at"] || !relayExternalDigest.MatchString(values["epoch"]) || !relayExternalDigest.MatchString(values["source_sha256"]) || !relayExternalDigest.MatchString(values["dns_policy_sha256"]) || status && !relayExternalDigest.MatchString(values["status_nonce"]) {
		return request, "", bad
	}
	request.SessionID, request.EntryNodeID, request.ExitID, request.ExitMode = values["session_id"], values["entry_node_id"], values["exit_id"], values["exit_mode"]
	request.SourceSHA256, request.DNSPolicySHA256 = values["source_sha256"], values["dns_policy_sha256"]
	request.Epoch, request.Peer = values["epoch"], values["peer"]
	request.Username, request.Password = values["listener_username"], values["listener_password"]
	return request, values["status_nonce"], nil
}
