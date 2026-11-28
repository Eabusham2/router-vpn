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

const multihopNodeChainPrefixLeasePath = "/api/multihop/chain/prefix/lease"
const multihopNodeChainPrefixCandidatePath = "/api/multihop/chain/prefix/candidate"

func (s *server) prefixPeer(w http.ResponseWriter, r *http.Request) (netip.Addr, bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	ip, err := s.authorized(r)
	if err != nil {
		http.Error(w, "authenticated tunnel peer required", http.StatusForbidden)
		return netip.Addr{}, false
	}
	if s.relay == nil {
		http.Error(w, "ordered prefix execution is unavailable", http.StatusServiceUnavailable)
		return netip.Addr{}, false
	}
	peer, err := netip.ParseAddr(ip.String())
	if err != nil || r.URL.RawQuery != "" {
		http.Error(w, "invalid ordered prefix request", http.StatusBadRequest)
		return netip.Addr{}, false
	}
	return peer, true
}
func prefixHTTPError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if errors.Is(err, multihoprelay.ErrOwnership) {
		status = http.StatusForbidden
	} else if errors.Is(err, multihoprelay.ErrBusy) {
		status = http.StatusConflict
	} else if errors.Is(err, multihoprelay.ErrUnavailable) {
		status = http.StatusServiceUnavailable
	}
	http.Error(w, http.StatusText(status), status)
}
func (s *server) multihopNodeChainPrefixLease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peer, ok := s.prefixPeer(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		challenge, sources, err := s.relay.PrefixAvailable(peer)
		if err != nil {
			prefixHTTPError(w, err)
			return
		}
		first, last, err := s.relay.PrefixPortRange(peer)
		if err != nil {
			prefixHTTPError(w, err)
			return
		}
		discovery := multihoprelay.NodeChainPrefixDiscovery{NodeID: s.cfg.NodeID, Challenge: challenge, FirstPort: first, LastPort: last, Prefixes: sources}
		raw, err := json.Marshal(discovery)
		if err != nil || discovery.Validate() != nil || len(raw) > multihoprelay.MaxNodeChainPrefixCapabilitiesBytes {
			prefixHTTPError(w, multihoprelay.ErrUnavailable)
			return
		}
		_, _ = w.Write(raw)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, multihoprelay.NodeChainPrefixMaximumRequestBytes))
	if err != nil {
		http.Error(w, "invalid ordered prefix request", http.StatusBadRequest)
		return
	}
	defer clear(raw)
	q, nonce, err := multihoprelay.DecodeNodeChainPrefixRequest(raw, r.Method == http.MethodPost)
	if err != nil {
		http.Error(w, "invalid ordered prefix request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodPut:
		var lease multihoprelay.NodeChainPrefixLease
		lease, err = s.relay.CreatePrefix(ctx, peer, q)
		if err == nil {
			_ = json.NewEncoder(w).Encode(lease)
			return
		}
	case http.MethodPost:
		var status multihoprelay.NodeChainPrefixLeaseStatus
		status, err = s.relay.PrefixStatus(ctx, peer, q, nonce)
		if err == nil {
			_ = json.NewEncoder(w).Encode(status)
			return
		}
	case http.MethodDelete:
		err = s.relay.DeletePrefix(ctx, peer, q)
		if err == nil {
			digest, _ := q.Digest()
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": 1, "purpose": multihoprelay.NodeChainPrefixPurpose, "session_id": q.SessionID, "request_sha256": digest, "stopped": true})
			return
		}
	}
	prefixHTTPError(w, err)
}
func (s *server) multihopNodeChainPrefixCandidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "PUT, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peer, ok := s.prefixPeer(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, multihoprelay.NodeChainPrefixMaximumRequestBytes))
	if err != nil {
		http.Error(w, "invalid ordered prefix candidate", http.StatusBadRequest)
		return
	}
	defer clear(raw)
	q, nonce, err := multihoprelay.DecodeNodeChainPrefixCandidateRequest(raw, r.Method == http.MethodPost)
	if err != nil {
		http.Error(w, "invalid ordered prefix candidate", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodPut:
		var receipt multihoprelay.NodeChainPrefixCandidateReceipt
		receipt, err = s.relay.CreatePrefixCandidate(ctx, peer, q)
		if err == nil {
			_ = json.NewEncoder(w).Encode(receipt)
			return
		}
	case http.MethodPost:
		var receipt multihoprelay.NodeChainPrefixCandidateReceipt
		receipt, err = s.relay.PrefixCandidateStatus(ctx, peer, q, nonce)
		if err == nil {
			_ = json.NewEncoder(w).Encode(receipt)
			return
		}
	case http.MethodDelete:
		err = s.relay.DeletePrefixCandidate(ctx, peer, q)
		if err == nil {
			digest, _ := q.Digest()
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": 1, "purpose": multihoprelay.NodeChainPrefixPurpose, "operation_id": q.OperationID, "request_sha256": digest, "stopped": true})
			return
		}
	}
	prefixHTTPError(w, err)
}
