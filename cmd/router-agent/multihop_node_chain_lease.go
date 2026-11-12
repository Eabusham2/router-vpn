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

const multihopNodeChainLeasePath = "/api/multihop/chain/lease"

func (s *server) multihopNodeChainLease(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "ordered server path is unavailable", http.StatusServiceUnavailable)
		return
	}
	peer, err := netip.ParseAddr(ip.String())
	if err != nil || r.URL.RawQuery != "" {
		http.Error(w, "invalid ordered lease request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		challenge, sources, err := s.relay.ChainAvailable(peer)
		if err != nil {
			http.Error(w, "ordered server path is unavailable", http.StatusServiceUnavailable)
			return
		}
		first, last, err := s.relay.ChainPortRange(peer)
		if err != nil {
			http.Error(w, "ordered server path is unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"node_id": s.cfg.NodeID, "challenge": challenge, "sources": sources, "first_port": first, "last_port": last})
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil {
		http.Error(w, "invalid ordered lease request", http.StatusBadRequest)
		return
	}
	defer clear(raw)
	request, nonce, err := multihoprelay.DecodeNodeChainLeaseRequest(raw, r.Method == http.MethodPost)
	if err != nil {
		http.Error(w, "invalid ordered lease request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodPut:
		var lease multihoprelay.NodeChainLease
		lease, err = s.relay.CreateChain(ctx, peer, request)
		if err == nil {
			_ = json.NewEncoder(w).Encode(lease)
			return
		}
	case http.MethodPost:
		var status multihoprelay.NodeChainLeaseStatus
		status, err = s.relay.ChainStatus(ctx, peer, request, nonce)
		if err == nil {
			_ = json.NewEncoder(w).Encode(status)
			return
		}
	case http.MethodDelete:
		err = s.relay.DeleteChain(ctx, peer, request)
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
	// Neither source credentials nor child/native paths enter an HTTP error.
	http.Error(w, http.StatusText(status), status)
}
