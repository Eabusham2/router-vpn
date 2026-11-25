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

const multihopNodeChainCandidatePath = "/api/multihop/chain/candidate"

func (s *server) multihopNodeChainCandidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPut && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "PUT, POST, DELETE")
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
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, multihoprelay.NodeChainCandidateMaximumBytes))
	if err != nil {
		http.Error(w, "invalid ordered lease request", http.StatusBadRequest)
		return
	}
	defer clear(raw)
	request, err := multihoprelay.DecodeNodeChainCandidateRequest(raw)
	if err != nil {
		http.Error(w, "invalid ordered lease request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodPut:
		var lease multihoprelay.NodeChainCandidateReceipt
		lease, err = s.relay.CreateChainCandidate(ctx, peer, request)
		if err == nil {
			_ = json.NewEncoder(w).Encode(lease)
			return
		}
		var absence *multihoprelay.CandidateRegistryAbsence
		if errors.As(err, &absence) {
			if negative, verifyErr := absence.Receipt(request, s.cfg.Token, time.Now()); verifyErr == nil && ctx.Err() == nil {
				_ = json.NewEncoder(w).Encode(negative)
				return
			}
		}
	case http.MethodPost:
		var status multihoprelay.NodeChainCandidateReceipt
		status, err = s.relay.ChainCandidateStatus(ctx, peer, request)
		if err == nil {
			_ = json.NewEncoder(w).Encode(status)
			return
		}
	case http.MethodDelete:
		err = s.relay.DeleteChainCandidate(ctx, peer, request)
		if err == nil {
			ack, ackErr := multihoprelay.NewNodeChainCandidateCloseAcknowledgement(request)
			if ackErr != nil {
				http.Error(w, "invalid candidate close acknowledgment", http.StatusBadGateway)
				return
			}
			_ = json.NewEncoder(w).Encode(ack)
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
