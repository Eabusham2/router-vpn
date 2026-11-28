package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"router-vpn/internal/multihoprelay"
)

const multihopNodeChainPrefixSelectionPath = "/api/multihop/chain/prefix/selection"

func (s *server) multihopNodeChainPrefixSelection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peer, ok := s.prefixPeer(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if r.Method == http.MethodGet {
		discovery, err := s.relay.PrefixSelectionAvailable(ctx, peer)
		if err != nil {
			prefixHTTPError(w, err)
			return
		}
		raw, err := json.Marshal(discovery)
		if err != nil || discovery.Validate() != nil || len(raw) > multihoprelay.MaxNodeChainPrefixCapabilitiesBytes {
			prefixHTTPError(w, multihoprelay.ErrUnavailable)
			return
		}
		_, _ = w.Write(raw)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, multihoprelay.NodeChainPrefixSelectionMaximumBytes))
	if err != nil {
		http.Error(w, "invalid ordered prefix selection", http.StatusBadRequest)
		return
	}
	defer clear(raw)
	request, err := multihoprelay.DecodeNodeChainPrefixSelectionRequest(raw)
	if err != nil {
		http.Error(w, "invalid ordered prefix selection", http.StatusBadRequest)
		return
	}
	var receipt multihoprelay.NodeChainPrefixSelectionReceipt
	if r.Method == http.MethodPost {
		receipt, err = s.relay.SelectPrefix(ctx, peer, request)
	} else {
		receipt, err = s.relay.DeletePrefixSelection(ctx, peer, request)
	}
	if err != nil {
		prefixHTTPError(w, err)
		return
	}
	if receipt.Validate(request) != nil || ctx.Err() != nil {
		prefixHTTPError(w, multihoprelay.ErrUnavailable)
		return
	}
	_ = json.NewEncoder(w).Encode(receipt)
}
