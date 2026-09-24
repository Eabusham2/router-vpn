package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"router-vpn/internal/multihoprelay"
	"time"
)

const multihopRelayPath = "/api/multihop/lease"
const multihopRelayConfig = "/etc/router-vpn/multihop-relays.json"

func (s *server) initializeMultihopRelay() error {
	path := getenv("ROUTER_VPN_MULTIHOP_CONFIG", multihopRelayConfig)
	raw, err := readPrivilegedState(path, 1<<20)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("private multihop relay configuration could not be read safely")
	}
	var cfg multihoprelay.Config
	if json.Unmarshal(raw, &cfg) != nil {
		return errors.New("invalid private multihop relay configuration")
	}
	if cfg.FirstPort < 26240 || cfg.LastPort > 26271 {
		return errors.New("relay listener ports must use the reserved 26240..26271 pool")
	}
	host, err := netip.ParseAddr(cfg.ListenIP)
	if err != nil {
		return errors.New("invalid relay listen IP")
	}
	covered := false
	for _, n := range s.nets {
		p, e := netip.ParsePrefix(n.String())
		if e == nil && p.Contains(host) {
			covered = true
		}
	}
	if !covered {
		return errors.New("relay listen IP must belong to the configured tunnel ranges")
	}
	manager, err := multihoprelay.New(cfg, s.cfg.NodeID, relayExecRunner{})
	if err != nil {
		return err
	}
	s.relay = manager
	// The dedicated range is reserved both here and in the persisted startup
	// augmentation, including for the independent Protected-DMZ administrator.
	for port := 26240; port <= 26271; port++ {
		s.cfg.ReservedPorts = append(s.cfg.ReservedPorts, port)
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			_ = manager.Sweep(context.Background())
		}
	}()
	return nil
}
func decodeRelayRequest(body io.Reader) (multihoprelay.Request, error) {
	var q multihoprelay.Request
	d := json.NewDecoder(body)
	bad := errors.New("expected one exact relay request")
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return q, bad
	}
	fields := map[string]string{}
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		if e != nil || !ok {
			return q, bad
		}
		if _, exists := fields[name]; exists {
			return q, bad
		}
		switch name {
		case "session_id", "entry_node_id", "exit_id", "exit_mode":
		default:
			return q, bad
		}
		var value *string
		if d.Decode(&value) != nil || value == nil || len(*value) == 0 || len(*value) > 128 {
			return q, bad
		}
		fields[name] = *value
	}
	if end, e := d.Token(); e != nil || end != json.Delim('}') || len(fields) != 4 {
		return q, bad
	}
	if _, e := d.Token(); e != io.EOF {
		return q, bad
	}
	q = multihoprelay.Request{SessionID: fields["session_id"], EntryNodeID: fields["entry_node_id"], ExitID: fields["exit_id"], ExitMode: fields["exit_mode"]}
	return q, nil
}
func registerMultihopRelayRoute(h *http.ServeMux, s *server) {
	h.HandleFunc(multihopRelayPath, s.multihopRelay)
}
func (s *server) multihopRelay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", 405)
		return
	}
	ip, err := s.authorized(r)
	if err != nil {
		http.Error(w, "authenticated tunnel peer required", 403)
		return
	}
	if s.relay == nil {
		http.Error(w, "server-side multihop has no provisioned exit registry", 503)
		return
	}
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]any{"node_id": s.cfg.NodeID, "execution": "server", "exits": s.relay.Available()})
		return
	}
	q, err := decodeRelayRequest(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		http.Error(w, "invalid relay request", 400)
		return
	}
	peer, err := netip.ParseAddr(ip.String())
	if err != nil {
		http.Error(w, "invalid peer", 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if r.Method == http.MethodDelete {
		err = s.relay.Delete(ctx, peer, q)
		if err == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": s.cfg.NodeID, "session_id": q.SessionID, "stopped": true})
			return
		}
	} else {
		lease, e := s.relay.Create(ctx, peer, q)
		err = e
		if err == nil {
			_ = json.NewEncoder(w).Encode(lease)
			return
		}
	}
	status := http.StatusBadGateway
	if errors.Is(err, multihoprelay.ErrOwnership) {
		status = 403
	}
	if errors.Is(err, multihoprelay.ErrBusy) {
		status = 409
	}
	if errors.Is(err, multihoprelay.ErrUnavailable) {
		status = 503
	}
	// Engine errors can contain private paths or imported transport material.
	http.Error(w, http.StatusText(status), status)
}
