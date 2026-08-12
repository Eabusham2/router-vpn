package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultAdminMutationListen = "127.0.0.1:8790"

type adminPeerPolicy struct {
	Interface  string   `json:"interface"`
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	CreatedAt  int64    `json:"created_at"`
}

type adminForwardRule struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	From       int    `json:"from"`
	To         int    `json:"to"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

type adminPersistentState struct {
	Version          int                `json:"version"`
	ForwardingMaster bool               `json:"forwarding_master"`
	LANAccess        bool               `json:"lan_access"`
	BannedPeers      []adminPeerPolicy  `json:"banned_peers"`
	RevokedPeers     []adminPeerPolicy  `json:"revoked_peers"`
	ForwardRules     []adminForwardRule `json:"forward_rules"`
	UpdatedAt        int64              `json:"updated_at"`
}

type adminMutationServer struct {
	token      string
	cfg        cfg
	statePath  string
	lanCIDR4   string
	lanCIDR6   string
	mu         sync.Mutex
	state      adminPersistentState
	tunnelNets []*net.IPNet
}

func init() {
	if strings.HasSuffix(os.Args[0], ".test") || os.Getenv("ROUTER_VPN_DISABLE_ADMIN_PLANE") == "1" {
		return
	}
	go startAdminMutationPlane()
}

func startAdminMutationPlane() {
	tokenPath := getenv("ROUTER_VPN_ADMIN_TOKEN_FILE", "/etc/router-vpn/setup-center.token")
	configPath := getenv("ROUTER_VPN_CONFIG", getenv("HOMEVPN_ROUTER_CONFIG", "/etc/router-vpn/router-agent.json"))
	listen := getenv("ROUTER_VPN_ADMIN_MUTATION_LISTEN", defaultAdminMutationListen)
	host, _, err := net.SplitHostPort(listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Printf("router persistent admin disabled: mutation listen must be loopback")
		return
	}

	var token string
	var c cfg
	for attempt := 0; attempt < 60; attempt++ {
		if b, err := os.ReadFile(tokenPath); err == nil {
			token = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(configPath); err == nil {
			_ = json.Unmarshal(b, &c)
		}
		if len(token) >= 32 && c.WANInterface != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(token) < 32 || c.WANInterface == "" {
		log.Printf("router persistent admin disabled: setup token/config unavailable")
		return
	}
	if c.NftTable == "" {
		c.NftTable = "router_vpn"
	}
	a := &adminMutationServer{
		token:     token,
		cfg:       c,
		statePath: getenv("ROUTER_VPN_ADMIN_STATE", "/var/lib/router-vpn/admin-state.json"),
		lanCIDR4:  strings.TrimSpace(getenv("ROUTER_VPN_LAN_CIDR", "192.168.50.0/24")),
		lanCIDR6:  strings.TrimSpace(getenv("ROUTER_VPN_LAN_CIDR6", "fd00::/8")),
	}
	for _, raw := range c.TunnelCIDRs {
		if _, n, err := net.ParseCIDR(raw); err == nil {
			a.tunnelNets = append(a.tunnelNets, n)
		}
	}
	if err := a.loadState(); err != nil {
		log.Printf("router persistent admin disabled: %v", err)
		return
	}
	if err := a.applyPolicy(); err != nil {
		log.Printf("router persistent admin initial policy: %v", err)
	}

	// main() recreates the Router VPN NAT table during startup. Restore our
	// tagged persistent forwards after that settles. Revocations are also
	// reasserted periodically so a separate WG/AWG service restart cannot
	// silently resurrect a revoked peer.
	go func() {
		time.Sleep(2 * time.Second)
		if err := a.applyPolicy(); err != nil {
			log.Printf("router persistent admin policy retry: %v", err)
		}
		if err := a.applyForwardRules(); err != nil {
			log.Printf("router persistent admin forward restore: %v", err)
		}
		a.applyRevocations()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			a.applyRevocations()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/settings", a.settings)
	mux.HandleFunc("/api/admin/forwarding", a.forwarding)
	mux.HandleFunc("/api/admin/forwarding/", a.forwardingByID)
	mux.HandleFunc("/api/admin/clients/ban", a.ban)
	mux.HandleFunc("/api/admin/clients/unban", a.unban)
	mux.HandleFunc("/api/admin/clients/revoke", a.revoke)
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("router persistent admin mutation plane listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("router persistent admin stopped: %v", err)
	}
}

func defaultAdminState() adminPersistentState {
	return adminPersistentState{Version: 1, ForwardingMaster: true, LANAccess: true, BannedPeers: []adminPeerPolicy{}, RevokedPeers: []adminPeerPolicy{}, ForwardRules: []adminForwardRule{}}
}

func normalizeAdminState(s adminPersistentState) adminPersistentState {
	if s.Version == 0 {
		s.Version = 1
	}
	if s.BannedPeers == nil {
		s.BannedPeers = []adminPeerPolicy{}
	}
	if s.RevokedPeers == nil {
		s.RevokedPeers = []adminPeerPolicy{}
	}
	if s.ForwardRules == nil {
		s.ForwardRules = []adminForwardRule{}
	}
	sort.Slice(s.ForwardRules, func(i, j int) bool { return s.ForwardRules[i].ID < s.ForwardRules[j].ID })
	return s
}

func (a *adminMutationServer) loadState() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := os.ReadFile(a.statePath)
	if errors.Is(err, os.ErrNotExist) {
		a.state = defaultAdminState()
		return a.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("read admin state: %w", err)
	}
	var s adminPersistentState
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("invalid admin state: %w", err)
	}
	if s.Version != 1 {
		return fmt.Errorf("unsupported admin state version %d", s.Version)
	}
	a.state = normalizeAdminState(s)
	return nil
}

func (a *adminMutationServer) persistLocked() error {
	a.state.UpdatedAt = time.Now().Unix()
	if err := os.MkdirAll(filepath.Dir(a.statePath), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.statePath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, a.statePath)
}

func (a *adminMutationServer) authorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.token)) == 1
}

func (a *adminMutationServer) require(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	if !a.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func cloneAdminState(s adminPersistentState) adminPersistentState {
	out := s
	out.BannedPeers = append([]adminPeerPolicy(nil), s.BannedPeers...)
	out.RevokedPeers = append([]adminPeerPolicy(nil), s.RevokedPeers...)
	out.ForwardRules = append([]adminForwardRule(nil), s.ForwardRules...)
	return out
}

func (a *adminMutationServer) rollbackLocked(old adminPersistentState, policy, forwards bool) {
	a.state = old
	if policy {
		_ = a.applyPolicyLocked()
	}
	if forwards {
		_ = a.applyForwardRulesLocked()
	}
}

func (a *adminMutationServer) settings(w http.ResponseWriter, r *http.Request) {
	if !a.require(w, r, http.MethodGet, http.MethodPut) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Method == http.MethodPut {
		old := cloneAdminState(a.state)
		var q struct {
			ForwardingMaster *bool `json:"forwarding_master"`
			LANAccess        *bool `json:"lan_access"`
		}
		if err := decodeAdminJSON(w, r, &q); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if q.ForwardingMaster == nil && q.LANAccess == nil {
			http.Error(w, "no supported setting supplied", http.StatusBadRequest)
			return
		}
		if q.ForwardingMaster != nil {
			a.state.ForwardingMaster = *q.ForwardingMaster
		}
		if q.LANAccess != nil {
			a.state.LANAccess = *q.LANAccess
		}
		if err := a.applyPolicyLocked(); err != nil {
			a.rollbackLocked(old, true, false)
			http.Error(w, err.Error(), 500)
			return
		}
		if err := a.persistLocked(); err != nil {
			a.rollbackLocked(old, true, false)
			http.Error(w, err.Error(), 500)
			return
		}
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"settings": map[string]any{"forwarding_master": a.state.ForwardingMaster, "lan_access": a.state.LANAccess, "updated_at": a.state.UpdatedAt},
		"banned_peers": a.state.BannedPeers,
		"revoked_peers": a.state.RevokedPeers,
		"capabilities": map[string]any{
			"ban_unban": true, "peer_revoke": true, "forwarding_master": true,
			"forwarding_rule_crud": true, "lan_access_write": true, "persistent_state": true,
			"server_update": false, "recovery_actions": false,
		},
	})
}

func (a *adminMutationServer) forwarding(w http.ResponseWriter, r *http.Request) {
	if !a.require(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Method == http.MethodPost {
		old := cloneAdminState(a.state)
		var q adminForwardRule
		if err := decodeAdminJSON(w, r, &q); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.validateAdminForward(&q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().Unix()
		if q.ID == "" {
			q.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
			q.CreatedAt = now
		}
		q.UpdatedAt = now
		replaced := false
		for i := range a.state.ForwardRules {
			if a.state.ForwardRules[i].ID == q.ID {
				if q.CreatedAt == 0 {
					q.CreatedAt = a.state.ForwardRules[i].CreatedAt
				}
				a.state.ForwardRules[i] = q
				replaced = true
				break
			}
		}
		if !replaced {
			a.state.ForwardRules = append(a.state.ForwardRules, q)
		}
		if err := a.applyForwardRulesLocked(); err != nil {
			a.rollbackLocked(old, false, true)
			http.Error(w, err.Error(), 500)
			return
		}
		if err := a.persistLocked(); err != nil {
			a.rollbackLocked(old, false, true)
			http.Error(w, err.Error(), 500)
			return
		}
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "master": a.state.ForwardingMaster, "rules": a.state.ForwardRules})
}

func (a *adminMutationServer) forwardingByID(w http.ResponseWriter, r *http.Request) {
	if !a.require(w, r, http.MethodDelete) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/forwarding/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "bad rule id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	old := cloneAdminState(a.state)
	out := make([]adminForwardRule, 0, len(a.state.ForwardRules))
	found := false
	for _, rule := range a.state.ForwardRules {
		if rule.ID == id {
			found = true
			continue
		}
		out = append(out, rule)
	}
	if !found {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	a.state.ForwardRules = out
	if err := a.applyForwardRulesLocked(); err != nil {
		a.rollbackLocked(old, false, true)
		http.Error(w, err.Error(), 500)
		return
	}
	if err := a.persistLocked(); err != nil {
		a.rollbackLocked(old, false, true)
		http.Error(w, err.Error(), 500)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": a.state.ForwardRules})
}

func (a *adminMutationServer) validateAdminForward(q *adminForwardRule) error {
	q.Protocol = strings.ToLower(strings.TrimSpace(q.Protocol))
	if q.Protocol != "tcp" && q.Protocol != "udp" && q.Protocol != "both" {
		return errors.New("protocol must be tcp, udp, or both")
	}
	if q.From < 1 || q.To < q.From || q.To > 65535 || q.To-q.From > 4096 {
		return errors.New("invalid or too-large range")
	}
	if q.TargetPort < 0 || q.TargetPort > 65535 {
		return errors.New("invalid target port")
	}
	for _, p := range a.cfg.ReservedPorts {
		if p >= q.From && p <= q.To {
			return fmt.Errorf("range includes reserved port %d", p)
		}
	}
	if q.TargetPort > 0 && q.From != q.To {
		return errors.New("custom target port requires a single external port")
	}
	ip := net.ParseIP(strings.TrimSpace(q.TargetIP))
	if ip == nil || !a.inTunnel(ip) {
		return errors.New("target_ip must be a Router VPN tunnel peer address")
	}
	q.TargetIP = ip.String()
	if strings.ContainsAny(q.ID, " /\\\t\r\n\"") {
		return errors.New("invalid rule id")
	}
	return nil
}

func (a *adminMutationServer) inTunnel(ip net.IP) bool {
	for _, n := range a.tunnelNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *adminMutationServer) validatePeerPolicy(q *adminPeerPolicy) error {
	q.Interface = strings.TrimSpace(q.Interface)
	q.PublicKey = strings.TrimSpace(q.PublicKey)
	if q.Interface == "" || q.PublicKey == "" {
		return errors.New("interface and public_key are required")
	}
	if strings.ContainsAny(q.Interface, " /\\\t\r\n") {
		return errors.New("invalid interface")
	}
	seen := map[string]bool{}
	clean := []string{}
	for _, raw := range q.AllowedIPs {
		ip, n, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil || !a.inTunnel(ip) {
			return fmt.Errorf("allowed IP %q is not a Router VPN tunnel address", raw)
		}
		ones, bits := n.Mask.Size()
		if (bits == 32 && ones != 32) || (bits == 128 && ones != 128) {
			return fmt.Errorf("allowed IP %q must be a host route", raw)
		}
		value := ip.String()
		if !seen[value] {
			seen[value] = true
			clean = append(clean, value)
		}
	}
	if len(clean) == 0 {
		return errors.New("at least one tunnel peer allowed_ip host route is required")
	}
	q.AllowedIPs = clean
	return nil
}

func peerPolicyIndex(items []adminPeerPolicy, publicKey string) int {
	for i := range items {
		if items[i].PublicKey == publicKey {
			return i
		}
	}
	return -1
}

func (a *adminMutationServer) ban(w http.ResponseWriter, r *http.Request) {
	if !a.require(w, r, http.MethodPost) {
		return
	}
	var q adminPeerPolicy
	if err := decodeAdminJSON(w, r, &q); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.validatePeerPolicy(&q); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if peerPolicyIndex(a.state.RevokedPeers, q.PublicKey) >= 0 {
		http.Error(w, "peer is revoked; it cannot be restored by unban", http.StatusConflict)
		return
	}
	old := cloneAdminState(a.state)
	q.CreatedAt = time.Now().Unix()
	if i := peerPolicyIndex(a.state.BannedPeers, q.PublicKey); i >= 0 {
		a.state.BannedPeers[i] = q
	} else {
		a.state.BannedPeers = append(a.state.BannedPeers, q)
	}
	if err := a.applyPolicyLocked(); err != nil {
		a.rollbackLocked(old, true, false)
		http.Error(w, err.Error(), 500)
		return
	}
	if err := a.persistLocked(); err != nil {
		a.rollbackLocked(old, true, false)
		http.Error(w, err.Error(), 500)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "banned": q})
}

func (a *adminMutationServer) unban(w http.ResponseWriter, r *http.Request) {
	if !a.require(w, r, http.MethodPost) {
		return
	}
	var q struct{ PublicKey string `json:"public_key"` }
	if err := decodeAdminJSON(w, r, &q); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	q.PublicKey = strings.TrimSpace(q.PublicKey)
	if q.PublicKey == "" {
		http.Error(w, "public_key is required", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if peerPolicyIndex(a.state.RevokedPeers, q.PublicKey) >= 0 {
		http.Error(w, "peer is revoked; unban intentionally does not undo revoke", http.StatusConflict)
		return
	}
	old := cloneAdminState(a.state)
	out := make([]adminPeerPolicy, 0, len(a.state.BannedPeers))
	for _, peer := range a.state.BannedPeers {
		if peer.PublicKey != q.PublicKey {
			out = append(out, peer)
		}
	}
	a.state.BannedPeers = out
	if err := a.applyPolicyLocked(); err != nil {
		a.rollbackLocked(old, true, false)
		http.Error(w, err.Error(), 500)
		return
	}
	if err := a.persistLocked(); err != nil {
		a.rollbackLocked(old, true, false)
		http.Error(w, err.Error(), 500)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "public_key": q.PublicKey, "banned": false})
}

func (a *adminMutationServer) revoke(w http.ResponseWriter, r *http.Request) {
	if !a.require(w, r, http.MethodPost) {
		return
	}
	var q adminPeerPolicy
	if err := decodeAdminJSON(w, r, &q); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.validatePeerPolicy(&q); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	old := cloneAdminState(a.state)
	q.CreatedAt = time.Now().Unix()
	if i := peerPolicyIndex(a.state.RevokedPeers, q.PublicKey); i >= 0 {
		a.state.RevokedPeers[i] = q
	} else {
		a.state.RevokedPeers = append(a.state.RevokedPeers, q)
	}
	if i := peerPolicyIndex(a.state.BannedPeers, q.PublicKey); i >= 0 {
		a.state.BannedPeers[i] = q
	} else {
		a.state.BannedPeers = append(a.state.BannedPeers, q)
	}
	if err := a.applyPolicyLocked(); err != nil {
		a.rollbackLocked(old, true, false)
		a.mu.Unlock()
		http.Error(w, err.Error(), 500)
		return
	}
	if err := a.persistLocked(); err != nil {
		a.rollbackLocked(old, true, false)
		a.mu.Unlock()
		http.Error(w, err.Error(), 500)
		return
	}
	a.mu.Unlock()
	removed, detail := removeLivePeer(q.Interface, q.PublicKey)
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": q, "live_peer_removed": removed, "detail": detail})
}

func (a *adminMutationServer) applyPolicy() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applyPolicyLocked()
}

func (a *adminMutationServer) applyPolicyLocked() error {
	const table = "router_vpn_admin"
	_ = nftScript("delete table inet " + table + "\n")
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "add chain inet %s input { type filter hook input priority -10; policy accept; }\n", table)
	fmt.Fprintf(&b, "add chain inet %s forward { type filter hook forward priority -10; policy accept; }\n", table)
	for _, peer := range a.state.BannedPeers {
		for _, raw := range peer.AllowedIPs {
			ip := net.ParseIP(raw)
			if ip == nil {
				continue
			}
			family := "ip"
			if ip.To4() == nil {
				family = "ip6"
			}
			fmt.Fprintf(&b, "add rule inet %s input %s saddr %s drop comment %q\n", table, family, ip.String(), "router-vpn banned peer")
			fmt.Fprintf(&b, "add rule inet %s forward %s saddr %s drop comment %q\n", table, family, ip.String(), "router-vpn banned peer")
		}
	}
	if !a.state.ForwardingMaster {
		for _, raw := range a.cfg.TunnelCIDRs {
			_, dst, err := net.ParseCIDR(raw)
			if err != nil {
				continue
			}
			family := "ip"
			if dst.IP.To4() == nil {
				family = "ip6"
			}
			fmt.Fprintf(&b, "add rule inet %s forward iifname %q %s daddr %s drop comment %q\n", table, a.cfg.WANInterface, family, dst.String(), "router-vpn forwarding master off")
		}
	}
	if !a.state.LANAccess {
		for _, raw := range a.cfg.TunnelCIDRs {
			_, src, err := net.ParseCIDR(raw)
			if err != nil {
				continue
			}
			family, dst := "ip", a.lanCIDR4
			if src.IP.To4() == nil {
				family, dst = "ip6", a.lanCIDR6
			}
			if _, _, err := net.ParseCIDR(dst); err != nil {
				continue
			}
			fmt.Fprintf(&b, "add rule inet %s forward %s saddr %s %s daddr %s drop comment %q\n", table, family, src.String(), family, dst, "router-vpn LAN access off")
		}
	}
	return nftScript(b.String())
}

func (a *adminMutationServer) applyForwardRules() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applyForwardRulesLocked()
}

func (a *adminMutationServer) applyForwardRulesLocked() error {
	out, err := exec.Command("nft", "-a", "list", "chain", "inet", a.cfg.NftTable, "prerouting").CombinedOutput()
	if err != nil {
		return fmt.Errorf("list forwarding chain: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var deletes strings.Builder
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "router-vpn admin rule") || !strings.Contains(line, "# handle ") {
			continue
		}
		parts := strings.Split(line, "# handle ")
		if len(parts) != 2 {
			continue
		}
		handle := strings.Fields(parts[1])
		if len(handle) == 0 {
			continue
		}
		if _, err := strconv.Atoi(handle[0]); err == nil {
			fmt.Fprintf(&deletes, "delete rule inet %s prerouting handle %s\n", a.cfg.NftTable, handle[0])
		}
	}
	if deletes.Len() > 0 {
		if err := nftScript(deletes.String()); err != nil {
			return err
		}
	}
	var adds strings.Builder
	for _, rule := range a.state.ForwardRules {
		if !rule.Enabled {
			continue
		}
		protos := []string{rule.Protocol}
		if rule.Protocol == "both" {
			protos = []string{"tcp", "udp"}
		}
		ports := strconv.Itoa(rule.From)
		if rule.To != rule.From {
			ports = fmt.Sprintf("%d-%d", rule.From, rule.To)
		}
		for _, proto := range protos {
			target := net.ParseIP(rule.TargetIP)
			if target != nil {
				fmt.Fprintf(&adds, "add rule inet %s prerouting iifname %q %s dport %s dnat to %s comment %q\n", a.cfg.NftTable, a.cfg.WANInterface, proto, ports, formatDNAT(target, rule.TargetPort), "router-vpn admin rule "+rule.ID)
			}
		}
	}
	if adds.Len() == 0 {
		return nil
	}
	return nftScript(adds.String())
}

func removeLivePeer(iface, publicKey string) (bool, string) {
	var details []string
	removed := false
	for _, command := range []string{"wg", "awg"} {
		if _, err := exec.LookPath(command); err != nil {
			continue
		}
		out, err := exec.Command(command, "set", iface, "peer", publicKey, "remove").CombinedOutput()
		if err == nil {
			removed = true
			details = append(details, command+": removed")
		} else {
			details = append(details, fmt.Sprintf("%s: %v: %s", command, err, strings.TrimSpace(string(out))))
		}
	}
	if len(details) == 0 {
		return false, "no WireGuard-family control tool installed"
	}
	return removed, strings.Join(details, "; ")
}

func (a *adminMutationServer) applyRevocations() {
	a.mu.Lock()
	items := append([]adminPeerPolicy(nil), a.state.RevokedPeers...)
	a.mu.Unlock()
	for _, peer := range items {
		removed, detail := removeLivePeer(peer.Interface, peer.PublicKey)
		if removed {
			log.Printf("reasserted revoked peer %s on %s", peer.PublicKey, peer.Interface)
		} else if detail != "no WireGuard-family control tool installed" {
			log.Printf("revoked peer %s on %s: %s", peer.PublicKey, peer.Interface, detail)
		}
	}
}
