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
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultAdminForwardingExtensionListen = "127.0.0.1:8791"
const adminProtectedDMZComment = "router-vpn admin protected dmz"

type adminProtectedDMZ struct {
	Owner     string `json:"owner"`
	TargetIP  string `json:"target_ip"`
	Protocol  string `json:"protocol"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

type adminForwardingExtensionState struct {
	Version   int                `json:"version"`
	Owners    map[string]string  `json:"owners"`
	DMZ       *adminProtectedDMZ `json:"protected_dmz,omitempty"`
	UpdatedAt int64              `json:"updated_at"`
}

type adminForwardingExtensionServer struct {
	token          string
	cfg            cfg
	statePath      string
	adminStatePath string
	mu             sync.Mutex
	dmzMu          sync.Mutex
	state          adminForwardingExtensionState
	tunnelNets     []*net.IPNet
}

func init() {
	if strings.HasSuffix(os.Args[0], ".test") || os.Getenv("ROUTER_VPN_DISABLE_ADMIN_PLANE") == "1" {
		return
	}
	go startAdminForwardingExtensionPlane()
}

func startAdminForwardingExtensionPlane() {
	// Let the config-reservation init finish first. It may redirect ROUTER_VPN_CONFIG
	// to a private augmented copy that includes dynamically discovered listeners.
	time.Sleep(250 * time.Millisecond)
	listen := getenv("ROUTER_VPN_ADMIN_FORWARDING_EXTENSION_LISTEN", defaultAdminForwardingExtensionListen)
	host, _, err := net.SplitHostPort(listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		log.Printf("router forwarding extension disabled: listen address must be loopback")
		return
	}
	tokenPath := getenv("ROUTER_VPN_ADMIN_TOKEN_FILE", "/etc/router-vpn/setup-center.token")
	var token string
	var c cfg
	for attempt := 0; attempt < 60; attempt++ {
		configPath := getenv("ROUTER_VPN_CONFIG", getenv("HOMEVPN_ROUTER_CONFIG", "/etc/router-vpn/router-agent.json"))
		if b, readErr := os.ReadFile(tokenPath); readErr == nil {
			token = strings.TrimSpace(string(b))
		}
		if b, readErr := os.ReadFile(configPath); readErr == nil {
			_ = json.Unmarshal(b, &c)
		}
		if len(token) >= 32 && c.WANInterface != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(token) < 32 || c.WANInterface == "" {
		log.Printf("router forwarding extension disabled: setup token/config unavailable")
		return
	}
	if c.NftTable == "" {
		c.NftTable = "router_vpn"
	}
	s := &adminForwardingExtensionServer{
		token:          token,
		cfg:            c,
		statePath:      getenv("ROUTER_VPN_ADMIN_FORWARDING_EXTENSION_STATE", "/var/lib/router-vpn/forwarding-extension.json"),
		adminStatePath: getenv("ROUTER_VPN_ADMIN_STATE", "/var/lib/router-vpn/admin-state.json"),
	}
	for _, raw := range c.TunnelCIDRs {
		if _, network, parseErr := net.ParseCIDR(raw); parseErr == nil {
			s.tunnelNets = append(s.tunnelNets, network)
		}
	}
	if err := s.loadState(); err != nil {
		log.Printf("router forwarding extension disabled: %v", err)
		return
	}

	go func() {
		// main() and the persistent admin plane recreate/restore the NAT table at
		// startup. Reapply the tagged DMZ rules after they settle and periodically
		// thereafter so a service/table restart cannot silently drop protection.
		time.Sleep(3 * time.Second)
		if err := s.applyProtectedDMZ(); err != nil {
			log.Printf("router protected DMZ restore: %v", err)
		}
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := s.applyProtectedDMZ(); err != nil {
				log.Printf("router protected DMZ reassert: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/forwarding-extension", s.status)
	mux.HandleFunc("/api/admin/forwarding-extension/owners/", s.owner)
	mux.HandleFunc("/api/admin/forwarding-extension/dmz", s.dmz)
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("router forwarding owner/Protected-DMZ extension listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("router forwarding extension stopped: %v", err)
	}
}

func defaultAdminForwardingExtensionState() adminForwardingExtensionState {
	return adminForwardingExtensionState{Version: 1, Owners: map[string]string{}}
}

func normalizeAdminForwardingExtensionState(s adminForwardingExtensionState) adminForwardingExtensionState {
	if s.Version == 0 {
		s.Version = 1
	}
	if s.Owners == nil {
		s.Owners = map[string]string{}
	}
	return s
}

func cloneAdminForwardingExtensionState(s adminForwardingExtensionState) adminForwardingExtensionState {
	out := s
	out.Owners = make(map[string]string, len(s.Owners))
	for id, owner := range s.Owners {
		out.Owners[id] = owner
	}
	if s.DMZ != nil {
		dmz := *s.DMZ
		out.DMZ = &dmz
	}
	return out
}

func (s *adminForwardingExtensionServer) loadState() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := readPrivilegedState(s.statePath, 256<<10)
	if errors.Is(err, os.ErrNotExist) {
		s.state = defaultAdminForwardingExtensionState()
		return s.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("read forwarding extension state: %w", err)
	}
	var state adminForwardingExtensionState
	if err := json.Unmarshal(b, &state); err != nil {
		return fmt.Errorf("decode forwarding extension state: %w", err)
	}
	if state.Version != 0 && state.Version != 1 {
		return fmt.Errorf("unsupported forwarding extension state version %d", state.Version)
	}
	s.state = normalizeAdminForwardingExtensionState(state)
	return nil
}

func (s *adminForwardingExtensionServer) persistLocked() error {
	next := normalizeAdminForwardingExtensionState(cloneAdminForwardingExtensionState(s.state))
	next.UpdatedAt = time.Now().Unix()
	body, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWritePrivilegedState(s.statePath, append(body, '\n')); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *adminForwardingExtensionServer) authorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) == 1
}

func (s *adminForwardingExtensionServer) require(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	allowed := false
	for _, method := range methods {
		if r.Method == method {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func validForwardingOwner(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validForwardingRuleID(value string) bool {
	if len(value) < 1 || len(value) > 96 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (s *adminForwardingExtensionServer) readAdminState() (adminPersistentState, error) {
	b, err := readPrivilegedState(s.adminStatePath, 512<<10)
	if err != nil {
		return adminPersistentState{}, fmt.Errorf("read admin forwarding state: %w", err)
	}
	var state adminPersistentState
	if err := json.Unmarshal(b, &state); err != nil {
		return adminPersistentState{}, fmt.Errorf("decode admin forwarding state: %w", err)
	}
	if state.Version != 1 {
		return adminPersistentState{}, fmt.Errorf("unsupported admin forwarding state version %d", state.Version)
	}
	return normalizeAdminState(state), nil
}

func (s *adminForwardingExtensionServer) status(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, http.MethodGet) {
		return
	}
	adminState, err := s.readAdminState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ids := map[string]bool{}
	for _, rule := range adminState.ForwardRules {
		ids[rule.ID] = true
	}

	s.mu.Lock()
	old := cloneAdminForwardingExtensionState(s.state)
	changed := false
	for id := range s.state.Owners {
		if !ids[id] {
			delete(s.state.Owners, id)
			changed = true
		}
	}
	persistenceWarning := ""
	if changed {
		if err := s.persistLocked(); err != nil {
			s.state = old
			persistenceWarning = "stale-owner cleanup was not committed: " + err.Error()
		}
	}
	owners := make(map[string]string, len(s.state.Owners))
	for id, owner := range s.state.Owners {
		owners[id] = owner
	}
	var dmz *adminProtectedDMZ
	if s.state.DMZ != nil {
		copyDMZ := *s.state.DMZ
		dmz = &copyDMZ
	}
	s.mu.Unlock()

	rules := make([]map[string]any, 0, len(adminState.ForwardRules))
	for _, rule := range adminState.ForwardRules {
		rules = append(rules, map[string]any{
			"id": rule.ID, "protocol": rule.Protocol, "from": rule.From, "to": rule.To,
			"target_ip": rule.TargetIP, "target_port": rule.TargetPort, "enabled": rule.Enabled,
			"created_at": rule.CreatedAt, "updated_at": rule.UpdatedAt, "owner": owners[rule.ID],
		})
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"ok": true, "forwarding_master": adminState.ForwardingMaster, "rules": rules,
		"protected_dmz": dmz, "reserved_ports": s.cfg.ReservedPorts,
		"persistence_warning": persistenceWarning,
		"semantics": "owners persist per normal rule; Protected DMZ covers only otherwise-unused unreserved WAN ports, excludes enabled explicit forwarding ranges, and remains gated by the forwarding master",
	})
}

func (s *adminForwardingExtensionServer) owner(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, http.MethodPut, http.MethodDelete) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/forwarding-extension/owners/")
	if !validForwardingRuleID(id) {
		http.Error(w, "invalid forwarding rule id", http.StatusBadRequest)
		return
	}
	adminState, err := s.readAdminState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	found := false
	for _, rule := range adminState.ForwardRules {
		if rule.ID == id {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "forwarding rule not found", http.StatusNotFound)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	old := cloneAdminForwardingExtensionState(s.state)
	if r.Method == http.MethodDelete {
		delete(s.state.Owners, id)
		if err := s.persistLocked(); err != nil {
			s.state = old
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "owner": ""})
		return
	}
	var body struct {
		Owner string `json:"owner"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	body.Owner = strings.TrimSpace(body.Owner)
	if !validForwardingOwner(body.Owner) {
		http.Error(w, "owner/client association is required and must be <=256 printable characters", http.StatusBadRequest)
		return
	}
	s.state.Owners[id] = body.Owner
	if err := s.persistLocked(); err != nil {
		s.state = old
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "owner": body.Owner})
}

func (s *adminForwardingExtensionServer) dmz(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, http.MethodPost, http.MethodDelete) {
		return
	}
	s.dmzMu.Lock()
	defer s.dmzMu.Unlock()

	if r.Method == http.MethodDelete {
		s.mu.Lock()
		old := cloneAdminForwardingExtensionState(s.state)
		s.state.DMZ = nil
		if err := s.persistLocked(); err != nil {
			s.state = old
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.mu.Unlock()
		if err := s.applyProtectedDMZLocked(); err != nil {
			rollbackErr := s.rollbackProtectedDMZLocked(old)
			http.Error(w, protectedDMZTransactionError(err, rollbackErr), http.StatusInternalServerError)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "protected_dmz": nil})
		return
	}

	var body adminProtectedDMZ
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	body.Owner = strings.TrimSpace(body.Owner)
	body.TargetIP = strings.TrimSpace(body.TargetIP)
	body.Protocol = strings.ToLower(strings.TrimSpace(body.Protocol))
	if body.Protocol == "" {
		body.Protocol = "both"
	}
	if !validForwardingOwner(body.Owner) {
		http.Error(w, "owner/client association is required", http.StatusBadRequest)
		return
	}
	if body.Protocol != "tcp" && body.Protocol != "udp" && body.Protocol != "both" {
		http.Error(w, "protocol must be tcp, udp, or both", http.StatusBadRequest)
		return
	}
	if err := s.validateTunnelTarget(body.TargetIP); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now().Unix()
	s.mu.Lock()
	old := cloneAdminForwardingExtensionState(s.state)
	body.CreatedAt = now
	if old.DMZ != nil && old.DMZ.CreatedAt > 0 {
		body.CreatedAt = old.DMZ.CreatedAt
	}
	body.UpdatedAt = now
	s.state.DMZ = &body
	if err := s.persistLocked(); err != nil {
		s.state = old
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()
	if err := s.applyProtectedDMZLocked(); err != nil {
		rollbackErr := s.rollbackProtectedDMZLocked(old)
		http.Error(w, protectedDMZTransactionError(err, rollbackErr), http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "protected_dmz": body})
}

func protectedDMZTransactionError(applyErr, rollbackErr error) string {
	if rollbackErr == nil {
		return "Protected DMZ live apply failed; prior durable/live state was restored: " + applyErr.Error()
	}
	return "Protected DMZ live apply failed and rollback is incomplete: " + applyErr.Error() + "; " + rollbackErr.Error()
}

// rollbackProtectedDMZLocked requires dmzMu. It restores durable intent first,
// then reasserts the prior live nftables state. Both failures are reported.
func (s *adminForwardingExtensionServer) rollbackProtectedDMZLocked(old adminForwardingExtensionState) error {
	s.mu.Lock()
	s.state = cloneAdminForwardingExtensionState(old)
	persistErr := s.persistLocked()
	s.mu.Unlock()
	liveErr := s.applyProtectedDMZLocked()
	if persistErr == nil && liveErr == nil {
		return nil
	}
	if persistErr != nil && liveErr != nil {
		return fmt.Errorf("durable restore failed: %v; live restore failed: %v", persistErr, liveErr)
	}
	if persistErr != nil {
		return fmt.Errorf("durable restore failed: %w", persistErr)
	}
	return fmt.Errorf("live restore failed: %w", liveErr)
}

func (s *adminForwardingExtensionServer) validateTunnelTarget(raw string) error {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return errors.New("target_ip must be a literal IPv4/IPv6 address")
	}
	for _, network := range s.tunnelNets {
		if network.Contains(ip) {
			return nil
		}
	}
	return errors.New("Protected DMZ target must be inside a Router VPN tunnel subnet")
}

func (s *adminForwardingExtensionServer) applyProtectedDMZ() error {
	s.dmzMu.Lock()
	defer s.dmzMu.Unlock()
	return s.applyProtectedDMZLocked()
}

func (s *adminForwardingExtensionServer) applyProtectedDMZLocked() error {
	s.mu.Lock()
	var dmz *adminProtectedDMZ
	if s.state.DMZ != nil {
		copyDMZ := *s.state.DMZ
		dmz = &copyDMZ
	}
	s.mu.Unlock()
	if err := s.removeProtectedDMZRules(); err != nil {
		return err
	}
	if dmz == nil || !dmz.Enabled {
		return nil
	}
	adminState, err := s.readAdminState()
	if err != nil {
		return err
	}
	if !adminState.ForwardingMaster {
		return nil
	}
	if err := s.validateTunnelTarget(dmz.TargetIP); err != nil {
		return err
	}
	return nftScript(s.protectedDMZScript(*dmz, adminState))
}

func protectedDMZAllowedRanges(reserved []int, explicit []adminForwardRule) []string {
	blocked := make([]bool, 65536)
	for _, port := range reserved {
		if port >= 1 && port <= 65535 {
			blocked[port] = true
		}
	}
	for _, rule := range explicit {
		if !rule.Enabled {
			continue
		}
		from, to := rule.From, rule.To
		if from < 1 {
			from = 1
		}
		if to > 65535 {
			to = 65535
		}
		if to < from {
			continue
		}
		for port := from; port <= to; port++ {
			blocked[port] = true
		}
	}
	out := []string{}
	start := 0
	for port := 1; port <= 65535; port++ {
		if blocked[port] {
			if start > 0 {
				out = append(out, portRange(start, port-1))
				start = 0
			}
			continue
		}
		if start == 0 {
			start = port
		}
	}
	if start > 0 {
		out = append(out, portRange(start, 65535))
	}
	return out
}

func (s *adminForwardingExtensionServer) protectedDMZScript(dmz adminProtectedDMZ, adminState adminPersistentState) string {
	protos := []string{dmz.Protocol}
	if dmz.Protocol == "both" {
		protos = []string{"tcp", "udp"}
	}
	target := net.ParseIP(dmz.TargetIP)
	if target == nil {
		return ""
	}
	var b strings.Builder
	for _, proto := range protos {
		for _, ports := range protectedDMZAllowedRanges(s.cfg.ReservedPorts, adminState.ForwardRules) {
			fmt.Fprintf(&b, "add rule inet %s prerouting iifname %q %s dport %s dnat to %s comment %q\n", s.cfg.NftTable, s.cfg.WANInterface, proto, ports, formatDNAT(target, 0), adminProtectedDMZComment)
		}
	}
	return b.String()
}

func (s *adminForwardingExtensionServer) removeProtectedDMZRules() error {
	out, err := exec.Command("nft", "-a", "list", "chain", "inet", s.cfg.NftTable, "prerouting").CombinedOutput()
	if err != nil {
		// During early startup the table may not exist yet. A later retry will
		// restore DMZ after main() creates it.
		if strings.Contains(strings.ToLower(string(out)), "no such file") || strings.Contains(strings.ToLower(string(out)), "does not exist") {
			return nil
		}
		return fmt.Errorf("list protected DMZ chain: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var deletes strings.Builder
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, adminProtectedDMZComment) || !strings.Contains(line, "# handle ") {
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
		if _, parseErr := strconv.Atoi(handle[0]); parseErr == nil {
			fmt.Fprintf(&deletes, "delete rule inet %s prerouting handle %s\n", s.cfg.NftTable, handle[0])
		}
	}
	if deletes.Len() == 0 {
		return nil
	}
	return nftScript(deletes.String())
}
