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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultAdminServerControlListen = "127.0.0.1:8792"
const serverControlTable = "router_vpn_server_control"

type adminServerControlState struct {
	Version   int   `json:"version"`
	Paused    bool  `json:"paused"`
	Emergency bool  `json:"emergency"`
	UpdatedAt int64 `json:"updated_at"`
}

type adminServerControl struct {
	token     string
	cfg       cfg
	statePath string
	mu        sync.Mutex
	state     adminServerControlState
}

func init() {
	if strings.HasSuffix(os.Args[0], ".test") || os.Getenv("ROUTER_VPN_DISABLE_ADMIN_PLANE") == "1" {
		return
	}
	go startAdminServerControlPlane()
}

func startAdminServerControlPlane() {
	// Wait for reserved_dynamic.go to finish augmenting ROUTER_VPN_CONFIG.
	time.Sleep(300 * time.Millisecond)
	listen := getenv("ROUTER_VPN_ADMIN_SERVER_CONTROL_LISTEN", defaultAdminServerControlListen)
	host, _, err := net.SplitHostPort(listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		log.Printf("router server control disabled: listen address must be loopback")
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
		log.Printf("router server control disabled: setup token/config unavailable")
		return
	}
	s := &adminServerControl{
		token: token,
		cfg: c,
		statePath: getenv("ROUTER_VPN_ADMIN_SERVER_CONTROL_STATE", "/var/lib/router-vpn/server-control.json"),
	}
	if err := s.load(); err != nil {
		log.Printf("router server control disabled: %v", err)
		return
	}
	if err := s.apply(); err != nil {
		log.Printf("router server control initial policy: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/server-control", s.status)
	mux.HandleFunc("/api/admin/server-control/stop", s.stop)
	mux.HandleFunc("/api/admin/server-control/emergency-stop", s.emergencyStop)
	mux.HandleFunc("/api/admin/server-control/resume", s.resume)
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("router authenticated server control plane listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("router server control stopped: %v", err)
	}
}

func defaultServerControlState() adminServerControlState {
	return adminServerControlState{Version: 1}
}

func (s *adminServerControl) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		s.state = defaultServerControlState()
		return s.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("read server control state: %w", err)
	}
	var state adminServerControlState
	if err := json.Unmarshal(b, &state); err != nil {
		return fmt.Errorf("decode server control state: %w", err)
	}
	if state.Version != 1 {
		return fmt.Errorf("unsupported server control state version %d", state.Version)
	}
	s.state = state
	return nil
}

func (s *adminServerControl) persistLocked() error {
	s.state.Version = 1
	s.state.UpdatedAt = time.Now().Unix()
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.statePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(s.statePath, 0o600)
}

func (s *adminServerControl) authorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) == 1
}

func (s *adminServerControl) require(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// Ports that are infrastructure/control-plane only and must remain reachable
// while Router VPN ingress is paused. All other reserved ports are Router VPN
// transport/service listeners and are fail-closed by Stop/Emergency Stop.
var serverControlInfrastructurePorts = map[int]bool{
	22: true, 53: true, 80: true, 1080: true, 3000: true,
	8786: true, 8787: true, 8789: true, 8790: true, 8791: true, 8792: true,
	9443: true, 14444: true, 18080: true, 45999: true,
}

func serverControlServicePorts(reserved []int) []int {
	seen := map[int]bool{}
	for _, port := range reserved {
		if port < 1 || port > 65535 || serverControlInfrastructurePorts[port] {
			continue
		}
		seen[port] = true
	}
	out := make([]int, 0, len(seen))
	for port := range seen {
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func renderServerControlRules(table, inputInterface string, paused bool, servicePorts []int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "add chain inet %s input { type filter hook input priority -20; policy accept; }\n", table)
	if !paused {
		return b.String()
	}
	for _, port := range servicePorts {
		p := strconv.Itoa(port)
		fmt.Fprintf(&b, "add rule inet %s input iifname %q tcp dport %s drop comment %q\n", table, inputInterface, p, "router-vpn server paused")
		fmt.Fprintf(&b, "add rule inet %s input iifname %q udp dport %s drop comment %q\n", table, inputInterface, p, "router-vpn server paused")
	}
	return b.String()
}

func (s *adminServerControl) apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked()
}

func (s *adminServerControl) applyLocked() error {
	_ = nftScript("delete table inet " + serverControlTable + "\n")
	return nftScript(renderServerControlRules(serverControlTable, s.cfg.WANInterface, s.state.Paused, serverControlServicePorts(s.cfg.ReservedPorts)))
}

func (s *adminServerControl) status(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, http.MethodGet) {
		return
	}
	s.mu.Lock()
	state := s.state
	ports := serverControlServicePorts(s.cfg.ReservedPorts)
	s.mu.Unlock()
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"paused": state.Paused,
		"emergency": state.Emergency,
		"updated_at": state.UpdatedAt,
		"blocked_service_ports": ports,
		"semantics": "Stop pauses Router VPN transport ingress while preserving Setup Center/admin/recovery infrastructure. Emergency Stop also removes live WireGuard-family peers. Resume restores ingress without rotating keys or deleting configuration.",
	})
}

func (s *adminServerControl) setState(paused, emergency bool) error {
	s.mu.Lock()
	old := s.state
	s.state.Paused = paused
	s.state.Emergency = emergency
	if err := s.applyLocked(); err != nil {
		s.state = old
		_ = s.applyLocked()
		s.mu.Unlock()
		return err
	}
	if err := s.persistLocked(); err != nil {
		s.state = old
		_ = s.applyLocked()
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	return nil
}

func (s *adminServerControl) stop(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, http.MethodPost) {
		return
	}
	if err := s.setState(true, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "paused": true, "emergency": false})
}

func (s *adminServerControl) resume(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, http.MethodPost) {
		return
	}
	if err := s.setState(false, false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"ok": true, "paused": false, "emergency": false})
}

func (s *adminServerControl) emergencyStop(w http.ResponseWriter, r *http.Request) {
	if !s.require(w, r, http.MethodPost) {
		return
	}
	if err := s.setState(true, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	peers, _, collectErrs := collectWireGuardPeers()
	removed := 0
	details := make([]string, 0, len(peers)+len(collectErrs))
	for _, peer := range peers {
		ok, detail := removeLivePeer(peer.Interface, peer.PublicKey)
		if ok {
			removed++
		}
		if detail != "" {
			details = append(details, peer.Interface+": "+detail)
		}
	}
	details = append(details, collectErrs...)
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"ok": true, "paused": true, "emergency": true,
		"live_peers_removed": removed, "peer_rows_seen": len(peers), "details": details,
	})
}
