package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultAdminListen = "127.0.0.1:8789"

type adminServer struct {
	token string
	cfg   cfg
}

type adminPeer struct {
	Source              string   `json:"source"`
	Interface           string   `json:"interface"`
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	LatestHandshakeUnix int64    `json:"latest_handshake_unix,omitempty"`
	HandshakeAgeSeconds int64    `json:"handshake_age_seconds,omitempty"`
	RXBytes             uint64   `json:"rx_bytes,omitempty"`
	TXBytes             uint64   `json:"tx_bytes,omitempty"`
	State               string   `json:"state"`
}

type adminListener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

// The admin plane is intentionally separate from the tunnel-client API. It is
// loopback-only and uses the Setup Center's server-side token, so a VPN client's
// forwarding token never becomes a blanket server-administration credential.
func init() {
	if strings.HasSuffix(os.Args[0], ".test") || os.Getenv("ROUTER_VPN_DISABLE_ADMIN_PLANE") == "1" {
		return
	}
	go startAdminPlane()
}

func startAdminPlane() {
	tokenPath := getenv("ROUTER_VPN_ADMIN_TOKEN_FILE", "/etc/router-vpn/setup-center.token")
	configPath := getenv("ROUTER_VPN_CONFIG", getenv("HOMEVPN_ROUTER_CONFIG", "/etc/router-vpn/router-agent.json"))
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
		log.Printf("router admin plane disabled: setup token/config unavailable")
		return
	}
	if c.NftTable == "" {
		c.NftTable = "router_vpn"
	}
	a := &adminServer{token: token, cfg: c}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/clients", a.clients)
	mux.HandleFunc("/api/admin/status", a.status)
	listen := getenv("ROUTER_VPN_ADMIN_LISTEN", defaultAdminListen)
	host, _, err := net.SplitHostPort(listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		log.Printf("router admin plane disabled: listen address must be loopback")
		return
	}
	server := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("router read-only admin plane listening on %s", listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("router admin plane stopped: %v", err)
	}
}

func (a *adminServer) authorized(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.token)) == 1
}

func (a *adminServer) requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return false
	}
	if !a.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func writeAdminJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *adminServer) clients(w http.ResponseWriter, r *http.Request) {
	if !a.requireGET(w, r) {
		return
	}
	peers, sources, errs := collectWireGuardPeers()
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"clients": peers,
		"coverage": map[string]any{
			"sources": sources,
			"semantics": "WireGuard-style peers use recent-handshake state; this is not a fake session list.",
			"other_proxy_protocols": "not session-enumerable yet",
		},
		"errors": errs,
	})
}

func (a *adminServer) status(w http.ResponseWriter, r *http.Request) {
	if !a.requireGET(w, r) {
		return
	}
	listeners, listenerErr := collectListeners()
	forwardCount, forwardErr := countForwardRules(a.cfg.NftTable)
	activeProtected := map[int]bool{}
	for _, item := range listeners {
		for _, port := range a.cfg.ReservedPorts {
			if item.Port == port {
				activeProtected[port] = true
			}
		}
	}
	reserved := append([]int(nil), a.cfg.ReservedPorts...)
	sort.Ints(reserved)
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"listeners": listeners,
		"reserved_ports": reserved,
		"active_reserved_ports": sortedIntKeys(activeProtected),
		"forwarding": map[string]any{
			"nft_table": a.cfg.NftTable,
			"rule_count": forwardCount,
			"master": "runtime-table-present",
		},
		"capabilities": map[string]any{
			"connected_clients": true,
			"service_listener_status": true,
			"forwarding_read_only": true,
			"ban_unban": false,
			"peer_revoke": false,
			"settings_write": false,
			"server_update": false,
		},
		"errors": compactErrors(listenerErr, forwardErr),
	})
}

func collectWireGuardPeers() ([]adminPeer, []string, []string) {
	commands := []string{"wg"}
	if _, err := exec.LookPath("awg"); err == nil {
		commands = append(commands, "awg")
	}
	all := map[string]*adminPeer{}
	var sources []string
	var errs []string
	for _, command := range commands {
		if _, err := exec.LookPath(command); err != nil {
			continue
		}
		rows, err := collectPeersFrom(command)
		if err != nil {
			errs = append(errs, command+": "+err.Error())
			continue
		}
		sources = append(sources, command)
		for _, peer := range rows {
			key := peer.Interface + "\x00" + peer.PublicKey
			if existing := all[key]; existing != nil {
				mergeAdminPeer(existing, peer)
				continue
			}
			copyPeer := peer
			all[key] = &copyPeer
		}
	}
	out := make([]adminPeer, 0, len(all))
	for _, peer := range all {
		classifyPeer(peer)
		out = append(out, *peer)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out, sources, errs
}

func collectPeersFrom(command string) ([]adminPeer, error) {
	peers := map[string]*adminPeer{}
	kinds := []string{"latest-handshakes", "transfer", "endpoints", "allowed-ips"}
	for _, kind := range kinds {
		out, err := exec.Command(command, "show", "all", kind).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("%s: %v: %s", kind, err, strings.TrimSpace(string(out)))
		}
		if err := applyWGOutput(peers, command, kind, string(out)); err != nil {
			return nil, err
		}
	}
	out := make([]adminPeer, 0, len(peers))
	for _, peer := range peers {
		out = append(out, *peer)
	}
	return out, nil
}

func applyWGOutput(peers map[string]*adminPeer, source, kind, output string) error {
	for _, raw := range strings.Split(strings.TrimSpace(output), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) < 3 {
			return fmt.Errorf("unexpected %s output", kind)
		}
		key := fields[0] + "\x00" + fields[1]
		peer := peers[key]
		if peer == nil {
			peer = &adminPeer{Source: source, Interface: fields[0], PublicKey: fields[1]}
			peers[key] = peer
		}
		switch kind {
		case "latest-handshakes":
			v, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				return fmt.Errorf("bad handshake timestamp")
			}
			peer.LatestHandshakeUnix = v
		case "transfer":
			if len(fields) < 4 {
				return fmt.Errorf("unexpected transfer output")
			}
			rx, err1 := strconv.ParseUint(fields[2], 10, 64)
			tx, err2 := strconv.ParseUint(fields[3], 10, 64)
			if err1 != nil || err2 != nil {
				return fmt.Errorf("bad transfer counters")
			}
			peer.RXBytes, peer.TXBytes = rx, tx
		case "endpoints":
			if fields[2] != "(none)" {
				peer.Endpoint = fields[2]
			}
		case "allowed-ips":
			if fields[2] != "(none)" {
				peer.AllowedIPs = strings.Split(fields[2], ",")
			}
		}
	}
	return nil
}

func mergeAdminPeer(dst *adminPeer, src adminPeer) {
	if dst.Source == "" {
		dst.Source = src.Source
	}
	if src.Endpoint != "" {
		dst.Endpoint = src.Endpoint
	}
	if len(src.AllowedIPs) > 0 {
		dst.AllowedIPs = src.AllowedIPs
	}
	if src.LatestHandshakeUnix > dst.LatestHandshakeUnix {
		dst.LatestHandshakeUnix = src.LatestHandshakeUnix
	}
	if src.RXBytes > dst.RXBytes {
		dst.RXBytes = src.RXBytes
	}
	if src.TXBytes > dst.TXBytes {
		dst.TXBytes = src.TXBytes
	}
}

func classifyPeer(peer *adminPeer) {
	if peer.LatestHandshakeUnix <= 0 {
		peer.State = "never-handshaken"
		return
	}
	age := time.Now().Unix() - peer.LatestHandshakeUnix
	if age < 0 {
		age = 0
	}
	peer.HandshakeAgeSeconds = age
	switch {
	case age <= 180:
		peer.State = "recent-handshake"
	case age <= 900:
		peer.State = "idle"
	default:
		peer.State = "stale"
	}
}

func collectListeners() ([]adminListener, error) {
	out, err := exec.Command("ss", "-H", "-lntu").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ss: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return parseListeners(string(out)), nil
}

func parseListeners(output string) []adminListener {
	seen := map[string]bool{}
	var result []adminListener
	for _, raw := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		local := fields[4]
		port := listenerPort(local)
		if port <= 0 {
			continue
		}
		key := proto + "\x00" + local
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, adminListener{Protocol: proto, Address: local, Port: port})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Protocol < result[j].Protocol
	})
	return result
}

func listenerPort(address string) int {
	if _, port, err := net.SplitHostPort(address); err == nil {
		value, _ := strconv.Atoi(port)
		return value
	}
	idx := strings.LastIndex(address, ":")
	if idx < 0 || idx+1 >= len(address) {
		return 0
	}
	value, _ := strconv.Atoi(strings.Trim(address[idx+1:], "[]"))
	return value
}

func countForwardRules(table string) (int, error) {
	out, err := exec.Command("nft", "list", "chain", "inet", table, "prerouting").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, " dnat to ") {
			count++
		}
	}
	return count, nil
}

func sortedIntKeys(values map[int]bool) []int {
	out := make([]int, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func compactErrors(values ...error) []string {
	out := []string{}
	for _, err := range values {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}
