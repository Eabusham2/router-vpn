package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

type cfg struct {
	Listen        string   `json:"listen"`
	Token         string   `json:"token"`
	NodeID        string   `json:"node_id"`
	TunnelCIDRs   []string `json:"tunnel_cidrs"`
	WANInterface  string   `json:"wan_interface"`
	ReservedPorts []int    `json:"reserved_ports"`
	NftTable      string   `json:"nft_table"`
	DAITAListen   string   `json:"daita_listen"`
}

type server struct {
	cfg  cfg
	nets []*net.IPNet
	mu   sync.Mutex
}

func main() {
	path := getenv("ROUTER_VPN_CONFIG", getenv("HOMEVPN_ROUTER_CONFIG", "/etc/router-vpn/router-agent.json"))
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var c cfg
	if err := json.Unmarshal(b, &c); err != nil {
		log.Fatal(err)
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8787"
	}
	if c.NftTable == "" {
		c.NftTable = "router_vpn"
	}
	if c.WANInterface == "" {
		log.Fatal("wan_interface is required")
	}
	if !validNodeID(c.NodeID) {
		log.Fatal("node_id is required and must be a lowercase SHA-256 hex value")
	}
	if c.DAITAListen == "" {
		c.DAITAListen = "0.0.0.0:45999"
	}
	s := &server{cfg: c}
	for _, raw := range c.TunnelCIDRs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			log.Fatalf("bad cidr %s: %v", raw, err)
		}
		s.nets = append(s.nets, n)
	}
	if err := s.ensureBaseRules(); err != nil {
		log.Fatal(err)
	}
	go s.runDAITASink()
	h := http.NewServeMux()
	h.HandleFunc("/health", s.health)
	h.HandleFunc("/api/forward", s.forward)
	h.HandleFunc("/api/forward/clear", s.clear)
	h.HandleFunc("/api/dns/benchmark", s.dnsBenchmark)
	log.Printf("router agent listening on %s", c.Listen)
	log.Fatal(http.ListenAndServe(c.Listen, h))
}

func getenv(k, v string) string {
	if x := os.Getenv(k); x != "" {
		return x
	}
	return v
}

func validNodeID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (s *server) runDAITASink() {
	pc, err := net.ListenPacket("udp", s.cfg.DAITAListen)
	if err != nil {
		log.Printf("DAITA-like cover endpoint disabled: %v", err)
		return
	}
	defer pc.Close()
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("DAITA-like cover endpoint: %v", err)
			return
		}
		if n <= 0 {
			continue
		}
		// Generate a bounded reverse-direction packet. The reply is never larger
		// than the request (and capped at 1200 bytes), so this cannot amplify traffic.
		replyN := n
		if replyN > 1200 {
			replyN = 1200
		}
		reply := make([]byte, replyN)
		if _, err := rand.Read(reply); err != nil {
			continue
		}
		_, _ = pc.WriteTo(reply, addr)
	}
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"node_id": s.cfg.NodeID,
		"proof":   "router-vpn-private-agent-v1",
	})
}

func (s *server) authorized(r *http.Request) (net.IP, error) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.cfg.Token)) != 1 {
		return nil, errors.New("bad token")
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return nil, errors.New("bad source")
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return ip, nil
		}
	}
	return nil, errors.New("source is not a tunnel peer")
}

func (s *server) forward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	ip, err := s.authorized(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var q common.ForwardRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&q); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := validateForward(q, s.cfg.ReservedPorts); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.applyForward(ip, q); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("content-type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

func (s *server) clear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	ip, err := s.authorized(r)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.clearPeerForwarding(ip); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprint(w, `{"ok":true}`)
}

var dnsCandidates = []struct {
	Name    string
	Address string
}{
	{"Cloudflare IPv4", "1.1.1.1"},
	{"Cloudflare IPv4 secondary", "1.0.0.1"},
	{"Google IPv4", "8.8.8.8"},
	{"Google IPv4 secondary", "8.8.4.4"},
	{"Quad9 IPv4", "9.9.9.9"},
	{"Quad9 IPv4 secondary", "149.112.112.112"},
	{"AdGuard DNS IPv4", "94.140.14.14"},
	{"AdGuard DNS IPv4 secondary", "94.140.15.15"},
	{"Control D IPv4", "76.76.2.0"},
	{"Control D IPv4 secondary", "76.76.10.0"},
	{"OpenDNS IPv4", "208.67.222.222"},
	{"OpenDNS IPv4 secondary", "208.67.220.220"},
	{"Cloudflare IPv6", "2606:4700:4700::1111"},
	{"Cloudflare IPv6 secondary", "2606:4700:4700::1001"},
	{"Google IPv6", "2001:4860:4860::8888"},
	{"Google IPv6 secondary", "2001:4860:4860::8844"},
	{"Quad9 IPv6", "2620:fe::fe"},
	{"Quad9 IPv6 secondary", "2620:fe::9"},
	{"AdGuard DNS IPv6", "2a10:50c0::ad1:ff"},
	{"AdGuard DNS IPv6 secondary", "2a10:50c0::ad2:ff"},
}

func (s *server) dnsBenchmark(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.authorized(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	results := make([]common.DNSBenchmarkResult, 0, len(dnsCandidates))
	for _, candidate := range dnsCandidates {
		values := make([]float64, 0, 5)
		for _, qtype := range []uint16{1, 28, 1, 28, 1} {
			if latency, err := dnsProbe(candidate.Address, qtype); err == nil {
				values = append(values, latency)
			}
		}
		family := "ipv4"
		if strings.Contains(candidate.Address, ":") {
			family = "ipv6"
		}
		result := common.DNSBenchmarkResult{Name: candidate.Name, Address: candidate.Address, Family: family, Working: len(values) > 0}
		if len(values) > 0 {
			sort.Float64s(values)
			result.LatencyMs = mathRound3(values[len(values)/2])
		}
		results = append(results, result)
	}
	working := append([]common.DNSBenchmarkResult(nil), results...)
	sort.SliceStable(working, func(i, j int) bool {
		if working[i].Working != working[j].Working {
			return working[i].Working
		}
		if !working[i].Working {
			return working[i].Name < working[j].Name
		}
		return working[i].LatencyMs < working[j].LatencyMs
	})
	winner := common.DNSBenchmarkResult{Name: "Cloudflare IPv4 fallback", Address: "1.1.1.1", Family: "ipv4", Working: false}
	for _, item := range working {
		if item.Working {
			winner = item
			break
		}
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"policy":      "fastest-public",
		"winner":      winner,
		"results":     results,
		"tested_from": "home-vpn-node",
		"test":        "five real DNS A/AAAA UDP queries; median shown",
	})
}

func dnsProbe(address string, qtype uint16) (float64, error) {
	packet := dnsPacket(qtype)
	network := "udp4"
	if strings.Contains(address, ":") {
		network = "udp6"
	}
	conn, err := net.DialTimeout(network, net.JoinHostPort(address, "53"), 1250*time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1250 * time.Millisecond))
	started := time.Now()
	if _, err := conn.Write(packet); err != nil {
		return 0, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 12 {
		return 0, errors.New("short DNS response")
	}
	rcode := buf[3] & 0x0f
	if rcode != 0 && rcode != 3 {
		return 0, fmt.Errorf("DNS rcode %d", rcode)
	}
	return float64(time.Since(started).Microseconds()) / 1000.0, nil
}

func dnsPacket(qtype uint16) []byte {
	packet := make([]byte, 12)
	_, _ = rand.Read(packet[:2])
	packet[2] = 0x01 // recursion desired
	packet[5] = 0x01 // one question
	for _, label := range strings.Split("example.com", ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return packet
}

func mathRound3(v float64) float64 {
	if v < 0 {
		return -mathRound3(-v)
	}
	return float64(int(v*1000+0.5)) / 1000
}

func validateForward(q common.ForwardRequest, reserved []int) error {
	if q.Protocol != "tcp" && q.Protocol != "udp" && q.Protocol != "both" {
		return errors.New("protocol must be tcp, udp, or both")
	}
	if q.DMZ {
		return errors.New("Protected DMZ is an authenticated Setup Center admin action; tunnel peers may create only explicit owned forwarding rules")
	}
	if q.From < 1 || q.To < q.From || q.To > 65535 || q.To-q.From > 4096 {
		return errors.New("invalid or too-large range")
	}
	if q.TargetPort < 0 || q.TargetPort > 65535 {
		return errors.New("invalid target port")
	}
	for _, p := range reserved {
		if p >= q.From && p <= q.To {
			return fmt.Errorf("range includes reserved port %d", p)
		}
	}
	if q.TargetPort > 0 && q.From != q.To {
		return errors.New("custom target port is only supported for one external port; use 0 to preserve a range")
	}
	return nil
}

func (s *server) ensureBaseRules() error {
	script := fmt.Sprintf(`
add table inet %s
add chain inet %s prerouting { type nat hook prerouting priority dstnat; policy accept; }
`, s.cfg.NftTable, s.cfg.NftTable)
	_ = nftScript(fmt.Sprintf("delete table inet %s\n", s.cfg.NftTable))
	return nftScript(script)
}

func (s *server) applyForward(ip net.IP, q common.ForwardRequest) error {
	protos := []string{q.Protocol}
	if q.Protocol == "both" {
		protos = []string{"tcp", "udp"}
	}
	var b strings.Builder
	marker := peerForwardComment(ip)
	for _, proto := range protos {
		ports := strconv.Itoa(q.From)
		if q.To != q.From {
			ports = fmt.Sprintf("%d-%d", q.From, q.To)
		}
		fmt.Fprintf(&b, "add rule inet %s prerouting iifname %q %s dport %s dnat to %s comment %q\n", s.cfg.NftTable, s.cfg.WANInterface, proto, ports, formatDNAT(ip, q.TargetPort), marker)
	}
	return nftScript(b.String())
}

const peerForwardCommentPrefix = "router-vpn peer forward "

func peerForwardComment(ip net.IP) string {
	return peerForwardCommentPrefix + ip.String()
}

func peerForwardDeleteScript(chainListing, table string, ip net.IP) string {
	marker := fmt.Sprintf("comment %q", peerForwardComment(ip))
	var b strings.Builder
	for _, line := range strings.Split(chainListing, "\n") {
		if !strings.Contains(line, marker) || !strings.Contains(line, "# handle ") {
			continue
		}
		parts := strings.Split(line, "# handle ")
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err == nil {
			fmt.Fprintf(&b, "delete rule inet %s prerouting handle %s\n", table, fields[0])
		}
	}
	return b.String()
}

func (s *server) clearPeerForwarding(ip net.IP) error {
	out, err := exec.Command("nft", "-a", "list", "chain", "inet", s.cfg.NftTable, "prerouting").CombinedOutput()
	if err != nil {
		return fmt.Errorf("list peer forwarding chain: %v: %s", err, strings.TrimSpace(string(out)))
	}
	script := peerForwardDeleteScript(string(out), s.cfg.NftTable, ip)
	if script == "" {
		return nil
	}
	return nftScript(script)
}

func allowedRanges(reserved []int) []string {
	seen := map[int]bool{}
	for _, p := range reserved {
		if p >= 1 && p <= 65535 {
			seen[p] = true
		}
	}
	vals := make([]int, 0, len(seen))
	for p := range seen {
		vals = append(vals, p)
	}
	sort.Ints(vals)
	start := 1
	out := []string{}
	for _, p := range vals {
		if p > start {
			out = append(out, portRange(start, p-1))
		}
		start = p + 1
	}
	if start <= 65535 {
		out = append(out, portRange(start, 65535))
	}
	return out
}

func portRange(a, b int) string {
	if a == b {
		return strconv.Itoa(a)
	}
	return fmt.Sprintf("%d-%d", a, b)
}

func formatDNAT(ip net.IP, port int) string {
	if ip.To4() == nil {
		if port > 0 {
			return fmt.Sprintf("[%s]:%d", ip, port)
		}
		return ip.String()
	}
	if port > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return ip.String()
}

func nftScript(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
