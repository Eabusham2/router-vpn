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

	"router-vpn/internal/common"
)

type cfg struct {
	Listen        string   `json:"listen"`
	Token         string   `json:"token"`
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
	log.Printf("router agent listening on %s", c.Listen)
	log.Fatal(http.ListenAndServe(c.Listen, h))
}

func getenv(k, v string) string {
	if x := os.Getenv(k); x != "" {
		return x
	}
	return v
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
	fmt.Fprint(w, `{"ok":true}`)
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
	if _, err := s.authorized(r); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := nftScript(fmt.Sprintf("flush chain inet %s prerouting\n", s.cfg.NftTable)); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprint(w, `{"ok":true}`)
}

func validateForward(q common.ForwardRequest, reserved []int) error {
	if q.Protocol != "tcp" && q.Protocol != "udp" && q.Protocol != "both" {
		return errors.New("protocol must be tcp, udp, or both")
	}
	if q.DMZ {
		return nil
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
	for _, proto := range protos {
		if q.DMZ {
			for _, r := range allowedRanges(s.cfg.ReservedPorts) {
				fmt.Fprintf(&b, "add rule inet %s prerouting iifname %q %s dport %s dnat to %s\n", s.cfg.NftTable, s.cfg.WANInterface, proto, r, formatDNAT(ip, 0))
			}
			continue
		}
		ports := strconv.Itoa(q.From)
		if q.To != q.From {
			ports = fmt.Sprintf("%d-%d", q.From, q.To)
		}
		fmt.Fprintf(&b, "add rule inet %s prerouting iifname %q %s dport %s dnat to %s\n", s.cfg.NftTable, s.cfg.WANInterface, proto, ports, formatDNAT(ip, q.TargetPort))
	}
	return nftScript(b.String())
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
