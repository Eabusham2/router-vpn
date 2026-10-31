package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type nativeMAXTLSReference struct {
	OuterPort    int
	Assets       map[string][]byte
	Packets      func() int64
	RejectedUUID func(string) bool
	BlockedUDP   func(string) bool
}

// This peer runs the exact pinned Xray server. Its sole egress is one captured
// private UDP service, redirected into an owned, counted loopback bridge. The
// compiled client keeps the actual public endpoint and every TLS/MAX layer;
// the graph fixture maps only that outer physical socket to OuterPort.
func nativeMAXTLSReferenceProcess(t *testing.T, binary, publicEndpoint, privateService string, middlePort int) *nativeMAXTLSReference {
	t.Helper()
	public, err := netip.ParseAddr(publicEndpoint)
	if err != nil || public.IsUnspecified() || public.IsLoopback() || public.IsMulticast() || public.Is4In6() {
		t.Fatal("MAX TLS reference requires its exact public node IP")
	}
	service, err := netip.ParseAddrPort(privateService)
	if err != nil || !service.Addr().IsPrivate() || service.Addr().Is4In6() || service.Port() == 0 || middlePort < 1 || middlePort > 65535 {
		t.Fatal("MAX TLS reference requires one exact private UDP service and owned middle port")
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reservation.Close() })
	bridge, packets := nativeMAXTLSUDPBridge(t, middlePort)
	certificate, private := nativeMultihopTrafficCertificate(t)
	pair, err := tls.X509KeyPair([]byte(certificate), []byte(private))
	if err != nil {
		t.Fatal(err)
	}
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	camouflage.EnableHTTP2 = true
	camouflage.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	camouflage.StartTLS()
	t.Cleanup(camouflage.Close)
	reality, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pq, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatal(err)
	}
	uuidBytes := make([]byte, 16)
	if _, err := rand.Read(uuidBytes); err != nil {
		t.Fatal(err)
	}
	uuidBytes[6], uuidBytes[8] = uuidBytes[6]&15|64, uuidBytes[8]&63|128
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", uuidBytes[:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])
	shortID := hex.EncodeToString(uuidBytes[:8])
	path := "/captured-max-" + hex.EncodeToString(uuidBytes)
	user := map[string]any{"id": uuid, "encryption": "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())}
	client := map[string]any{
		"inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": 1090, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}},
		"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": publicEndpoint, "port": 24443, "users": []any{user}}}}, "streamSettings": map[string]any{
			"network": "xhttp", "security": "reality", "xhttpSettings": map[string]any{"path": path, "mode": "auto"},
			"realitySettings": map[string]any{"serverName": "exit-certificate.example", "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(reality.PublicKey().Bytes()), "shortId": shortID},
			"finalmask":       map[string]any{"tcp": []any{map[string]any{"type": "fragment", "settings": map[string]any{"packets": "tlshello", "length": "100-300", "delay": "10-30", "maxSplit": "3-7"}}}},
		}}},
	}
	_, bridgePort, err := net.SplitHostPort(bridge)
	if err != nil {
		t.Fatal(err)
	}
	bits := 128
	if service.Addr().Is4() {
		bits = 32
	}
	server := map[string]any{
		"log": map[string]any{"loglevel": "debug"},
		"inbounds": []any{map[string]any{"tag": "captured-max-node", "listen": "127.0.0.1", "port": reservation.Addr().(*net.TCPAddr).Port, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": uuid}}, "decryption": "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(seed)}, "streamSettings": map[string]any{
			"network": "xhttp", "security": "reality", "xhttpSettings": map[string]any{"path": path, "mode": "auto"},
			"realitySettings": map[string]any{"target": camouflage.Listener.Addr().String(), "serverNames": []string{"exit-certificate.example"}, "privateKey": base64.RawURLEncoding.EncodeToString(reality.Bytes()), "shortIds": []string{shortID}},
		}}},
		"outbounds": []any{map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "private-middle", "protocol": "freedom", "settings": map[string]any{"redirect": bridge, "finalRules": []any{
			map[string]any{"action": "allow", "network": "udp", "ip": []string{"127.0.0.1/32"}, "port": bridgePort},
			map[string]any{"action": "block", "blockDelay": "0-0"},
		}}}},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"captured-max-node"}, "network": "udp", "ip": []string{service.Addr().String() + "/" + strconv.Itoa(bits)}, "port": strconv.Itoa(int(service.Port())), "outboundTag": "private-middle"}}},
	}
	clear(seed)
	process, port := nativeMAXTLSStartXray(t, binary, server, reservation, "transport/internet/splithttp: listening TCP for XHTTP on ")
	asset, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	return &nativeMAXTLSReference{
		OuterPort: port, Assets: map[string][]byte{"outer-xray.json": asset}, Packets: packets,
		RejectedUUID: func(value string) bool {
			return nativeMAXTLSRejected(process.diagnostics(), value)
		},
		BlockedUDP: func(destination string) bool {
			address, err := netip.ParseAddrPort(destination)
			if err != nil || address.String() != destination {
				return false
			}
			diagnostic := process.diagnostics()
			return strings.Contains(diagnostic, "default route for udp:"+destination+"\n") && strings.Contains(diagnostic, " accepted udp:"+destination+" [captured-max-node >> block]")
		},
	}
}

func nativeMAXTLSRejected(diagnostic, uuid string) bool {
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' || strings.ToLower(uuid) != uuid {
		return false
	}
	if decoded, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", "")); err != nil || len(decoded) != 16 {
		return false
	}
	for _, line := range strings.Split(diagnostic, "\n") {
		if strings.Contains(line, " rejected ") && strings.HasSuffix(strings.TrimSpace(line), "invalid request user id: "+uuid) {
			return true
		}
	}
	return false
}

// Every source association owns a distinct connected UDP socket. Neither
// received payload bytes nor a late source can change its only destination.
func nativeMAXTLSUDPBridge(t *testing.T, middlePort int) (string, func() int64) {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var jobs sync.WaitGroup
	var count atomic.Int64
	closing := false
	peers := map[netip.AddrPort]*net.UDPConn{}
	jobs.Add(1)
	go func() {
		defer jobs.Done()
		buffer := make([]byte, 65535)
		for {
			n, source, err := listener.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				return
			}
			peer := peers[source]
			if peer == nil {
				peer, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: middlePort})
				if err != nil {
					mu.Unlock()
					continue
				}
				peers[source] = peer
				jobs.Add(1)
				go func(upstream *net.UDPConn, destination netip.AddrPort) {
					defer jobs.Done()
					defer func() {
						_ = upstream.Close()
						mu.Lock()
						if peers[destination] == upstream {
							delete(peers, destination)
						}
						mu.Unlock()
					}()
					reply := make([]byte, 65535)
					for {
						n, err := upstream.Read(reply)
						if err != nil {
							return
						}
						if _, err := listener.WriteToUDPAddrPort(reply[:n], destination); err != nil {
							return
						}
					}
				}(peer, source)
			}
			mu.Unlock()
			if n, err := peer.Write(buffer[:n]); err == nil && n > 0 {
				count.Add(1)
			}
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closing = true
		_ = listener.Close()
		for _, peer := range peers {
			_ = peer.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { jobs.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned MAX TLS UDP bridge did not join")
		}
	})
	return listener.LocalAddr().String(), count.Load
}

type nativeMAXTLSXrayProcess struct {
	command *exec.Cmd
	log     *os.File
	done    chan struct{}
	err     error // Published only when Wait closes done.
	close   sync.Once
}

func (p *nativeMAXTLSXrayProcess) diagnostics() string {
	file, err := os.Open(p.log.Name())
	if err != nil {
		return ""
	}
	defer file.Close()
	raw, _ := io.ReadAll(io.LimitReader(file, 1<<20))
	return string(raw)
}

func (p *nativeMAXTLSXrayProcess) stop(t *testing.T) {
	t.Helper()
	p.close.Do(func() {
		select {
		case <-p.done:
		default:
			_ = p.command.Process.Kill()
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
				t.Error("owned MAX TLS reference process did not join")
			}
		}
		_ = p.log.Close()
	})
}

// Retain the selected port while constructing every sibling listener. Retry
// only an owned child that actually exited with the exact bind collision; a
// successful TCP accept alone cannot impersonate the captured Xray process.
func nativeMAXTLSStartXray(t *testing.T, binary string, graph map[string]any, reservation net.Listener, binding string) (*nativeMAXTLSXrayProcess, int) {
	t.Helper()
	directory := t.TempDir()
	defer func() {
		if reservation != nil {
			_ = reservation.Close()
		}
	}()
	for attempt := 0; attempt < 3; attempt++ {
		address := reservation.Addr().String()
		port := reservation.Addr().(*net.TCPAddr).Port
		graph["inbounds"].([]any)[0].(map[string]any)["port"] = port
		graph["log"] = map[string]any{"loglevel": "debug"}
		raw, err := json.Marshal(graph)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, fmt.Sprintf("reference-%d.json", attempt))
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		log, err := os.OpenFile(filepath.Join(directory, fmt.Sprintf("reference-%d.log", attempt)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "run", "-c", path)
		command.Stdout, command.Stderr = log, log
		if err := reservation.Close(); err != nil {
			_ = log.Close()
			t.Fatal(err)
		}
		if err := command.Start(); err != nil {
			_ = log.Close()
			t.Fatal(err)
		}
		process := &nativeMAXTLSXrayProcess{command: command, log: log, done: make(chan struct{})}
		go func() { process.err = command.Wait(); close(process.done) }()
		collision, err := process.ready(address, binding)
		if err == nil {
			t.Cleanup(func() {
				process.stop(t)
				if t.Failed() {
					t.Logf("owned MAX TLS reference diagnostics:\n%s", process.diagnostics())
				}
			})
			return process, port
		}
		process.stop(t)
		if !collision || attempt == 2 {
			t.Fatalf("MAX TLS reference readiness: %v\n%s", err, process.diagnostics())
		}
		reservation, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("MAX TLS reference exhausted owned bind attempts")
	return nil, 0
}

// Xray emits platform.LineSeparator(): CRLF on Windows and LF elsewhere.
// Only complete records from the retained child log can witness its exact bind
// and startup. A different listener or an unrelated "started" line cannot.
func nativeMAXTLSStartupRecords(diagnostic, address string, binding string) bool {
	if address == "" || binding == "" {
		return false
	}
	bound, started := false, false
	for _, record := range strings.SplitAfter(diagnostic, "\n") {
		if !strings.HasSuffix(record, "\n") {
			continue
		}
		line := strings.TrimSuffix(strings.TrimSuffix(record, "\n"), "\r")
		bound = bound || strings.HasSuffix(line, binding+address)
		started = started || strings.Contains(line, "core: Xray ") && strings.HasSuffix(line, " started")
	}
	return bound && started
}

func TestNativeMAXTLSStartupRecords(t *testing.T) {
	address := "127.0.0.1:40981"
	for _, binding := range []string{"transport/internet/tcp: listening TCP on ", "transport/internet/splithttp: listening TCP for XHTTP on "} {
		for _, ending := range []string{"\n", "\r\n"} {
			bound := "2026/10/31 00:00:00 [Info] " + binding + address + ending
			started := "2026/10/31 00:00:00 [Warning] core: Xray 26.10 started" + ending
			if !nativeMAXTLSStartupRecords(bound+started, address, binding) {
				t.Fatalf("exact owned Xray records were rejected: binding=%q ending=%q", binding, ending)
			}
			for name, diagnostic := range map[string]string{
				"missing-bind":     started,
				"missing-start":    bound,
				"wrong-address":    strings.ReplaceAll(bound, address, "127.0.0.2:40981") + started,
				"extended-address": strings.ReplaceAll(bound, address, address+"0") + started,
				"bind-suffix":      strings.ReplaceAll(bound, address, address+" trailing") + started,
				"truncated-bind":   started + strings.TrimSuffix(bound, ending),
				"truncated-start":  bound + strings.TrimSuffix(started, ending),
				"unrelated-start":  bound + "core: Xray 26.10" + ending + "other component started" + ending,
			} {
				if nativeMAXTLSStartupRecords(diagnostic, address, binding) {
					t.Errorf("unowned or incomplete Xray record was accepted: %s ending=%q", name, ending)
				}
			}
			if nativeMAXTLSStartupRecords(bound+started, "", binding) {
				t.Fatal("empty listener identity was accepted")
			}
			if nativeMAXTLSStartupRecords(bound+started, address, "") {
				t.Fatal("empty listener kind was accepted")
			}
		}
	}
}

func (p *nativeMAXTLSXrayProcess) ready(address, binding string) (bool, error) {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			text := syscall.EADDRINUSE.Error()
			if runtime.GOOS == "windows" {
				text = syscall.Errno(10048).Error()
			}
			collision := p.err != nil && strings.Contains(p.diagnostics(), "listen tcp "+address+": bind: "+text)
			return collision, fmt.Errorf("captured Xray process exited before readiness: %w", p.err)
		default:
		}
		diagnostic := p.diagnostics()
		if nativeMAXTLSStartupRecords(diagnostic, address, binding) {
			connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				_ = connection.Close()
				select {
				case <-p.done:
					return false, errors.New("captured Xray process exited during readiness")
				default:
					return false, nil
				}
			}
		}
		select {
		case <-p.done:
		case <-deadline.C:
			return false, errors.New("captured Xray process did not prove its listeners and startup")
		case <-tick.C:
		}
	}
}

func TestNativeMAXTLSReferenceRejectsUnownedWitnesses(t *testing.T) {
	uuid := "22222222-2222-4222-8222-222222222222"
	line := "from 127.0.0.1:1234 rejected proxy/vless/encoding: invalid request user id: " + uuid + "\n"
	if !nativeMAXTLSRejected(line, uuid) {
		t.Fatal("actual exact UUID rejection record was ignored")
	}
	for _, diagnostic := range []string{"", strings.ReplaceAll(line, "rejected", "accepted"), strings.ReplaceAll(line, uuid, "11111111-1111-4111-8111-111111111111"), strings.TrimSpace(line) + "a\n"} {
		if nativeMAXTLSRejected(diagnostic, uuid) {
			t.Fatal("unrelated or incomplete record impersonated an attempted wrong UUID")
		}
	}
	if nativeMAXTLSRejected(line, "") || nativeMAXTLSRejected(line, uuid[:35]) {
		t.Fatal("partial identity received a rejection witness")
	}
}

func TestNativeMAXTLSReferenceEncryptedUDPAndRejectionWitnesses(t *testing.T) {
	binary := os.Getenv("ROUTER_VPN_XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("exact pinned Xray peer is supplied by the mandatory native bundle gate")
	}
	_, echo := nativeMultihopTrafficEcho(t)
	reference := nativeMAXTLSReferenceProcess(t, binary, "198.51.100.22", "10.88.0.1:8388", echo)
	original := append([]byte(nil), reference.Assets["outer-xray.json"]...)
	for _, fault := range []string{"none", "wrong-uuid", "wrong-private-service", "restored"} {
		t.Run(fault, func(t *testing.T) {
			graph := retainedGraph(t, original)
			next := graph["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			next["address"], next["port"] = "127.0.0.1", reference.OuterPort
			wrong := "22222222-2222-4222-8222-222222222222"
			if fault == "wrong-uuid" {
				next["users"].([]any)[0].(map[string]any)["id"] = wrong
			}
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer reservation.Close()
			// This exact Xray version opens each SOCKS UDP association only after
			// its TCP handshake. The subsequent exchange proves that owned socket;
			// startup must not wait for a nonexistent shared UDP listener.
			_, port := nativeMAXTLSStartXray(t, binary, graph, reservation, "transport/internet/tcp: listening TCP on ")
			before := reference.Packets()
			target := 8388
			if fault == "wrong-private-service" {
				target--
			}
			err = nativeMultihopTrafficExchangeTo(port, target, "udp", [4]byte{10, 88, 0, 1}, 4*time.Second)
			if fault == "none" || fault == "restored" {
				if err != nil || reference.Packets() < before+3 {
					t.Fatal("complete TLS outer changed or bypassed actual encrypted UDP", err, reference.Packets()-before)
				}
			} else if err == nil || reference.Packets() != before {
				t.Fatal("wrong identity or private destination reached the counted middle", fault, err)
			}
			if fault == "wrong-uuid" && !reference.RejectedUUID(wrong) || fault == "wrong-private-service" && !reference.BlockedUDP("10.88.0.1:8387") {
				t.Fatal("failed traffic lacked its exact owned native rejection witness", fault)
			}
			if !bytes.Equal(original, reference.Assets["outer-xray.json"]) {
				t.Fatal("negative trial changed the source restored by the next owner")
			}
		})
	}
}
