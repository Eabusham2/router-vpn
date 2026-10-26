package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The shipping native CLI carries these bytes over a real encrypted WireGuard
// entry and authenticated native Naive exit. Only the physical entry address
// maps to loopback; the exit keeps its captured documentation address and the
// entry server authorizes exactly that exit socket. No OS TUN, host route,
// private router, public network or user credential is used by this test.
func TestNativeMultihopWGNaiveEncryptedLoopback(t *testing.T) {
	binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI")
	if binary == "" {
		t.Skip("complete shipping native runtime supplied by the package gate")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	loopback := ""
	for _, adapter := range interfaces {
		if adapter.Flags&net.FlagLoopback != 0 {
			loopback = adapter.Name
			break
		}
	}
	if loopback == "" {
		t.Fatal("native loopback traffic fixture needs its loopback adapter")
	}
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		t.Run(mode, func(t *testing.T) {
			root, selection := nativeMultihopCapturedFixture(t, "wg", "off")
			selection.Entry.DAITAEnabled, selection.Exit.DAITAEnabled = false, false
			selection.Entry.DNSMode, selection.Entry.DNSProtocol, selection.Entry.DNSHost, selection.Entry.DNSPort, selection.Entry.DNSServerName, selection.Entry.DNSPath = "home", "", "", 0, "", ""
			clientPrivate, _ := base64.StdEncoding.DecodeString(testWGKey('p'))
			clientKey, err := ecdh.X25519().NewPrivateKey(clientPrivate)
			if err != nil {
				t.Fatal(err)
			}
			serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"wg.conf", "wg-socks.conf"} {
				path := filepath.Join(root, "generated", "entry", "wg", name)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.ReplaceAll(raw, []byte(testWGKey('q')), []byte(base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes())))
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if name == "wg.conf" {
					selection.Entry.NodeProofID, err = nodeProofIDFromWGConfig(raw)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			selection.Control = cloneRouterProfile(selection.Entry)
			selection.ExitMode = mode
			certificate, private := nativeMultihopTrafficCertificate(t)
			exitPort := nativeMultihopTrafficPort(t, "tcp")
			assets := nativeMultihopProxyExitAssets(t, selection.Exit, mode)
			exitGraph := retainedGraph(t, assets["sing-box.json"])
			exitOutbound := exitGraph["outbounds"].([]any)[0].(map[string]any)
			exitOutbound["tls"].(map[string]any)["certificate"] = []string{certificate}
			raw, _ := json.Marshal(exitGraph)
			if err := os.WriteFile(filepath.Join(root, "generated", "exit", mode, "sing-box.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeMultihopSelection(context.Background(), root, selection, []string{mode}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileRetainedNativeMultihopLaunch(selection, nil)
			if err != nil {
				t.Fatal(err)
			}
			tcpEcho, udpEcho := nativeMultihopTrafficEcho(t)
			nativeMultihopTrafficProcess(t, binary, map[string]any{
				"inbounds":  []any{map[string]any{"type": "naive", "tag": "exit-server", "listen": "127.0.0.1", "listen_port": exitPort, "users": []any{map[string]any{"username": "captured-naive-user", "password": "captured-naive-password"}}, "tls": map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{private}}}},
				"outbounds": []any{map[string]any{"type": "direct", "tag": "echo-only"}},
				"route": map[string]any{"rules": []any{
					map[string]any{"ip_cidr": []string{"127.0.0.1/32"}, "network": "tcp", "port": tcpEcho, "action": "route", "outbound": "echo-only"},
					map[string]any{"ip_cidr": []string{"127.0.0.1/32"}, "network": "udp", "port": udpEcho, "action": "route", "outbound": "echo-only"},
					map[string]any{"action": "reject"}}},
			}, exitPort)
			faults := []string{"none", "wrong-exit-key", "restored-key"}
			if mode == "naive-h3" {
				faults = append(faults, "first-handshake-retry")
			}
			for _, fault := range faults {
				t.Run(fault, func(t *testing.T) {

					// Every trial owns its WG server. A late packet from a retired
					// client cannot roam a shared peer into the replacement trial.
					entryPort := nativeMultihopTrafficPort(t, "udp")
					nativeMultihopTrafficProcess(t, binary, map[string]any{
						"endpoints": []any{map[string]any{"type": "wireguard", "tag": "entry-server", "system": false, "bind_interface": loopback, "address": []string{"10.77.0.1/24"}, "listen_port": entryPort, "private_key": base64.StdEncoding.EncodeToString(serverKey.Bytes()), "peers": []any{map[string]any{"public_key": base64.StdEncoding.EncodeToString(clientKey.PublicKey().Bytes()), "allowed_ips": []string{"10.77.0.2/32"}}}}},
						"outbounds": []any{map[string]any{"type": "direct", "tag": "exit-only"}},
						"route": map[string]any{"rules": []any{
							map[string]any{"ip_cidr": []string{selection.Exit.Endpoint + "/32"}, "port": 8443, "action": "route", "outbound": "exit-only", "override_address": "127.0.0.1", "override_port": exitPort},
							map[string]any{"ip_cidr": []string{"10.77.0.1/32", "127.0.0.1/32"}, "network": "tcp", "port": tcpEcho, "action": "route", "outbound": "exit-only", "override_address": "127.0.0.1"},
							map[string]any{"action": "reject"}}},
					}, 0)

					var retry *nativeWGFirstHandshakeGate
					if fault == "first-handshake-retry" {
						retry = nativeMultihopDelayFirstWGHandshake(t, entryPort, 4500*time.Millisecond)
						entryPort = retry.port
					}
					graph := retainedGraph(t, launch.config)
					clientPort := nativeMultihopTrafficPort(t, "tcp")
					// This input substitution only avoids opening an OS interface.
					// All compiled transports, DNS and entry/exit detours stay real.
					readyPort := nativeMultihopTrafficPort(t, "tcp")
					graph["inbounds"] = []any{
						map[string]any{"type": "socks", "tag": "fixture-traffic", "listen": "127.0.0.1", "listen_port": clientPort},
						map[string]any{"type": "socks", "tag": "fixture-entry-ready", "listen": "127.0.0.1", "listen_port": readyPort},
					}
					route := graph["route"].(map[string]any)
					route["rules"] = append([]any{map[string]any{"inbound": []string{"fixture-entry-ready"}, "action": "route", "outbound": "entry-wg"}}, route["rules"].([]any)...)

					// The mapped physical socket is loopback, so the ordinary WAN
					// interface binding is inapplicable in this isolated adapter.
					graph["route"].(map[string]any)["auto_detect_interface"] = false
					entry := graph["endpoints"].([]any)[0].(map[string]any)
					entry["bind_interface"] = loopback
					peer := entry["peers"].([]any)[0].(map[string]any)
					peer["address"], peer["port"] = "127.0.0.1", entryPort
					for _, raw := range graph["outbounds"].([]any) {
						out := raw.(map[string]any)
						if out["tag"] == "proxy" {
							if out["type"] != "naive" || out["detour"] != "entry-wg" || out["server"] != selection.Exit.Endpoint {
								t.Fatal("serialized shipping graph lost its actual native detour")
							}
							if fault == "wrong-exit-key" {
								out["password"] = "foreign-node-secret"
							}
						}
					}
					nativeMultihopTrafficProcess(t, binary, graph, clientPort)
					// Listener readiness is not encrypted path readiness. Match the
					// application's bounded entry-proof phase, then retain the original
					// four-second per-exit exchange assertions (including wrong keys).
					nativeMultihopAwaitEncryptedEntry(t, readyPort, tcpEcho)
					if retry != nil {
						retry.requireObservedRetry(t)
					}
					for _, network := range []string{"tcp", "udp"} {
						port := tcpEcho
						if network == "udp" {
							port = udpEcho
						}
						err := nativeMultihopTrafficExchange(clientPort, port, network)
						if fault != "wrong-exit-key" && err != nil || fault == "wrong-exit-key" && err == nil {
							t.Fatal("actual encrypted entry/exit result", network, fault, err)
						}
					}
				})
			}
		})
	}
}

func nativeMultihopTrafficCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "exit-certificate.example"}, DNSNames: []string{"exit-certificate.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

func nativeMultihopTrafficPort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.LocalAddr().(*net.UDPAddr).Port
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func nativeMultihopTrafficProcess(t *testing.T, binary string, graph map[string]any, readyPort int) {
	t.Helper()
	directory := t.TempDir()
	graph["log"] = map[string]any{"level": "debug", "timestamp": false}
	raw, _ := json.Marshal(graph)
	path := filepath.Join(directory, "native.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(directory, "native.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "run", "-D", directory, "-c", path)
	command.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned native traffic process did not drain")
		}
		_ = log.Close()
		if t.Failed() {
			body, _ := os.ReadFile(log.Name())
			if len(body) > 16000 {
				body = body[len(body)-16000:]
			}
			t.Logf("isolated native fixture diagnostics: %s", body)
		}
	})
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		select {
		case err := <-done:
			t.Fatal("owned native traffic process exited before readiness", err)
		default:
		}
		body, readErr := os.ReadFile(log.Name())
		started := readErr == nil && bytes.Contains(body, []byte("sing-box started"))
		if readyPort != 0 && started {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(readyPort)), 50*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return
			}
		} else if readyPort == 0 && started {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned native traffic process never became ready")
}

func nativeMultihopTrafficEcho(t *testing.T) (int, int) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	closed := false
	t.Cleanup(func() {
		tcp.Close()
		udp.Close()
		mu.Lock()
		defer mu.Unlock()
		closed = true
		for connection := range connections {
			connection.Close()
		}
	})
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			connections[conn] = true
			mu.Unlock()
			go func() {
				_, _ = io.Copy(conn, conn)
				conn.Close()
				mu.Lock()
				delete(connections, conn)
				mu.Unlock()
			}()
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, address, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], address)
		}
	}()
	return tcp.Addr().(*net.TCPAddr).Port, udp.LocalAddr().(*net.UDPAddr).Port
}

func nativeMultihopTrafficExchange(proxy, target int, network string) error {
	return nativeMultihopTrafficExchangeTo(proxy, target, network, [4]byte{127, 0, 0, 1}, 4*time.Second)
}

func nativeMultihopTrafficExchangeTo(proxy, target int, network string, destination [4]byte, timeout time.Duration) error {
	return nativeMultihopTrafficExchangeMarked(proxy, target, network, destination, timeout, nil)
}

func nativeMultihopTrafficExchangeMarked(proxy, target int, network string, destination [4]byte, timeout time.Duration, marker []byte) error {
	control, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxy)), 3*time.Second)
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(timeout))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	hello := make([]byte, 2)
	if _, err := io.ReadFull(control, hello); err != nil {
		return err
	}
	if !bytes.Equal(hello, []byte{5, 0}) {
		return errors.New("native fixture SOCKS authentication rejected")
	}
	request := []byte{5, 1, 0, 1, destination[0], destination[1], destination[2], destination[3], byte(target >> 8), byte(target)}
	if network == "udp" {
		request = []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	}
	if _, err := control.Write(request); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(control, header); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 0 || header[3] != 1 {
		return fmt.Errorf("native fixture SOCKS request rejected: %x", header)
	}
	address := make([]byte, 6)
	if _, err := io.ReadFull(control, address); err != nil {
		return err
	}
	var traffic net.Conn = control
	if network == "udp" {
		relay := int(binary.BigEndian.Uint16(address[4:]))
		traffic, err = net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(relay)))
		if err != nil {
			return err
		}
		defer traffic.Close()
		_ = traffic.SetDeadline(time.Now().Add(timeout))
	}
	for _, size := range []int{64, 1200, 2000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		copy(payload, marker)
		packet := payload
		if network == "udp" {
			packet = append([]byte{0, 0, 0, 1, destination[0], destination[1], destination[2], destination[3], byte(target >> 8), byte(target)}, payload...)
		}
		if _, err := traffic.Write(packet); err != nil {
			return err
		}
		got := make([]byte, len(packet))
		if _, err := io.ReadFull(traffic, got); err != nil {
			return err
		}
		if !bytes.Equal(got, packet) {
			return errors.New("encrypted native TCP/UDP payload changed")
		}
	}
	return nil
}
