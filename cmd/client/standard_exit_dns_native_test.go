//go:build linux && routervpn_stock_dns_native

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// This is an actual pinned-core DNS/mixed subgraph acceptance test. It keeps
// the shared compiled proof route and DNS selection unchanged. TUN and the
// encrypted exit are outside this narrow test; a real local responder replaces
// the selected server and a direct outbound replaces that exit boundary.
// Missing native capabilities fail this explicit gate; they never skip it.
type legacyDNSNativeResponder struct {
	endpoint string
	queries  atomic.Int64
	answer   atomic.Bool
	close    func()
}

func newLegacyDNSNativeResponder(t *testing.T, transport string) *legacyDNSNativeResponder {
	t.Helper()
	result := &legacyDNSNativeResponder{}
	result.answer.Store(true)
	reply := func(query []byte) []byte {
		if len(query) < 17 {
			return nil
		}
		result.queries.Add(1)
		if !result.answer.Load() {
			return nil
		}
		response := append([]byte(nil), query[:2]...)
		response = append(response, []byte{0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}...)
		response = append(response, query[12:]...)
		return append(response, []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 203, 0, 113, 20}...)
	}
	if transport == "udp" {
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		result.endpoint = listener.LocalAddr().String()
		done := make(chan struct{})
		go func() {
			defer close(done)
			buffer := make([]byte, 16*1024)
			for {
				n, remote, err := listener.ReadFrom(buffer)
				if err != nil {
					return
				}
				if response := reply(buffer[:n]); response != nil {
					_, _ = listener.WriteTo(response, remote)
				}
			}
		}()
		result.close = func() { _ = listener.Close(); <-done }
	} else {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		result.endpoint = listener.Addr().String()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var workers sync.WaitGroup
		go func() {
			defer close(done)
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					stopped := make(chan struct{})
					stop := context.AfterFunc(ctx, func() { _ = connection.Close(); close(stopped) })
					defer func() {
						if !stop() {
							<-stopped
						}
						_ = connection.Close()
					}()
					for {
						var size [2]byte
						if _, err := io.ReadFull(connection, size[:]); err != nil {
							return
						}
						length := int(binary.BigEndian.Uint16(size[:]))
						if length < 17 || length > 16*1024 {
							return
						}
						query := make([]byte, length)
						if _, err := io.ReadFull(connection, query); err != nil {
							return
						}
						if response := reply(query); response != nil {
							frame := make([]byte, 2+len(response))
							binary.BigEndian.PutUint16(frame, uint16(len(response)))
							copy(frame[2:], response)
							if _, err := connection.Write(frame); err != nil {
								return
							}
						}
					}
				}()
			}
		}()
		result.close = func() { cancel(); _ = listener.Close(); <-done; workers.Wait() }
	}
	t.Cleanup(result.close)
	return result
}

func legacyDNSNativeSubgraph(t *testing.T, endpoint, transport string, cache bool) []byte {
	t.Helper()
	_, a := standardBootstrapCommandFixture(t)
	profile, exit := standardPreparedPolicyFixture(t, "socks5")
	command, err := nativeStandardExitCommand(a, profile, common.RouterProfile{}, exit, true)
	if err != nil {
		t.Fatal(err)
	}
	graph := readStandardPreparedPolicy(t, command.Args[3])
	full, _ := json.Marshal(graph)
	selected, err := expectedDNSSelection(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLegacyStandardDNSGraph(full, selected); err != nil {
		t.Fatal(err)
	}
	dns := graph["dns"].(map[string]any)
	route := graph["route"].(map[string]any)
	proofRule := route["rules"].([]any)[0]
	if !reflect.DeepEqual(proofRule, legacyDNSProofRoute()) || !reflect.DeepEqual(dns["rules"], []any{legacyDNSProofSelection()}) {
		t.Fatal("subgraph lost the actual compiled proof rules")
	}
	var proofInbound any
	for _, raw := range graph["inbounds"].([]any) {
		if raw.(map[string]any)["tag"] == "standard-exit-proof" {
			proofInbound = raw
		}
	}
	if proofInbound == nil {
		t.Fatal("compiled listener missing")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	server := dns["servers"].([]any)[0].(map[string]any)
	server["type"], server["server"], server["server_port"] = transport, host, port
	if cache {
		dns["rules"].([]any)[0].(map[string]any)["disable_cache"] = false
	}
	// Preserve the full compiled DNS object and the actual mixed inbound/rule.
	// The only routing changes remove TUN and substitute the exit boundary.
	subgraph := map[string]any{"log": map[string]any{"level": "warn"}, "dns": dns, "inbounds": []any{proofInbound}, "outbounds": []any{map[string]any{"type": "direct", "tag": "custom-exit"}}, "route": map[string]any{"rules": []any{proofRule}, "final": "custom-exit"}}
	raw, err := json.Marshal(subgraph)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func legacyDNSStartPinnedCore(t *testing.T, binary string, raw []byte) *legacyDNSListener {
	t.Helper()
	directory := t.TempDir()
	config := filepath.Join(directory, "subgraph.json")
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	logfile := filepath.Join(directory, "core.log")
	log, err := os.OpenFile(logfile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	pidfd := -1
	cmd := exec.Command(binary, "run", "-D", directory, "-c", config)
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd, Pdeathsig: syscall.SIGKILL}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	original := os.NewFile(uintptr(pidfd), "original-native-stock-dns-child")
	joined := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(joined) }()
	t.Cleanup(func() {
		// os.Process retains this created process's own pidfd; no PID reacquisition.
		_ = cmd.Process.Kill()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("original pinned core did not join")
		}
		_ = original.Close()
		_ = log.Close()
		current, err := os.ReadFile(config)
		if err != nil || sha256.Sum256(current) != sha256.Sum256(raw) {
			t.Error("native subgraph configuration changed")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		select {
		case <-joined:
			output, _ := os.ReadFile(logfile)
			t.Fatalf("pinned core exited before original DNS listener capture: %v: %s", waitErr, output)
		default:
		}
		listener, err := captureLegacyDNSListener(ctx, original, netip.MustParseAddrPort("127.0.0.1:1099"))
		if err == nil {
			t.Cleanup(func() {
				if err := listener.Close(); err != nil {
					t.Error(err)
				}
			})
			return listener
		}
		if !errors.Is(err, errLegacyDNSListenerNotFound) || ctx.Err() != nil {
			output, _ := os.ReadFile(logfile)
			t.Fatalf("pinned core native listener capture: %v: %s", err, output)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLegacyStandardDNSPinnedCore(t *testing.T) {
	binary := os.Getenv("ROUTERVPN_STOCK_DNS_CORE")
	expected := os.Getenv("ROUTERVPN_STOCK_DNS_CORE_SHA256")
	if !filepath.IsAbs(binary) || len(expected) != 64 {
		t.Fatal("native gate requires the exact completed bundle binary and SHA256")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expected {
		t.Fatal("native gate binary differs from completed bundle")
	}
	t.Cleanup(func() {
		current, err := os.ReadFile(binary)
		if err != nil || sha256.Sum256(current) != digest {
			t.Error("pinned core changed during native acceptance")
		}
	})
	for _, transport := range []string{"udp", "tcp"} {
		for _, cache := range []bool{false, true} {
			name := transport + "-uncached"
			if cache {
				name = transport + "-cached-negative-control"
			}
			t.Run(name, func(t *testing.T) {
				server := newLegacyDNSNativeResponder(t, transport)
				listener := legacyDNSStartPinnedCore(t, binary, legacyDNSNativeSubgraph(t, server.endpoint, transport, cache))
				exchange := func() error {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					return exchangeLegacyStandardDNS(ctx, "127.0.0.1:1099")
				}
				if err := exchange(); err != nil {
					t.Fatal("actual selected resolver exchange failed", err)
				}
				if err := listener.Current(); err != nil {
					t.Fatal(err)
				}
				first := server.queries.Load()
				if first != 1 {
					t.Fatal("selected resolver did not receive exactly the first real query", first)
				}
				server.answer.Store(false)
				err := exchange()
				if cache {
					if err != nil || server.queries.Load() != first {
						t.Fatal("negative control did not expose old cached success after resolver failure", err, server.queries.Load())
					}
				} else if err == nil || server.queries.Load() <= first {
					t.Fatal("uncached selected proof borrowed old success from a dead resolver", err, server.queries.Load())
				}
				if err := listener.Current(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
