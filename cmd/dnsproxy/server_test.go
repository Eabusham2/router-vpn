package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func dnsCLIEnvironment(extra ...string) []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "HOMEVPN_DNS_") && !strings.HasPrefix(entry, "ROUTER_VPN_TEST_DNS_") && !strings.HasPrefix(entry, "GODEBUG=") && !strings.HasPrefix(entry, "GORACE=") {
			env = append(env, entry)
		}
	}
	return append(env, append([]string{"ROUTER_VPN_TEST_DNS_MAIN=1", "GODEBUG=x509usefallbackroots=1", "GORACE=atexit_sleep_ms=0"}, extra...)...)
}

func startDNSCLI(t *testing.T, f *dnsTestH3, useEnvironment bool, name string) (string, func()) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "isolated-ca.pem")
	if err := os.WriteFile(ca, f.pem, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestDNSProxyCLIProcess$", "--", "--listen", "127.0.0.1:0"}
	env := dnsCLIEnvironment("ROUTER_VPN_TEST_DNS_CA=" + ca)
	if useEnvironment {
		env = append(env, "HOMEVPN_DNS_PROTOCOL=doh3", "HOMEVPN_DNS_HOST="+f.upstream.Server,
			"HOMEVPN_DNS_PORT="+strconv.Itoa(f.upstream.Port), "HOMEVPN_DNS_SERVER_NAME="+name, "HOMEVPN_DNS_PATH="+f.upstream.Path)
	} else {
		args = append(args, "--protocol", "h3", "--server", f.upstream.Server, "--port", strconv.Itoa(f.upstream.Port), "--server-name", name, "--path", f.upstream.Path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	command := exec.CommandContext(ctx, os.Args[0], args...)
	command.Env = env
	stderr, err := command.StderrPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	lines := make(chan string, 64)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
			}
		}
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if runtime.GOOS == "windows" {
				// Windows does not implement os.Interrupt for child processes.
				// Context-driven listener/worker shutdown is exercised below.
				_ = command.Process.Kill()
			} else {
				_ = command.Process.Signal(os.Interrupt)
			}
			err := command.Wait()
			cancel()
			<-drained
			if runtime.GOOS != "windows" && err != nil {
				t.Errorf("actual DNS CLI did not shut down cleanly: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	for {
		select {
		case line := <-lines:
			const marker = "RouterVPN DNS listening on "
			if _, rest, found := strings.Cut(line, marker); found {
				address, selected, ok := strings.Cut(rest, " -> ")
				if !ok || selected != describe(f.upstream) {
					t.Fatal("CLI did not retain selected H3 address and port", line)
				}
				return address, stop
			}
		case <-ctx.Done():
			t.Fatal("actual DNS CLI did not open its local listeners", ctx.Err())
		}
	}
}

func TestDNSProxyCLIKernelProbeThroughActualHTTP3(t *testing.T) {
	for _, kind := range []string{"flags", "captured-environment", "wrong-certificate-name"} {
		t.Run(kind, func(t *testing.T) {
			f := newDNSTestH3(t, func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != "/owned-query?node=captured" {
					t.Error("kernel proxy changed the captured resolver path")
				}
				w.Header().Set("content-type", "application/dns-message")
				_, _ = w.Write(dnsTestResponse(t, r))
			})
			name := dnsTestName
			if kind == "wrong-certificate-name" {
				name = "wrong.dns-proxy.invalid"
			}
			address, stop := startDNSCLI(t, f, kind == "captured-environment", name)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			// This is the same randomized-question probe called by the actual
			// kernel tunnel's selected-DNS proof, not a generic reachability ping.
			probeTimeout := 2 * time.Second
			if kind == "wrong-certificate-name" {
				probeTimeout = 300 * time.Millisecond
			}
			elapsed, err := common.ProbeDNSUDP(ctx, address, 1, probeTimeout)
			if kind == "wrong-certificate-name" {
				if err == nil || f.requests.Load() != 0 {
					t.Fatal("wrong TLS identity produced a successful kernel DNS proof", err)
				}
			} else {
				if err != nil || elapsed <= 0 {
					t.Fatal("actual selected H3 CLI failed kernel DNS proof", err)
				}
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					t.Fatal(err)
				}
				localPort, _ := strconv.Atoi(port)
				query := dnsTestQuery(t)
				response, err := dnsTCP(ctx, query, upstream{Server: host, Port: localPort}, false)
				if err != nil || common.ValidateDNSProbeResponse(query, response) != nil || f.requests.Load() != 2 || f.conns.Load() != 1 {
					t.Fatal("local UDP/TCP did not share the captured H3 owner", err, f.requests.Load(), f.conns.Load())
				}
			}
			stop()
			udp, err := net.ListenPacket("udp4", address)
			if err != nil {
				t.Fatal("CLI shutdown retained its UDP listener", err)
			}
			_ = udp.Close()
			tcp, err := net.Listen("tcp4", address)
			if err != nil {
				t.Fatal("CLI shutdown retained its TCP listener", err)
			}
			_ = tcp.Close()
		})
	}
}

func TestDNSProxyCancellationJoinsLocalWorkersAndH3Owner(t *testing.T) {
	entered := make(chan struct{}, 2)
	requestsDone := make(chan struct{}, 2)
	f := newDNSTestH3(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
		requestsDone <- struct{}{}
	})
	resolver, err := newDNSResolver(f.upstream, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- serveDNSProxy(ctx, udp, tcp, resolver) }()
	client, err := net.Dial("udp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = client.Write(dnsTestQuery(t))
	connection, err := net.Dial("tcp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := writeDNSFrame(connection, dnsTestQuery(t)); err != nil {
		t.Fatal(err)
	}
	// A client that never completes its frame must also be cancelled and joined.
	half, err := net.Dial("tcp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer half.Close()
	_, _ = half.Write([]byte{0})
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("real local query did not reach H3 before shutdown")
		}
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy reported no bounded cancellation of owned request workers")
	}
	if err := resolver.Close(); err != nil {
		t.Fatal("proxy failed to join H3 connection/transport/socket", err)
	}
	for range 2 {
		select {
		case <-requestsDone:
		case <-time.After(3 * time.Second):
			t.Fatal("remote HTTP/3 stream remained live after owner close")
		}
	}
	for _, client := range []net.Conn{connection, half} {
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		if count, err := client.Read(one[:]); count != 0 || err == nil {
			t.Fatal("cancelled local TCP worker returned an old response", count, err)
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("cancelled local TCP worker retained its socket", err)
		}
	}
	if _, err := resolver.resolve(context.Background(), dnsTestQuery(t)); err == nil {
		t.Fatal("closed proxy owner accepted a replacement query")
	}
}

func TestDNSProxyListenerFailureCancelsOtherListener(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	defer tcp.Close()
	resolver, err := newDNSResolver(upstream{Protocol: "udp", Server: "192.0.2.53", Port: 53}, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveDNSProxy(context.Background(), udp, tcp, resolver) }()
	_ = udp.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("unexpected listener failure was not surfaced", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed UDP listener did not retire TCP listener")
	}
	if _, err := tcp.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(fmt.Errorf("second listener was not closed: %w", err))
	}
}
