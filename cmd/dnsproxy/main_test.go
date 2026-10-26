package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This subprocess runs the real shipping main, including flags/environment and
// startup order. A deliberately invalid listen port ensures accepted policy
// also exits before opening a socket. No resolver or tunnel is contacted.
func TestDNSProxyCLIProcess(t *testing.T) {
	if os.Getenv("ROUTER_VPN_TEST_DNS_MAIN") != "1" {
		return
	}
	// A private test CA is installed only in this test entrypoint. The actual
	// command has no insecure/alternate-root switch and uses the OS trust store.
	if path := os.Getenv("ROUTER_VPN_TEST_DNS_CA"); path != "" {
		pem, err := os.ReadFile(path)
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			t.Fatal("invalid isolated test CA", err)
		}
		x509.SetFallbackRoots(pool)
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			flag.CommandLine = flag.NewFlagSet("router-vpn-dns", flag.ExitOnError)
			main()
			return
		}
	}
	t.Fatal("missing subprocess CLI arguments")
}

func TestDNSProxyCLIValidatesSelectedTransportBeforeListener(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		env  string
		want string
	}{
		{"h3", []string{"--protocol", "h3"}, "", "65536"},
		{"doh3", []string{"--protocol", "doh3"}, "", "65536"},
		{"alias-case", []string{"--protocol", " DOH3 "}, "", "65536"},
		{"environment-h3", nil, "HOMEVPN_DNS_PROTOCOL=doh3", "65536"},
		{"hostname", []string{"--protocol", "tls", "--server", "dns.example"}, "", "literal upstream IP"},
		{"bad-port", []string{"--port", "wrong"}, "", "refusing to replace the selected port"},
		{"bad-env-port", nil, "HOMEVPN_DNS_PORT=wrong", "refusing to replace the selected port"},
		{"negative-port", []string{"--port", "-1"}, "", "invalid DNS upstream port"},
		{"large-port", []string{"--port", "65536"}, "", "invalid DNS upstream port"},
		{"bad-path", []string{"--protocol", "https", "--path", "//foreign.example/query"}, "", "local absolute path"},
		{"udp", []string{"--protocol", "udp"}, "", "65536"},
		{"tcp", []string{"--protocol", "tcp"}, "", "65536"},
		{"tls", []string{"--protocol", "tls", "--server-name", "dns.example"}, "", "65536"},
		{"dot", []string{"--protocol", "dot", "--server-name", "dns.example"}, "", "65536"},
		{"https", []string{"--protocol", "https", "--server-name", "dns.example"}, "", "65536"},
		{"doh", []string{"--protocol", "doh", "--server-name", "dns.example"}, "", "65536"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			args := []string{"-test.run=^TestDNSProxyCLIProcess$", "--", "--listen", "127.0.0.1:65536", "--server", "192.0.2.53"}
			args = append(args, test.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "HOMEVPN_DNS_") && !strings.HasPrefix(entry, "ROUTER_VPN_TEST_DNS_MAIN=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, "ROUTER_VPN_TEST_DNS_MAIN=1")
			if test.env != "" {
				cmd.Env = append(cmd.Env, test.env)
			}
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), test.want) || strings.Contains(string(out), "DNS listening") {
				t.Fatalf("real CLI did not reject before listener: %v %s", err, out)
			}
		})
	}
}

func TestDNSProxyTransportDefaultsRetainExplicitPorts(t *testing.T) {
	for protocol, port := range map[string]int{"udp": 53, "tcp": 53, "tls": 853, "dot": 853, "https": 443, "doh": 443, "h3": 443, "doh3": 443} {
		for _, requested := range []int{0, 5443} {
			got, err := normalizeDNSUpstream(upstream{Protocol: protocol, Server: "192.0.2.53", Port: requested, ServerName: "dns.example"})
			want := port
			if requested != 0 {
				want = requested
			}
			if err != nil || got.Port != want {
				t.Fatal("selected transport default or explicit port changed", protocol, requested, got.Port, err)
			}
		}
	}
}

func TestDNSProxyCLIContainsCompletePinnedNotices(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDNSProxyCLIProcess$", "--", "--licenses")
	command.Env = dnsCLIEnvironment("HOMEVPN_DNS_PORT=not-a-port", "HOMEVPN_DNS_HOST=foreign.invalid")
	output, err := command.Output()
	// The test harness appends PASS after main returns. The actual command
	// embeds and prints the exact JSON bytes before any transport/listener work.
	if err != nil || !bytes.HasPrefix(output, dnsProxyNotices) {
		t.Fatal("actual CLI lost its embedded notices", err)
	}
	var payload struct {
		Toolchain string `json:"toolchain"`
		Modules   []struct {
			Path     string            `json:"path"`
			Version  string            `json:"version"`
			Sum      string            `json:"sum"`
			Licenses []json.RawMessage `json:"licenses"`
		} `json:"modules"`
	}
	if json.Unmarshal(dnsProxyNotices, &payload) != nil || payload.Toolchain != "go1.26.3" || len(payload.Modules) != 6 {
		t.Fatal("compiled notices do not describe the pinned H3 dependency closure")
	}
	for _, module := range payload.Modules {
		if module.Path == "" || module.Version == "" || !strings.HasPrefix(module.Sum, "h1:") || len(module.Licenses) == 0 {
			t.Fatal("compiled dependency notice is incomplete")
		}
	}
}
