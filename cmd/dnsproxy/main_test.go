package main

import (
	"context"
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
		{"h3", []string{"--protocol", "h3"}, "", "refusing to silently downgrade"},
		{"doh3", []string{"--protocol", "doh3"}, "", "refusing to silently downgrade"},
		{"alias-case", []string{"--protocol", " DOH3 "}, "", "refusing to silently downgrade"},
		{"environment-h3", nil, "HOMEVPN_DNS_PROTOCOL=doh3", "refusing to silently downgrade"},
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
	for protocol, port := range map[string]int{"udp": 53, "tcp": 53, "tls": 853, "dot": 853, "https": 443, "doh": 443} {
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
