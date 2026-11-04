package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func standardBootstrapCommandFixture(t *testing.T) (string, *app) {
	t.Helper()
	root := desktopAWGPrivateTestRoot(t)
	for _, path := range []string{"modes/native-standard-exit-linux.sh", "modes/native-multihop-darwin.sh", "client/native-multihop-windows.ps1"} {
		path = filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		// Preparation validates helper presence; this test never starts a helper.
		if err := os.WriteFile(path, []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOMEVPN_ROOT", root)
	return root, &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")}}
}

func standardBootstrapCommandDirectory(t *testing.T, command *exec.Cmd, endpoint string) string {
	t.Helper()
	if command == nil {
		t.Fatal("shipping builder returned no command")
	}
	var directory string
	for i, value := range command.Args {
		if (value == "-RuntimeDir" || value == "up") && i+1 < len(command.Args) {
			directory = command.Args[i+1]
			break
		}
	}
	if directory == "" {
		t.Fatal("shipping helper lost its prepared directory")
	}
	var endpoints []string
	for _, value := range command.Env {
		if strings.HasPrefix(value, "HOMEVPN_ENDPOINT=") {
			endpoints = append(endpoints, strings.TrimPrefix(value, "HOMEVPN_ENDPOINT="))
		}
	}
	if len(endpoints) == 0 || endpoints[len(endpoints)-1] != endpoint {
		t.Fatal("shipping helper did not receive the captured physical endpoint", endpoints)
	}
	return directory
}

func assertNoStandardBootstrapWorkspace(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "run", "native-standard-exit"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed bootstrap left a runnable workspace", entries)
	}
}

func TestStandardBootstrapShippingCommandsFreezeEveryStockProtocol(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			_, a := standardBootstrapCommandFixture(t)
			control, exit := standardPreparedPolicyFixture(t, protocol)
			exit.Server = "transport.example.test"
			control.MTUPolicy, control.ManualMTU = "manual", 1320
			before, err := json.Marshal([]any{control, exit})
			if err != nil {
				t.Fatal(err)
			}
			queries := []string{}
			bootstrap := standardExitBootstrap{network: func() string { return "captured-interface-generation" }, lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
				queries = append(queries, host)
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
					t.Fatal("endpoint lookup lacks its bounded operation deadline")
				}
				return []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("203.0.113.20")}, nil
			}}
			command, err := nativeStandardExitCommandWithBootstrap(a, control, common.RouterProfile{}, exit, true, bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			directory := standardBootstrapCommandDirectory(t, command, "203.0.113.20")
			graph := readStandardPreparedPolicy(t, directory)
			assertStandardPreparedDevicePolicy(t, graph, 1320, true, true, "custom-exit")
			literal := exit
			literal.Server = "203.0.113.20"
			endpoint, outbound, err := directStandardExitRuntimeParts(literal)
			if err != nil {
				t.Fatal(err)
			}
			family, expected := "outbounds", outbound
			if endpoint != nil {
				family, expected = "endpoints", endpoint
			}
			actual := graph[family].([]any)[0].(map[string]any)
			for _, field := range []string{"private_key", "peers", "password", "username", "server", "server_port", "tls"} {
				want, _ := json.Marshal(expected[field])
				got, _ := json.Marshal(actual[field])
				if string(want) != string(got) {
					t.Fatalf("bootstrap changed captured %s: %s != %s", field, got, want)
				}
			}
			after, _ := json.Marshal([]any{control, exit})
			if string(before) != string(after) || !reflect.DeepEqual(queries, []string{"transport.example.test"}) {
				t.Fatal("bootstrap changed saved source or queried a non-transport destination", queries)
			}
		})
	}
}

func TestStandardBootstrapShippingCommandsCaptureBothEntryKinds(t *testing.T) {
	for _, kind := range []string{"external", "external-shared-host", "router-vpn"} {
		t.Run(kind, func(t *testing.T) {
			root, a := standardBootstrapCommandFixture(t)
			control, exit := standardPreparedPolicyFixture(t, "socks5")
			exit.Server = "exit.example.test"
			var entry common.RouterProfile
			var sourcePath, sourceConfig string
			detour := "custom-exit"
			if kind == "router-vpn" {
				entry = common.RouterProfile{ID: "captured-router", NodeKind: "router-vpn", NodeProofID: strings.Repeat("c", 64), Endpoint: "entry.example.test:51820", IPv6Mode: "on", HomeLANAccess: true, MTUPolicy: "auto", RouterAPI: "http://10.77.0.1:8787", APIToken: "captured-private-test-token", AdGuardIPv4: "10.77.0.1"}
				generated, err := nativeGeneratedDir(root, entry.ID, "wg")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(generated, 0700); err != nil {
					t.Fatal(err)
				}
				sourcePath = filepath.Join(generated, "wg.conf")
				sourceConfig = fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.66.0.2/32\nMTU = 1500\n[Peer]\nPublicKey = %s\nEndpoint = entry.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n", testWGKey('c'), testWGKey('d'))
				if err := os.WriteFile(sourcePath, []byte(sourceConfig), 0600); err != nil {
					t.Fatal(err)
				}
				control.DNSMode, control.DNSHost, detour = "home", "10.77.0.1", "entry-wg"
			} else {
				upstream := validTestStandardExit("socks5")
				upstream.ID, upstream.Server = "captured-entry", "entry.example.test"
				if kind == "external-shared-host" {
					upstream.Server = "EXIT.example.test"
				}
				var err error
				entry, err = desktopExternalCapture(control, upstream)
				if err != nil {
					t.Fatal(err)
				}
				entry.HomeLANAccess, entry.IPv6Mode = true, "on"
			}
			before, err := json.Marshal([]any{control, entry, exit})
			if err != nil {
				t.Fatal(err)
			}
			queries := []string{}
			bootstrap := standardExitBootstrap{network: func() string { return "captured-network" }, lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
				queries = append(queries, host)
				address := "203.0.113.20"
				if host == "entry.example.test" {
					address = "198.51.100.20"
				}
				return []netip.Addr{netip.MustParseAddr(address)}, nil
			}}
			var command *exec.Cmd
			if kind == "router-vpn" {
				command, err = nativeStandardExitCommandWithBootstrap(a, control, entry, exit, false, bootstrap)
			} else {
				command, err = nativeExternalEntryStandardExitCommandWithBootstrap(a, control, entry, exit, bootstrap)
			}
			if err != nil {
				t.Fatal(err)
			}
			physical := "198.51.100.20"
			wantQueries := []string{"exit.example.test", "entry.example.test"}
			if kind == "external-shared-host" {
				physical, wantQueries = "203.0.113.20", []string{"exit.example.test"}
			}
			graph := readStandardPreparedPolicy(t, standardBootstrapCommandDirectory(t, command, physical))
			assertStandardPreparedDevicePolicy(t, graph, 1280, true, true, detour)
			after, _ := json.Marshal([]any{control, entry, exit})
			if string(before) != string(after) || !reflect.DeepEqual(queries, wantQueries) {
				t.Fatal("entry bootstrap changed captured source or did not resolve each distinct transport once", queries)
			}
			if sourcePath != "" {
				raw, err := os.ReadFile(sourcePath)
				if err != nil || string(raw) != sourceConfig {
					t.Fatal("bootstrap modified the linked router's private source", err)
				}
			}
		})
	}
}

func TestStandardBootstrapRejectsInvalidWholeGraphBeforeLookup(t *testing.T) {
	for _, fault := range []string{"manual-mtu", "unknown-mtu", "unknown-ipv6", "missing-key", "tcp-only-udp", "tcp-only-h3", "resolver-hostname", "paired-response"} {
		t.Run(fault, func(t *testing.T) {
			root := desktopAWGPrivateTestRoot(t)
			control, exit := standardPreparedPolicyFixture(t, "http-connect")
			exit.Server = "exit.example.test"
			switch fault {
			case "manual-mtu":
				control.MTUPolicy, control.ManualMTU = "manual", 9001
			case "unknown-mtu":
				control.MTUPolicy = "guess"
			case "unknown-ipv6":
				control.IPv6Mode = "guess"
			case "missing-key":
				exit = validTestStandardExit("wireguard")
				exit.Server, exit.WGPrivateKey = "exit.example.test", ""
			case "tcp-only-udp":
				control.DNSProtocol = "udp"
			case "tcp-only-h3":
				control.DNSMode, control.DNSProtocol, control.DNSServerName = "doh3", "h3", "resolver.example.test"
			case "resolver-hostname":
				control.DNSHost = "resolver.example.test"
			case "paired-response":
				exit.ResponseProbe = &common.ExternalResponseProbe{}
			}
			queries := 0
			bootstrap := standardExitBootstrap{network: func() string { return "network" }, lookup: func(context.Context, string) ([]netip.Addr, error) {
				queries++
				return []netip.Addr{netip.MustParseAddr("203.0.113.20")}, nil
			}}
			result, err := prepareCapturedStandardExit(context.Background(), root, control, common.RouterProfile{}, exit, true, bootstrap)
			if err == nil || result.directory != "" || queries != 0 {
				t.Fatal("invalid whole graph reached endpoint lookup or runtime preparation", err, queries)
			}
			assertNoStandardBootstrapWorkspace(t, root)
		})
	}
}

func TestStandardBootstrapRejectsUnusableAnswers(t *testing.T) {
	for _, fault := range []string{"empty", "error", "too-many", "private", "loopback", "mapped", "unspecified", "multicast", "shared-address", "ipv6-off"} {
		t.Run(fault, func(t *testing.T) {
			root := desktopAWGPrivateTestRoot(t)
			control, exit := standardPreparedPolicyFixture(t, "socks5")
			exit.Server = "exit.example.test"
			bootstrap := standardExitBootstrap{network: func() string { return "network" }, lookup: func(context.Context, string) ([]netip.Addr, error) {
				switch fault {
				case "empty":
					return nil, nil
				case "error":
					return nil, errors.New("endpoint lookup failed")
				case "too-many":
					return make([]netip.Addr, 33), nil
				}
				address := map[string]string{"private": "192.168.50.1", "loopback": "127.0.0.1", "mapped": "::ffff:203.0.113.20", "unspecified": "0.0.0.0", "multicast": "224.0.0.1", "shared-address": "100.64.0.1", "ipv6-off": "2001:db8::20"}[fault]
				return []netip.Addr{netip.MustParseAddr(address)}, nil
			}}
			result, err := prepareCapturedStandardExit(context.Background(), root, control, common.RouterProfile{}, exit, true, bootstrap)
			if err == nil || result.directory != "" {
				t.Fatal("unusable endpoint answer produced a runnable graph", err)
			}
			assertNoStandardBootstrapWorkspace(t, root)
		})
	}
}

func TestStandardBootstrapRetiresCancellationAndNetworkChanges(t *testing.T) {
	for _, fault := range []string{"cancelled", "lookup-cancel", "empty-network", "before-query", "after-query", "before-write", "after-write"} {
		t.Run(fault, func(t *testing.T) {
			root := desktopAWGPrivateTestRoot(t)
			control, exit := standardPreparedPolicyFixture(t, "socks5")
			exit.Server = "exit.example.test"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "cancelled" {
				cancel()
			}
			networkReads := 0
			bootstrap := standardExitBootstrap{network: func() string {
				networkReads++
				if fault == "empty-network" {
					return ""
				}
				changeAt := map[string]int{"before-query": 2, "after-query": 3, "before-write": 4, "after-write": 5}[fault]
				if changeAt != 0 && networkReads >= changeAt {
					return "replacement-network"
				}
				return "original-network"
			}, lookup: func(context.Context, string) ([]netip.Addr, error) {
				if fault == "lookup-cancel" {
					cancel()
				}
				return []netip.Addr{netip.MustParseAddr("203.0.113.20")}, nil
			}}
			result, err := prepareCapturedStandardExit(ctx, root, control, common.RouterProfile{}, exit, true, bootstrap)
			if err == nil || result.directory != "" {
				t.Fatal("retired bootstrap produced a runnable graph", err)
			}
			assertNoStandardBootstrapWorkspace(t, root)
		})
	}
}

func TestStandardBootstrapLiteralAndIPv6Policy(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprint(ipv6), func(t *testing.T) {
			root := desktopAWGPrivateTestRoot(t)
			control, exit := standardPreparedPolicyFixture(t, "socks5")
			bootstrap := standardExitBootstrap{}
			want := exit.Server
			if ipv6 {
				control.IPv6Mode = "on"
				exit.Server, want = "ipv6.example.test", "2001:db8::20"
				bootstrap = standardExitBootstrap{network: func() string { return "network" }, lookup: func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr(want)}, nil
				}}
			}
			result, err := prepareCapturedStandardExit(context.Background(), root, control, common.RouterProfile{}, exit, true, bootstrap)
			if err != nil || result.endpoint != want {
				t.Fatal("literal endpoint or enabled IPv6 policy was lost", result.endpoint, err)
			}
			assertStandardPreparedDevicePolicy(t, readStandardPreparedPolicy(t, result.directory), 1280, true, !ipv6, "custom-exit")
		})
	}
}
