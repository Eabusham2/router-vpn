package mobiletor

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type serverTorSessionFixture struct {
	wire       *desktopControlFixture
	owner      *DesktopControl
	session    *ServerTorSession
	proxy      *TCPProxy
	command    string
	configured atomic.Bool
	enabled    atomic.Bool
	mutate     atomic.Bool
	busy       atomic.Bool
	progress   atomic.Int32
	busySeen   chan struct{}
	address    atomic.Value
	expected   map[string][]string
}

func newServerTorSessionFixture(t *testing.T, mode string, mutate func(string, string) string) *serverTorSessionFixture {
	t.Helper()
	f := &serverTorSessionFixture{busySeen: make(chan struct{}, 1)}
	f.progress.Store(100)
	f.expected = withEmptyProxies(map[string][]string{
		"DisableNetwork": {"1"}, "__ReloadTorrcOnSIGHUP": {"0"}, "SocksPort": {"127.0.0.1:19950 IsolateSOCKSAuth"}, "UseBridges": {"0"},
		"Bridge": {""}, "ClientTransportPlugin": {""},
	})
	f.command = `SETCONF DisableNetwork=1 __ReloadTorrcOnSIGHUP=0 SocksPort="127.0.0.1:19950 IsolateSOCKSAuth"`
	if mode == "tor" {
		var err error
		f.proxy, err = StartTCPProxy(context.Background(), func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("control-only fixture never opens an Internet socket")
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.proxy.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
		address, username, password, err := f.proxy.binding()
		if err != nil {
			t.Fatal(err)
		}
		f.expected["Socks5Proxy"], f.expected["Socks5ProxyUsername"], f.expected["Socks5ProxyPassword"] = []string{address}, []string{username}, []string{password}
		f.command += " UseBridges=0 Socks5Proxy=" + torQuote(address) + " Socks5ProxyUsername=" + torQuote(username) + " Socks5ProxyPassword=" + torQuote(password)
	} else {
		f.expected["UseBridges"], f.expected["Bridge"], f.expected["ClientTransportPlugin"] = []string{"1"}, []string{obfs4Bridge}, []string{"obfs4 socks5 127.0.0.1:18443"}
		f.command += ` UseBridges=1 ClientTransportPlugin="obfs4 socks5 127.0.0.1:18443" Bridge="` + obfs4Bridge + `"`
	}
	claimed, quiescing := false, false
	f.wire = newDesktopControlFixture(t, func(command, reply string, _ int) string {
		if command == "TAKEOWNERSHIP" {
			claimed = true
			return reply
		}
		if !claimed {
			return reply
		}
		switch {
		case command == f.command:
			f.configured.Store(true)
			quiescing = false
			reply = "250 OK\r\n"
		case command == "SETCONF DisableNetwork=0":
			if !f.configured.Load() {
				t.Error("unconfigured server owner enabled Tor")
			}
			f.enabled.Store(true)
			reply = "250 OK\r\n"
		case command == "GETCONF "+configurationKeys && f.configured.Load():
			var out strings.Builder
			for _, key := range strings.Fields(configurationKeys) {
				values := f.expected[key]
				if key == "DisableNetwork" && f.enabled.Load() {
					values = []string{"0"}
				}
				for _, value := range values {
					out.WriteString("250-" + key)
					if value != "" {
						out.WriteString("=" + value)
					}
					out.WriteString("\r\n")
				}
			}
			reply = out.String() + "250 OK\r\n"
		case command == "SIGNAL RELOAD":
			if f.enabled.Load() {
				t.Error("enabled server owner reloaded bootstrap")
			}
			reply = "250 OK\r\n"
		case command == clearConfiguration:
			f.configured.Store(false)
			f.enabled.Store(false)
			quiescing = true
			reply = "250 OK\r\n"
		case command == "SIGNAL CLEARDNSCACHE":
			reply = "250 OK\r\n"
		case command == "GETINFO "+strings.Join(idleInventories, " "):
			if quiescing && f.busy.Load() {
				reply = strings.Replace(reply, "orconn-status=\r\n", "orconn-status=owned-guard CONNECTED\r\n", 1)
				select {
				case f.busySeen <- struct{}{}:
				default:
				}
			}
		case strings.HasPrefix(command, "GETINFO net/listeners/or "):
			var out strings.Builder
			for _, key := range strings.Fields(strings.TrimPrefix(command, "GETINFO ")) {
				value := ""
				if key == "net/listeners/control" {
					value = strconv.Quote(f.address.Load().(string))
				} else if key == "net/listeners/socks" && f.enabled.Load() {
					value = `"127.0.0.1:19950"`
				}
				out.WriteString("250-" + key + "=" + value + "\r\n")
			}
			reply = out.String() + "250 OK\r\n"
		case command == "GETINFO status/bootstrap-phase status/circuit-established net/listeners/socks":
			circuit := "0"
			if f.progress.Load() == 100 {
				circuit = "1"
			}
			reply = bootstrapReply(strconv.Itoa(int(f.progress.Load())), circuit, `"127.0.0.1:19950"`)
		}
		if f.mutate.Load() && mutate != nil {
			return mutate(command, reply)
		}
		return reply
	})
	f.address.Store(f.wire.address)
	var err error
	f.owner, err = NewDesktopControl(context.Background(), f.wire.connection, f.wire.cookie, f.wire.pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.owner.Close() })
	f.session, err = NewServerTorSession(f.owner, serverTorPolicy(t, serverTorSource(mode)), 19950)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *serverTorSessionFixture) start(t *testing.T) {
	t.Helper()
	listeners := map[string]string{}
	if f.proxy == nil {
		listeners["obfs4"] = "127.0.0.1:18443"
	}
	if err := f.session.Configure(context.Background(), listeners, f.proxy); err != nil {
		t.Fatal(err)
	}
	if err := f.session.EnableNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestServerTorSessionBindsOnlyItsAuthenticatedPlainOrBridgeOwner(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge"} {
		t.Run(mode, func(t *testing.T) {
			f := newServerTorSessionFixture(t, mode, nil)
			if f.session.Current() || f.session.SourceSHA256() != serverTorPolicy(t, serverTorSource(mode)).SourceSHA256() {
				t.Fatal("new no-TUN session claimed current or lost source")
			}
			if err := f.session.EnableNetwork(context.Background()); err == nil {
				t.Fatal("unconfigured owner enabled networking")
			}
			if _, err := NewServerTorSession(f.owner, serverTorPolicy(t, serverTorSource(mode)), 19950); err == nil {
				t.Fatal("second server owner seized the child")
			}
			f.start(t)
			status, err := f.session.WaitBootstrap(context.Background())
			if err != nil || status.Progress != 100 || !status.CircuitEstablished || status.SOCKSAddress != f.session.SocksAddress() || !f.session.Current() {
				t.Fatal("actual control readback did not match captured server path", status, err)
			}
			if err := f.session.Configure(context.Background(), nil, nil); err == nil {
				t.Fatal("old server child admitted replacement configuration")
			}
			if _, err := f.session.Bootstrap(context.Background()); err != nil {
				t.Fatal("rejected replacement damaged the original owner", err)
			}
			if err := f.session.Quiesce(context.Background()); err != nil || f.session.Current() {
				t.Fatal("server Tor failed its control drain", err)
			}
			if err := f.session.EnableNetwork(context.Background()); err == nil {
				t.Fatal("quiesced owner resumed networking")
			}
		})
	}
}

func TestServerTorSessionRejectsWrongGuardAndListenerBindingsBeforeMutation(t *testing.T) {
	plain := newServerTorSessionFixture(t, "tor", nil)
	before := len(plain.wire.snapshot())
	if plain.session.Configure(context.Background(), nil, nil) == nil || plain.session.Configure(context.Background(), map[string]string{"obfs4": "127.0.0.1:18443"}, plain.proxy) == nil || len(plain.wire.snapshot()) != before {
		t.Fatal("plain Tor admitted a missing or mixed guard owner")
	}
	bridge := newServerTorSessionFixture(t, "tor-bridge", nil)
	before = len(bridge.wire.snapshot())
	for _, listeners := range []map[string]string{nil, {"obfs4": "0.0.0.0:18443"}, {"obfs4": "127.0.0.1:19950"}, {"obfs4": bridge.wire.address}, {"obfs4": "127.0.0.1:18443", "meek": "127.0.0.1:18444"}} {
		if bridge.session.Configure(context.Background(), listeners, nil) == nil || len(bridge.wire.snapshot()) != before {
			t.Fatal("unowned bridge listener mutated server Tor")
		}
	}
	if bridge.session.Configure(context.Background(), map[string]string{"obfs4": "127.0.0.1:18443"}, plain.proxy) == nil || len(bridge.wire.snapshot()) != before {
		t.Fatal("bridge server owner borrowed plain guard credentials")
	}
	plain.start(t)
	bridge.start(t)
}

func TestServerTorChangedProcessConfigurationAndGuardRetireItsOwner(t *testing.T) {
	mutations := map[string]func(string, string) string{
		"process": func(_, reply string) string {
			return strings.Replace(reply, "process/pid=13579", "process/pid=24680", 1)
		},
		"socks": func(_, reply string) string { return strings.ReplaceAll(reply, "127.0.0.1:19950", "127.0.0.1:19951") },
		"plugin-exec": func(_, reply string) string {
			return strings.Replace(reply, "obfs4 socks5 127.0.0.1:18443", "obfs4 exec /private/helper", 1)
		},
		"bridge": func(_, reply string) string { return strings.Replace(reply, obfs4Bridge, meekBridge, 1) },
		"extra-dns": func(_, reply string) string {
			return strings.Replace(reply, "net/listeners/dns=\r\n", "net/listeners/dns=\"127.0.0.1:5353\"\r\n", 1)
		},
		"proxy": func(_, reply string) string {
			return strings.Replace(reply, "250-Socks5Proxy\r\n", "250-Socks5Proxy=private replacement\r\n", 1)
		},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newServerTorSessionFixture(t, "tor-bridge", mutation)
			f.start(t)
			f.mutate.Store(true)
			if _, err := f.session.Bootstrap(context.Background()); err == nil || strings.Contains(err.Error(), "private replacement") || f.session.Current() {
				t.Fatal("changed child retained authority or leaked captured values")
			}
		})
	}
	f := newServerTorSessionFixture(t, "tor", nil)
	f.start(t)
	if err := f.proxy.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.session.Bootstrap(context.Background()); err == nil || f.session.Current() {
		t.Fatal("closed plain guard retained server Tor authority")
	}
}

func TestServerTorQuiescenceWaitsForItsActualConnectionsAndCancelNeverRevives(t *testing.T) {
	f := newServerTorSessionFixture(t, "tor-bridge", nil)
	f.start(t)
	f.busy.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.session.Quiesce(ctx) }()
	select {
	case <-f.busySeen:
	case <-ctx.Done():
		t.Fatal("quiescence never inspected owned connections")
	}
	if f.session.Current() {
		t.Fatal("retiring Tor owner remained current")
	}
	select {
	case err := <-done:
		t.Fatal("control drain acknowledged a live connection", err)
	default:
	}
	f.busy.Store(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cancelled := newServerTorSessionFixture(t, "tor-bridge", nil)
	cancelled.start(t)
	cancelled.progress.Store(50)
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := cancelled.session.WaitBootstrap(ctx); err == nil || cancelled.session.Current() {
		t.Fatal("cancelled bootstrap accepted a partial circuit")
	}
	// Even a later successful native status cannot grant readiness to that
	// retired session; the control owner is permanent, never reauthenticated.
	cancelled.progress.Store(100)
	if _, err := cancelled.session.Bootstrap(context.Background()); err == nil {
		t.Fatal("late bootstrap revived a cancelled operation")
	}
}
