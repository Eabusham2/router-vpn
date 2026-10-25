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

const desktopConfigureCommand = `SETCONF DisableNetwork=1 __ReloadTorrcOnSIGHUP=0 SocksPort="127.0.0.1:19950 IsolateSOCKSAuth" UseBridges=1 ClientTransportPlugin="obfs4 socks5 127.0.0.1:18443" Bridge="` + obfs4Bridge + `"`

type desktopSessionFixture struct {
	wire       *desktopControlFixture
	owner      *DesktopControl
	session    *DesktopBridgeSession
	busy       atomic.Bool
	busySeen   chan struct{}
	mutation   atomic.Int32
	configured atomic.Bool
	enabled    atomic.Bool
	address    atomic.Value
}

func newDesktopSessionFixture(t *testing.T, alter func(string, string, int) string) *desktopSessionFixture {
	t.Helper()
	f := &desktopSessionFixture{busySeen: make(chan struct{}, 1)}
	admitted, quiescing := false, false
	getConfig := func(enabled bool) string {
		reply := strings.Replace(bridgeConfigReply(), "SocksPort=auto IsolateSOCKSAuth", "SocksPort=127.0.0.1:19950 IsolateSOCKSAuth", 1)
		if enabled {
			reply = strings.Replace(reply, "DisableNetwork=1", "DisableNetwork=0", 1)
		}
		return reply
	}
	f.wire = newDesktopControlFixture(t, func(command, reply string, pidReads int) string {
		if command == "TAKEOWNERSHIP" {
			admitted = true
			return reply
		}
		if !admitted {
			return reply
		}
		switch {
		case command == desktopConfigureCommand:
			f.configured.Store(true)
			quiescing = false
			reply = "250 OK\r\n"
		case command == "SETCONF DisableNetwork=0":
			if !f.configured.Load() {
				t.Error("unconfigured session enabled networking")
			}
			f.enabled.Store(true)
			reply = "250 OK\r\n"
		case command == "GETCONF "+configurationKeys:
			if f.configured.Load() {
				reply = getConfig(f.enabled.Load())
			}
		case command == "SIGNAL RELOAD":
			if f.enabled.Load() {
				t.Error("enabled session reloaded bootstrap")
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
				reply = strings.Replace(reply, "orconn-status=\r\n", "orconn-status=old-connection CONNECTED\r\n", 1)
				select {
				case f.busySeen <- struct{}{}:
				default:
				}
			}
		case strings.HasPrefix(command, "GETINFO net/listeners/or "):
			var output strings.Builder
			for _, key := range strings.Fields(strings.TrimPrefix(command, "GETINFO ")) {
				value := ""
				if key == "net/listeners/control" {
					value = strconv.Quote(f.address.Load().(string))
				}
				if key == "net/listeners/socks" && f.enabled.Load() {
					value = `"127.0.0.1:19950"`
				}
				output.WriteString("250-" + key + "=" + value + "\r\n")
			}
			reply = output.String() + "250 OK\r\n"
		case command == "GETINFO status/bootstrap-phase status/circuit-established net/listeners/socks":
			reply = bootstrapReply("100", "1", `"127.0.0.1:19950"`)
		}
		if alter != nil && f.mutation.Load() != 0 {
			return alter(command, reply, pidReads)
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
	f.session, err = NewDesktopBridgeSession(f.owner, desktopPolicy(t, desktopProfile(), "linux"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *desktopSessionFixture) start(t *testing.T) {
	t.Helper()
	if err := f.session.Configure(context.Background(), map[string]string{"obfs4": "127.0.0.1:18443"}); err != nil {
		t.Fatal(err)
	}
	if err := f.session.EnableNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSessionBindsOnePlanAndProvesActualControlReadback(t *testing.T) {
	f := newDesktopSessionFixture(t, nil)
	if f.session.Current() {
		t.Fatal("new session claimed current before configuration")
	}
	if err := f.session.EnableNetwork(context.Background()); err == nil {
		t.Fatal("unconfigured captured session enabled Tor")
	}
	if _, err := NewDesktopBridgeSession(f.owner, desktopPolicy(t, desktopProfile(), "linux")); err == nil {
		t.Fatal("second session claimed same child")
	}
	listeners := map[string]string{"obfs4": "127.0.0.1:18443"}
	if err := f.session.Configure(context.Background(), listeners); err != nil {
		t.Fatal(err)
	}
	listeners["obfs4"] = "127.0.0.1:18444"
	if f.session.Current() {
		t.Fatal("disabled configured session claimed current")
	}
	if err := f.session.EnableNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := f.session.WaitBootstrap(context.Background())
	if err != nil || status.Progress != 100 || !status.CircuitEstablished || status.SOCKSAddress != "127.0.0.1:19950" || !f.session.Current() {
		t.Fatal("captured Tor bootstrap did not match exact enabled owner", status, err)
	}
	if f.session.Metadata().SourceSHA256 != desktopPolicy(t, desktopProfile(), "linux").SourceSHA256() {
		t.Fatal("session lost captured source")
	}
	for _, command := range f.wire.snapshot() {
		if strings.Contains(command, " exec ") || strings.Contains(command, "18444") || strings.HasPrefix(command, "SETCONF Socks5Proxy=") {
			t.Fatal("captured PT selection acquired process bypass or mutable replacement")
		}
	}
	if err := f.session.Configure(context.Background(), listeners); err == nil {
		t.Fatal("old child reconfigured for another listener")
	}
	if _, err := f.session.Verify(context.Background()); err != nil {
		t.Fatal("rejected replacement damaged original session", err)
	}
}

func TestDesktopSessionRejectsUnownedPTAndSocksCollisionsBeforeMutation(t *testing.T) {
	f := newDesktopSessionFixture(t, nil)
	before := len(f.wire.snapshot())
	for _, listeners := range []map[string]string{
		{}, {"obfs4": "0.0.0.0:18443"}, {"obfs4": "127.0.0.1:18443 exec /tmp/helper"},
		{"obfs4": "127.0.0.1:19950"}, {"obfs4": f.wire.address}, {"obfs4": "127.0.0.1:18443", "snowflake": "127.0.0.1:18444"},
	} {
		if err := f.session.Configure(context.Background(), listeners); err == nil {
			t.Fatal("unowned PT listener configured Tor")
		}
		if len(f.wire.snapshot()) != before {
			t.Fatal("invalid PT plan mutated actual child")
		}
	}
	f.start(t)
}

func TestDesktopSessionChangedRuntimeReadbackRetiresOwner(t *testing.T) {
	for name, alter := range map[string]func(string, string, int) string{
		"bridge": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-Bridge="+obfs4Bridge, "250-Bridge="+meekBridge, 1)
		},
		"plugin": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "obfs4 socks5 127.0.0.1:18443", "obfs4 socks5 127.0.0.1:18444", 1)
		},
		"plugin-exec": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "obfs4 socks5 127.0.0.1:18443", "obfs4 exec /private/helper", 1)
		},
		"duplicate-plugin": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-ClientTransportPlugin=obfs4 socks5 127.0.0.1:18443", "250-ClientTransportPlugin=obfs4 socks5 127.0.0.1:18443\r\n250-ClientTransportPlugin=obfs4 socks5 127.0.0.1:18443", 1)
		},
		"socks-policy": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "SocksPort=127.0.0.1:19950 IsolateSOCKSAuth", "SocksPort=127.0.0.1:19950", 1)
		},
		"proxy": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-Socks5Proxy\r\n", "250-Socks5Proxy=private proxy detail\r\n", 1)
		},
		"wrong-child": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "process/pid=13579", "process/pid=24680", 1)
		},
		"extra-dns-listener": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "net/listeners/dns=\r\n", "net/listeners/dns=\"127.0.0.1:5353\"\r\n", 1)
		},
		"wrong-socks-listener": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, `net/listeners/socks="127.0.0.1:19950"`, `net/listeners/socks="127.0.0.1:19951"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDesktopSessionFixture(t, alter)
			f.start(t)
			f.mutation.Store(1)
			if _, err := f.session.Verify(context.Background()); err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("changed captured runtime accepted or private reply exposed", err)
			}
			if f.session.Current() || !errors.Is(f.owner.VerifyProcess(context.Background()), net.ErrClosed) {
				t.Fatal("changed runtime owner revived")
			}
		})
	}
}

func TestDesktopSessionChecksDisabledPlanAgainBeforeEnable(t *testing.T) {
	f := newDesktopSessionFixture(t, func(cmd, reply string, _ int) string {
		return strings.Replace(reply, "DisableNetwork=1", "DisableNetwork=0", 1)
	})
	if err := f.session.Configure(context.Background(), map[string]string{"obfs4": "127.0.0.1:18443"}); err != nil {
		t.Fatal(err)
	}
	f.mutation.Store(1)
	if err := f.session.EnableNetwork(context.Background()); err == nil {
		t.Fatal("changed disabled plan authorized Enable")
	}
	if f.enabled.Load() || f.session.Current() {
		t.Fatal("invalid readback still enabled networking")
	}
}

func TestDesktopSessionFailedConfigurationNeverAuthorizesEnable(t *testing.T) {
	for _, rejectReload := range []bool{false, true} {
		f := newDesktopSessionFixture(t, func(cmd, reply string, _ int) string {
			if rejectReload && cmd == "SIGNAL RELOAD" {
				return "552 reload rejected\r\n"
			}
			if !rejectReload {
				return strings.Replace(reply, "obfs4 socks5 127.0.0.1:18443", "obfs4 socks5 127.0.0.1:18444", 1)
			}
			return reply
		})
		f.mutation.Store(1)
		if f.session.Configure(context.Background(), map[string]string{"obfs4": "127.0.0.1:18443"}) == nil {
			t.Fatal("failed configuration gained captured authority")
		}
		if f.session.EnableNetwork(context.Background()) == nil || f.enabled.Load() || f.session.Current() {
			t.Fatal("failed configuration enabled Tor")
		}
	}
}

func TestDesktopSessionQuiesceWaitsAndCannotReleaseReplacement(t *testing.T) {
	old, replacement := newDesktopSessionFixture(t, nil), newDesktopSessionFixture(t, nil)
	old.start(t)
	replacement.start(t)
	old.busy.Store(true)
	done := make(chan error, 1)
	go func() { done <- old.session.Quiesce(context.Background()) }()
	select {
	case <-old.busySeen:
	case <-time.After(time.Second):
		t.Fatal("quiescence never checked real inventories")
	}
	if old.session.Current() {
		t.Fatal("retiring old session remained current")
	}
	select {
	case <-done:
		t.Fatal("busy old connections were acknowledged quiescent")
	default:
	}
	if _, err := replacement.session.Verify(context.Background()); err != nil {
		t.Fatal("old quiescence disturbed replacement", err)
	}
	old.busy.Store(false)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("quiescent control did not release its barrier")
	}
	before := len(old.wire.snapshot())
	if err := old.session.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(old.wire.snapshot()) != before {
		t.Fatal("idempotent quiescence reopened the old controller")
	}
	if old.session.EnableNetwork(context.Background()) == nil || old.session.Current() {
		t.Fatal("quiesced session revived")
	}
	if _, err := NewDesktopBridgeSession(old.owner, desktopPolicy(t, desktopProfile(), "linux")); err == nil {
		t.Fatal("quiesced child reused for another session")
	}
	if _, err := replacement.session.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSessionQuiesceCancellationDoesNotAcknowledgeDrain(t *testing.T) {
	f := newDesktopSessionFixture(t, nil)
	f.start(t)
	f.busy.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.session.Quiesce(ctx) }()
	select {
	case <-f.busySeen:
	case <-time.After(time.Second):
		t.Fatal("quiescence did not begin")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled quiescence pretended drain")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled quiescence hung")
	}
	if f.session.state.Load() == desktopSessionQuiesced || f.session.Current() {
		t.Fatal("unverified old child acknowledged clean shutdown")
	}
	if f.session.Quiesce(context.Background()) == nil {
		t.Fatal("closed control inferred Tor/PT/process drain")
	}
}
