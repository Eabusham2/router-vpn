package mobiletor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var lastRelayTestIdentity = LastRelayIdentity{SessionSHA256: strings.Repeat("1", 64), SourceSHA256: strings.Repeat("2", 64), Generation: 7, Nonce: strings.Repeat("3", 64)}

func lastRelayTestInfo(highwater uint64) string {
	return fmt.Sprintf("version=1 transport=begindir min_ttl_ms=100 max_ttl_ms=10000 max_response_bytes=8192 generation_highwater=%d", highwater)
}

func lastRelayTestFields(identity LastRelayIdentity) map[string]string {
	return map[string]string{"version": "1", "state": "armed", "reason": "captured", "session": identity.SessionSHA256, "source": identity.SourceSHA256,
		"generation": strconv.FormatUint(identity.Generation, 10), "anchor": "111", "circuit": "222", "stream": "0", "relay_stream": "0", "end_reason": "0",
		"exit": strings.Repeat("4", 40), "path_sha256": strings.Repeat("5", 64), "address": identity.address(), "port": "1", "expires_ms": "1000", "request_bytes": "0", "response_bytes": "0"}
}

func lastRelayTestEncode(fields map[string]string) string {
	keys := []string{"version", "state", "reason", "session", "source", "generation", "anchor", "circuit", "stream", "relay_stream", "end_reason", "exit", "path_sha256", "address", "port", "expires_ms", "request_bytes", "response_bytes"}
	var values []string
	for _, key := range keys {
		if value, ok := fields[key]; ok {
			values = append(values, key+"="+value)
		}
	}
	return strings.Join(values, " ")
}

type lastRelayControlWire struct {
	client, server net.Conn
	control        *Control
	done           chan struct{}
	writes         atomic.Int64
	mu             sync.Mutex
	commands       []string
}

func newLastRelayControlWire(t *testing.T, response func(string) string) *lastRelayControlWire {
	t.Helper()
	client, server := net.Pipe()
	control, err := NewControl(client)
	if err != nil {
		t.Fatal(err)
	}
	wire := &lastRelayControlWire{client: client, server: server, control: control, done: make(chan struct{})}
	go func() {
		defer close(wire.done)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if !strings.HasSuffix(line, "\r\n") {
				return
			}
			line = strings.TrimSuffix(line, "\r\n")
			wire.writes.Add(1)
			wire.mu.Lock()
			wire.commands = append(wire.commands, line)
			wire.mu.Unlock()
			if _, err := io.WriteString(server, response(line)); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		select {
		case <-wire.done:
		case <-time.After(time.Second):
			t.Error("last-relay control fixture did not join")
		}
	})
	return wire
}

func TestLastRelayControlExactCapabilityAndOneUseCommandIdentity(t *testing.T) {
	fields := lastRelayTestFields(lastRelayTestIdentity)
	wire := newLastRelayControlWire(t, func(command string) string {
		if command == "ROUTERVPN_LASTRELAY INFO" {
			return "250 " + lastRelayTestInfo(6) + "\r\n"
		}
		if strings.HasPrefix(command, "ROUTERVPN_LASTRELAY CAPTURE ") {
			want := "ROUTERVPN_LASTRELAY CAPTURE " + lastRelayTestIdentity.SessionSHA256 + " " + lastRelayTestIdentity.SourceSHA256 + " 7 1000 111 " + strings.Repeat("a", 32) + " " + strings.Repeat("b", 64) + " " + lastRelayTestIdentity.Nonce
			if command != want {
				t.Errorf("capture command lost exact identity, TTL or isolation")
			}
		} else if strings.HasPrefix(command, "ROUTERVPN_LASTRELAY CLOSE ") {
			fields["state"], fields["reason"], fields["expires_ms"] = "stopped", "controller", "0"
		} else {
			want := "ROUTERVPN_LASTRELAY STATUS " + lastRelayTestIdentity.SessionSHA256 + " " + lastRelayTestIdentity.SourceSHA256 + " 7 " + lastRelayTestIdentity.Nonce
			if command != want {
				t.Errorf("status command changed captured nonce or source")
			}
			fields["state"], fields["stream"], fields["relay_stream"], fields["expires_ms"] = "connected", "333", "7", "900"
		}
		return "250 " + lastRelayTestEncode(fields) + "\r\n"
	})
	capability, err := wire.control.LastRelayInfo(t.Context())
	if err != nil || capability.GenerationHighWater != 6 {
		t.Fatal(capability, err)
	}
	armed, err := wire.control.CaptureLastRelay(t.Context(), lastRelayTestIdentity, time.Second, 111, strings.Repeat("a", 32), strings.Repeat("b", 64))
	if err != nil || armed.State != "armed" || armed.AnchorStream != 111 || armed.Address != lastRelayTestIdentity.address() {
		t.Fatal(armed, err)
	}
	connected, err := wire.control.LastRelayStatus(t.Context(), lastRelayTestIdentity)
	if err != nil || connected.Stream != 333 || connected.RelayStream != 7 || validateLastRelayProgress(armed, connected) != nil {
		t.Fatal(connected, err)
	}
	stopped, err := wire.control.CloseLastRelay(t.Context(), lastRelayTestIdentity)
	if err != nil || stopped.State != "stopped" || stopped.Stream != connected.Stream || validateLastRelayProgress(connected, stopped) != nil || wire.writes.Load() != 4 {
		t.Fatal(stopped, err)
	}
}

func TestLastRelayControlRejectsMalformedOrChangedNativeReceipts(t *testing.T) {
	faults := map[string]string{"version": "2", "state": "ready", "reason": "accepted", "session": strings.Repeat("6", 64), "source": strings.Repeat("7", 64), "generation": "8", "anchor": "0", "circuit": "4294967296", "stream": "111", "relay_stream": "65536", "end_reason": "256", "exit": strings.Repeat("A", 40), "path_sha256": strings.Repeat("x", 64), "address": "unowned.example", "port": "2", "expires_ms": "0", "request_bytes": "999", "response_bytes": "8193"}
	for key, value := range faults {
		t.Run(key, func(t *testing.T) {
			fields := lastRelayTestFields(lastRelayTestIdentity)
			fields[key] = value
			wire := newLastRelayControlWire(t, func(string) string { return "250 " + lastRelayTestEncode(fields) + "\r\n" })
			if _, err := wire.control.LastRelayStatus(t.Context(), lastRelayTestIdentity); err == nil {
				t.Fatal("changed or malformed native status was accepted")
			}
			if _, err := wire.control.LastRelayInfo(t.Context()); err == nil || wire.writes.Load() != 1 {
				t.Fatal("bad native receipt retained its controller authority")
			}
		})
	}
	for _, change := range []string{"duplicate", "missing", "extra", "spaces", "number-leading-zero", "number-sign", "number-fraction", "wrong-nonce", "wrong-generation-address", "oversized", "multiline"} {
		t.Run(change, func(t *testing.T) {
			fields := lastRelayTestFields(lastRelayTestIdentity)
			text := lastRelayTestEncode(fields)
			switch change {
			case "duplicate":
				text += " source=" + lastRelayTestIdentity.SourceSHA256
			case "missing":
				delete(fields, "circuit")
				text = lastRelayTestEncode(fields)
			case "extra":
				text += " elapsed_ms=1"
			case "spaces":
				text = strings.Replace(text, " state=", "  state=", 1)
			case "number-leading-zero":
				text = strings.Replace(text, "anchor=111", "anchor=0111", 1)
			case "number-sign":
				text = strings.Replace(text, "anchor=111", "anchor=+111", 1)
			case "number-fraction":
				text = strings.Replace(text, "anchor=111", "anchor=111.0", 1)
			case "wrong-nonce":
				fields["address"] = strings.Replace(fields["address"], ".333", ".933", 1)
				text = lastRelayTestEncode(fields)
			case "wrong-generation-address":
				fields["address"] = "8" + fields["address"][1:]
				text = lastRelayTestEncode(fields)
			case "oversized":
				text += strings.Repeat("x", 9000)
			case "multiline":
				text += "\r\n250 another=owner"
			}
			wire := newLastRelayControlWire(t, func(string) string {
				if change == "multiline" {
					return "250-" + text + "\r\n"
				}
				return "250 " + text + "\r\n"
			})
			if _, err := wire.control.LastRelayStatus(t.Context(), lastRelayTestIdentity); err == nil {
				t.Fatal("noncanonical status acquired a measurement identity")
			}
		})
	}
}

func TestLastRelayControlCapabilitiesAndArgumentsCannotExpand(t *testing.T) {
	for _, alter := range []func(string) string{
		func(s string) string { return strings.Replace(s, "transport=begindir", "transport=connect", 1) },
		func(s string) string { return strings.Replace(s, "min_ttl_ms=100", "min_ttl_ms=0", 1) },
		func(s string) string { return strings.Replace(s, "max_ttl_ms=10000", "max_ttl_ms=30000", 1) },
		func(s string) string {
			return strings.Replace(s, "max_response_bytes=8192", "max_response_bytes=65536", 1)
		},
		func(s string) string {
			return strings.Replace(s, "generation_highwater=6", "generation_highwater=9223372036854775808", 1)
		},
		func(s string) string { return s + " generation_highwater=6" },
	} {
		wire := newLastRelayControlWire(t, func(string) string { return "250 " + alter(lastRelayTestInfo(6)) + "\r\n" })
		if _, err := wire.control.LastRelayInfo(t.Context()); err == nil {
			t.Fatal("changed native capability was accepted")
		}
	}
	wire := newLastRelayControlWire(t, func(string) string { return "250 " + lastRelayTestInfo(6) + "\r\n" })
	for _, fault := range []string{"session", "source", "nonce", "generation-zero", "generation-large", "ttl-small", "ttl-large", "ttl-fraction", "anchor-zero", "anchor-large", "username", "password"} {
		identity, ttl, anchor, username, password := lastRelayTestIdentity, time.Second, uint64(111), strings.Repeat("a", 32), strings.Repeat("b", 64)
		switch fault {
		case "session":
			identity.SessionSHA256 = strings.Repeat("A", 64)
		case "source":
			identity.SourceSHA256 = "injected\r\nSIGNAL HALT"
		case "nonce":
			identity.Nonce = ""
		case "generation-zero":
			identity.Generation = 0
		case "generation-large":
			identity.Generation = math.MaxUint64
		case "ttl-small":
			ttl = 99 * time.Millisecond
		case "ttl-large":
			ttl = 10001 * time.Millisecond
		case "ttl-fraction":
			ttl = time.Second + time.Nanosecond
		case "anchor-zero":
			anchor = 0
		case "anchor-large":
			anchor = math.MaxUint64
		case "username":
			username = "unowned"
		case "password":
			password = ""
		}
		if _, err := wire.control.CaptureLastRelay(t.Context(), identity, ttl, anchor, username, password); err == nil || wire.writes.Load() != 0 {
			t.Fatal("invalid local argument touched the controller", fault)
		}
	}
	if _, err := wire.control.LastRelayInfo(t.Context()); err != nil {
		t.Fatal("argument rejection retired an untouched valid controller", err)
	}
}

func TestLastRelayReadOnlyDiscoveryBindsActualSocketAndNumericTarget(t *testing.T) {
	locator := LastRelayAnchorLocator{SessionSHA256: lastRelayTestIdentity.SessionSHA256, SourceSHA256: lastRelayTestIdentity.SourceSHA256,
		SOCKSUsername: strings.Repeat("a", 64), SOCKSPassword: strings.Repeat("b", 64), Client: netip.MustParseAddrPort("127.0.0.1:34567"), Target: netip.MustParseAddrPort("1.1.1.1:443")}
	for _, fault := range []string{"", "client", "target", "port", "source", "duplicate", "anchor", "circuit", "path"} {
		t.Run("receipt-"+fault, func(t *testing.T) {
			wire := newLastRelayControlWire(t, func(command string) string {
				arguments, _ := locator.arguments()
				if command != "ROUTERVPN_LASTRELAY ANCHOR "+arguments {
					t.Error("anchor lookup changed captured socket tuple")
				}
				text := "version=1 session=" + locator.SessionSHA256 + " source=" + locator.SourceSHA256 + " anchor=111 circuit=222 exit=" + strings.Repeat("4", 40) + " path_sha256=" + strings.Repeat("5", 64) + " client_ip=127.0.0.1 client_port=34567 target_ip=1.1.1.1 target_port=443"
				switch fault {
				case "client":
					text = strings.Replace(text, "client_ip=127.0.0.1", "client_ip=127.0.0.2", 1)
				case "target":
					text = strings.Replace(text, "target_ip=1.1.1.1", "target_ip=1.0.0.1", 1)
				case "port":
					text = strings.Replace(text, "client_port=34567", "client_port=34568", 1)
				case "source":
					text = strings.Replace(text, "source="+locator.SourceSHA256, "source="+strings.Repeat("9", 64), 1)
				case "duplicate":
					text += " anchor=111"
				case "anchor":
					text = strings.Replace(text, "anchor=111", "anchor=0", 1)
				case "circuit":
					text = strings.Replace(text, "circuit=222", "circuit=0", 1)
				case "path":
					text = strings.Replace(text, strings.Repeat("5", 64), strings.Repeat("z", 64), 1)
				}
				return "250 " + text + "\r\n"
			})
			anchor, err := wire.control.LookupLastRelayAnchor(t.Context(), locator)
			if (err != nil) != (fault != "") || err == nil && (anchor.AnchorStream != 111 || anchor.Circuit != 222 || anchor.Client != locator.Client || anchor.Target != locator.Target) {
				t.Fatal("lookup accepted wrong tuple or lost native path", anchor, err)
			}
		})
	}
	for _, target := range []string{"127.0.0.1:443", "10.0.0.1:443", "[::ffff:1.1.1.1]:443", "[fe80::1%lo]:443", "1.1.1.1:0"} {
		bad := locator
		bad.Target = netip.MustParseAddrPort(target)
		if _, err := bad.arguments(); err == nil {
			t.Fatal("lookup admitted a non-public or noncanonical target", target)
		}
	}
}

func TestLastRelayControlInterruptedFrameRetiresOnlyItsCapturedSocket(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	wire := newLastRelayControlWire(t, func(string) string {
		close(entered)
		<-release
		return "250 " + lastRelayTestInfo(6) + "\r\n"
	})
	other := newLastRelayControlWire(t, func(string) string { return "250 " + lastRelayTestInfo(90) + "\r\n" })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := wire.control.LastRelayInfo(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual framed request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled native frame returned a capability")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled native frame did not unblock")
	}
	close(release)
	if capability, err := other.control.LastRelayInfo(t.Context()); err != nil || capability.GenerationHighWater != 90 {
		t.Fatal("cancellation retired another native controller", capability, err)
	}
	if _, err := wire.control.LastRelayInfo(t.Context()); err == nil || wire.writes.Load() != 1 {
		t.Fatal("cancelled control socket admitted a later reply")
	}
}
