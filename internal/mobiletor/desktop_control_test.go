package mobiletor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type desktopControlFixture struct {
	connection net.Conn
	address    string
	cookie     []byte
	pid        int
	mu         sync.Mutex
	commands   []string
	done       chan struct{}
	seen       chan string
	alter      func(string, string, int) string
}

func newDesktopControlFixture(t *testing.T, alter func(string, string, int) string) *desktopControlFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &desktopControlFixture{address: listener.Addr().String(), cookie: bytes.Repeat([]byte{0x91}, 32), pid: 13579, done: make(chan struct{}), seen: make(chan string, 64), alter: alter}
	connection, err := net.Dial("tcp4", fixture.address)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	fixture.connection = connection
	server, err := listener.Accept()
	listener.Close()
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(); server.Close(); <-fixture.done })
	go func() {
		defer close(fixture.done)
		defer server.Close()
		reader := bufio.NewReader(server)
		var clientHash []byte
		pidReads := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.TrimSuffix(line, "\r\n")
			fixture.mu.Lock()
			fixture.commands = append(fixture.commands, command)
			fixture.mu.Unlock()
			fixture.seen <- command
			reply := "250 OK\r\n"
			switch {
			case strings.HasPrefix(command, "AUTHCHALLENGE SAFECOOKIE "):
				nonce, err := hex.DecodeString(strings.TrimPrefix(command, "AUTHCHALLENGE SAFECOOKIE "))
				if err != nil || len(nonce) != 32 {
					t.Error("client challenge omitted its fresh nonce")
					return
				}
				serverNonce := bytes.Repeat([]byte{0x73}, 32)
				transcript := append(append(append([]byte(nil), fixture.cookie...), nonce...), serverNonce...)
				serverHMAC := hmac.New(sha256.New, []byte("Tor safe cookie authentication server-to-controller hash"))
				_, _ = serverHMAC.Write(transcript)
				clientHMAC := hmac.New(sha256.New, []byte("Tor safe cookie authentication controller-to-server hash"))
				_, _ = clientHMAC.Write(transcript)
				clientHash = clientHMAC.Sum(nil)
				reply = "250 AUTHCHALLENGE SERVERHASH=" + hex.EncodeToString(serverHMAC.Sum(nil)) + " SERVERNONCE=" + hex.EncodeToString(serverNonce) + "\r\n"
			case strings.HasPrefix(command, "AUTHENTICATE "):
				value, err := hex.DecodeString(strings.TrimPrefix(command, "AUTHENTICATE "))
				if err != nil || clientHash == nil || !hmac.Equal(value, clientHash) || bytes.Equal(value, fixture.cookie) {
					t.Error("client failed SAFECOOKIE response or disclosed cookie")
					return
				}
			case command == "GETINFO process/pid net/listeners/control":
				pidReads++
				reply = fmt.Sprintf("250-process/pid=%d\r\n250-net/listeners/control=%s\r\n250 OK\r\n", fixture.pid, strconv.Quote(fixture.address))
			case command == "GETCONF "+configurationKeys:
				reply = idleConfigReply
			case command == "GETINFO "+strings.Join(idleInventories, " "):
				reply = strings.Replace(inventoryReply(""), "net/listeners/control=\r\n", "net/listeners/control="+strconv.Quote(fixture.address)+"\r\n", 1)
			case command == "TAKEOWNERSHIP":
			default:
				if alter == nil {
					t.Error("unexpected standalone control command", command)
					return
				}
				reply = "552 fixture has no such command\r\n"
			}
			if alter != nil {
				reply = alter(command, reply, pidReads)
			}
			if reply != "" {
				if _, err := io.WriteString(server, reply); err != nil {
					return
				}
			}
		}
	}()
	return fixture
}

func (f *desktopControlFixture) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

func TestDesktopControlSAFECOOKIEBindsActualProcessAndSoleListener(t *testing.T) {
	var nonces []string
	for range 2 {
		fixture := newDesktopControlFixture(t, nil)
		cookie := append([]byte(nil), fixture.cookie...)
		control, err := NewDesktopControl(context.Background(), fixture.connection, cookie, fixture.pid)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cookie, fixture.cookie) || control.PID() != fixture.pid || control.Address() != fixture.address {
			t.Fatal("authentication modified the caller cookie or captured owner")
		}
		if err := control.VerifyProcess(context.Background()); err != nil {
			t.Fatal(err)
		}
		commands := fixture.snapshot()
		if len(commands) != 7 || !strings.HasPrefix(commands[0], "AUTHCHALLENGE SAFECOOKIE ") || !strings.HasPrefix(commands[1], "AUTHENTICATE ") || commands[2] != "GETINFO process/pid net/listeners/control" || commands[3] != "GETCONF "+configurationKeys || commands[4] != "GETINFO "+strings.Join(idleInventories, " ") || commands[5] != "TAKEOWNERSHIP" {
			t.Fatal("authentication/process/startup/ownership ordering changed")
		}
		nonces = append(nonces, commands[0])
		if strings.Contains(strings.Join(commands, "\n"), hex.EncodeToString(cookie)) {
			t.Fatal("raw cookie appeared on control wire")
		}
		if err := control.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(control.VerifyProcess(context.Background()), net.ErrClosed) {
			t.Fatal("closed owner was reusable")
		}
	}
	if nonces[0] == nonces[1] {
		t.Fatal("authentication reused its client nonce")
	}
}

func TestDesktopControlRejectsWrongCookiePIDListenerAndEnabledStartup(t *testing.T) {
	for name, alter := range map[string]func(string, string, int) string{
		"wrong-hmac": func(cmd, reply string, _ int) string {
			if strings.HasPrefix(cmd, "AUTHCHALLENGE ") {
				return "250 AUTHCHALLENGE SERVERHASH=" + strings.Repeat("0", 64) + " SERVERNONCE=" + strings.Repeat("0", 64) + "\r\n"
			}
			return reply
		},
		"duplicate-challenge": func(cmd, reply string, _ int) string {
			if strings.HasPrefix(cmd, "AUTHCHALLENGE ") {
				return "250 AUTHCHALLENGE SERVERHASH=" + strings.Repeat("0", 64) + " SERVERHASH=" + strings.Repeat("1", 64) + "\r\n"
			}
			return reply
		},
		"authentication-rejected": func(cmd, reply string, _ int) string {
			if strings.HasPrefix(cmd, "AUTHENTICATE ") {
				return "515 private authentication detail\r\n"
			}
			return reply
		},
		"wrong-pid": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "process/pid=13579", "process/pid=13580", 1)
		},
		"duplicate-pid": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-process/pid=13579", "250-process/pid=13579\r\n250-process/pid=13579", 1)
		},
		"missing-pid": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-process/pid=13579\r\n", "", 1)
		},
		"other-control": func(cmd, reply string, _ int) string {
			if cmd == "GETINFO process/pid net/listeners/control" {
				return "250-process/pid=13579\r\n250-net/listeners/control=\"127.0.0.1:19999\"\r\n250 OK\r\n"
			}
			return reply
		},
		"extra-control": func(cmd, reply string, _ int) string {
			if cmd == "GETINFO process/pid net/listeners/control" {
				return strings.Replace(reply, "\"\r\n250 OK", "\" \"127.0.0.1:19999\"\r\n250 OK", 1)
			}
			return reply
		},
		"enabled-network": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "DisableNetwork=1", "DisableNetwork=0", 1)
		},
		"torrc-reload": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "__ReloadTorrcOnSIGHUP=0", "__ReloadTorrcOnSIGHUP=1", 1)
		},
		"external-pt-process": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-ClientTransportPlugin\r\n", "250-ClientTransportPlugin=obfs4 exec /private/helper\r\n", 1)
		},
		"old-socks-listener": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-SocksPort=0", "250-SocksPort=19050", 1)
		},
		"old-proxy": func(cmd, reply string, _ int) string {
			return strings.Replace(reply, "250-Socks5Proxy\r\n", "250-Socks5Proxy=private proxy detail\r\n", 1)
		},
		"live-or-connection": func(cmd, reply string, _ int) string {
			if strings.HasPrefix(cmd, "GETINFO orconn-status") {
				return strings.Replace(reply, "orconn-status=\r\n", "orconn-status=private OR connection\r\n", 1)
			}
			return reply
		},
		"unowned-listener": func(cmd, reply string, _ int) string {
			if strings.HasPrefix(cmd, "GETINFO orconn-status") {
				return strings.Replace(reply, "net/listeners/dns=\r\n", "net/listeners/dns=\"0.0.0.0:5353\"\r\n", 1)
			}
			return reply
		},
		"cached-address": func(cmd, reply string, _ int) string {
			if strings.HasPrefix(cmd, "GETINFO orconn-status") {
				return strings.Replace(reply, "address-mappings/cache=\r\n", "address-mappings/cache=private lookup\r\n", 1)
			}
			return reply
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDesktopControlFixture(t, alter)
			owner, err := NewDesktopControl(context.Background(), fixture.connection, fixture.cookie, fixture.pid)
			if err == nil || owner != nil || strings.Contains(err.Error(), "private") {
				t.Fatal("unowned control admitted or private daemon reply exposed", err)
			}
			for _, command := range fixture.snapshot() {
				if command == "TAKEOWNERSHIP" {
					t.Fatal("unverified process was seized")
				}
			}
			select {
			case <-fixture.done:
			case <-time.After(time.Second):
				t.Fatal("failed authentication retained the real socket")
			}
		})
	}
}

func TestDesktopControlRetiresAfterChangedProcessOrCanceledRead(t *testing.T) {
	for _, cancellation := range []bool{false, true} {
		fixture := newDesktopControlFixture(t, func(cmd, reply string, pidReads int) string {
			if cmd == "GETINFO process/pid net/listeners/control" && pidReads == 2 {
				if cancellation {
					return ""
				}
				return strings.Replace(reply, "process/pid=13579", "process/pid=24680", 1)
			}
			return reply
		})
		owner, err := NewDesktopControl(context.Background(), fixture.connection, fixture.cookie, fixture.pid)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- owner.VerifyProcess(ctx) }()
		if cancellation {
			for count := 0; count < 2; {
				if <-fixture.seen == "GETINFO process/pid net/listeners/control" {
					count++
				}
			}
			cancel()
		}
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("changed or canceled process still owned")
			}
		case <-time.After(time.Second):
			t.Fatal("control cancellation did not unblock its real read")
		}
		cancel()
		if !errors.Is(owner.VerifyProcess(context.Background()), net.ErrClosed) {
			t.Fatal("retired desktop control revived")
		}
		select {
		case <-fixture.done:
		case <-time.After(time.Second):
			t.Fatal("retired owner retained its control socket")
		}
	}
}

func TestDesktopControlMalformedChallengeAndInvalidCapture(t *testing.T) {
	for _, reply := range [][]string{nil, {"AUTHCHALLENGE"}, {"AUTHCHALLENGE SERVERHASH=00 SERVERNONCE=00"}, {"AUTHCHALLENGE SERVERHASH=" + strings.Repeat("0", 64) + " OTHER=" + strings.Repeat("0", 64)}, {"AUTHCHALLENGE SERVERHASH=" + strings.Repeat("g", 64) + " SERVERNONCE=" + strings.Repeat("0", 64)}, {"AUTHCHALLENGE SERVERHASH=" + strings.Repeat("0", 64) + " SERVERNONCE=" + strings.Repeat("0", 64), "unexpected"}} {
		if _, _, err := desktopChallenge(reply); err == nil {
			t.Fatal("malformed challenge admitted")
		}
	}
	for _, capture := range []struct {
		cookie []byte
		pid    int
	}{{nil, 13579}, {make([]byte, 31), 13579}, {make([]byte, 33), 13579}, {make([]byte, 32), 0}} {
		fixture := newDesktopControlFixture(t, nil)
		if owner, err := NewDesktopControl(context.Background(), fixture.connection, capture.cookie, capture.pid); err == nil || owner != nil {
			t.Fatal("invalid capture admitted")
		}
		if len(fixture.snapshot()) != 0 {
			t.Fatal("invalid capture performed authentication")
		}
	}
	for _, address := range []net.Addr{nil, &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 19051}, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 19051}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}, &net.UnixAddr{Name: "/private/socket", Net: "unix"}} {
		if _, err := desktopLoopbackAddress(address); err == nil {
			t.Fatal("unowned desktop control address admitted")
		}
	}
}
