package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func proxyTestClient(t *testing.T, proxy *TCPProxy, user, password string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", proxy.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte{5, 2, 0, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil || reply != [2]byte{5, 2} {
		t.Fatal("private proxy did not require RFC1929", err)
	}
	request := append([]byte{1, byte(len(user))}, []byte(user)...)
	request = append(request, byte(len(password)))
	request = append(request, []byte(password)...)
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(connection, reply[:]); err != nil {
		t.Fatal(err)
	}
	if user == proxy.username && password == proxy.password {
		if reply != [2]byte{1, 0} {
			t.Fatal("current private proxy authentication failed")
		}
	} else if reply != [2]byte{1, 1} {
		t.Fatal("another session's credentials authenticated")
	}
	return connection
}

func proxyTestRequest(destination string) []byte {
	endpoint := netip.MustParseAddrPort(destination)
	address := endpoint.Addr()
	kind := byte(4)
	if address.Is4() {
		kind = 1
	}
	request := append([]byte{5, 1, 0, kind}, address.AsSlice()...)
	return binary.BigEndian.AppendUint16(request, endpoint.Port())
}

func proxyTestReply(t *testing.T, connection net.Conn, success bool) {
	t.Helper()
	var reply [10]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[2] != 0 || (reply[1] == 0) != success {
		t.Fatal("unexpected private proxy CONNECT outcome")
	}
}

func TestTCPProxyActualPayloadUsesCapturedLiteralTCP(t *testing.T) {
	for _, target := range []string{"203.0.113.17:9001", "[2001:db8::17]:443"} {
		t.Run(target, func(t *testing.T) {
			var calls atomic.Int32
			peerDone := make(chan struct{})
			proxy, err := StartTCPProxy(context.Background(), func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != target {
					t.Error("ordinary Tor escaped its captured literal TCP destination")
					return nil, net.ErrClosed
				}
				calls.Add(1)
				client, peer := net.Pipe()
				go func() {
					defer close(peerDone)
					defer peer.Close()
					_, _ = io.Copy(peer, peer)
				}()
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = proxy.Close(context.Background()) })
			connection := proxyTestClient(t, proxy, proxy.username, proxy.password)
			if _, err := connection.Write(proxyTestRequest(target)); err != nil {
				t.Fatal(err)
			}
			proxyTestReply(t, connection, true)
			payload := bytes.Repeat([]byte("ordinary-Tor-protected-TCP\x00"), 8192)
			writeDone := make(chan error, 1)
			go func() { _, err := connection.Write(payload); writeDone <- err }()
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, received); err != nil || !bytes.Equal(received, payload) {
				t.Fatal("captured ordinary Tor payload changed", err)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			if err := proxy.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-peerDone:
			case <-time.After(time.Second):
				t.Fatal("actual captured peer did not stop")
			}
			if calls.Load() != 1 || proxy.network.count != 0 || len(proxy.clients) != 0 {
				t.Fatal("ordinary Tor released live proxy sockets")
			}
		})
	}
}

func TestTCPProxyRejectsNoAuthStaleCredentialsAndUnownedDestinations(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unowned dial")
	}
	first, err := StartTCPProxy(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())
	second, err := StartTCPProxy(context.Background(), dial)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	if first.username == second.username || first.password == second.password {
		t.Fatal("ordinary Tor sessions reused proxy authentication")
	}
	_ = proxyTestClient(t, second, first.username, first.password)
	connection, err := net.DialTimeout("tcp", second.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	_, _ = connection.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(connection, greeting[:]); err != nil || greeting != [2]byte{5, 0xff} {
		t.Fatal("ordinary Tor proxy accepted no authentication", err)
	}
	_ = connection.Close()
	requests := [][]byte{
		{5, 2, 0, 1}, {5, 3, 0, 1}, {5, 1, 1, 1}, {5, 1, 0, 3},
		proxyTestRequest("127.0.0.1:80"), proxyTestRequest("0.0.0.0:80"),
		proxyTestRequest("10.0.0.1:443"), proxyTestRequest("224.0.0.1:80"),
		proxyTestRequest("[::1]:443"), proxyTestRequest("[fe80::1]:443"),
		proxyTestRequest("[fc00::1]:443"), proxyTestRequest("203.0.113.17:0"),
	}
	for _, request := range requests {
		connection := proxyTestClient(t, second, second.username, second.password)
		if _, err := connection.Write(request); err != nil {
			t.Fatal(err)
		}
		proxyTestReply(t, connection, false)
		_ = connection.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("rejected proxy traffic reached the protected lower owner")
	}
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := second.binding(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("retired proxy retained a usable configuration binding")
	}
}

type proxyLateConn struct {
	net.Conn
	closeEntered chan struct{}
	closeRelease <-chan struct{}
	once         sync.Once
	failure      string
}

func (c *proxyLateConn) Close() error {
	c.once.Do(func() {
		close(c.closeEntered)
		<-c.closeRelease
		_ = c.Conn.Close()
	})
	return errors.New(c.failure)
}

func TestTCPProxyCloseRetainsLateDialAndRealSocketClose(t *testing.T) {
	entered, dialRelease := make(chan struct{}), make(chan struct{})
	closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	late := &proxyLateConn{Conn: left, closeEntered: closeEntered, closeRelease: closeRelease, failure: "private-upstream-credential"}
	proxy, err := StartTCPProxy(context.Background(), func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		<-dialRelease
		return late, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var releaseDialOnce, releaseCloseOnce sync.Once
	releaseDial := func() { releaseDialOnce.Do(func() { close(dialRelease) }) }
	releaseClose := func() { releaseCloseOnce.Do(func() { close(closeRelease) }) }
	t.Cleanup(func() { releaseDial(); releaseClose(); _ = proxy.Close(context.Background()) })
	connection := proxyTestClient(t, proxy, proxy.username, proxy.password)
	_, _ = connection.Write(proxyTestRequest("203.0.113.19:443"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("captured dial never started")
	}
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = proxy.Close(wait)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending ordinary Tor dial was released", err)
	}
	releaseDial()
	select {
	case <-closeEntered:
	case <-time.After(time.Second):
		t.Fatal("late ordinary Tor socket was not closed")
	}
	select {
	case <-proxy.Done():
		t.Fatal("late ordinary Tor native socket close escaped ownership")
	default:
	}
	releaseClose()
	err = proxy.Close(context.Background())
	if err == nil || strings.Contains(err.Error(), late.failure) || strings.Contains(err.Error(), proxy.password) {
		t.Fatal("proxy close failure was lost or exposed private data")
	}
	if again := proxy.Close(context.Background()); again == nil || again.Error() != err.Error() {
		t.Fatal("ordinary Tor close failure was not sticky")
	}
}

type proxySlowRead struct {
	net.Conn
	entered chan struct{}
	closed  chan struct{}
	release <-chan struct{}
	read    sync.Once
	close   sync.Once
}

func (c *proxySlowRead) Read([]byte) (int, error) {
	c.read.Do(func() { close(c.entered) })
	<-c.closed
	<-c.release
	return 0, io.EOF
}

func (c *proxySlowRead) Close() error {
	c.close.Do(func() { close(c.closed); _ = c.Conn.Close() })
	return nil
}

func TestTCPProxyCloseJoinsActualCapturedRead(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	release := make(chan struct{})
	slow := &proxySlowRead{Conn: left, entered: make(chan struct{}), closed: make(chan struct{}), release: release}
	proxy, err := StartTCPProxy(context.Background(), func(context.Context, string, string) (net.Conn, error) { return slow, nil })
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { unblock(); _ = proxy.Close(context.Background()) })
	connection := proxyTestClient(t, proxy, proxy.username, proxy.password)
	_, _ = connection.Write(proxyTestRequest("203.0.113.20:443"))
	proxyTestReply(t, connection, true)
	select {
	case <-slow.entered:
	case <-time.After(time.Second):
		t.Fatal("actual captured read never started")
	}
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = proxy.Close(wait)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("ordinary Tor released an active physical read", err)
	}
	select {
	case <-proxy.Done():
		t.Fatal("physical ordinary Tor read was not joined")
	default:
	}
	unblock()
	if err := proxy.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
