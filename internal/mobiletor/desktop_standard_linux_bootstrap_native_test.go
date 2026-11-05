//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func init() {
	if (len(os.Args) == 3 || len(os.Args) == 4) && os.Args[1] == "routervpn-standard-bootstrap-peer" {
		var e error
		if len(os.Args) == 4 {
			e = desktopLinuxBootstrapTCPPeer(os.Args[2], strings.Contains(os.Args[3], "cancel"))
		} else {
			e = desktopLinuxBootstrapPeer(os.Args[2])
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(91)
		}
		os.Exit(0)
	}
}
func desktopLinuxBootstrapPeer(address string) error {
	notice, release := os.NewFile(3, "bootstrap-notice"), os.NewFile(4, "bootstrap-release")
	defer notice.Close()
	defer release.Close()
	conn, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(address), Port: 53})
	if e != nil {
		return e
	}
	defer conn.Close()
	if _, e = notice.Write([]byte{'R'}); e != nil {
		return e
	}
	var original []byte
	var source netip.AddrPort
	released := make(chan error, 1)
	go func() { var signal [1]byte; _, e := io.ReadFull(release, signal[:]); released <- e }()
	// The inherited parent process deadline joins this peer on every path. While
	// the original lookup is held, competing sockets receive immediate replies:
	// the negative witness therefore detects a broadened native permission.
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		select {
		case e := <-released:
			if e != nil {
				return e
			}
			if original == nil {
				return errors.New("release preceded original query")
			}
			_, e = conn.WriteToUDPAddrPort(original, source)
			return e
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		buffer := make([]byte, 512)
		n, from, e := conn.ReadFromUDPAddrPort(buffer)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			return e
		}
		if original == nil {
			original = append([]byte(nil), buffer[:n]...)
			source = from
			if _, e = notice.Write([]byte{'Q'}); e != nil {
				return e
			}
			continue
		}
		if _, e = conn.WriteToUDPAddrPort(buffer[:n], from); e != nil {
			return e
		}
	}
	return context.DeadlineExceeded
}
func TestDesktopLinuxGuardianKernelStandardBootstrapSocket(t *testing.T) {
	for _, mode := range []string{"original", "cancel-after-grant", "tcp-original", "tcp-cancel-after-grant"} {
		t.Run(mode, func(t *testing.T) { desktopLinuxBootstrapSocketProof(t, mode) })
	}
}
func desktopLinuxBootstrapSocketProof(t *testing.T, mode string) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("bootstrap native proof requires original isolated guardian namespace")
	}
	network := "udp"
	if strings.HasPrefix(mode, "tcp-") {
		network = "tcp"
	}
	cancelled := strings.Contains(mode, "cancel-after-grant")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	notifyR, notifyW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer notifyR.Close()
	releaseR, releaseW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer releaseW.Close()
	image, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	peer := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", image, "routervpn-standard-bootstrap-peer", "198.18.0.2")
	if network == "tcp" {
		peer.Args = append(peer.Args, mode)
	}
	peer.ExtraFiles = []*os.File{notifyW, releaseR}
	peer.Stderr = os.Stderr
	if e = peer.Start(); e != nil {
		t.Fatal(e)
	}
	notifyW.Close()
	releaseR.Close()
	joined := false
	defer func() {
		if !joined {
			cancel()
			_ = peer.Wait()
		}
	}()
	var signal [1]byte
	if _, e = io.ReadFull(notifyR, signal[:]); e != nil || signal[0] != 'R' {
		t.Fatal("original DNS peer readiness", e)
	}
	lease, e := os.OpenFile(t.TempDir()+"/mutation.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	capture := desktopSocketFixtureCapture()
	// The resolver is deliberately not one of the original broad outer endpoint
	// exceptions. Only the newly acknowledged exact socket can reach it.
	p, e := NewDesktopLinuxStandardProtection(ctx, hex.EncodeToString(nonce[:]), capture.SourceSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.99")}, false, lease)
	if p != nil {
		defer func() { _ = p.CleanupBootstrap(ctx, lease); _ = p.Release(ctx, lease); _ = p.Close(ctx) }()
	}
	if e != nil {
		t.Fatal(e)
	}
	before, e := p.Receipt(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ordinaryBlocked := func() {
		t.Helper()
		if network == "tcp" {
			c, e := net.DialTimeout("tcp", "198.18.0.2:53", 100*time.Millisecond)
			if e == nil {
				_ = c.Close()
				t.Fatal("bootstrap admitted an ordinary TCP socket")
			}
			return
		}
		c, e := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: 53})
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_, e = c.Write([]byte("unowned socket"))
		if e == nil {
			var answer [64]byte
			_, e = c.Read(answer[:])
		}
		if e == nil {
			t.Fatal("bootstrap admitted an ordinary socket to the captured resolver")
		}
	}
	ordinaryBlocked()
	q := []byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 'n', 'o', 'd', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	work, stopWork := context.WithCancel(ctx)
	defer stopWork()
	go func() {
		b, e := p.BootstrapDNSExchangeNetwork(work, lease, netip.MustParseAddr("198.18.0.2"), network, q)
		done <- result{b, e}
	}()
	if _, e = io.ReadFull(notifyR, signal[:]); e != nil || signal[0] != 'Q' {
		t.Fatal("actual granted socket did not transmit", e)
	}
	ordinaryBlocked()
	if cancelled {
		stopWork()
	}
	if _, e = releaseW.Write([]byte{'D'}); e != nil {
		t.Fatal(e)
	}
	resultValue := <-done
	if cancelled {
		if !errors.Is(resultValue.err, context.Canceled) || resultValue.body != nil {
			t.Fatal("cancelled original lookup adopted reply", resultValue.err)
		}
	} else if resultValue.err != nil || !bytes.Equal(resultValue.body, q) {
		t.Fatal("original bootstrap socket failed", resultValue.err)
	}
	after, e := p.Receipt(ctx)
	if e != nil || !bytes.Equal(after.Baseline, before.Baseline) || after.TableHandle != before.TableHandle || p.bootstrap != nil {
		t.Fatal("successful lookup did not restore exact original baseline", e)
	}
	if e = p.Current(ctx, lease); e != nil {
		t.Fatal(e)
	}
	if e = peer.Wait(); e != nil {
		t.Fatal(e)
	}
	joined = true
}

func desktopLinuxBootstrapTCPPeer(address string, cancelled bool) error {
	notice, release := os.NewFile(3, "bootstrap-notice"), os.NewFile(4, "bootstrap-release")
	defer notice.Close()
	defer release.Close()
	listener, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(address), Port: 53})
	if e != nil {
		return e
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(15 * time.Second))
	if _, e = notice.Write([]byte{'R'}); e != nil {
		return e
	}
	conn, e := listener.AcceptTCP()
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var length [2]byte
	if _, e = io.ReadFull(conn, length[:]); e != nil {
		return e
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 17 || n > 278 {
		return errors.New("invalid original TCP DNS frame")
	}
	frame := make([]byte, n+2)
	copy(frame, length[:])
	if _, e = io.ReadFull(conn, frame[2:]); e != nil {
		return e
	}
	if _, e = notice.Write([]byte{'Q'}); e != nil {
		return e
	}
	var signal [1]byte
	if _, e = io.ReadFull(release, signal[:]); e != nil {
		return e
	}
	if cancelled {
		return nil
	}
	for len(frame) > 0 {
		n, e := conn.Write(frame)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
