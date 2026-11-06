//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func init() {
	if len(os.Args) == 3 && (os.Args[1] == "routervpn-bootstrap-group-peer" || os.Args[1] == "routervpn-bootstrap-group-client") {
		var err error
		if os.Args[1] == "routervpn-bootstrap-group-peer" {
			err = bootstrapGroupNativePeer(os.Args[2])
		} else {
			err = bootstrapGroupNativeClient(os.Args[2])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(93)
		}
		os.Exit(0)
	}
}
func bootstrapGroupNativePeer(mode string) error {
	var sockets []*net.UDPConn
	for _, port := range []int{4053, 5053} {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: port})
		if err != nil {
			return err
		}
		sockets = append(sockets, c)
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	}
	ready := os.NewFile(3, "group-peer-ready")
	if _, err := ready.Write([]byte{'R'}); err != nil {
		return err
	}
	ready.Close()
	type arrival struct {
		index int
		from  netip.AddrPort
		body  []byte
		err   error
	}
	arrivals := make(chan arrival, 2)
	for i, c := range sockets {
		go func(i int, c *net.UDPConn) {
			buffer := make([]byte, 512)
			n, from, err := c.ReadFromUDPAddrPort(buffer)
			arrivals <- arrival{i, from, buffer[:n], err}
		}(i, c)
	}
	var both [2]arrival
	for i := 0; i < 2; i++ {
		v := <-arrivals
		if v.err != nil {
			return v.err
		}
		if !bytes.Equal(v.body, bootstrapUpstreamQuestion()) {
			return errors.New("group peer received unowned/substituted question")
		}
		both[v.index] = v
	}
	arrived := os.NewFile(4, "group-both-arrived")
	if _, err := arrived.Write([]byte{'B'}); err != nil {
		return err
	}
	arrived.Close()
	// Neither peer replies before BOTH original sockets arrive. Serial resolver
	// fallback necessarily times out and cannot satisfy this independent barrier.
	for _, v := range both {
		if mode == "close-active" || mode == "loser-cancel" && v.index == 1 {
			continue
		}
		body := v.body
		if mode == "invalid-first" && v.index == 0 {
			body = []byte("invalid independent DNS reply")
		}
		if mode == "invalid-first" && v.index == 1 {
			time.Sleep(100 * time.Millisecond)
		}
		if _, err := sockets[v.index].WriteToUDPAddrPort(body, v.from); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"arrivals": 2, "barrier": true})
}
func bootstrapGroupNativeClient(mode string) (failure error) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		return errors.New("group client requires original guarded namespace")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "routervpn-group-client-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	lease, err := os.OpenFile(filepath.Join(dir, "lease"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lease.Close()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	capture := desktopSocketFixtureCapture()
	p, err := NewDesktopLinuxStandardProtection(ctx, hex.EncodeToString(nonce[:]), capture.SourceSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.99")}, false, lease)
	if err != nil {
		return err
	}
	defer func() {
		failure = errors.Join(failure, p.CleanupBootstrap(ctx, lease), p.Release(ctx, lease), p.Close(ctx))
	}()
	before, err := p.Receipt(ctx)
	if err != nil {
		return err
	}
	group, err := p.BeginBootstrapDNSGroup(ctx, lease)
	if err != nil {
		return err
	}
	query, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	type response struct {
		body []byte
		err  error
	}
	results := make(chan response, 2)
	for _, port := range []uint16{4053, 5053} {
		u := DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.AddrPortFrom(netip.MustParseAddr("198.18.0.2"), port), Network: "udp"}
		route, e := u.route(ctx, 0, netip.AddrPort{})
		if e != nil {
			return e
		}
		u.InterfaceIndex = route.Interface.Index
		go func(u DesktopLinuxBootstrapDNSUpstream) {
			body, e := group.Exchange(query, u, bootstrapUpstreamQuestion())
			results <- response{body, e}
		}(u)
	}
	if mode == "close-active" {
		arrived := os.NewFile(3, "group-both-arrived")
		defer arrived.Close()
		var signal [1]byte
		if _, err = io.ReadFull(arrived, signal[:]); err != nil || signal[0] != 'B' {
			return errors.Join(err, errors.New("both original queries did not reach peer before Close"))
		}
		if err = group.Close(ctx); err != nil {
			return err
		}
		if group.active != 0 || !group.closed {
			return errors.New("group Close returned before original active IO joined")
		}
	}
	valid, invalid, canceled := 0, 0, 0
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err == nil && bytes.Equal(r.body, bootstrapUpstreamQuestion()) {
			valid++
			if mode == "loser-cancel" {
				stop()
			}
		} else if r.err == nil {
			invalid++
		} else if errors.Is(r.err, context.Canceled) {
			canceled++
		} else {
			return errors.Join(r.err, errors.New("group peer overlap failed"))
		}
	}
	if mode == "close-active" {
		if canceled != 2 || valid != 0 {
			return errors.New("group Close did not cancel both active original sockets")
		}
	} else if mode == "loser-cancel" {
		if valid != 1 || canceled != 1 {
			return errors.New("group did not join canceled loser")
		}
	} else if mode == "invalid-first" {
		if valid != 1 || invalid != 1 {
			return errors.New("invalid answer canceled valid sibling")
		}
	} else if valid != 2 {
		return errors.New("two independent peers did not overlap")
	}
	if mode == "unknown-receipt" || mode == "stale-generation" {
		if err = bootstrapGroupNativeMutationControl(ctx, group, mode); err != nil {
			return err
		}
	}
	if err = group.Close(ctx); err != nil {
		return err
	}
	after, err := p.Receipt(ctx)
	if err != nil || p.bootstrap != nil || !bytes.Equal(before.Baseline, after.Baseline) || before.TableHandle != after.TableHandle {
		return errors.Join(err, errors.New("group failed original full baseline restoration"))
	}
	for _, member := range group.members {
		if member.conn != nil || member.file != nil || member.handle != 0 && !member.retired {
			return errors.New("group returned before all original sockets/grants joined")
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": mode, "valid": valid, "baseline_restored": true})
}

// Create one real original transaction without updating the group's ledger.
// Unknown receipts are resumed by Close; the stale-generation case advances
// only from that same creation receipt, never from a fresh generation read.
func bootstrapGroupNativeMutationControl(ctx context.Context, g *DesktopLinuxBootstrapDNSGroup, mode string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.owner.baseline
	u := DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.MustParseAddrPort("198.18.0.2:6053"), Network: "udp"}
	route, err := u.route(ctx, 0, netip.AddrPort{})
	if err != nil {
		return err
	}
	member := &desktopLinuxStandardBootstrap{group: g, route: route, remote: u.Endpoint, network: "udp", upstream: &u, mark: 0x94345678}
	g.members = append(g.members, member)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		return err
	}
	member.file = os.NewFile(uintptr(fd), "group-original-uncertain-socket")
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(member.mark)); err != nil {
		return err
	}
	if err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, route.Interface.Name); err != nil {
		return err
	}
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: route.Address.As4()}); err != nil {
		return err
	}
	local, err := syscall.Getsockname(fd)
	if err != nil {
		return err
	}
	member.local = desktopLinuxBootstrapSockaddr(local)
	member.socket, err = desktopLinuxSocketIdentity(member.file)
	if err != nil {
		return err
	}
	rule, err := desktopLinuxBootstrapRuleWireForUpstream(route, member.local, u, member.mark, "rvb_223456789abcdef001")
	if err != nil {
		return err
	}
	member.grant, err = b.netlink.newBootstrapGrant(g.generation, b.nft.table(), "rvb_223456789abcdef001", rule, member.mark, time.Now().Add(time.Second))
	if err != nil {
		return err
	}
	member.attempted = true
	transaction := member.grant
	original := bytes.Join(transaction.requests, nil)
	if mode == "unknown-receipt" {
		b.netlink.mu.Lock()
		b.netlink.bootstrap = transaction
		err = syscall.Sendto(int(b.netlink.file.Fd()), original, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		transaction.sent = err == nil
		b.netlink.mu.Unlock()
		if err != nil {
			return err
		}
		if _, err = g.observe(ctx); err == nil {
			return errors.New("group adopted unknown original receipt")
		}
		if transaction.complete() || !bytes.Equal(original, bytes.Join(transaction.requests, nil)) {
			return errors.New("group replayed uncertain creation")
		}
		return nil
	}
	if err = b.netlink.bootstrapExchange(ctx, transaction); err != nil {
		return err
	}
	member.handle = transaction.ruleHandle
	if _, err = g.observe(ctx); err == nil {
		return errors.New("group adopted a fresh generation without original ledger receipt")
	}
	if err = g.acknowledge(transaction); err != nil {
		return err
	}
	_, err = g.observe(ctx)
	return err
}
func TestDesktopLinuxGuardianKernelStandardBootstrapGroup(t *testing.T) {
	for _, mode := range []string{"overlap", "loser-cancel", "close-active", "invalid-first", "unknown-receipt", "stale-generation"} {
		t.Run(mode, func(t *testing.T) {
			if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
				t.Fatal("group proof requires mandatory isolated native namespace")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			image, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			readyR, readyW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyR.Close()
			arriveR, arriveW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer arriveR.Close()
			defer arriveW.Close()
			peer := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", image, "routervpn-bootstrap-group-peer", mode)
			peer.ExtraFiles = []*os.File{readyW, arriveW}
			var output, diagnostic bytes.Buffer
			peer.Stdout = &output
			peer.Stderr = &diagnostic
			if err = peer.Start(); err != nil {
				readyW.Close()
				t.Fatal(err)
			}
			readyW.Close()
			arriveW.Close()
			joined := false
			defer func() {
				if !joined {
					_ = peer.Process.Kill()
					_ = peer.Wait()
				}
			}()
			var signal [1]byte
			if _, err = io.ReadFull(readyR, signal[:]); err != nil || signal[0] != 'R' {
				t.Fatal("group peer readiness", err, diagnostic.String())
			}
			client := exec.CommandContext(ctx, image, "routervpn-bootstrap-group-client", mode)
			client.ExtraFiles = []*os.File{arriveR}
			raw, err := client.CombinedOutput()
			if err != nil {
				t.Fatal("actual concurrent protected group", err, string(raw))
			}
			if err = peer.Wait(); err != nil {
				joined = true
				t.Fatal("independent overlap barrier", err, diagnostic.String())
			}
			joined = true
			var note struct {
				Arrivals int  `json:"arrivals"`
				Barrier  bool `json:"barrier"`
			}
			if json.Unmarshal(output.Bytes(), &note) != nil || note.Arrivals != 2 || !note.Barrier {
				t.Fatal("independent peer did not prove overlap", output.String())
			}
			var result struct {
				Mode     string `json:"mode"`
				Baseline bool   `json:"baseline_restored"`
			}
			if json.Unmarshal(raw, &result) != nil || result.Mode != mode || !result.Baseline {
				t.Fatal("group omitted original cleanup verdict", string(raw))
			}
		})
	}
}
