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
	"runtime"
	"syscall"
	"testing"
	"time"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "routervpn-bootstrap-expiry-peer" {
		err := func() error {
			c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: 53})
			if e != nil {
				return e
			}
			defer c.Close()
			ready := os.NewFile(3, "expiry-peer-ready")
			if _, e = ready.Write([]byte{'R'}); e != nil {
				return e
			}
			ready.Close()
			for {
				buffer := make([]byte, 512)
				n, from, e := c.ReadFromUDPAddrPort(buffer)
				if e != nil {
					return e
				}
				if _, e = c.WriteToUDPAddrPort(buffer[:n], from); e != nil {
					return e
				}
			}
		}()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(91)
	}
}

func TestDesktopLinuxGuardianKernelStandardBootstrapFiniteGrant(t *testing.T) {
	for _, mode := range []string{"kernel-expiry", "late-original-receipts", "wrong-endpoint", "generation-change", "same-handle-replacement"} {
		t.Run(mode, func(t *testing.T) { desktopLinuxBootstrapFiniteGrantProof(t, mode) })
	}
}
func desktopLinuxBootstrapFiniteGrantProof(t *testing.T, mode string) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("finite bootstrap grant requires mandatory isolated native namespace")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if mode == "generation-change" || mode == "same-handle-replacement" {
		desktopLinuxBootstrapConditionalGrantProof(t, mode)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	readyR, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyR.Close()
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	peer := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", image, "routervpn-bootstrap-expiry-peer")
	peer.ExtraFiles = []*os.File{readyW}
	peer.Stderr = os.Stderr
	if err = peer.Start(); err != nil {
		readyW.Close()
		t.Fatal(err)
	}
	readyW.Close()
	defer func() { _ = peer.Process.Kill(); _ = peer.Wait() }()
	var signal [1]byte
	if _, err = io.ReadFull(readyR, signal[:]); err != nil || signal[0] != 'R' {
		t.Fatal("independent UDP peer readiness", err)
	}
	lease, err := os.OpenFile(t.TempDir()+"/lease", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	capture := desktopSocketFixtureCapture()
	p, err := NewDesktopLinuxStandardProtection(ctx, hex.EncodeToString(nonce[:]), capture.SourceSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.99")}, false, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := p.CleanupBootstrap(ctx, lease); e != nil {
			t.Error("final bootstrap join", e)
		}
		if e := p.Release(ctx, lease); e != nil {
			t.Error("original baseline release", e)
		}
		if e := p.Close(ctx); e != nil {
			t.Error("original baseline endpoint close", e)
		}
	}()
	baseline, err := p.Receipt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := p.baseline
	if err = b.enter(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.cleanupBootstrapLocked(ctx, lease); err != nil {
			t.Error("original finite grant cleanup", err)
		}
		b.gate <- struct{}{}
	}()
	generation, err := b.observe(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	route, err := desktopLinuxBootstrapRouteFor(ctx, netip.MustParseAddr("198.18.0.2"), 0, netip.AddrPort{}, "udp")
	if err != nil {
		t.Fatal(err)
	}
	socket := &desktopLinuxStandardBootstrap{route: route, remote: netip.MustParseAddrPort("198.18.0.2:53"), network: "udp", mark: 0x92345678}
	p.bootstrap, b.crossTransfer = socket, "bootstrap"
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket.file = os.NewFile(uintptr(fd), "original-expiry-socket")
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(socket.mark)); err != nil {
		t.Fatal(err)
	}
	if err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, route.Interface.Name); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{Addr: route.Address.As4()}); err != nil {
		t.Fatal(err)
	}
	local, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	socket.local = desktopLinuxBootstrapSockaddr(local)
	socket.socket, err = desktopLinuxSocketIdentity(socket.file)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := desktopLinuxBootstrapRuleWire(route, socket.local, socket.remote, socket.mark, "udp", "rvb_0123456789abcdef01")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	if mode == "late-original-receipts" {
		deadline = time.Now().Add(time.Second)
	}
	g, err := b.netlink.newBootstrapGrant(generation, b.nft.table(), "rvb_0123456789abcdef01", rule, socket.mark, deadline)
	if err != nil {
		t.Fatal(err)
	}
	socket.grant, socket.attempted = g, true
	if mode == "late-original-receipts" {
		// Real original send, intentionally no receive. Model only the lost caller
		// acknowledgement boundary; all replies below still come from the kernel.
		b.netlink.mu.Lock()
		b.netlink.bootstrap = g
		err = syscall.Sendto(int(b.netlink.file.Fd()), bytes.Join(g.requests, nil), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		g.sent = err == nil
		b.netlink.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		canceled, stop := context.WithCancel(ctx)
		stop()
		if err = b.netlink.bootstrapExchange(canceled, g); err == nil || g.complete() {
			t.Fatal("canceled observer consumed/renewed original transaction", err)
		}
		time.Sleep(time.Until(deadline) + 100*time.Millisecond)
	}
	if err = b.netlink.bootstrapExchange(ctx, g); err != nil || !g.complete() {
		t.Fatal("original creation echo/commit recovery", err)
	}
	socket.handle = g.ruleHandle
	if g.ruleHandle == 0 || g.setHandle == 0 {
		t.Fatal("kernel omitted exact object identities")
	}
	if generation, err := b.netlink.generation(ctx); err != nil || generation != g.generation() {
		t.Fatal("creation was replayed or changed original generation", generation, err)
	}
	if err = syscall.Connect(fd, &syscall.SockaddrInet4{Addr: socket.remote.Addr().As4(), Port: 53}); err != nil {
		t.Fatal(err)
	}
	socket.connected = true
	socket.conn, err = net.FileConn(socket.file)
	if err != nil {
		t.Fatal(err)
	}
	probe := func(want bool) {
		t.Helper()
		_ = socket.conn.SetDeadline(time.Now().Add(120 * time.Millisecond))
		payload := []byte("original finite kernel permit")
		_, e := socket.conn.Write(payload)
		if e == nil {
			buffer := make([]byte, 128)
			var n int
			n, e = socket.conn.Read(buffer)
			if e == nil && !bytes.Equal(buffer[:n], payload) {
				t.Fatal("peer response changed")
			}
		}
		if (e == nil) != want {
			t.Fatal("actual kernel packet verdict", mode, want, e)
		}
	}
	switch mode {
	case "kernel-expiry":
		probe(true)
		// No cleanup/timer removes either object. Continued traffic cannot refresh
		// membership; an actual post-expiry send must fail despite the held socket.
		until := time.Now().Add(g.duration + 150*time.Millisecond)
		refreshUntil := time.Now().Add(g.duration / 2)
		for time.Now().Before(refreshUntil) {
			probe(true)
			time.Sleep(50 * time.Millisecond)
		}
		if delay := time.Until(until); delay > 0 {
			time.Sleep(delay)
		}
		probe(false)
		if present, err := socket.observe(ctx, b); err != nil || !present || socket.grantLive {
			t.Fatal("kernel expiry lost objects or renewed original element", present, err)
		}
	case "late-original-receipts":
		probe(false)
		if present, err := socket.observe(ctx, b); err != nil || !present || socket.grantLive {
			t.Fatal("late receipt adopted a renewed permit", present, err)
		}
	case "wrong-endpoint":
		replacement, err := desktopLinuxOpenBaselineNetlink()
		if err != nil {
			t.Fatal(err)
		}
		defer replacement.close()
		if _, err = replacement.newBootstrapRemoval(g.generation(), g); err == nil {
			t.Fatal("another real endpoint adopted original handles")
		}
		probe(true)

	}
	if err = p.cleanupBootstrapLocked(ctx, lease); err != nil {
		t.Fatal("original set/rule exact cleanup", err)
	}
	if _, err = b.observe(ctx, false); err != nil {
		t.Fatal("original baseline not restored", err)
	}
	if baseline.TableHandle != b.nft.TableHandle || p.bootstrap != nil || b.crossTransfer != "" {
		t.Fatal("cleanup replaced original baseline authority")
	}
}

// The conditional mutation controls own an unhooked test table. They do not
// corrupt a production baseline and then hide failed retirement at namespace
// teardown. Its exact original table handle is captured from creation echo and
// removed through the same original endpoint, with checked absence afterward.
func desktopLinuxBootstrapConditionalGrantProof(t *testing.T, mode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	table := linuxBootstrapTransactionTable()
	request := map[string]any{"nftables": []any{map[string]any{"add": map[string]any{"table": map[string]any{"family": "inet", "name": table}}}, map[string]any{"add": map[string]any{"chain": map[string]any{"family": "inet", "table": table, "name": "output"}}}}}
	body, _ := json.Marshal(request)
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-a", "-e", "-j", "-f", "-"}, string(body))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	var tableHandle uint64
	for _, row := range response.NFTables {
		if add, ok := row["add"].(map[string]any); ok {
			if object, ok := add["table"].(map[string]any); ok && object["name"] == table && object["family"] == "inet" {
				tableHandle = desktopLinuxNumber(object["handle"])
			}
		}
	}
	if tableHandle == 0 {
		t.Fatal("fixture omitted original table creation handle", string(raw))
	}
	n, err := desktopLinuxOpenBaselineNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := n.close(); e != nil {
			t.Error(e)
		}
	}()
	defer func() {
		generation, e := n.generation(ctx)
		if e != nil {
			t.Error("fixture cleanup generation", e)
			return
		}
		if ack, _, e := n.delete(ctx, generation, tableHandle); e != nil || !ack {
			t.Error("exact original fixture table cleanup", ack, e)
			return
		}
		raw, e := desktopLinuxNFTCommand(ctx, []string{"-j", "list", "tables"}, "")
		if e != nil {
			t.Error("fixture absence", e)
			return
		}
		var view struct {
			NFTables []map[string]any `json:"nftables"`
		}
		if e = json.Unmarshal(raw, &view); e != nil {
			t.Error(e)
			return
		}
		for _, row := range view.NFTables {
			if object, ok := row["table"].(map[string]any); ok && object["family"] == "inet" && object["name"] == table {
				t.Error("original fixture table survived exact retirement")
			}
		}
	}()
	generation, err := n.generation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	route := desktopLinuxBootstrapRoute{Interface: net.Interface{Name: "eth0", Index: 2}, Address: netip.MustParseAddr("192.0.2.2")}
	rule, err := desktopLinuxBootstrapRuleWire(route, netip.MustParseAddrPort("192.0.2.2:40000"), netip.MustParseAddrPort("192.0.2.53:53"), 0x92345678, "udp", "rvb_0123456789abcdef01")
	if err != nil {
		t.Fatal(err)
	}
	g, err := n.newBootstrapGrant(generation, table, "rvb_0123456789abcdef01", rule, 0x92345678, time.Now().Add(8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err = n.bootstrapExchange(ctx, g); err != nil {
		t.Fatal(err)
	}
	before, err := n.generation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "generation-change" {
		desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("add rule inet %s output counter drop comment \"expiry-fixture-extra\"\n", table))
	} else {
		desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("replace rule inet %s output handle %d counter drop\n", table, g.ruleHandle))
	}
	removal, err := n.newBootstrapRemoval(before, g)
	if err != nil {
		t.Fatal(err)
	}
	err = n.bootstrapExchange(ctx, removal)
	if !errors.Is(err, syscall.ERESTART) || !removal.rejected || removal.committed {
		t.Fatal("stale exact-handle cleanup changed intervening kernel policy", err)
	}
	rows, err := desktopLinuxNFTReadTable(ctx, table)
	if err != nil {
		t.Fatal(err)
	}
	rulePresent, setPresent := false, false
	for _, row := range rows {
		if r, ok := row["rule"].(map[string]any); ok && desktopLinuxNumber(r["handle"]) == g.ruleHandle {
			rulePresent = true
		}
		if set, ok := row["set"].(map[string]any); ok && desktopLinuxNumber(set["handle"]) == g.setHandle {
			setPresent = true
		}
	}
	if !rulePresent || !setPresent {
		t.Fatal("rejected transaction removed an original rule or timer set")
	}
}
