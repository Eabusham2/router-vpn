//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "routervpn-linux-guardian-crash-source" {
		if err := desktopLinuxTestCrashSource(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(84)
		}
		os.Exit(85)
	}

	if len(os.Args) == 3 && os.Args[1] == "routervpn-owned-socket-helper" {
		if err := RunDesktopLinuxSocketHelper(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(81)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "routervpn-linux-guardian-peer" {
		if err := desktopLinuxTestPeer(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(82)
		}
		os.Exit(0)
	}
}

func desktopLinuxTestCrashSource(remoteText string) error {
	remote, err := netip.ParseAddrPort(remoteText)
	if err != nil {
		return err
	}
	physical, err := net.InterfaceByName("rvpn-test")
	if err != nil {
		return err
	}
	options := DesktopLinuxSocketOptions{Interfaces: []DesktopLinuxSocketInterface{{Name: physical.Name, Index: uint32(physical.Index), Address: netip.MustParseAddr("198.18.0.1")}}, PrivateDestinations: []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}}}
	policy, err := NewDesktopLinuxSocketPolicy(context.Background(), desktopSocketFixtureCapture(), options)
	if err != nil {
		return err
	}
	broker, err := NewDesktopSocketBroker(context.Background(), policy.capture, policy, func() bool { return true })
	if err != nil {
		return err
	}
	connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		return err
	}
	connection.SetDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("parent crash probe")); err != nil {
		return err
	}
	buffer := make([]byte, 64)
	if _, err = connection.Read(buffer); err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(desktopLinuxCrashReceipt{NFT: policy.nft, UID: policy.uid, Account: policy.account, GuardianPID: policy.command.Process.Pid}); err != nil {
		return err
	}
	var signal [1]byte
	if _, err = io.ReadFull(os.Stdin, signal[:]); err != nil {
		return err
	}
	os.Exit(83) // Deliberately bypasses all native defers and broker teardown.
	return nil
}

// This readback witness is memory-only, so a blocked guardian call cannot
// postpone expiry. A clock rollback must invalidate a future observation
// rather than making it current until wall time catches up.
func checkDesktopLinuxPolicyCurrentFreshness(t *testing.T) {
	t.Helper()
	capture := desktopSocketFixtureCapture()
	owner := desktopSocketFixturePolicy().owner
	for _, test := range []struct {
		name     string
		observed int64
		current  bool
	}{
		{"fresh", time.Now().UnixMilli(), true},
		{"missing", 0, false},
		{"future", time.Now().Add(time.Hour).UnixMilli(), false},
		{"expired", time.Now().Add(-DesktopSocketReadbackAge - time.Second).UnixMilli(), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &DesktopLinuxSocketPolicy{capture: capture, owner: owner}
			policy.current.Store(true)
			policy.observed.Store(test.observed)
			if policy.Current(capture, owner) != test.current {
				t.Fatal("Linux physical policy accepted an invalid readback age or rejected a fresh one")
			}
			_, err := policy.Owner()
			if (err == nil) != test.current {
				t.Fatal("Linux physical owner admission disagrees with readback freshness", err)
			}
			if test.current {
				foreign := capture
				foreign.NetworkID = strings.Repeat("f", 32)
				changed := owner
				changed.Generation++
				if policy.Current(foreign, owner) || policy.Current(capture, changed) {
					t.Fatal("fresh readback conferred authority on another capture or generation")
				}
				policy.closing.Store(true)
				if policy.Current(capture, owner) {
					t.Fatal("closing Linux owner retained admission")
				}
			}
		})
	}
}

func TestDesktopLinuxPolicyCurrentFreshness(t *testing.T) {
	checkDesktopLinuxPolicyCurrentFreshness(t)
}

type desktopLinuxCrashReceipt struct {
	NFT         *desktopLinuxNFT
	UID         uint32
	Account     string
	GuardianPID int
}

func desktopLinuxTestPeer(network string) error {
	address := "198.18.0.2:0"
	if strings.HasSuffix(network, "6") {
		address = "[fd50::2]:0"
	}
	if strings.HasPrefix(network, "tcp") {
		listener, err := net.Listen(network, address)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Println(listener.Addr().String())
		go func() { io.Copy(io.Discard, os.Stdin); listener.Close() }()
		for {
			peer, err := listener.Accept()
			if err != nil {
				return nil
			}
			go func() { defer peer.Close(); io.Copy(peer, peer) }()
		}
	}
	peer, err := net.ListenPacket(network, address)
	if err != nil {
		return err
	}
	defer peer.Close()
	fmt.Println(peer.LocalAddr().String())
	go func() { io.Copy(io.Discard, os.Stdin); peer.Close() }()
	buffer := make([]byte, 65536)
	for {
		n, address, err := peer.ReadFrom(buffer)
		if err != nil {
			return nil
		}
		if _, err = peer.WriteTo(buffer[:n], address); err != nil {
			return err
		}
	}
}

func desktopLinuxKernelPeer(t *testing.T, network string) netip.AddrPort {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("ip", "netns", "exec", "rvpn-peer", executable, "routervpn-linux-guardian-peer", network)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		input.Close()
		if err := command.Wait(); err != nil {
			t.Error("physical peer join", err)
		}
	})
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	remote, err := netip.ParseAddrPort(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	return remote
}

func desktopLinuxKernelBaseline(t *testing.T) {
	t.Helper()
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("isolated kernel namespace is required")
	}
	desktopLinuxKernelInstallBaseline(t, desktopSocketFixtureCapture())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", desktopLinuxNFTTable}, ""); err != nil {
			t.Error(err)
		}
	})
}

func desktopLinuxKernelInstallBaseline(t *testing.T, capture DesktopSocketCapture) {
	t.Helper()
	script := fmt.Sprintf(`add table inet router_vpn_killswitch
add chain inet router_vpn_killswitch output { type filter hook output priority -310; policy drop; comment "routervpn-owned-baseline:%s:%s"; }
add rule inet router_vpn_killswitch output oifname "lo" accept
add rule inet router_vpn_killswitch output oifname { "wg", "awg", "router-vpn" } accept
add rule inet router_vpn_killswitch output ip protocol udp udp sport 68 udp dport 67 accept
add rule inet router_vpn_killswitch output ip6 nexthdr ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
`, capture.SessionID, capture.SourceSHA256)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := desktopLinuxNFTCommand(ctx, []string{"-f", "-"}, script); err != nil {
		t.Fatal(err)
	}
}

func desktopLinuxKernelPolicy(t *testing.T, destinations []DesktopLinuxSocketDestination) *DesktopLinuxSocketPolicy {
	t.Helper()
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("Linux guardian tests require the explicit isolated namespace runner; they never skip or modify host policy")
	}
	desktopLinuxKernelBaseline(t)
	capture := desktopSocketFixtureCapture()
	physical, err := net.InterfaceByName("rvpn-test")
	if err != nil {
		t.Fatal(err)
	}
	options := DesktopLinuxSocketOptions{Interfaces: []DesktopLinuxSocketInterface{{Name: physical.Name, Index: uint32(physical.Index), Address: netip.MustParseAddr("198.18.0.1")}, {Name: physical.Name, Index: uint32(physical.Index), Address: netip.MustParseAddr("fd50::1")}}, PrivateDestinations: destinations}
	policy, err := NewDesktopLinuxSocketPolicy(context.Background(), capture, options)
	if policy != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := policy.Close(ctx); err != nil {
				t.Error("actual guardian source cleanup", err)
			}
		})
	}
	if err != nil {
		t.Fatal("actual guardian preparation", err)
	}
	return policy
}

func desktopLinuxKernelBroker(t *testing.T, p *DesktopLinuxSocketPolicy) *DesktopSocketBroker {
	t.Helper()
	return desktopLinuxKernelBrokerCurrent(t, p, func() bool { return true })
}

func desktopLinuxKernelBrokerCurrent(t *testing.T, p *DesktopLinuxSocketPolicy, current func() bool) *DesktopSocketBroker {
	t.Helper()
	broker, err := NewDesktopSocketBroker(context.Background(), p.capture, p, current)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(15 * time.Second)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := broker.Close(ctx)
			cancel()
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Error("actual guardian did not drain", err)
				break
			}
		}
	})
	return broker
}

func TestDesktopLinuxGuardianKernelTCPAndUDP(t *testing.T) {
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			remote := desktopLinuxKernelPeer(t, network)
			policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: network[:3], Address: remote}})
			broker := desktopLinuxKernelBroker(t, policy)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			connection, err := broker.DialContext(ctx, network, remote.String())
			if err != nil {
				t.Fatal("actual protected connect", err)
			}
			var raw syscall.RawConn
			if network[:3] == "tcp" {
				raw, err = connection.(*desktopSocketConn).socket.conn.(syscall.Conn).SyscallConn()
			} else {
				raw, err = connection.(*desktopConnectedPacket).packet.socket.packet.(syscall.Conn).SyscallConn()
			}
			if err != nil {
				t.Fatal(err)
			}
			var uid uint32
			raw.Control(func(fd uintptr) {
				var st syscall.Stat_t
				if e := syscall.Fstat(int(fd), &st); e != nil {
					t.Error(e)
				}
				uid = st.Uid
			})
			if uid != policy.uid || uid == 0 {
				t.Fatalf("kernel creator UID=%d want %d", uid, policy.uid)
			}
			data := []byte("owned physical bytes")
			connection.SetDeadline(time.Now().Add(time.Second))
			if _, err = connection.Write(data); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, len(data))
			if _, err = io.ReadFull(connection, buffer); err != nil || string(buffer) != string(data) {
				t.Fatal("actual physical bytes", string(buffer), err)
			}
			if err = connection.Close(); err != nil {
				t.Fatal(err)
			}
			closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err = broker.Close(closeCtx); err != nil {
				t.Fatal(err)
			}
			if err = policy.nft.allAbsent(closeCtx); err != nil {
				t.Fatal(err)
			}
			if err = desktopLinuxVerifyAccount(policy.account, policy.uid); err == nil {
				t.Fatal("normal close did not retire its isolated account")
			}
			if _, err = os.Stat(filepath.Join(desktopLinuxIdentities, policy.account)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("normal close retained an identity record", err)
			}
		})
	}
}

func TestDesktopLinuxGuardianKernelRejectsWrongUIDAndPrivatePeer(t *testing.T) {
	remote := desktopLinuxKernelPeer(t, "udp4")
	policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopLinuxKernelBroker(t, policy)
	rootSocket, err := net.ListenPacket("udp4", "198.18.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rootSocket.Close()
	raw, _ := rootSocket.(syscall.Conn).SyscallConn()
	binding, _ := policy.Select(context.Background(), policy.capture, "udp", remote)
	if err = policy.Bind(context.Background(), policy.capture, binding, "udp4", raw); err == nil {
		t.Fatal("root-created descriptor acquired isolated UID authority")
	}
	if _, err = broker.DialContext(context.Background(), "udp4", netip.AddrPortFrom(remote.Addr(), remote.Port()+1).String()); err == nil {
		t.Fatal("uncaptured private peer was allowed")
	}
	// A real lower-level kernel negative: even a perfectly matching tuple must
	// reject a root-created socket because its UID differs from the captured UID.
	grant := DesktopSocketGrant{Capture: policy.capture, Binding: binding, SocketID: strings.Repeat("9", 32), Network: "udp", Local: netip.MustParseAddrPort(rootSocket.LocalAddr().String()), Remote: remote, Sequence: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err = policy.nft.grant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	rootSocket.WriteTo([]byte("wrong UID"), net.UDPAddrFromAddrPort(remote))
	rootSocket.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buffer := make([]byte, 64)
	if n, _, err := rootSocket.ReadFrom(buffer); err == nil || n != 0 {
		t.Fatal("exact tuple bypassed kernel UID ownership", n, err)
	}
	if err = policy.nft.revoke(ctx, grant); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopLinuxGuardianKernelExpirySurvivesGuardianCrash(t *testing.T) {
	remote := desktopLinuxKernelPeer(t, "udp4")
	policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	binding, err := policy.Select(context.Background(), policy.capture, "udp", remote)
	if err != nil {
		t.Fatal(err)
	}
	creation := DesktopSocketCreation{Capture: policy.capture, Binding: binding, SocketID: strings.Repeat("a", 32), Network: "udp"}
	reply, err := policy.CreateSocket(context.Background(), creation)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.File.Close()
	raw, _ := reply.File.SyscallConn()
	if err = policy.Bind(context.Background(), policy.capture, binding, "udp4", raw); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Bind(int(reply.File.Fd()), &syscall.SockaddrInet4{Addr: binding.LocalAddress.As4()}); err != nil {
		t.Fatal(err)
	}
	local, err := desktopSocketLocal(int(reply.File.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	grant := DesktopSocketGrant{Capture: policy.capture, Binding: binding, SocketID: creation.SocketID, Network: "udp", Local: local, Remote: remote, Sequence: 1}
	if _, err = policy.Grant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	packet, err := net.FilePacketConn(reply.File)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	packet.SetDeadline(time.Now().Add(time.Second))
	packet.WriteTo([]byte("before crash"), net.UDPAddrFromAddrPort(remote))
	buffer := make([]byte, 64)
	if _, _, err = packet.ReadFrom(buffer); err != nil {
		t.Fatal("exact owned kernel permit did not carry bytes", err)
	}
	if err = policy.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-policy.joined:
	case <-time.After(time.Second):
		t.Fatal("guardian process did not join")
	}
	if policy.Current(policy.capture, policy.owner) {
		t.Fatal("dead guardian stayed current")
	}
	if err = desktopLinuxVerifyAccount(policy.account, policy.uid); err != nil {
		t.Fatal("guardian crash reused its account", err)
	}
	// There is deliberately no broker or application cleanup worker in this
	// test: the actual kernel must expire the permission independently.
	deadline := time.Now().Add(11 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := policy.nft.absent(ctx, grant)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("kernel grant did not independently expire", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	packet.SetDeadline(time.Now().Add(150 * time.Millisecond))
	packet.WriteTo([]byte("after expiry"), net.UDPAddrFromAddrPort(remote))
	if n, _, err := packet.ReadFrom(buffer); err == nil || n != 0 {
		t.Fatal("kernel carried bytes after permission expiry", n, err)
	}
	packet.Close()
	reply.File.Close()
	closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = policy.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	if err = policy.nft.allAbsent(closeCtx); err != nil {
		t.Fatal(err)
	}
	if err = desktopLinuxVerifyAccount(policy.account, policy.uid); err != nil {
		t.Fatal("exceptional close released quarantined UID", err)
	}
}

func TestDesktopLinuxGuardianKernelSocketRetirementReusesCapacity(t *testing.T) {
	remote := desktopLinuxKernelPeer(t, "udp4")
	policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopLinuxKernelBroker(t, policy)
	for index := 0; index < DesktopSocketLimit+2; index++ {
		connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
		if err != nil {
			t.Fatalf("retired socket exhausted guardian capacity at %d: %v", index, err)
		}
		if err = connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopLinuxGuardianKernelRejectsChangedBaseline(t *testing.T) {
	remote := desktopLinuxKernelPeer(t, "udp4")
	policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := desktopLinuxNFTCommand(ctx, []string{"-f", "-"}, "add rule inet router_vpn_killswitch output accept\n"); err != nil {
		t.Fatal(err)
	}
	if err := policy.nft.verify(ctx, true); err == nil {
		t.Fatal("new global output accept inherited physical session authority")
	}
}

func TestDesktopLinuxGuardianKernelNativeParentCrash(t *testing.T) {
	// Retain and reap the orphan guardian itself, not only the killed source.
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 36, 1, 0, 0, 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	defer syscall.Syscall6(syscall.SYS_PRCTL, 36, 0, 0, 0, 0, 0)
	remote := desktopLinuxKernelPeer(t, "udp4")
	desktopLinuxKernelBaseline(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "routervpn-linux-guardian-crash-source", remote.String())
	command.Stderr = os.Stderr
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	var receipt desktopLinuxCrashReceipt
	if err = json.NewDecoder(output).Decode(&receipt); err != nil {
		command.Process.Kill()
		command.Wait()
		t.Fatal(err)
	}
	if receipt.GuardianPID < 2 || receipt.NFT == nil || receipt.UID == 0 {
		t.Fatal("source omitted actual guardian capture")
	}
	if _, err = input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	input.Close()
	if err = command.Wait(); err == nil {
		t.Fatal("source unexpectedly returned through normal cleanup")
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := receipt.NFT.allAbsent(ctx)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native crash left physical permits", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var status syscall.WaitStatus
	for {
		pid, err := syscall.Wait4(receipt.GuardianPID, &status, syscall.WNOHANG, nil)
		if err != nil {
			t.Fatal("guardian crash cleanup process could not be joined", err)
		}
		if pid == receipt.GuardianPID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guardian did not join after native crash")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err = desktopLinuxVerifyAccount(receipt.Account, receipt.UID); err != nil {
		t.Fatal("native crash released quarantined identity", err)
	}
}

func TestDesktopLinuxGuardianKernelBlockedControlRetainsSourcePort(t *testing.T) {
	remote := desktopLinuxKernelPeer(t, "udp4")
	policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	broker := desktopLinuxKernelBroker(t, policy)
	connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		t.Fatal(err)
	}
	local := connection.LocalAddr().String()
	if err = policy.command.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer policy.command.Process.Signal(syscall.SIGCONT)
	blocked, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, file, err := policy.call(blocked, desktopLinuxRequest{Operation: "probe", Capture: policy.capture}, nil, true)
	cancel()
	if file != nil {
		file.Close()
	}
	if err == nil || policy.Current(policy.capture, policy.owner) {
		t.Fatal("blocked guardian acknowledgment retained current authority")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = broker.Close(closeCtx)
	cancel()
	if err == nil {
		t.Fatal("blocked guardian discarded unknown cleanup ownership")
	}
	if reused, err := net.ListenPacket("udp4", local); err == nil {
		reused.Close()
		t.Fatal("unknown kernel permit released its exact bound source port")
	}
	if err = policy.command.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	closeCtx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = broker.Close(closeCtx); err != nil {
		t.Fatal("resumed guardian did not finish retained cleanup", err)
	}
	if err = policy.nft.allAbsent(closeCtx); err != nil {
		t.Fatal(err)
	}
	reused, err := net.ListenPacket("udp4", local)
	if err != nil {
		t.Fatal("joined source still retained its unpermitted source port", err)
	}
	reused.Close()
	if err = desktopLinuxVerifyAccount(policy.account, policy.uid); err != nil {
		t.Fatal("unknown control outcome recycled its identity", err)
	}
}

func TestDesktopLinuxGuardianKernelRejectsStaleCaptureAndGeneration(t *testing.T) {
	t.Run("readback-freshness", checkDesktopLinuxPolicyCurrentFreshness)
	remote := desktopLinuxKernelPeer(t, "udp4")
	policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	stale := policy.capture
	stale.NetworkID = strings.Repeat("f", 32)
	binding, err := policy.Select(context.Background(), policy.capture, "udp", remote)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = policy.Select(context.Background(), stale, "udp", remote); err == nil {
		t.Fatal("stale network capture selected a physical binding")
	}
	creation := DesktopSocketCreation{Capture: stale, Binding: binding, SocketID: strings.Repeat("e", 32), Network: "udp"}
	if got, err := policy.CreateSocket(context.Background(), creation); err == nil || got.File != nil {
		if got.File != nil {
			got.File.Close()
		}
		t.Fatal("stale network capture created a physical socket")
	}
	grant := DesktopSocketGrant{Capture: stale, Binding: binding, SocketID: creation.SocketID, Network: "udp", Local: netip.AddrPortFrom(binding.LocalAddress, 40000), Remote: remote, Sequence: 1}
	if _, err = policy.Grant(context.Background(), grant); err == nil {
		t.Fatal("stale network capture installed a physical permit")
	}
	before, err := os.ReadDir(desktopLinuxIdentities)
	if err != nil {
		t.Fatal(err)
	}
	stale.SessionID = strings.Repeat("d", 32)
	stale.SourceSHA256 = strings.Repeat("c", 64)
	failed, err := NewDesktopLinuxSocketPolicy(context.Background(), stale, policy.options)
	if err == nil {
		t.Fatal("new source adopted an old privileged firewall baseline")
	}
	if failed != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := failed.Close(ctx); err != nil {
			t.Error("rejected preparation did not join", err)
		}
		cancel()
	}
	after, err := os.ReadDir(desktopLinuxIdentities)
	if err != nil || len(after) != len(before) {
		t.Fatal("stale preparation mutated the managed account registry", err)
	}
	var current atomic.Bool
	current.Store(true)
	broker := desktopLinuxKernelBrokerCurrent(t, policy, current.Load)
	connection, err := broker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		t.Fatal(err)
	}
	current.Store(false)
	if _, err = connection.Write([]byte("stale generation")); err == nil {
		t.Fatal("replaced native network generation still carried bytes")
	}
	select {
	case <-broker.joined:
	case <-time.After(3 * time.Second):
		t.Fatal("native generation replacement did not autonomously retire its sockets")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = policy.nft.allAbsent(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopLinuxGuardianKernelOldCleanupPreservesReplacement(t *testing.T) {
	remote := desktopLinuxKernelPeer(t, "udp4")
	old := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	oldBroker := desktopLinuxKernelBroker(t, old)
	if _, err := oldBroker.DialContext(context.Background(), "udp4", remote.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err := desktopLinuxNFTCommand(ctx, []string{"delete", "table", "inet", desktopLinuxNFTTable}, "")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	replacementCapture := DesktopSocketCapture{SessionID: strings.Repeat("b", 32), SourceSHA256: strings.Repeat("c", 64), NetworkID: strings.Repeat("d", 32)}
	desktopLinuxKernelInstallBaseline(t, replacementCapture)
	replacement, err := NewDesktopLinuxSocketPolicy(context.Background(), replacementCapture, old.options)
	if replacement != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := replacement.Close(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	newBroker := desktopLinuxKernelBroker(t, replacement)
	connection, err := newBroker.DialContext(context.Background(), "udp4", remote.String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = oldBroker.Close(ctx); err != nil {
		t.Fatal("old owner could not retire independently", err)
	}
	if err = replacement.nft.verify(ctx, true); err != nil {
		t.Fatal("old cleanup changed replacement firewall ownership", err)
	}
	connection.SetDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("replacement remains connected")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, err = connection.Read(buffer); err != nil {
		t.Fatal("old cleanup broke the replacement physical path", err)
	}
	connection.Close()
}

func TestDesktopLinuxGuardianKernelFinishRequiresDescriptorRetirement(t *testing.T) {
	remote := desktopLinuxKernelPeer(t, "udp4")
	policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
	binding, err := policy.Select(context.Background(), policy.capture, "udp", remote)
	if err != nil {
		t.Fatal(err)
	}
	creation := DesktopSocketCreation{Capture: policy.capture, Binding: binding, SocketID: strings.Repeat("f", 32), Network: "udp"}
	created, err := policy.CreateSocket(context.Background(), creation)
	if err != nil {
		t.Fatal(err)
	}
	defer created.File.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = policy.Close(ctx); err == nil {
		t.Fatal("finish released its UID before native descriptor retirement")
	}
	if err = desktopLinuxVerifyAccount(policy.account, policy.uid); err != nil {
		t.Fatal("unretired source lost its isolated identity", err)
	}
	if err = created.File.Close(); err != nil {
		t.Fatal(err)
	}
	if err = policy.ReleaseSocket(ctx, creation); err != nil {
		t.Fatal(err)
	}
	if err = policy.Close(ctx); err != nil {
		t.Fatal("properly retired source did not close", err)
	}
}
