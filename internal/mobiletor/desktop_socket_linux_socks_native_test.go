//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "routervpn-linux-socks-peer" {
		if err := desktopLinuxSOCKSNativePeer(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(86)
		}
		os.Exit(0)
	}
}

// This is an independent transport witness in the runner's other network
// namespace. The pinned SOCKS negotiation is tested by the generated engine;
// these cases exercise the actual guardian/UID/nft association authority.
func desktopLinuxSOCKSNativePeer(network string) error {
	holdEOF := network == "tcp4-hold-eof"
	if holdEOF {
		network = "tcp4"
	}
	address := "192.168.50.2:0"
	if network == "tcp6" || network == "udp6" {
		address = "[fd50::2]:0"
	} else if network == "udp6-public" {
		network, address = "udp6", "[2606:4700:4700::1111]:0"
	}
	if strings.HasPrefix(network, "tcp") {
		listener, err := net.Listen(network, address)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Println(listener.Addr())
		done := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(done); _ = listener.Close() }()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return nil
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
				if holdEOF {
					// Keep the independent peer open after the original client
					// half-close. The exact peer tuple still exists, so only
					// the native TCP state can reject this control.
					<-done
				}
			}()
		}
	}
	packet, err := net.ListenPacket(network, address)
	if err != nil {
		return err
	}
	defer packet.Close()
	fmt.Println(packet.LocalAddr())
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); _ = packet.Close() }()
	buffer := make([]byte, 2048)
	for {
		count, remote, err := packet.ReadFrom(buffer)
		if err != nil {
			return nil
		}
		if _, err := packet.WriteTo(buffer[:count], remote); err != nil {
			return err
		}
	}
}

func desktopLinuxSOCKSKernelPeer(t *testing.T, network string) netip.AddrPort {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("ip", "netns", "exec", "rvpn-peer", executable, "routervpn-linux-socks-peer", network)
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		if err := command.Wait(); err != nil {
			t.Error("independent SOCKS transport peer join", err)
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

func desktopLinuxSOCKSCarrier(t *testing.T) {
	t.Helper()
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("SOCKS native carrier requires the fresh isolated guardian namespaces")
	}
	// These addresses exist only on the independent veth peer. There is no
	// host route change, outside datagram or connection to a public resolver.
	pairs := [][2][]string{
		{{"netns", "exec", "rvpn-peer", "ip", "addr", "add", "192.168.50.2/32", "dev", "rvpn-peer"}, {"netns", "exec", "rvpn-peer", "ip", "addr", "del", "192.168.50.2/32", "dev", "rvpn-peer"}},
		{{"route", "add", "192.168.50.2/32", "dev", "rvpn-test"}, {"route", "del", "192.168.50.2/32", "dev", "rvpn-test"}},
		{{"netns", "exec", "rvpn-peer", "ip", "-6", "addr", "add", "2606:4700:4700::1111/128", "dev", "rvpn-peer", "nodad"}, {"netns", "exec", "rvpn-peer", "ip", "-6", "addr", "del", "2606:4700:4700::1111/128", "dev", "rvpn-peer"}},
		{{"-6", "route", "add", "2606:4700:4700::1111/128", "dev", "rvpn-test"}, {"-6", "route", "del", "2606:4700:4700::1111/128", "dev", "rvpn-test"}},
	}
	for _, pair := range pairs {
		if output, err := exec.Command("ip", pair[0]...).CombinedOutput(); err != nil {
			t.Fatalf("fresh owned carrier: %v %s", err, output)
		}
		remove := append([]string(nil), pair[1]...)
		t.Cleanup(func() {
			if output, err := exec.Command("ip", remove...).CombinedOutput(); err != nil {
				t.Errorf("owned carrier retirement: %v %s", err, output)
			}
		})
	}
}

func desktopLinuxSOCKSExchange(t *testing.T, connection net.Conn) {
	t.Helper()
	data := []byte("original control owns this native relay")
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(data); err != nil {
		t.Fatal("actual associated relay write", err)
	}
	buffer := make([]byte, len(data))
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != string(data) {
		t.Fatal("actual associated relay bytes", string(buffer), err)
	}
}

func desktopLinuxSOCKSControl(t *testing.T, broker *DesktopSocketBroker, remote netip.AddrPort) (net.Conn, *desktopSocketPeer) {
	t.Helper()
	control, err := broker.DialContext(context.Background(), "tcp", remote.String())
	if err != nil {
		t.Fatal("original native TCP control", err)
	}
	desktopLinuxSOCKSExchange(t, control)
	socket := control.(*desktopSocketConn).socket
	socket.mu.Lock()
	peer := socket.peers[remote]
	socket.mu.Unlock()
	return control, peer
}

func desktopLinuxSOCKSReceipt(t *testing.T, peer *desktopSocketPeer) DesktopSocketReceipt {
	t.Helper()
	receipt, valid := peer.snapshot()
	if !valid || !validDesktopSocketReceipt(receipt, receipt.Grant, time.Now()) {
		t.Fatal("native association lost its current acknowledged receipt")
	}
	return receipt
}

func TestDesktopLinuxGuardianKernelSOCKSAssociation(t *testing.T) {
	desktopLinuxSOCKSCarrier(t)
	for _, scenario := range []struct{ name, control, relay string }{
		{"private-ipv4", "tcp4", "udp4"}, {"private-ipv6", "tcp6", "udp6"}, {"public-cross-family", "tcp4", "udp6-public"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			remote := desktopLinuxSOCKSKernelPeer(t, scenario.control)
			relay := desktopLinuxSOCKSKernelPeer(t, scenario.relay)
			policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "tcp", Address: remote}})
			original := append([]DesktopLinuxSocketDestination(nil), policy.options.PrivateDestinations...)
			broker := desktopLinuxKernelBroker(t, policy)
			if relay.Addr().IsPrivate() {
				if wrong, err := broker.DialContext(context.Background(), "udp", relay.String()); err == nil {
					wrong.Close()
					t.Fatal("ordinary UDP borrowed the selected private SOCKS exception")
				}
			}
			control, controlPeer := desktopLinuxSOCKSControl(t, broker, remote)
			firstControl := desktopLinuxSOCKSReceipt(t, controlPeer)
			connection, err := broker.DialSOCKSRelay(context.Background(), control, relay.String())
			if err != nil {
				t.Fatal("owned native SOCKS relay", err)
			}
			desktopLinuxSOCKSExchange(t, connection)
			socket := connection.(*desktopConnectedPacket).packet.socket
			socket.mu.Lock()
			relayPeer := socket.peers[relay]
			socket.mu.Unlock()
			firstRelay := desktopLinuxSOCKSReceipt(t, relayPeer)
			rows, err := desktopLinuxNFTReadTable(context.Background(), policy.nft.table())
			if err != nil {
				t.Fatal(err)
			}
			element, found, err := policy.nft.findElement(rows, firstRelay.Grant)
			prefix := firstRelay.Grant.SocketID + ":1:socks:" + firstControl.Grant.SocketID + ":"
			if err != nil || !found || !strings.HasPrefix(fmt.Sprint(element["comment"]), prefix) {
				t.Fatal("native relay omitted its original control annotation", err)
			}
			deadline := time.Now().Add(7 * time.Second)
			for scenario.name != "public-cross-family" {
				desktopLinuxSOCKSExchange(t, connection)
				currentControl := desktopLinuxSOCKSReceipt(t, controlPeer)
				currentRelay := desktopLinuxSOCKSReceipt(t, relayPeer)
				if currentControl.Grant.Sequence > firstControl.Grant.Sequence && currentRelay.Grant.Sequence > firstRelay.Grant.Sequence {
					break
				}
				if !time.Now().Before(deadline) {
					t.Fatal("original control and associated UDP did not independently renew")
				}
				time.Sleep(50 * time.Millisecond)
			}
			secondControl, _ := desktopLinuxSOCKSControl(t, broker, remote)
			second, err := broker.DialSOCKSRelay(context.Background(), secondControl, relay.String())
			if err != nil {
				t.Fatal("independent sibling association", err)
			}
			desktopLinuxSOCKSExchange(t, second)
			if err := control.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Write([]byte("stale")); err == nil {
				t.Fatal("retired original TCP left its UDP child usable")
			}
			if err := policy.nft.absent(context.Background(), firstRelay.Grant); err != nil {
				t.Fatal("original relay permit remained after joined control retirement", err)
			}
			desktopLinuxSOCKSExchange(t, second)
			if !reflect.DeepEqual(policy.options.PrivateDestinations, original) || len(policy.options.LANPrefixes) != 0 {
				t.Fatal("dynamic association widened shared native policy")
			}
			if err := secondControl.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, fault := range []string{"future-control", "changed-binding", "native-control-absent", "closed-control", "plain-relay-bypass", "parent-before-child", "association-reuse"} {
		t.Run("reject/"+fault, func(t *testing.T) {
			network := "tcp4"
			if fault == "closed-control" {
				network = "tcp4-hold-eof"
			}
			remote := desktopLinuxSOCKSKernelPeer(t, network)
			relay := desktopLinuxSOCKSKernelPeer(t, "udp4")
			policy := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "tcp", Address: remote}})
			broker := desktopLinuxKernelBroker(t, policy)
			control, peer := desktopLinuxSOCKSControl(t, broker, remote)
			peer.op.Lock()
			defer peer.op.Unlock()
			receipt := desktopLinuxSOCKSReceipt(t, peer)
			association := desktopLinuxSOCKSAssociation{Control: receipt.Grant, Binding: receipt.Grant.Binding, Remote: relay, SocketID: strings.Repeat("a", 32)}
			request := desktopLinuxRequest{Operation: "socks-associate", Capture: policy.capture, SOCKS: &association}
			witness := "invalid actual SOCKS association acquired native authority"
			switch fault {
			case "future-control":
				association.Control.Sequence += 100
			case "changed-binding":
				association.Binding.InterfaceIndex++
			case "native-control-absent":
				if err := policy.nft.revoke(context.Background(), receipt.Grant); err != nil {
					t.Fatal(err)
				}
				witness = "missing actual TCP permit admitted a derived SOCKS association"
			case "closed-control":
				raw, err := control.(*desktopSocketConn).socket.conn.(syscall.Conn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var failure error
				if err := raw.Control(func(fd uintptr) { failure = syscall.Shutdown(int(fd), syscall.SHUT_WR) }); err != nil || failure != nil {
					t.Fatal(err, failure)
				}
				if err := raw.Control(func(fd uintptr) {
					actual, err := desktopLinuxSOCKSPeer(int(fd))
					if err != nil || actual != remote {
						failure = errors.New("half-closed control lost its independent original peer tuple")
					}
				}); err != nil || failure != nil {
					t.Fatal(err, failure)
				}
				witness = "non-established actual TCP admitted a derived SOCKS association"
			case "plain-relay-bypass":
				packet, err := broker.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
				if err != nil {
					t.Fatal(err)
				}
				socket := packet.(*desktopSocketPacket).socket
				request = desktopLinuxRequest{Operation: "grant", Capture: policy.capture, Grant: DesktopSocketGrant{Capture: policy.capture, Binding: socket.binding, SocketID: socket.id, Network: "udp", Local: socket.local, Remote: relay, Sequence: 1}}
			case "parent-before-child", "association-reuse":
				connection, err := broker.DialSOCKSRelay(context.Background(), control, relay.String())
				if err != nil {
					t.Fatal(err)
				}
				if fault == "parent-before-child" {
					request = desktopLinuxRequest{Operation: "revoke", Capture: policy.capture, Grant: receipt.Grant}
					witness = "native TCP permit retired before its original UDP descriptor"
				} else if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
			}
			_, file, err := policy.call(context.Background(), request, nil, true)
			if file != nil {
				file.Close()
				t.Fatal("association returned unrequested native rights")
			}
			if err == nil || policy.Current(policy.capture, policy.owner) {
				t.Fatal(witness)
			}
			if !errors.Is(control.SetDeadline(time.Now()), net.ErrClosed) && broker.Current() {
				t.Fatal("rejected native association did not revoke source admission")
			}
		})
	}
}
