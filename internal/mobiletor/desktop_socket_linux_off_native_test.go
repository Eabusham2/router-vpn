//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This case runs only in the existing disposable native namespace gate. It
// independently observes ordinary host traffic and the original isolated UID
// socket before, during and after an actual expiring kernel permit.
func TestDesktopLinuxGuardianKernelNodeOff(t *testing.T) {
	for _, ending := range []string{"live", "guardian-death", "channel-loss"} {
		t.Run(ending, func(t *testing.T) {
			remote := desktopLinuxKernelPeer(t, "udp4")
			baseline := linuxNodeBaselinePolicyFixture(t, false, "off")
			created, err := baseline.Created(context.Background())
			if err != nil || !created.HostProtectionOff {
				t.Fatal(err)
			}
			linuxNodeBaselineBypass(t, remote, false)
			policy := linuxNodeBaselineSource(t, baseline, false, DesktopLinuxSocketDestination{Network: "udp", Address: remote})
			prepared, err := policy.ObservePreparedProtection(context.Background(), policy.capture)
			if err != nil || !created.MatchesPrepared(prepared) || prepared.DenyHandle == 0 {
				t.Fatal("Off original preparation lost UID deny receipt", err)
			}
			linuxNodeBaselineBypass(t, remote, false)
			binding, err := policy.Select(context.Background(), policy.capture, "udp", remote)
			if err != nil {
				t.Fatal(err)
			}
			creation := DesktopSocketCreation{Capture: policy.capture, Binding: binding, SocketID: strings.Repeat("a", 32), Network: "udp"}
			socket, err := policy.CreateSocket(context.Background(), creation)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.File.Close()
			raw, _ := socket.File.SyscallConn()
			if err = policy.Bind(context.Background(), policy.capture, binding, "udp4", raw); err != nil {
				t.Fatal(err)
			}
			if err = syscall.Bind(int(socket.File.Fd()), &syscall.SockaddrInet4{Addr: binding.LocalAddress.As4()}); err != nil {
				t.Fatal(err)
			}
			local, err := desktopSocketLocal(int(socket.File.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			packet, err := net.FilePacketConn(socket.File)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			exchange := func(allowed bool) {
				t.Helper()
				packet.SetDeadline(time.Now().Add(200 * time.Millisecond))
				_, writeErr := packet.WriteTo([]byte("original Off UID"), net.UDPAddrFromAddrPort(remote))
				body := make([]byte, 64)
				n, _, readErr := packet.ReadFrom(body)
				ok := writeErr == nil && readErr == nil && string(body[:n]) == "original Off UID"
				if ok != allowed {
					t.Fatal("Off socket bypassed expiring UID grant or lost permitted bytes", allowed, writeErr, readErr)
				}
			}
			exchange(false)
			grant := DesktopSocketGrant{Capture: policy.capture, Binding: binding, SocketID: creation.SocketID, Network: "udp", Local: local, Remote: remote, Sequence: 1}
			foreign := grant
			foreign.Capture.SourceSHA256 = strings.Repeat("9", 64)
			if _, err := policy.Grant(context.Background(), foreign); err == nil {
				t.Fatal("foreign source acquired original Off grant")
			}
			if _, err := policy.Grant(context.Background(), grant); err != nil {
				t.Fatal(err)
			}
			exchange(true)
			if ending != "live" {
				if ending == "guardian-death" {
					if err := policy.command.Process.Kill(); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := policy.channel.Close(); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case <-policy.joined:
				case <-time.After(3 * time.Second):
					t.Fatal("original failed guardian did not join")
				}
			}
			deadline := time.Now().Add(11 * time.Second)
			for {
				if err := policy.nft.absent(context.Background(), grant); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Off original grant did not expire in kernel")
				}
				time.Sleep(50 * time.Millisecond)
			}
			exchange(false)
			linuxNodeBaselineBypass(t, remote, false)
			if err := policy.Revoke(context.Background(), grant); err != nil {
				t.Fatal(err)
			}
			// A live caller descriptor still prevents successful original-source join.
			closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err = policy.Close(closeCtx)
			cancel()
			if err == nil {
				t.Fatal("Off source released its original UID while descriptor remained")
			}
			// net.FilePacketConn owns an actual duplicate. Closing only the original
			// returned wrapper must not acknowledge its surviving kernel alias.
			socket.File.Close()
			if err := policy.ReleaseSocket(context.Background(), creation); err == nil {
				t.Fatal("surviving kernel duplicate released Off UID deny")
			}
			exchange(false)
			packet.Close()
			if err := policy.ReleaseSocket(context.Background(), creation); err != nil {
				t.Fatal(err)
			}
			if err := policy.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := policy.ObserveJoinedSource(context.Background(), policy.capture); err != nil {
				t.Fatal("Off original guardian did not join", err)
			}
			if err := baseline.ObserveClosed(context.Background()); err != nil {
				t.Fatal("Off UID deny survived successful source join", err)
			}
			if err := baseline.Release(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := ReadDesktopLinuxNodeAbsence(context.Background(), policy.capture.SessionID); err != nil {
				t.Fatal(err)
			}
			linuxNodeBaselineBypass(t, remote, false)

		})
	}
}
