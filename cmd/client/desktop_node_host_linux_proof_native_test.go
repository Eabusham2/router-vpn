//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

// This tests the exact proof-socket primitive against actual kernel sockets
// in the existing isolated network namespace. The fixture's veth is explicitly
// not a TUN or encrypted Router proof; assembled command acceptance is separate.
func TestDesktopLinuxGuardianKernelNodeProofSocket(t *testing.T) {
	iface, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || iface.Index < 1 {
		t.Fatal("Linux proof-socket tests require their actual isolated native namespace", err)
	}
	for _, scenario := range []string{"tcp4", "tcp6", "udp-rejected", "wrong-family", "wrong-index", "wrong-name", "wrong-mtu", "cancelled", "closed-original"} {
		t.Run(scenario, func(t *testing.T) {
			network, family, kind, protocol := "tcp4", syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP
			if scenario == "tcp6" {
				network, family = "tcp6", syscall.AF_INET6
			}
			if scenario == "udp-rejected" {
				kind, protocol = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP
			}
			fd, err := syscall.Socket(family, kind|syscall.SOCK_CLOEXEC, protocol)
			if err != nil {
				t.Fatal("actual owned proof socket could not be created", err)
			}
			file := os.NewFile(uintptr(fd), "original-proof-socket")
			defer file.Close()
			raw, err := file.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			if index, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, linuxNodeProofBindToIfIndex); err != nil || index != 0 {
				t.Fatal("new original proof socket was already bound", err)
			}
			live := desktopNodeMTURecord{Interface: iface.Name, Index: iface.Index, MTU: iface.MTU}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var originalClosedError error
			switch scenario {
			case "wrong-family":
				network = "tcp6"
			case "wrong-index":
				live.Index += 10000
			case "wrong-name":
				live.Interface = "another-iface"
			case "wrong-mtu":
				live.MTU++
			case "cancelled":
				cancel()
			case "closed-original":
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				originalClosedError = raw.Control(func(uintptr) { t.Fatal("closed original socket invoked a native operation") })
				if originalClosedError == nil {
					t.Fatal("closed original socket did not preserve its actual native error")
				}
			}
			err = bindDesktopLinuxNodeProofSocket(ctx, network, raw, live)
			if scenario == "tcp4" || scenario == "tcp6" {
				if err != nil {
					t.Fatal("captured native proof socket was not bound to its exact interface", err)
				}
				index, indexErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, linuxNodeProofBindToIfIndex)
				name, nameErr := desktopLinuxNodeProofBoundName(fd)
				if indexErr != nil || nameErr != nil || index != iface.Index || name != iface.Name {
					t.Fatal("proof returned before its original kernel binding was established", indexErr, nameErr)
				}
			} else {
				if err == nil {
					t.Fatal("proof socket admitted a changed captured owner", scenario)
				}
				if scenario == "closed-original" {
					if !errors.Is(err, originalClosedError) {
						t.Fatal("proof lost its original closed descriptor error", err)
					}
				} else if index, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, linuxNodeProofBindToIfIndex); err != nil || index != 0 {
					t.Fatal("failed proof changed its original socket's binding", err)
				}
			}
		})
	}
}
