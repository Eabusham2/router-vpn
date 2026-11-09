//go:build linux || darwin || windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func importedMTUKernelLoopback(t *testing.T) desktopNodeMTURecord {
	t.Helper()
	if runtime.GOOS == "linux" {
		// The kernel-binding test needs only the real loopback index. Reading
		// the kernel's IPv6 table avoids requiring a full interface inventory;
		// it never stands in for the production native-TUN observation.
		body, err := os.ReadFile("/proc/net/if_inet6")
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 6 || fields[0] != "00000000000000000000000000000001" || fields[5] != "lo" {
				continue
			}
			index, err := strconv.ParseUint(fields[1], 16, 31)
			if err != nil || index < 1 {
				t.Fatal("kernel loopback index unavailable", err)
			}
			return desktopNodeMTURecord{Interface: "lo", Index: int(index), Reader: 1, MTU: 1400}
		}
		t.Fatal("kernel IPv6 table has no original loopback interface")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagUp != 0 && item.Flags&net.FlagLoopback != 0 {
			return desktopNodeMTURecord{Interface: item.Name, Index: item.Index, Reader: 1, MTU: 1400}
		}
	}
	t.Fatal("no actual loopback interface for native socket binding test")
	return desktopNodeMTURecord{}
}

func TestDesktopImportedMTUKernelSocketBinding(t *testing.T) {
	live := importedMTUKernelLoopback(t)
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		for _, fault := range []string{"original", "type", "family", "transport", "index", "cancelled"} {
			t.Run(network+"/"+fault, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				calls := 0
				var bindingErr error
				config := net.ListenConfig{Control: func(actual, _ string, raw syscall.RawConn) error {
					if actual != network {
						t.Fatal("socket creator changed original network", actual, network)
					}
					return raw.Control(func(fd uintptr) {
						calls++
						requested, captured := network, live
						switch fault {
						case "type":
							if strings.HasPrefix(network, "tcp") {
								requested = "udp" + network[3:]
							} else {
								requested = "tcp" + network[3:]
							}
						case "family":
							requested = network[:3] + "6"
							if strings.HasSuffix(network, "6") {
								requested = network[:3] + "4"
							}
						case "transport":
							requested = "tcp"
						case "index":
							captured.Index = 0
						case "cancelled":
							cancel()
						}
						bindingErr = bindDesktopImportedMTUKernel(ctx, requested, fd, captured)
					})
				}}
				address := "127.0.0.1:0"
				if strings.HasSuffix(network, "6") {
					address = "[::1]:0"
				}
				var openErr error
				if strings.HasPrefix(network, "tcp") {
					listener, err := config.Listen(ctx, network, address)
					openErr = err
					if listener != nil {
						defer listener.Close()
					}
				} else {
					packet, err := config.ListenPacket(ctx, network, address)
					openErr = err
					if packet != nil {
						defer packet.Close()
					}
				}
				if calls != 1 || fault != "cancelled" && openErr != nil {
					t.Fatal("actual native socket was not created and retained", calls, openErr)
				}
				if (bindingErr == nil) != (fault == "original") {
					t.Fatal("native MTU binding accepted a changed socket or rejected the original", bindingErr)
				}
				if fault == "cancelled" && !errors.Is(bindingErr, context.Canceled) {
					t.Fatal("native binding lost its original cancellation", bindingErr)
				}
			})
		}
	}
}

type importedMTUNeverSocket struct{ calls int }

func (r *importedMTUNeverSocket) Control(func(uintptr)) error {
	r.calls++
	return errors.New("invalid owner reached kernel control")
}
func (*importedMTUNeverSocket) Read(func(uintptr) bool) error  { return errors.New("unexpected read") }
func (*importedMTUNeverSocket) Write(func(uintptr) bool) error { return errors.New("unexpected write") }

func TestDesktopImportedMTUSocketRequiresOriginalLease(t *testing.T) {
	for _, fault := range []string{"nil-caller", "cancelled", "missing-guard", "replaced-lease", "changed-reader", "unqualified-network"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			raw := &importedMTUNeverSocket{}
			live := desktopNodeMTURecord{Interface: "captured-tun", Index: 7, Reader: 1, MTU: 1400}
			network := "udp4"
			guardErr := errors.New("original native lease replaced")
			current := func(original context.Context) error {
				if original != ctx {
					t.Error("native lease check replaced the original caller")
				}
				return nil
			}
			switch fault {
			case "nil-caller":
				ctx = nil
			case "cancelled":
				cancel()
			case "missing-guard":
				current = nil
			case "replaced-lease":
				current = func(context.Context) error { return guardErr }
			case "changed-reader":
				live.Reader = 0
			case "unqualified-network":
				network = "udp"
			}
			err := bindDesktopImportedMTUSocket(ctx, network, raw, live, current)
			if err == nil || raw.calls != 0 || fault == "replaced-lease" && !errors.Is(err, guardErr) ||
				fault == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("native MTU socket reached the kernel without its original lease", raw.calls, err)
			}
		})
	}
}
