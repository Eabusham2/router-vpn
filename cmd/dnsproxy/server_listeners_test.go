package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func dnsTestTCP(address *net.TCPAddr) (net.Listener, error) {
	return net.ListenTCP("tcp", address)
}

func TestDNSListenersShareOwnedTCPPort(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			udp, tcp, err := listenDNSProxyWith(address, dnsTestTCP, func(selected *net.UDPAddr) (*net.UDPConn, error) {
				// This callback runs at the real UDP bind boundary. TCP must
				// already own the exact address, including IPv6 and its zone.
				foreign, bindErr := net.Listen("tcp", selected.String())
				if bindErr == nil {
					_ = foreign.Close()
					t.Fatal("UDP binding preceded TCP ownership")
				}
				return net.ListenUDP("udp", selected)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			defer udp.Close()
			if tcp.Addr().String() != udp.LocalAddr().String() {
				t.Fatal("DNS listeners selected different addresses", tcp.Addr(), udp.LocalAddr())
			}
		})
	}
}

func TestDNSListenersReleasePartialOwnerBeforeEphemeralRetry(t *testing.T) {
	var previous net.Listener
	var blocker *net.UDPConn
	defer func() {
		if blocker != nil {
			_ = blocker.Close()
		}
	}()
	attempts := 0
	udp, tcp, err := listenDNSProxyWith("127.0.0.1:0", func(address *net.TCPAddr) (net.Listener, error) {
		if previous != nil {
			_ = previous.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			if _, err := previous.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatal("partial TCP listener was not closed before retry", err)
			}
		}
		owned, err := dnsTestTCP(address)
		if owned != nil {
			t.Cleanup(func() { _ = owned.Close() })
		}
		previous = owned
		return owned, err
	}, func(address *net.UDPAddr) (*net.UDPConn, error) {
		attempts++
		if attempts == 1 {
			var err error
			blocker, err = net.ListenUDP("udp", address)
			if err != nil {
				t.Fatal(err)
			}
		}
		return net.ListenUDP("udp", address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	defer tcp.Close()
	if attempts != 2 {
		t.Fatal("ephemeral collision did not retry once", attempts)
	}
}

func TestDNSListenersRetryBoundAndFixedPortPreserveFailure(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "ephemeral", true: "fixed"}[fixed], func(t *testing.T) {
			listen := "127.0.0.1:0"
			if fixed {
				port, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listen = port.Addr().String()
				_ = port.Close()
			}
			failure := errors.New("owned UDP admission failure")
			var owners []net.Listener
			udp, tcp, err := listenDNSProxyWith(listen, func(address *net.TCPAddr) (net.Listener, error) {
				owned, err := dnsTestTCP(address)
				if err == nil {
					t.Cleanup(func() { _ = owned.Close() })
					owners = append(owners, owned)
				}
				return owned, err
			}, func(address *net.UDPAddr) (*net.UDPConn, error) {
				if fixed && address.String() != listen {
					t.Fatal("fixed DNS port was replaced", address, listen)
				}
				return nil, failure
			})
			if udp != nil || tcp != nil || !errors.Is(err, failure) {
				t.Fatal("failed listeners were published or cause was lost", udp, tcp, err)
			}
			want := 8
			if fixed {
				want = 1
			}
			if len(owners) != want {
				t.Fatal("listener retry bound changed", len(owners), want)
			}
			for _, owner := range owners {
				_ = owner.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
				if _, err := owner.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Fatal("failed partial owner remained open", err)
				}
			}
		})
	}
}

func TestDNSListenersFixedBusyTCPNeverFallsBack(t *testing.T) {
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	udp, tcp, err := listenDNSProxyWith(busy.Addr().String(), dnsTestTCP, func(*net.UDPAddr) (*net.UDPConn, error) {
		t.Fatal("busy fixed TCP port still attempted UDP")
		return nil, nil
	})
	if err == nil || udp != nil || tcp != nil || !strings.Contains(err.Error(), "bind") {
		t.Fatal("busy fixed port was replaced or concealed", udp, tcp, err)
	}
}
