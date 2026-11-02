package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"runtime"
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
			udp, tcp, err := listenDNSProxyWith(address, func(selected *net.TCPAddr) (net.Listener, error) {
				if runtime.GOOS == "windows" && (selected.Port < 16384 || selected.Port >= 49152) {
					t.Fatal("production Windows DNS allocator bypassed its independent bounded candidates", selected)
				}
				return dnsTestTCP(selected)
			}, func(selected *net.UDPAddr) (*net.UDPConn, error) {
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
	candidates, held := dnsTestOwnedCandidates(t)
	for index := 1; index < len(held); index++ {
		if err := held[index].udp.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var previous net.Listener
	attempts, tcpAttempts := 0, 0
	udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, candidates, func(address *net.TCPAddr) (net.Listener, error) {
		if previous != nil {
			_ = previous.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			if _, err := previous.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatal("partial TCP listener was not closed before retry", err)
			}
		}
		if tcpAttempts >= len(held) || address.Port != int(candidates[tcpAttempts]) {
			t.Fatal("partial-owner fixture lost its next captured candidate", address)
		}
		owned := held[tcpAttempts].tcp
		tcpAttempts++
		previous = owned
		return owned, nil
	}, func(address *net.UDPAddr) (*net.UDPConn, error) {
		attempts++
		return net.ListenUDP("udp", address)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	defer tcp.Close()
	if attempts != 2 || tcpAttempts != 2 {
		t.Fatal("ephemeral collision did not retry once", attempts, tcpAttempts)
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
			var candidates [8]uint16
			var held [8]dnsTestOwnedPair
			if !fixed {
				candidates, held = dnsTestOwnedCandidates(t)
			}
			address, err := net.ResolveTCPAddr("tcp", listen)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("owned UDP admission failure")
			var owners []net.Listener
			udp, tcp, err := listenDNSProxyCandidates(address, candidates, func(address *net.TCPAddr) (net.Listener, error) {
				var owned net.Listener
				var err error
				if fixed {
					owned, err = dnsTestTCP(address)
				} else {
					if len(owners) >= len(held) || address.Port != int(candidates[len(owners)]) {
						t.Fatal("retry exceeded or replaced its captured candidate list", address)
					}
					owned = held[len(owners)].tcp
				}
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

type dnsTestOwnedPair struct {
	tcp *net.TCPListener
	udp *net.UDPConn
}

// Retain actual admission on both protocols before arranging a collision. A
// test's blocker must not assume that either OS ephemeral allocator supplies
// a port usable by the other protocol on the current native host.
func dnsTestOwnedCandidates(t *testing.T) ([8]uint16, [8]dnsTestOwnedPair) {
	t.Helper()
	var ports [8]uint16
	var held [8]dnsTestOwnedPair
	count := 0
	seen := make(map[uint16]bool)
	for range 8 {
		candidates, err := dnsListenerPortCandidates(true, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, port := range candidates {
			if seen[port] {
				continue
			}
			seen[port] = true
			tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			if err != nil {
				continue
			}
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			if err != nil {
				if closeErr := tcp.Close(); closeErr != nil {
					t.Fatal("fixture could not retire its partial TCP owner", closeErr)
				}
				continue
			}
			t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
			ports[count], held[count] = port, dnsTestOwnedPair{tcp, udp}
			count++
			if count == len(ports) {
				return ports, held
			}
		}
	}
	t.Fatal("fixture could not retain eight actual TCP/UDP candidate pairs within 64 attempts", count)
	return ports, held
}

func TestDNSListenerPortCandidates(t *testing.T) {
	for _, fill := range []byte{0, 255} {
		actual, err := dnsListenerPortCandidates(true, bytes.NewReader(bytes.Repeat([]byte{fill}, 16)))
		var expected [8]uint16
		for index := range expected {
			start := 0
			if fill == 255 {
				start = 32767
			}
			expected[index] = uint16(16384 + (start+index)%32768)
		}
		if err != nil || actual != expected {
			t.Fatal("DNS candidate selection lost its bounded distinct entropy-derived ports", actual, expected, err)
		}
	}
	if ports, err := dnsListenerPortCandidates(false, nil); err != nil || ports != [8]uint16{} {
		t.Fatal("non-Windows or fixed allocation unexpectedly consumed entropy", ports, err)
	}
	for _, entropy := range []io.Reader{nil, bytes.NewReader(make([]byte, 15))} {
		if ports, err := dnsListenerPortCandidates(true, entropy); err == nil || ports != [8]uint16{} {
			t.Fatal("Windows DNS candidates concealed incomplete entropy", ports, err)
		}
	}
}

func TestDNSListenersRejectInvalidCandidatesBeforeBinding(t *testing.T) {
	valid := [8]uint16{16384, 16385, 16386, 16387, 16388, 16389, 16390, 16391}
	for _, port := range []uint16{0, 16383, 16385, 49152} {
		bad := valid
		bad[0] = port
		if udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{}, bad, func(*net.TCPAddr) (net.Listener, error) {
			t.Fatal("invalid candidate reached a TCP bind")
			return nil, nil
		}, func(*net.UDPAddr) (*net.UDPConn, error) {
			t.Fatal("invalid candidate reached a UDP bind")
			return nil, nil
		}); err == nil || udp != nil || tcp != nil {
			t.Fatal("invalid DNS candidate authority was accepted", bad, err)
		}
	}
	if udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{Port: 53}, valid, func(*net.TCPAddr) (net.Listener, error) {
		t.Fatal("fixed candidate replacement reached TCP")
		return nil, nil
	}, func(*net.UDPAddr) (*net.UDPConn, error) {
		t.Fatal("fixed candidate replacement reached UDP")
		return nil, nil
	}); err == nil || udp != nil || tcp != nil {
		t.Fatal("fixed DNS port accepted replacement candidates", err)
	}
}

func TestDNSListenersCandidatesRecoverBothProtocolConflicts(t *testing.T) {
	candidates, held := dnsTestOwnedCandidates(t)
	// First candidate has an actually held UDP conflict; second retains its
	// actual TCP conflict; only the third has both protocols released.
	if err := held[0].tcp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := held[2].tcp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := held[2].udp.Close(); err != nil {
		t.Fatal(err)
	}
	tcpCalls, udpCalls := 0, 0
	var previous *net.TCPListener
	udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, candidates, func(address *net.TCPAddr) (net.Listener, error) {
		if previous != nil {
			_ = previous.SetDeadline(time.Now().Add(time.Second))
			if _, err := previous.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatal("DNS candidate retry retained the previous partial listener", err)
			}
		}
		if tcpCalls >= len(candidates) || address.Port != int(candidates[tcpCalls]) {
			t.Fatal("DNS candidate order changed before a real bind", address)
		}
		tcpCalls++
		listener, err := net.ListenTCP("tcp4", address)
		if err == nil {
			previous = listener
			t.Cleanup(func() { _ = listener.Close() })
		}
		return listener, err
	}, func(address *net.UDPAddr) (*net.UDPConn, error) {
		udpCalls++
		return net.ListenUDP("udp4", address)
	})
	if err != nil || tcp == nil || udp == nil {
		t.Fatal("DNS candidates did not recover both actual protocol conflicts", tcpCalls, udpCalls, err)
	}
	defer tcp.Close()
	defer udp.Close()
	if tcpCalls != 3 || udpCalls != 2 || tcp.Addr().(*net.TCPAddr).Port != int(candidates[2]) || udp.LocalAddr().String() != tcp.Addr().String() {
		t.Fatal("DNS candidate retry published another pair or changed its bounded order", tcpCalls, udpCalls, tcp.Addr(), udp.LocalAddr())
	}
}

func TestDNSListenersCandidateTCPFailureBound(t *testing.T) {
	candidates, err := dnsListenerPortCandidates(true, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("captured Windows TCP candidate denial")
	calls := 0
	udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{}, candidates, func(address *net.TCPAddr) (net.Listener, error) {
		if calls >= len(candidates) || address.Port != int(candidates[calls]) {
			t.Fatal("denied TCP candidates exceeded or replaced their exact bound", address, calls)
		}
		calls++
		return (*net.TCPListener)(nil), failure
	}, func(*net.UDPAddr) (*net.UDPConn, error) {
		t.Fatal("unowned TCP candidate reached UDP")
		return nil, nil
	})
	if calls != 8 || udp != nil || tcp != nil || !errors.Is(err, failure) {
		t.Fatal("DNS TCP denials lost their eight-attempt bound or exact error", calls, err)
	}
}

func TestDNSListenersCandidatePolicyEscapesDeniedEphemeralSelection(t *testing.T) {
	candidates, err := dnsListenerPortCandidates(true, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	denied := errors.New("captured UDP denial for the independent TCP ephemeral selection")
	lastRequestedPort, calls := 0, 0
	udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, candidates, func(address *net.TCPAddr) (net.Listener, error) {
		lastRequestedPort = address.Port
		calls++
		return dnsTestTCP(address)
	}, func(address *net.UDPAddr) (*net.UDPConn, error) {
		// Model only the observed Windows protocol reservation at its actual
		// bind boundary. Every successful TCP and UDP owner is a real socket.
		if lastRequestedPort == 0 {
			return nil, denied
		}
		return net.ListenUDP("udp", address)
	})
	if err != nil || udp == nil || tcp == nil {
		t.Fatal("DNS candidates did not escape protocol-denied ephemeral selection", calls, err)
	}
	defer tcp.Close()
	defer udp.Close()
	if calls > 8 || tcp.Addr().String() != udp.LocalAddr().String() {
		t.Fatal("DNS candidate policy did not retain its bounded actual pair", calls)
	}
}

type dnsTestCloseFailure struct {
	net.Listener
	failure error
}

func (l *dnsTestCloseFailure) Close() error {
	return errors.Join(l.Listener.Close(), l.failure)
}

func TestDNSListenersCandidateCloseFailureStopsRetry(t *testing.T) {
	candidates, held := dnsTestOwnedCandidates(t)
	bindFailure, closeFailure := errors.New("captured UDP admission failed"), errors.New("original TCP retirement is unknown")
	calls := 0
	udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, candidates, func(*net.TCPAddr) (net.Listener, error) {
		calls++
		if calls != 1 {
			t.Fatal("DNS retried after losing its original listener retirement")
		}
		return &dnsTestCloseFailure{held[0].tcp, closeFailure}, nil
	}, func(*net.UDPAddr) (*net.UDPConn, error) { return nil, bindFailure })
	if udp != nil || tcp != nil || calls != 1 || !errors.Is(err, bindFailure) || !errors.Is(err, closeFailure) {
		t.Fatal("DNS listener admission concealed failed original cleanup", calls, err)
	}
}

func TestDNSListenersRejectSubstitutedCapturedPorts(t *testing.T) {
	for _, substitute := range []string{"tcp", "udp"} {
		t.Run(substitute, func(t *testing.T) {
			candidates, held := dnsTestOwnedCandidates(t)
			ownedTCP := held[0].tcp
			calls := 0
			udp, tcp, err := listenDNSProxyCandidates(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, candidates, func(address *net.TCPAddr) (net.Listener, error) {
				calls++
				if substitute == "tcp" {
					ownedTCP = held[1].tcp
					// A constructor cannot rewrite the captured requested port
					// and then present that different socket as the original.
					address.Port = int(candidates[1])
				}
				return ownedTCP, nil
			}, func(*net.UDPAddr) (*net.UDPConn, error) {
				if substitute == "tcp" {
					t.Fatal("substituted TCP authority reached UDP")
				}
				return held[1].udp, nil
			})
			if err == nil || udp != nil || tcp != nil || calls != 1 {
				t.Fatal("DNS published or retried substituted captured endpoint authority", substitute, calls, err)
			}
			_ = ownedTCP.SetDeadline(time.Now().Add(time.Second))
			if _, err := ownedTCP.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatal("substituted listener left its returned TCP owner open", err)
			}
			if substitute == "udp" {
				_ = held[1].udp.SetReadDeadline(time.Now().Add(time.Second))
				if _, _, err := held[1].udp.ReadFromUDP(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
					t.Fatal("substituted listener left its returned UDP owner open", err)
				}
				if err := held[1].tcp.SetDeadline(time.Time{}); err != nil {
					t.Fatal("substituted UDP cleanup closed an unrelated TCP owner", err)
				}
			}
			if err := held[0].udp.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal("candidate cleanup closed an unreturned UDP owner", err)
			}
		})
	}
}
