package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"router-vpn/internal/common"
)

const maxDNSWorkers = 256

func runDNSProxy(parent context.Context, listen string, u upstream) (result error) {
	udp, tcp, err := listenDNSProxy(listen)
	if err != nil {
		return err
	}
	defer udp.Close()
	defer tcp.Close()
	resolver, err := newDNSResolver(u, nil)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, resolver.Close()) }()
	log.Printf("RouterVPN DNS listening on %s -> %s", udp.LocalAddr(), describe(u))
	return serveDNSProxy(parent, udp, tcp, resolver)
}

func listenDNSProxy(listen string) (*net.UDPConn, net.Listener, error) {
	return listenDNSProxyWith(listen, func(address *net.TCPAddr) (net.Listener, error) {
		return net.ListenTCP("tcp", address)
	}, func(address *net.UDPAddr) (*net.UDPConn, error) {
		return net.ListenUDP("udp", address)
	})
}

// TCP owns the selected port before UDP adopts it. Windows TCP and UDP have
// independent dynamic/excluded ranges, so repeated port-zero choices can all
// land in a range rejected by the other transport. Only Windows port-zero
// requests use eight distinct random candidates below its default dynamic
// range; both actual binds still have to succeed. Fixed ports never change.
func listenDNSProxyWith(listen string, openTCP func(*net.TCPAddr) (net.Listener, error), openUDP func(*net.UDPAddr) (*net.UDPConn, error)) (*net.UDPConn, net.Listener, error) {
	address, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		return nil, nil, err
	}
	candidates, err := dnsListenerPortCandidates(address.Port == 0 && runtime.GOOS == "windows", rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return listenDNSProxyCandidates(address, candidates, openTCP, openUDP)
}

func dnsListenerPortCandidates(windows bool, entropy io.Reader) ([8]uint16, error) {
	var ports [8]uint16
	if !windows {
		return ports, nil
	}
	if entropy == nil {
		return ports, errors.New("DNS listener candidates require captured entropy")
	}
	var data [16]byte
	if _, err := io.ReadFull(entropy, data[:]); err != nil {
		return ports, fmt.Errorf("DNS listener candidate entropy: %w", err)
	}
	seen := make(map[uint16]bool, len(ports))
	for index := range ports {
		port := uint16(16384) + binary.LittleEndian.Uint16(data[2*index:])%32768
		for seen[port] {
			port = 16384 + (port-16384+1)%32768
		}
		ports[index], seen[port] = port, true
	}
	return ports, nil
}

func listenDNSProxyCandidates(address *net.TCPAddr, candidates [8]uint16, openTCP func(*net.TCPAddr) (net.Listener, error), openUDP func(*net.UDPAddr) (*net.UDPConn, error)) (*net.UDPConn, net.Listener, error) {
	if address == nil || address.Port < 0 || address.Port > 65535 || openTCP == nil || openUDP == nil {
		return nil, nil, errors.New("DNS listeners require a captured endpoint and both constructors")
	}
	diverse := candidates != [8]uint16{}
	if diverse {
		seen := make(map[uint16]bool, len(candidates))
		for _, port := range candidates {
			if address.Port != 0 || port < 16384 || port >= 49152 || seen[port] {
				return nil, nil, errors.New("DNS listeners require eight distinct bounded candidates only for port zero")
			}
			seen[port] = true
		}
	}
	attempts := 1
	if address.Port == 0 {
		attempts = len(candidates)
	}
	var failures []error
	for index := range attempts {
		requested := *address
		requested.IP = append(net.IP(nil), address.IP...)
		if diverse {
			requested.Port = int(candidates[index])
		}
		requestedPort := requested.Port
		tcp, err := openTCP(&requested)
		// net.ListenTCP returns a pointer, whose nil failure value can be
		// preserved inside this interface seam. It is not a partial owner.
		if actual, ok := tcp.(*net.TCPListener); ok && actual == nil {
			tcp = nil
		}
		if err != nil {
			if tcp != nil {
				if closeErr := tcp.Close(); closeErr != nil {
					return nil, nil, errors.Join(err, closeErr)
				}
			}
			if !diverse {
				return nil, nil, err
			}
			failures = append(failures, err)
			continue
		}
		if tcp == nil {
			return nil, nil, errors.New("DNS TCP listener has no captured owner")
		}
		selected, ok := tcp.Addr().(*net.TCPAddr)
		if !ok || selected == nil || selected.Port <= 0 || selected.Port > 65535 || (requestedPort != 0 && selected.Port != requestedPort) {
			return nil, nil, errors.Join(errors.New("DNS TCP listener did not own an actual port"), tcp.Close())
		}
		captured := net.UDPAddr{IP: append(net.IP(nil), selected.IP...), Port: selected.Port, Zone: selected.Zone}
		udp, udpErr := openUDP(&captured)
		if udpErr == nil {
			if udp != nil {
				actual, ok := udp.LocalAddr().(*net.UDPAddr)
				if ok && actual != nil && actual.Port == selected.Port && actual.IP.Equal(selected.IP) && actual.Zone == selected.Zone {
					return udp, tcp, nil
				}
			}
			udpErr = errors.New("DNS UDP listener did not retain the captured TCP endpoint")
			var closeUDP error
			if udp != nil {
				closeUDP = udp.Close()
			}
			return nil, nil, errors.Join(udpErr, closeUDP, tcp.Close())
		}
		// Do not retry if releasing the previous owner failed.
		var closeUDP error
		if udp != nil {
			closeUDP = udp.Close()
		}
		if closeErr := errors.Join(closeUDP, tcp.Close()); closeErr != nil {
			return nil, nil, errors.Join(udpErr, closeErr)
		}
		failures = append(failures, udpErr)
	}
	return nil, nil, fmt.Errorf("DNS could not reserve the same TCP/UDP port after %d attempt(s): %w", attempts, errors.Join(failures...))
}

// Listener loops stop before waiting for workers, so no late accepted request
// can Add to a completed WaitGroup. Every query receives this captured owner's
// context. Shutdown joins the workers before releasing their shared H3 owner.
func serveDNSProxy(parent context.Context, udp *net.UDPConn, tcp net.Listener, resolver *dnsResolver) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(context.Canceled)
	var loops, workers sync.WaitGroup
	slots := make(chan struct{}, maxDNSWorkers)
	start := func(work func()) bool {
		if ctx.Err() != nil {
			return false
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				work()
			}()
			return true
		default:
			return false
		}
	}
	loops.Add(2)
	go func() {
		defer loops.Done()
		buffer := make([]byte, 65536)
		for {
			count, address, err := udp.ReadFromUDP(buffer)
			if err != nil {
				cancel(err)
				return
			}
			if common.ValidateDNSForwardQuery(buffer[:count]) != nil {
				continue
			}
			query := append([]byte(nil), buffer[:count]...)
			start(func() {
				response, err := resolver.resolve(ctx, query)
				if err == nil && ctx.Err() == nil {
					_, _ = udp.WriteToUDP(response, address)
				}
			})
		}
	}()
	go func() {
		defer loops.Done()
		for {
			connection, err := tcp.Accept()
			if err != nil {
				cancel(err)
				return
			}
			if !start(func() { serveDNSClient(ctx, connection, resolver) }) {
				_ = connection.Close()
			}
		}
	}()
	<-ctx.Done()
	_ = udp.Close()
	_ = tcp.Close()
	loops.Wait()
	workers.Wait()
	if parent.Err() != nil {
		return nil
	}
	return context.Cause(ctx)
}

func serveDNSClient(ctx context.Context, conn net.Conn, resolver *dnsResolver) {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = conn.Close() })
	defer func() {
		if !stop() {
			<-done
		}
		_ = conn.Close()
	}()
	for ctx.Err() == nil {
		if conn.SetDeadline(time.Now().Add(15*time.Second)) != nil {
			return
		}
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(header[:]))
		if size < 12 {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil || common.ValidateDNSForwardQuery(query) != nil {
			return
		}
		response, err := resolver.resolve(ctx, query)
		if err != nil || ctx.Err() != nil {
			return
		}
		if err := writeDNSFrame(conn, response); err != nil {
			return
		}
	}
}
