package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

// TCP owns the selected port before UDP adopts it. Windows may reserve TCP
// ranges that its UDP ephemeral allocator can still select. A requested zero
// port may retry a UDP collision, but every partial TCP owner is closed before
// another attempt. A fixed port is never replaced with another port.
func listenDNSProxyWith(listen string, openTCP func(*net.TCPAddr) (net.Listener, error), openUDP func(*net.UDPAddr) (*net.UDPConn, error)) (*net.UDPConn, net.Listener, error) {
	address, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		return nil, nil, err
	}
	attempts := 1
	if address.Port == 0 {
		attempts = 8
	}
	var lastUDPError error
	for range attempts {
		tcp, err := openTCP(address)
		if err != nil {
			return nil, nil, err
		}
		selected, ok := tcp.Addr().(*net.TCPAddr)
		if !ok || selected.Port == 0 {
			return nil, nil, errors.Join(errors.New("DNS TCP listener did not own an actual port"), tcp.Close())
		}
		udp, udpErr := openUDP(&net.UDPAddr{IP: append(net.IP(nil), selected.IP...), Port: selected.Port, Zone: selected.Zone})
		if udpErr == nil {
			return udp, tcp, nil
		}
		// Do not retry if releasing the previous owner failed.
		if closeErr := tcp.Close(); closeErr != nil {
			return nil, nil, errors.Join(udpErr, closeErr)
		}
		lastUDPError = udpErr
	}
	return nil, nil, fmt.Errorf("DNS could not reserve the same TCP/UDP port after %d attempt(s): %w", attempts, lastUDPError)
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
