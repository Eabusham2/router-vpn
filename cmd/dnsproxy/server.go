package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"router-vpn/internal/common"
)

const maxDNSWorkers = 256

func runDNSProxy(parent context.Context, listen string, u upstream) (result error) {
	udpAddress, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return err
	}
	defer udp.Close()
	// A requested zero port is one shared ephemeral UDP/TCP port. Production
	// callers pass 127.0.0.1:53; tests do not need privilege or a system resolver.
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		return err
	}
	defer tcp.Close()
	resolver, err := newDNSResolver(u, nil)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, resolver.Close()) }()
	log.Printf("RouterVPN DNS listening on %s -> %s", udp.LocalAddr(), describe(u))
	return serveDNSProxy(parent, udp, tcp, resolver)
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
