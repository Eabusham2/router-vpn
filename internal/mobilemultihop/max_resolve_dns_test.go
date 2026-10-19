package mobilemultihop

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercise Go's actual DNS wire exchange through an explicitly captured local
// transport. Dial never uses the nameserver argument supplied by the host OS,
// and the fixture rejects every query except this selected MAX node's A/AAAA.
func TestMAXHostnameUsesActualCapturedDNSExchange(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var mu sync.Mutex
	queries := map[uint16]int{}
	connections := map[net.Conn]bool{}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					t.Error("captured DNS framing", err)
					return
				}
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 17 || n > 4096 {
					t.Error("invalid captured DNS request size")
					return
				}
				request := make([]byte, n)
				if _, err := io.ReadFull(conn, request); err != nil {
					t.Error(err)
					return
				}
				position := 12
				var labels []string
				for position < len(request) && request[position] != 0 {
					count := int(request[position])
					position++
					if count > 63 || position+count >= len(request) {
						t.Error("invalid DNS question label")
						return
					}
					labels = append(labels, string(request[position:position+count]))
					position += count
				}
				position++
				if position+4 > len(request) || strings.Join(labels, ".") != "captured-max.example" || binary.BigEndian.Uint16(request[4:6]) != 1 {
					t.Error("DNS escaped the exact captured hostname")
					return
				}
				kind := binary.BigEndian.Uint16(request[position : position+2])
				if (kind != 1 && kind != 28) || binary.BigEndian.Uint16(request[position+2:position+4]) != 1 {
					t.Error("unexpected DNS question type")
					return
				}
				mu.Lock()
				queries[kind]++
				mu.Unlock()
				response := append([]byte(nil), request[:position+4]...)
				binary.BigEndian.PutUint16(response[2:4], 0x8180)
				binary.BigEndian.PutUint16(response[6:8], 1)
				binary.BigEndian.PutUint16(response[8:10], 0)
				binary.BigEndian.PutUint16(response[10:12], 0)
				answer := netip.MustParseAddr("192.0.2.171").AsSlice()
				if kind == 28 {
					answer = netip.MustParseAddr("2001:db8::171").AsSlice()
				}
				response = append(response, 0xc0, 0x0c, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 1, 0, byte(len(answer)))
				response = append(response, answer...)
				binary.BigEndian.PutUint16(size[:], uint16(len(response)))
				if _, err := conn.Write(append(size[:], response...)); err != nil {
					t.Error("captured DNS response", err)
				}
			}()
		}
	}()
	defer func() {
		listener.Close()
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()
	ownedAddress := listener.Addr().String()
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ownedAddress)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	files, metadata := maxHostnameFixture(t, "max-quic-awg", "aes-256-gcm+xor-whitening", "captured-max.example.")
	capture, err := CaptureMAXProfile("max-quic-awg", pqEncoded(files), metadata)
	if err != nil {
		t.Fatal(err)
	}
	result, err := capture.Resolve(ctx, func(ctx context.Context, host string) ([]netip.Addr, error) {
		return resolver.LookupNetIP(ctx, "ip", host)
	})
	if err != nil || result.Endpoint() != "192.0.2.171" {
		t.Fatal("actual captured DNS answer was not compiled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if queries[1] != 1 || queries[28] != 1 || len(queries) != 2 {
		t.Fatal("lookup did not remain bounded to the captured node's two address families", queries)
	}
}
