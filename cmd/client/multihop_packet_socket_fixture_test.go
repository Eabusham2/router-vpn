package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
)

// A native SOCKS listener normally binds to the entry's private tunnel IP.
// This test cannot create that OS address. Forward its native authentication
// and stream verbatim; only the UDP association's loopback bind address/port
// is translated to the captured private address and one owned fixture port.
// UDP frames/destinations remain opaque, and the real relay must still carry
// them through the independently keyed WireGuard exit. Nothing routes around
// either encrypted endpoint or answers the traffic on behalf of the server.
func nativeMultihopPrivateSOCKSAdapter(t *testing.T, controlPort, packetPort, backendPort int) {
	t.Helper()
	address := func(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }
	control, err := net.Listen("tcp", address(controlPort))
	if err != nil {
		t.Fatal(err)
	}
	packets, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: packetPort})
	if err != nil {
		_ = control.Close()
		t.Fatal(err)
	}
	type association struct {
		upstream *net.UDPConn
		client   *net.UDPAddr
	}
	var mu sync.Mutex
	var current *association
	var closing bool
	connections := map[net.Conn]bool{}
	var jobs sync.WaitGroup
	jobs.Add(2)
	go func() {
		defer jobs.Done()
		buffer := make([]byte, 65535)
		for {
			n, client, err := packets.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			mu.Lock()
			owner := current
			if owner != nil && owner.client == nil {
				owner.client = client
			}
			valid := owner != nil && owner.client.String() == client.String()
			mu.Unlock()
			if valid {
				_, _ = owner.upstream.Write(buffer[:n])
			}
		}
	}()
	go func() {
		defer jobs.Done()
		for {
			front, err := control.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				_ = front.Close()
				return
			}
			connections[front] = true
			jobs.Add(1)
			mu.Unlock()
			go func() {
				defer jobs.Done()
				defer func() { _ = front.Close(); mu.Lock(); delete(connections, front); mu.Unlock() }()
				back, err := net.Dial("tcp", address(backendPort))
				if err != nil {
					return
				}
				mu.Lock()
				if closing {
					mu.Unlock()
					_ = back.Close()
					return
				}
				connections[back] = true
				mu.Unlock()
				defer func() { _ = back.Close(); mu.Lock(); delete(connections, back); mu.Unlock() }()
				// SOCKS5 greeting; keep the actual server's method decision.
				hello := make([]byte, 2)
				if _, err := io.ReadFull(front, hello); err != nil || hello[0] != 5 || hello[1] == 0 {
					return
				}
				methods := make([]byte, int(hello[1]))
				if _, err := io.ReadFull(front, methods); err != nil {
					return
				}
				if _, err := back.Write(append(hello, methods...)); err != nil {
					return
				}
				if _, err := io.ReadFull(back, hello); err != nil {
					return
				}
				if _, err := front.Write(hello); err != nil || hello[0] != 5 || hello[1] != 2 {
					return
				}
				// Forward the native username/password authentication unchanged.
				auth := make([]byte, 2)
				if _, err := io.ReadFull(front, auth); err != nil || auth[0] != 1 {
					return
				}
				user := make([]byte, int(auth[1])+1)
				if _, err := io.ReadFull(front, user); err != nil {
					return
				}
				password := make([]byte, int(user[len(user)-1]))
				if _, err := io.ReadFull(front, password); err != nil {
					return
				}
				credentials := append(append(auth, user...), password...)
				_, err = back.Write(credentials)
				clear(credentials)
				clear(password)
				clear(user)
				if err != nil {
					return
				}
				if _, err := io.ReadFull(back, auth); err != nil {
					return
				}
				if _, err := front.Write(auth); err != nil || auth[0] != 1 || auth[1] != 0 {
					return
				}
				request, err := nativePacketSOCKSAddress(front)
				if err != nil {
					return
				}
				if _, err := back.Write(request); err != nil {
					return
				}
				reply, err := nativePacketSOCKSAddress(back)
				if err != nil {
					return
				}
				if request[1] == 3 && reply[1] == 0 {
					if reply[3] != 1 || !net.IP(reply[4:8]).IsLoopback() {
						return
					}
					upstream, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(reply[8:10]))})
					if err != nil {
						return
					}
					owner := &association{upstream: upstream}
					mu.Lock()
					if closing || current != nil {
						mu.Unlock()
						_ = upstream.Close()
						return
					}
					current = owner
					jobs.Add(1)
					mu.Unlock()
					defer func() {
						_ = upstream.Close()
						mu.Lock()
						if current == owner {
							current = nil
						}
						mu.Unlock()
					}()
					go func() {
						defer jobs.Done()
						data := make([]byte, 65535)
						for {
							n, err := upstream.Read(data)
							if err != nil {
								return
							}
							mu.Lock()
							client, valid := owner.client, current == owner
							mu.Unlock()
							if valid && client != nil {
								_, _ = packets.WriteToUDP(data[:n], client)
							}
						}
					}()
					copy(reply[4:8], []byte{10, 77, 0, 1})
					binary.BigEndian.PutUint16(reply[8:10], uint16(packetPort))
				}
				if _, err := front.Write(reply); err != nil {
					return
				}
				jobs.Add(1)
				go func() { defer jobs.Done(); _, _ = io.Copy(back, front); _ = back.Close() }()
				_, _ = io.Copy(front, back)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = control.Close()
		_ = packets.Close()
		mu.Lock()
		closing = true
		for conn := range connections {
			_ = conn.Close()
		}
		if current != nil {
			_ = current.upstream.Close()
		}
		mu.Unlock()
		jobs.Wait()
	})
}

func nativePacketSOCKSAddress(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 5 {
		return nil, errors.New("not a SOCKS5 native fixture response")
	}
	length := 0
	switch header[3] {
	case 1:
		length = 6
	case 4:
		length = 18
	case 3:
		prefix := make([]byte, 1)
		if _, err := io.ReadFull(conn, prefix); err != nil {
			return nil, err
		}
		header = append(header, prefix[0])
		length = int(prefix[0]) + 2
	default:
		return nil, errors.New("invalid SOCKS5 native fixture address")
	}
	address := make([]byte, length)
	if _, err := io.ReadFull(conn, address); err != nil {
		return nil, err
	}
	return append(header, address...), nil
}
