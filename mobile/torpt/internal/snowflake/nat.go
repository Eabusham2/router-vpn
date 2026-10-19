/*
The majority of this code is taken from a utility I wrote for pion/stun
https://github.com/pion/stun/blob/master/cmd/stun-nat-behaviour/main.go

Copyright 2018 Pion LLC

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package snowflake_client

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4"
	"github.com/pion/webrtc/v4"
)

// RFC 5780 discovery is a broker matching hint only. A missing/unsupported
// response remains unknown; it is never used as VPN connectivity evidence.
func updateNATType(ctx context.Context, servers []webrtc.ICEServer, broker *BrokerChannel, network transport.Net) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, server := range servers {
		if bounded.Err() != nil {
			return
		}
		parsed, err := ice.ParseURL(server.URLs[0])
		if err != nil {
			continue
		}
		address := net.JoinHostPort(parsed.Host, strconv.Itoa(parsed.Port))
		value, err := detectNAT(bounded, network, address)
		if err == nil && bounded.Err() == nil {
			broker.SetNATType(value)
			return
		}
	}
}

func detectNAT(ctx context.Context, network transport.Net, address string) (string, error) {
	changed, err := restrictedMapping(ctx, network, address)
	if err != nil {
		return natUnknown, err
	}
	if changed {
		return "strict", nil
	}
	changed, err = restrictedFiltering(ctx, network, address)
	if err != nil {
		return natUnknown, err
	}
	if changed {
		return "moderate", nil
	}
	return "open", nil
}

type stunSocket struct {
	connection transport.UDPConn
	primary    *net.UDPAddr
	ctx        context.Context
	stop       func() bool
	once       sync.Once
	done       chan struct{}
}

func openSTUN(ctx context.Context, network transport.Net, address string) (*stunSocket, error) {
	var primary *net.UDPAddr
	var err error
	if resolver, ok := network.(interface {
		ResolveUDPAddrContext(context.Context, string, string) (*net.UDPAddr, error)
	}); ok {
		primary, err = resolver.ResolveUDPAddrContext(ctx, "udp4", address)
	} else {
		primary, err = network.ResolveUDPAddr("udp4", address)
	}
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	conn, err := network.ListenUDP("udp4", nil)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("Snowflake NAT socket is missing")
	}
	socket := &stunSocket{connection: conn, primary: primary, ctx: ctx, done: make(chan struct{})}
	socket.stop = context.AfterFunc(ctx, socket.closeSocket)
	if ctx.Err() != nil {
		socket.Close()
		return nil, ctx.Err()
	}
	return socket, nil
}
func (s *stunSocket) closeSocket() { s.once.Do(func() { _ = s.connection.Close(); close(s.done) }) }
func (s *stunSocket) Close()       { s.stop(); s.closeSocket(); <-s.done }
func (s *stunSocket) roundTrip(destination, expected *net.UDPAddr, change bool) (*stun.Message, error) {
	if s.ctx.Err() != nil {
		return nil, s.ctx.Err()
	}
	deadline := time.Now().Add(10 * time.Second)
	if parent, ok := s.ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := s.connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	request, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return nil, err
	}
	if change {
		request.Add(stun.AttrChangeRequest, []byte{0, 0, 0, 6})
	}
	if _, err = s.connection.WriteTo(request.Raw, destination); err != nil {
		return nil, err
	}
	for {
		var data [2048]byte
		n, source, err := s.connection.ReadFrom(data[:])
		if err != nil {
			return nil, err
		}
		if s.ctx.Err() != nil {
			return nil, s.ctx.Err()
		}
		remote, ok := source.(*net.UDPAddr)
		if !ok || !remote.IP.Equal(expected.IP) || remote.Port != expected.Port {
			continue
		}
		response := &stun.Message{Raw: append([]byte(nil), data[:n]...)}
		if response.Decode() != nil || response.TransactionID != request.TransactionID || response.Type != stun.BindingSuccess {
			continue
		}
		return response, nil
	}
}
func parseNATResponse(response *stun.Message) (stun.XORMappedAddress, *net.UDPAddr, error) {
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil {
		return mapped, nil, err
	}
	var other stun.OtherAddress
	if err := other.GetFrom(response); err != nil {
		return mapped, nil, err
	}
	if other.IP.To4() == nil || other.IP.IsUnspecified() || other.IP.IsMulticast() || other.Port < 1 || other.Port > 65535 {
		return mapped, nil, errors.New("Snowflake NAT alternate endpoint is invalid")
	}
	return mapped, &net.UDPAddr{IP: append(net.IP(nil), other.IP...), Port: other.Port}, nil
}
func restrictedMapping(ctx context.Context, network transport.Net, address string) (bool, error) {
	socket, err := openSTUN(ctx, network, address)
	if err != nil {
		return false, err
	}
	defer socket.Close()
	first, err := socket.roundTrip(socket.primary, socket.primary, false)
	if err != nil {
		return false, err
	}
	mapped, other, err := parseNATResponse(first)
	if err != nil {
		return false, err
	}
	second, err := socket.roundTrip(other, other, false)
	if err != nil {
		return false, err
	}
	var alternate stun.XORMappedAddress
	if err = alternate.GetFrom(second); err != nil {
		return false, err
	}
	return !mapped.IP.Equal(alternate.IP) || mapped.Port != alternate.Port, nil
}
func restrictedFiltering(ctx context.Context, network transport.Net, address string) (bool, error) {
	socket, err := openSTUN(ctx, network, address)
	if err != nil {
		return false, err
	}
	defer socket.Close()
	first, err := socket.roundTrip(socket.primary, socket.primary, false)
	if err != nil {
		return false, err
	}
	_, other, err := parseNATResponse(first)
	if err != nil {
		return false, err
	}
	_, err = socket.roundTrip(socket.primary, other, true)
	if err == nil {
		return false, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return true, nil
	}
	return false, err
}
