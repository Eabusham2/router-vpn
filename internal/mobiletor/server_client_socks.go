package mobiletor

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// The only dial is the authenticated front through the captured Router. The
// destination remains SOCKS data and is never resolved or dialed on this host.
func dialServerTorSOCKS(parent context.Context, front, username, password, destination string, dial DialContext) (connection net.Conn, failure error) {
	host, portText, err := net.SplitHostPort(destination)
	port, portErr := strconv.Atoi(portText)
	if parent == nil || parent.Err() != nil || dial == nil || err != nil || portErr != nil || port < 1 || port > 65535 || host == "" || len(host) > 253 || !capturedHex(username, 24) || !capturedHex(password, 24) || username == password {
		return nil, errServerTorClient
	}
	request := []byte{5, 1, 0}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if address.Zone() != "" || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() {
			return nil, errServerTorClient
		}
		if address.Is4() {
			request = append(request, 1)
		} else {
			request = append(request, 4)
		}
		request = append(request, address.AsSlice()...)
	} else {
		for _, character := range host {
			if character <= 0x20 || character >= 0x7f || strings.ContainsRune("/\\:@", character) {
				return nil, errServerTorClient
			}
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	connection, err = dial(ctx, "tcp", front)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, errServerTorClient
	}
	owned := connection
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = owned.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
		if failure != nil || ctx.Err() != nil {
			_ = owned.Close()
			connection, failure = nil, errServerTorClient
		}
	}()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return nil, errServerTorClient
	}
	if _, err = connection.Write([]byte{5, 1, 2}); err != nil {
		return nil, errServerTorClient
	}
	var answer [2]byte
	if _, err = io.ReadFull(connection, answer[:]); err != nil || answer != [2]byte{5, 2} {
		return nil, errServerTorClient
	}
	auth := append([]byte{1, byte(len(username))}, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	_, err = connection.Write(auth)
	clear(auth)
	if err != nil {
		return nil, errServerTorClient
	}
	if _, err = io.ReadFull(connection, answer[:]); err != nil || answer != [2]byte{1, 0} {
		return nil, errServerTorClient
	}
	if _, err = connection.Write(request); err != nil {
		return nil, errServerTorClient
	}
	var header [4]byte
	if _, err = io.ReadFull(connection, header[:]); err != nil || header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, errServerTorClient
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		if _, err = io.ReadFull(connection, answer[:1]); err != nil || answer[0] == 0 {
			return nil, errServerTorClient
		}
		length = int(answer[0])
	default:
		return nil, errServerTorClient
	}
	if _, err = io.ReadFull(connection, make([]byte, length+2)); err != nil || ctx.Err() != nil || connection.SetDeadline(time.Time{}) != nil {
		return nil, errServerTorClient
	}
	return connection, nil
}
