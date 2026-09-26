package startwhitening

import (
	"errors"
	"fmt"
	"syscall"
)

// UDPSocketBufferBytes bounds each owned send/receive queue. Darwin rejects an
// atomic UDP write larger than its send buffer even when the IP packet is valid.
// This changes only our UDP sockets, never host-wide sysctls, TCP or path MTU.
const UDPSocketBufferBytes = 256 * 1024

type udpBufferSetter interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// ConfigureUDPSocket is also used by the shipping server relay and by its echo
// test endpoints. A setup failure must precede packet IO, not become truncation.
func ConfigureUDPSocket(socket udpBufferSetter) error {
	if socket == nil {
		return errors.New("missing owned UDP socket")
	}
	if err := socket.SetWriteBuffer(UDPSocketBufferBytes); err != nil {
		return fmt.Errorf("configure owned UDP send buffer: %w", err)
	}
	if err := socket.SetReadBuffer(UDPSocketBufferBytes); err != nil {
		return fmt.Errorf("configure owned UDP receive buffer: %w", err)
	}
	return nil
}

// UDPControl is appended AFTER the native platform's existing socket protection
// callback. It does not choose addresses/interfaces or initiate network traffic.
func UDPControl(network, _ string, raw syscall.RawConn) error {
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil
	}
	if raw == nil {
		return errors.New("missing owned UDP descriptor")
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) { socketErr = setUDPBuffers(fd) }); err != nil {
		return err
	}
	return socketErr
}
