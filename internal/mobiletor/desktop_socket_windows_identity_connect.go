//go:build windows

package mobiletor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

type desktopWindowsIdentityEndpointTransition struct{ before, after uint64 }

func (*desktopWindowsIdentityEndpointTransition) Error() string {
	return "Windows socket transfer changed its retained ALE endpoint during inspection"
}

// A read can straddle the real resource-assignment→connected TCP transition.
// Only that captured pending operation can retry, and only after the new kernel
// endpoint independently proves the same token, application, exact local tuple
// and captured destination as the already retained I/O object. A successful
// retry must still prove all original/returned/I/O descriptors agree at once.
func (p *DesktopWindowsSocketIdentity) verifyPendingTransitionLocked(creation DesktopSocketCreation, transition *desktopWindowsIdentityEndpointTransition) error {
	record := p.sockets[creation.SocketID]
	if record == nil || record.creation != creation || record.connect == nil || !p.validCreation(creation) {
		return errors.New("Windows endpoint change has no captured native Connect")
	}
	connection := record.connect
	if connection.phase != desktopWindowsTCPPending || connection.operation == nil || connection.operation.Err() != nil || connection.io == nil || record.endpoint != connection.boundEndpoint || connection.boundEndpoint == 0 {
		return errors.New("Windows endpoint retry is not the current pending Connect")
	}
	candidate := transition.after
	if transition.before != connection.boundEndpoint {
		if transition.after != connection.boundEndpoint {
			return errors.New("Windows endpoint retry did not witness the captured bound endpoint")
		}
		candidate = transition.before
	}
	if candidate == 0 || candidate == connection.boundEndpoint {
		return errors.New("Windows endpoint retry has no distinct connected endpoint")
	}
	properties, appID, err := p.api.endpointProperties(p.engine, candidate)
	if err != nil {
		return err
	}
	local, localErr := desktopWindowsALEAddress(properties.IPVersion, properties.LocalAddress)
	remote, remoteErr := desktopWindowsALEAddress(properties.IPVersion, properties.RemoteAddress)
	if localErr != nil || remoteErr != nil || properties.TokenModifiedID != p.statistics.ModifiedID || !bytes.Equal(appID, p.appID) || properties.Protocol != syscall.IPPROTO_TCP || netip.AddrPortFrom(local, properties.LocalPort) != connection.local || netip.AddrPortFrom(remote, properties.RemotePort) != connection.target {
		return errors.Join(localErr, remoteErr, errors.New("Windows endpoint retry changed the captured kernel owner or complete tuple"))
	}
	ioEndpoint, err := desktopWindowsALEEndpoint(desktopWindowsRaw{connection.io})
	if err != nil || ioEndpoint != candidate || connection.operation.Err() != nil {
		return errors.Join(err, errors.New("Windows endpoint retry lost the actual pending I/O owner"))
	}
	return nil
}

type desktopWindowsTCPPhase uint8

const (
	desktopWindowsTCPPending desktopWindowsTCPPhase = iota
	desktopWindowsTCPConnected
	desktopWindowsTCPFailed
)

// The identity gate owns this record. The I/O object itself remains owned by
// the importer/broker; this record grants no authority to close it early.
type desktopWindowsIdentityTCP struct {
	io            *desktopWindowsSocket
	operation     context.Context
	target, local netip.AddrPort
	boundEndpoint uint64
	phase         desktopWindowsTCPPhase
}

// Only a source-created transfer can register the actual I/O duplicate before
// Connect. Public callers cannot submit a token, endpoint ID, receipt or a new
// socket to declare that an already observed kernel transition is acceptable.
type desktopWindowsIdentityNative struct {
	native   DesktopSocketNative
	identity *DesktopWindowsSocketIdentity
	creation DesktopSocketCreation
}

func (n *desktopWindowsIdentityNative) SyscallConn() (syscall.RawConn, error) {
	return n.native.SyscallConn()
}
func (n *desktopWindowsIdentityNative) Close() error { return n.native.Close() }

func (n *desktopWindowsIdentityNative) beginNativeTCP(ctx context.Context, io *desktopWindowsSocket) error {
	p := n.identity
	if ctx == nil || ctx.Err() != nil || io == nil || !p.validCreation(n.creation) || n.creation.Network != "tcp" {
		return net.ErrClosed
	}
	return p.call(ctx, false, func() error {
		record := p.sockets[n.creation.SocketID]
		if record == nil || record.returned != n || record.creation != n.creation || record.connect != nil {
			return errors.New("Windows TCP import replaced or replayed its captured source")
		}
		before, err := p.inspectSocketLocked(n.creation)
		if err != nil || before.EndpointID == 0 || before.PeerConnected || before.Remote.Port() != 0 || !before.Remote.Addr().IsUnspecified() {
			return errors.Join(err, errors.New("Windows TCP import lacks its complete pre-connect identity"))
		}
		if !io.remote.IsValid() || io.remote.Port() == 0 || io.remote.Addr().IsUnspecified() || io.remote.Addr().IsMulticast() || io.remote.Addr().Is4In6() || io.remote.Addr().Zone() != "" || io.remote.Addr().Is4() != before.Local.Addr().Is4() {
			return errors.New("Windows TCP import has no captured numeric peer")
		}
		raw := desktopWindowsRaw{io}
		endpoint, err := desktopWindowsALEEndpoint(raw)
		if err != nil || endpoint != before.EndpointID {
			return errors.Join(err, errors.New("Windows TCP import substituted the pre-connect kernel endpoint"))
		}
		// The returned descriptor actually performed Bind. Confirm its exact
		// original/returned kernel owner again around the I/O endpoint read.
		// Do not ask a newly duplicated descriptor's provider cache to stand in
		// for that proof before Connect. Its own completed tuple is mandatory
		// in the connector and in finishNativeTCP before any connection escapes.
		confirmed, err := p.inspectSocketLocked(n.creation)
		if err != nil || confirmed.EndpointID != before.EndpointID || confirmed.TokenModifiedID != before.TokenModifiedID ||
			confirmed.Local != before.Local || confirmed.Remote != before.Remote || confirmed.PeerConnected ||
			confirmed.Family != before.Family || confirmed.Protocol != before.Protocol || !bytes.Equal(confirmed.AppID, before.AppID) || io.boundLocal != before.Local {
			return errors.Join(err, errors.New("Windows TCP import lost its independently captured bound tuple and owner"))
		}
		endpoint, err = desktopWindowsALEEndpoint(raw)
		if err != nil || endpoint != confirmed.EndpointID {
			return errors.Join(err, errors.New("Windows TCP import changed its confirmed I/O kernel endpoint"))
		}
		if ctx.Err() != nil || !p.validCreation(n.creation) {
			return net.ErrClosed
		}
		record.connect = &desktopWindowsIdentityTCP{io: io, operation: ctx, target: io.remote, local: before.Local, boundEndpoint: before.EndpointID, phase: desktopWindowsTCPPending}
		return nil
	})
}

func (n *desktopWindowsIdentityNative) finishNativeTCP(ctx context.Context, io *desktopWindowsSocket, connectErr error) error {
	p := n.identity
	return p.call(ctx, connectErr != nil, func() error {
		record := p.sockets[n.creation.SocketID]
		if record == nil || record.returned != n || record.creation != n.creation || record.connect == nil || record.connect.io != io || record.connect.phase != desktopWindowsTCPPending {
			return errors.New("Windows TCP completion lost its captured import operation")
		}
		if connectErr != nil {
			record.connect.phase = desktopWindowsTCPFailed
			return nil
		}
		inspection, err := p.inspectSocketLocked(n.creation)
		if err != nil || !inspection.PeerConnected {
			return errors.Join(err, errors.New("Windows TCP completion lacks an independently connected peer"))
		}
		if ctx.Err() != nil || record.connect.operation.Err() != nil || !p.validCreation(n.creation) {
			return net.ErrClosed
		}
		record.connect.phase = desktopWindowsTCPConnected
		return nil
	})
}

// Resource-assignment and connected TCP endpoints have separate WFP lifetimes.
// A changed endpoint is accepted only during the one registered native Connect,
// with all three live descriptors agreeing and independently verified kernel
// token, application, local tuple and captured remote. UDP and uncaptured TCP
// retain the original exact-endpoint rule.
func desktopWindowsIdentityInspectProvider(record *desktopWindowsIdentitySocket, returned syscall.RawConn, endpoint uint64, local, remote netip.AddrPort) (bool, error) {
	peerRaw := returned
	pending := false
	if connection := record.connect; connection != nil {
		if record.creation.Network != "tcp" || connection.io == nil || connection.operation == nil || connection.boundEndpoint == 0 || connection.local != local || (connection.phase != desktopWindowsTCPPending && connection.phase != desktopWindowsTCPConnected) {
			return false, errors.New("Windows TCP proof lost its registered import")
		}
		pending = connection.phase == desktopWindowsTCPPending
		if pending && connection.operation.Err() != nil {
			return false, errors.New("Windows TCP proof belongs to a cancelled import")
		}
		if remote.Port() == 0 && remote.Addr().IsUnspecified() {
			if !pending {
				return false, errors.New("Windows connected TCP endpoint lost its kernel remote")
			}
		} else if remote != connection.target {
			return false, errors.New("Windows TCP kernel peer differs from the captured connect target")
		}
		peerRaw = desktopWindowsRaw{connection.io}
		ioEndpoint, err := desktopWindowsALEEndpoint(peerRaw)
		if err != nil {
			return false, fmt.Errorf("Windows imported I/O ALE readback: %w", err)
		}
		if ioEndpoint != endpoint {
			return false, &desktopWindowsIdentityEndpointTransition{before: endpoint, after: ioEndpoint}
		}
		if record.endpoint != endpoint && (!pending || record.endpoint != connection.boundEndpoint || remote.Port() == 0 || remote.Addr().IsUnspecified()) {
			return false, errors.New("Windows TCP endpoint changed outside its one captured connect transition")
		}
	} else {
		if record.endpoint != 0 && record.endpoint != endpoint {
			return false, errors.New("Windows socket transfer changed its retained ALE endpoint")
		}
		if record.creation.Network == "tcp" && (remote.Port() != 0 || !remote.Addr().IsUnspecified()) {
			return false, errors.New("Windows TCP connection has no captured native import")
		}
	}
	// Interface ownership stays on the exact returned descriptor that received
	// Bind. Its local provider state is valid; a pre-connect duplicate's peer
	// cache is not evidence about the live connected I/O descriptor.
	if err := desktopWindowsIdentityProviderLocal(returned, local); err != nil {
		return false, fmt.Errorf("Windows returned descriptor local readback: %w", err)
	}
	connected, err := desktopWindowsIdentityProviderTuple(peerRaw, local, remote, pending)
	if err != nil {
		return false, fmt.Errorf("Windows I/O descriptor tuple readback: %w", err)
	}
	if pending && record.connect.operation.Err() != nil {
		return false, errors.New("Windows TCP proof was cancelled before publication")
	}
	return connected, nil
}

func desktopWindowsIdentityProviderLocal(raw syscall.RawConn, local netip.AddrPort) error {
	var socketErr error
	err := raw.Control(func(handle uintptr) {
		address, readErr := syscall.Getsockname(syscall.Handle(handle))
		if readErr != nil {
			socketErr = readErr
			return
		}
		actual, readErr := desktopWindowsIdentitySocketAddress(address)
		if readErr != nil || actual != local {
			socketErr = errors.Join(readErr, errors.New("Windows ALE local tuple disagrees with the retained socket"))
		}
	})
	return errors.Join(err, socketErr)
}

func desktopWindowsIdentityProviderTuple(raw syscall.RawConn, local, remote netip.AddrPort, pending bool) (bool, error) {
	if !pending {
		if err := desktopWindowsIdentityProviderLocal(raw, local); err != nil {
			return false, fmt.Errorf("Winsock local tuple: %w", err)
		}
	}
	var connected bool
	var socketErr error
	err := raw.Control(func(handle uintptr) {
		peer, readErr := syscall.Getpeername(syscall.Handle(handle))
		if errors.Is(readErr, desktopSocketNotConnected) || errors.Is(readErr, syscall.Errno(10022)) {
			// A real pending Connect can already have an exact kernel remote
			// before Getpeername reports connection completion. The caller has
			// verified that remote against the captured target and live operation;
			// this remains PeerConnected=false and cannot finish the import.
			if !pending && (remote.Port() != 0 || !remote.Addr().IsUnspecified()) {
				socketErr = errors.New("Windows unconnected socket has a conflicting ALE remote tuple")
			}
			return
		}
		if readErr != nil {
			socketErr = fmt.Errorf("Winsock connected peer: %w", readErr)
			return
		}
		actual, readErr := desktopWindowsIdentitySocketAddress(peer)
		if readErr != nil || actual != remote {
			socketErr = errors.Join(readErr, errors.New("Windows ALE remote tuple disagrees with the I/O socket"))
			return
		}
		connected = true
	})
	if err == nil && socketErr == nil && connected && pending {
		// Pending imports already proved the returned descriptor's real bind
		// and the I/O descriptor's same ALE owner. A connected provider must now
		// expose that exact local tuple too; no read failure is suppressed.
		if localErr := desktopWindowsIdentityProviderLocal(raw, local); localErr != nil {
			return false, fmt.Errorf("Winsock completed local tuple: %w", localErr)
		}
	}
	return connected, errors.Join(err, socketErr)
}

func desktopWindowsIdentityCaptureRetirement(record *desktopWindowsIdentitySocket) error {
	if record.connect != nil {
		io := record.connect.io
		io.mu.Lock()
		closed := io.closed
		io.mu.Unlock()
		if !closed {
			return errors.New("Windows socket retirement precedes actual imported I/O close and join")
		}
	}
	if record.finalCaptured || record.original == nil || (record.endpoint == 0 && record.connect == nil) {
		return nil
	}
	// A cancelled Connect may finish before its normal proof is published. Read
	// the still-retained original before closing it, so its actual final endpoint
	// cannot be forgotten even when the importer returned an error. This grants
	// no permission and never marks a failed/cancelled operation connected.
	raw, err := record.original.SyscallConn()
	if err != nil {
		return err
	}
	endpoint, err := desktopWindowsALEEndpoint(raw)
	if err != nil {
		return err
	}
	record.finalEndpoint, record.finalCaptured = endpoint, true
	return nil
}
