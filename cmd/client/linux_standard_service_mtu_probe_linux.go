//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"

	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// The public sample must traverse the very TUN whose reader was changed. A
// localhost SOCKS dial would test the exit while bypassing that interface.
func (o *linuxStandardServiceMTUOwner) DialThroughTunnel(ctx context.Context, expected mobilemtu.State, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("standard MTU supports bounded IPv4 public TCP probes")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errors.New("standard MTU probe destination is not the captured HTTPS service")
	}
	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return nil, err
	}
	defer o.launch.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	receipt, err := o.requireStateLocked(ctx, expected)
	if err != nil {
		return nil, err
	}
	var destinations []string
	if host == "speed.cloudflare.com" {
		binding := o.launch.prepared.requestEpoch.mtuBinding
		response, err := o.rpcLocked(ctx, "mtu-resolve", &linuxStandardServiceMTURequest{Expected: &binding})
		if err != nil {
			return nil, err
		}
		if response.Current != binding {
			return nil, errors.New("standard MTU DNS response changed original reader")
		}
		for _, literal := range response.Addresses {
			ip, err := netip.ParseAddr(literal)
			if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return nil, errors.New("standard MTU DNS returned a non-public IPv4 address")
			}
			destinations = append(destinations, net.JoinHostPort(ip.String(), port))
		}
	} else if host == "1.1.1.1" {
		destinations = []string{address}
	} else {
		return nil, errors.New("standard MTU probe requested an uncaptured destination")
	}
	if len(destinations) == 0 {
		return nil, errors.New("standard MTU selected DNS returned no public IPv4 address")
	}
	dialer := net.Dialer{ControlContext: func(call context.Context, network, address string, raw syscall.RawConn) error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		actual, err := o.requireStateLocked(call, expected)
		if err != nil {
			return err
		}
		if actual.Name != receipt.Name || actual.Index != receipt.Index || actual.Incarnation != receipt.Incarnation || actual.MTU != receipt.MTU {
			return errors.New("standard MTU native interface changed before socket binding")
		}
		var bindErr error
		err = raw.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, receipt.Name)
		})
		return errors.Join(err, bindErr)
	}}
	var failure error
	for _, destination := range destinations {
		connection, err := dialer.DialContext(ctx, "tcp4", destination)
		if err != nil {
			failure = errors.Join(failure, err)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if _, err := o.requireStateLocked(ctx, expected); err != nil {
			_ = connection.Close()
			return nil, err
		}
		o.sockets.Add(1)
		owned := &linuxStandardMTUConn{Conn: connection, owner: o}
		context.AfterFunc(ctx, func() { _ = owned.Close() })
		return owned, nil
	}
	return nil, failure
}

type linuxStandardMTUConn struct {
	net.Conn
	owner *linuxStandardServiceMTUOwner
	once  sync.Once
	err   error
}

func (c *linuxStandardMTUConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		// Native close joins before removing this socket from admission. Socket
		// retirement cannot wait behind another probe holding the launch gate.
		c.owner.sockets.Add(-1)
	})
	return c.err
}

func (o *linuxStandardServiceMTUOwner) VerifyExternal(ctx context.Context, expected mobilemtu.State) error {
	if _, err := o.CaptureContext(ctx); err != nil {
		return err
	}
	err := mobilemultihop.ProveExternalPublicIP(ctx, func(call context.Context, tag, address string) (net.Conn, error) {
		if tag != "custom-exit" {
			return nil, errors.New("standard MTU exit proof changed graph tag")
		}
		return o.DialThroughTunnel(call, expected, "tcp", address)
	}, "custom-exit", o.launch.mtuExit.ExpectedPublicIP)
	if err != nil {
		return err
	}
	if err := mobilemtu.LockContext(ctx, &o.launch.mu); err != nil {
		return err
	}
	defer o.launch.mu.Unlock()
	_, err = o.requireStateLocked(ctx, expected)
	return err
}

var _ mobilemtu.ExternalOwner = (*linuxStandardServiceMTUOwner)(nil)
var _ mobilemtu.ContextOwner = (*linuxStandardServiceMTUOwner)(nil)
var _ mobilemtu.RollbackOwner = (*linuxStandardServiceMTUOwner)(nil)
