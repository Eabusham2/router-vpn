//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"time"
)

// Resume only the original socket's original transaction. A timeout leaves its
// remaining kernel replies queued for a later cleanup call. It never resends,
// reallocates sequence numbers, reopens a socket, or searches for an object.
func (n *desktopLinuxBaselineNetlink) bootstrapExchange(ctx context.Context, g *desktopLinuxBootstrapGrant) (failure error) {
	if n == nil || g == nil || ctx == nil {
		return errors.New("bootstrap mutation lost its original transaction")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !g.owns(n) {
		return errors.New("bootstrap transaction belongs to another original endpoint")
	}
	if g.complete() {
		return nil
	}
	if n.file == nil || n.port == 0 || n.uncertain != nil || g.poison != nil || n.bootstrap != nil && n.bootstrap != g || g.sent && n.bootstrap != g || ctx.Err() != nil {
		return errors.Join(n.uncertain, g.poison, ctx.Err(), errors.New("bootstrap mutation has no live original endpoint"))
	}
	if len(g.requests) < 4 || len(g.requests) > 5 {
		return errors.New("invalid bootstrap transaction width")
	}
	for _, r := range g.requests {
		if len(r) < 20 || binary.NativeEndian.Uint32(r[12:16]) != n.port {
			return errors.New("bootstrap transaction changed its original port")
		}
	}
	raw, err := n.file.SyscallConn()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	if earlier, ok := ctx.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	if err = n.file.SetDeadline(deadline); err != nil {
		return err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = n.file.SetDeadline(time.Now()); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
		reset := n.file.SetDeadline(time.Time{})
		failure = errors.Join(failure, ctx.Err(), reset)
		if reset != nil {
			g.poison = errors.Join(g.poison, reset)
		}
		if g.complete() {
			n.bootstrap = nil
		}
	}()
	n.bootstrap = g
	if !g.sent {
		if !g.originalDeadline.IsZero() && !time.Now().Add(g.duration).Before(g.originalDeadline) {
			n.bootstrap = nil
			return errors.New("bootstrap creation exhausted original processing reserve")
		}
		request := bytes.Join(g.requests, nil)
		if len(request) > 8192 {
			n.bootstrap = nil
			return errors.New("bootstrap transaction exceeds native bound")
		}
		var nativeErr error
		err = raw.Write(func(fd uintptr) bool {
			if nativeErr = ctx.Err(); nativeErr != nil {
				return true
			}
			nativeErr = syscall.Sendto(int(fd), request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
			if errors.Is(nativeErr, syscall.EAGAIN) || errors.Is(nativeErr, syscall.EINTR) {
				return false
			}
			g.sent = nativeErr == nil
			return true
		})
		if err != nil || nativeErr != nil {
			if !g.sent {
				n.bootstrap = nil
			}
			return errors.Join(err, nativeErr)
		}
	}
	for !g.complete() {
		buffer := make([]byte, 64<<10)
		var size, flags int
		var source syscall.Sockaddr
		var nativeErr error
		err = raw.Read(func(fd uintptr) bool {
			size, _, flags, source, nativeErr = syscall.Recvmsg(int(fd), buffer, nil, 0)
			return !errors.Is(nativeErr, syscall.EAGAIN) && !errors.Is(nativeErr, syscall.EINTR)
		})
		if err != nil || nativeErr != nil {
			failure = errors.Join(err, nativeErr)
			if !errors.Is(failure, os.ErrDeadlineExceeded) && ctx.Err() == nil {
				g.poison = failure
			}
			return failure
		}
		if size < 0 || size > len(buffer) {
			g.poison = errors.New("bootstrap native reply exceeds bound")
			return g.poison
		}
		if err = g.datagram(buffer[:size], source, flags, n.port); err != nil {
			if !g.rejected {
				g.poison = err
			}
			return err
		}
	}
	return nil
}
func (g *desktopLinuxBootstrapGrant) datagram(data []byte, source syscall.Sockaddr, flags int, port uint32) error {
	kernel, ok := source.(*syscall.SockaddrNetlink)
	if !ok || kernel.Family != syscall.AF_NETLINK || kernel.Pid != 0 || kernel.Groups != 0 || flags != 0 || port == 0 || len(data) == 0 {
		return errors.New("bootstrap reply is not its complete kernel datagram")
	}
	for len(data) > 0 {
		if len(data) < 16 {
			return errors.New("bootstrap reply has truncated header")
		}
		length := int(binary.NativeEndian.Uint32(data))
		aligned := (length + 3) &^ 3
		if length < 16 || aligned > len(data) || !bytes.Equal(data[length:aligned], make([]byte, aligned-length)) {
			return errors.New("bootstrap reply has invalid framing")
		}
		messages, err := syscall.ParseNetlinkMessage(data[:aligned])
		if err != nil || len(messages) != 1 || messages[0].Header.Pid != port || messages[0].Header.Flags&syscall.NLM_F_MULTI != 0 {
			return errors.New("bootstrap reply has ambiguous origin")
		}
		if err = g.receipt(&messages[0]); err != nil {
			return err
		}
		data = data[aligned:]
	}
	return nil
}
func (n *desktopLinuxBaselineNetlink) newBootstrapGrant(generation uint32, table, set string, rule []byte, mark uint32, deadline time.Time) (*desktopLinuxBootstrapGrant, error) {
	if n == nil {
		return nil, errors.New("bootstrap lost original native endpoint")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.file == nil || n.port == 0 || n.uncertain != nil || n.bootstrap != nil || n.seq > ^uint32(0)-8 {
		return nil, errors.New("bootstrap endpoint has pending or exhausted authority")
	}
	duration, err := desktopLinuxBootstrapPermitDuration(time.Until(deadline))
	if err != nil {
		return nil, err
	}
	seq := n.seq + 3
	n.seq = seq + 4
	requests, err := desktopLinuxBootstrapCreateRequests(generation, table, set, rule, mark, duration, seq, n.port)
	if err != nil {
		return nil, err
	}
	return &desktopLinuxBootstrapGrant{owner: n, file: n.file, port: n.port, requests: requests, table: table, set: set, duration: duration, originalDeadline: deadline}, nil
}
func (n *desktopLinuxBaselineNetlink) newBootstrapRemoval(generation uint32, g *desktopLinuxBootstrapGrant) (*desktopLinuxBootstrapGrant, error) {
	if n == nil || g == nil || !g.complete() || g.rejected {
		return nil, errors.New("bootstrap removal has no committed original grant")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !g.owns(n) {
		return nil, errors.New("bootstrap removal belongs to another original endpoint")
	}
	if n.file == nil || n.uncertain != nil || n.bootstrap != nil || n.seq > ^uint32(0)-8 {
		return nil, errors.New("bootstrap removal lost original endpoint")
	}
	seq := n.seq + 3
	n.seq = seq + 3
	requests, err := desktopLinuxBootstrapDeleteGrantRequests(generation, g.table, g.ruleHandle, g.setHandle, seq, n.port)
	if err != nil {
		return nil, err
	}
	return &desktopLinuxBootstrapGrant{owner: n, file: n.file, port: n.port, requests: requests, table: g.table, set: g.set}, nil
}
