//go:build darwin

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// DesktopDarwinControl exposes the existing native framing and kernel peer
// checks to the retained controller/engine bootstrap. It transfers no file
// rights, grants no PF authority, and never authenticates a serialized PID.
// The caller binds each receive to its actual created child or inherited peer.
type DesktopDarwinControl struct {
	channel   *net.UnixConn
	gate      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func NewDesktopDarwinControlPair() (*DesktopDarwinControl, *os.File, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, nil, errors.New("native control requires its privileged original creator")
	}
	channel, child, err := desktopDarwinSocketPair()
	if err != nil {
		return nil, child, err
	}
	return newDesktopDarwinControl(channel), child, nil
}

// CaptureDesktopDarwinControl consumes only the fixed inherited descriptor3;
// the existing guardian parser verifies its root-created unnamed stream.
func CaptureDesktopDarwinControl() (*DesktopDarwinControl, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errors.New("native control requires its privileged inherited child")
	}
	channel, err := desktopDarwinHelperChannel()
	if err != nil {
		return nil, err
	}
	return newDesktopDarwinControl(channel), nil
}

func newDesktopDarwinControl(channel *net.UnixConn) *DesktopDarwinControl {
	c := &DesktopDarwinControl{channel: channel, gate: make(chan struct{}, 1)}
	c.gate <- struct{}{}
	return c
}

func (c *DesktopDarwinControl) operation(ctx context.Context, receiving bool) (func(), error) {
	if c == nil || c.channel == nil || c.gate == nil || ctx == nil {
		return nil, errors.New("native control has no original bounded operation")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.gate:
	}
	release := func() { c.gate <- struct{}{} }
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	if receiving {
		deadline = time.Time{}
	}
	if supplied, ok := ctx.Deadline(); ok && (deadline.IsZero() || supplied.Before(deadline)) {
		deadline = supplied
	}
	if err := c.channel.SetDeadline(deadline); err != nil {
		release()
		return nil, err
	}
	// Cancelled partial frames permanently retire this exact stream. No later
	// request may reinterpret a preceding operation's unfinished bytes.
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); close(joined) })
	return func() {
		defer release()
		if !stop() {
			<-joined
		}
	}, nil
}

func (c *DesktopDarwinControl) Send(ctx context.Context, raw json.RawMessage) error {
	stop, err := c.operation(ctx, false)
	if err != nil {
		return err
	}
	defer stop()
	if !json.Valid(raw) {
		return errors.New("native control output is not one bounded JSON value")
	}
	if err := desktopDarwinSend(c.channel, raw, nil); err != nil {
		_ = c.Close()
		return errors.Join(ctx.Err(), err)
	}
	return ctx.Err()
}

func (c *DesktopDarwinControl) Receive(ctx context.Context, actualPeer uint32) (json.RawMessage, error) {
	stop, err := c.operation(ctx, true)
	if err != nil {
		return nil, err
	}
	defer stop()
	var raw json.RawMessage
	reader := &desktopDarwinControlFrame{UnixConn: c.channel, ctx: ctx}
	file, err := desktopDarwinReceiveBounded(reader, &raw, actualPeer, 0, time.Time{})
	if file != nil {
		_ = file.Close()
		err = errors.Join(err, errors.New("native bootstrap received unexpected descriptor rights"))
	}
	if err != nil || ctx.Err() != nil {
		_ = c.Close()
		return nil, errors.Join(ctx.Err(), err)
	}
	return raw, nil
}

func (c *DesktopDarwinControl) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.channel != nil {
			c.closeErr = c.channel.Close()
		}
	})
	return c.closeErr
}

// Idle time belongs to the caller's lifetime. Once any frame byte arrives,
// all remaining bytes share one five-second deadline, including fragments.
type desktopDarwinControlFrame struct {
	*net.UnixConn
	ctx     context.Context
	started bool
}

func (r *desktopDarwinControlFrame) ReadMsgUnix(data, control []byte) (int, int, int, *net.UnixAddr, error) {
	n, oob, flags, peer, err := r.UnixConn.ReadMsgUnix(data, control)
	if !r.started && n > 0 {
		r.started = true
		deadline := time.Now().Add(5 * time.Second)
		if supplied, ok := r.ctx.Deadline(); ok && supplied.Before(deadline) {
			deadline = supplied
		}
		err = errors.Join(err, r.SetReadDeadline(deadline))
	}
	return n, oob, flags, peer, err
}
