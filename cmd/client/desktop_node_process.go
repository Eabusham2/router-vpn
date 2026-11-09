package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
)

// desktopNodeProcess is the actual native child owner. A command descriptor may
// still identify a connection transaction, but it never supplies this process's
// handle, Job membership, exit observation or cleanup authority.
type desktopNodeProcess interface {
	Started() bool
	Alive() error
	Wait(context.Context) (uint32, error)
	Close(context.Context) error
}

type desktopNodeOwnedChild interface {
	Alive() error
	Close(context.Context) error
}

type desktopNodeProcessWaiter interface {
	Wait(context.Context) (uint32, error)
	Close() error
}

// The child owns termination and its complete descendant group. The independent
// waiter is duplicated from that exact creation handle before publication, so
// retiring the child's handle cannot turn an unobserved exit into ErrClosed.
type desktopNodeProcessOwner struct {
	child             desktopNodeOwnedChild
	waiter            desktopNodeProcessWaiter
	controller        func() error
	controllerContext func(context.Context) error
	pins              []io.Closer
	started           bool
	waitDone          chan struct{}
	waitCode          uint32
	waitErr           error
	retiring          atomic.Bool
	closeGate         chan struct{}
	childJoined       bool
	waiterClosed      bool
	closed            bool
}

func newDesktopNodeProcessOwner(controller func() error) *desktopNodeProcessOwner {
	owner := &desktopNodeProcessOwner{controller: controller, closeGate: make(chan struct{}, 1)}
	owner.closeGate <- struct{}{}
	return owner
}

// Called once before the owner is visible to another goroutine. This observer
// has no PID lookup and no independent cancellation that could manufacture an
// exit. Checked child Close joins the process before this observer is released.
func (owner *desktopNodeProcessOwner) observe(waiter desktopNodeProcessWaiter) {
	owner.waiter = waiter
	owner.waitDone = make(chan struct{})
	go func() {
		owner.waitCode, owner.waitErr = waiter.Wait(context.Background())
		close(owner.waitDone)
	}()
}

func (owner *desktopNodeProcessOwner) Started() bool {
	return owner != nil && owner.started
}

func (owner *desktopNodeProcessOwner) Alive() error {
	if owner == nil || !owner.started || owner.child == nil || owner.controller == nil || owner.retiring.Load() {
		return errors.New("the captured native Node process is not live")
	}
	if err := owner.controller(); err != nil {
		return err
	}
	if err := owner.child.Alive(); err != nil {
		return err
	}
	if owner.retiring.Load() {
		return errors.New("the captured native Node process is retiring")
	}
	return owner.controller()
}

// Strict observations require both original callbacks; legacy Alive remains
// available to callers that have not admitted a bounded operation.
func (owner *desktopNodeProcessOwner) AliveContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("native process observation omitted original caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if owner == nil || !owner.started || owner.child == nil || owner.controllerContext == nil || owner.retiring.Load() {
		return errors.New("captured native process has no bounded live owner")
	}
	child, ok := owner.child.(interface{ AliveContext(context.Context) error })
	if !ok {
		return errors.New("captured native child omitted bounded observation")
	}
	if err := owner.controllerContext(ctx); err != nil {
		return err
	}
	if err := child.AliveContext(ctx); err != nil {
		return err
	}
	if owner.retiring.Load() {
		return errors.New("captured native process is retiring")
	}
	return errors.Join(owner.controllerContext(ctx), ctx.Err())
}

func (owner *desktopNodeProcessOwner) Wait(ctx context.Context) (uint32, error) {
	if ctx == nil || owner == nil || !owner.started || owner.waitDone == nil {
		return 0, errors.New("the captured native Node process has no retained exit observer")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-owner.waitDone:
		return owner.waitCode, owner.waitErr
	}
}

// Close revokes new use immediately. Failed Job/process joins retain every
// runtime pin and the exact child for retry; a second caller shares this same
// retirement, rather than dropping a handle or acknowledging an earlier error.
func (owner *desktopNodeProcessOwner) Close(ctx context.Context) error {
	if owner == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("native Node retirement requires a bounded caller")
	}
	owner.retiring.Store(true)
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-owner.closeGate:
	}
	defer func() { owner.closeGate <- struct{}{} }()
	if owner.closed {
		return nil
	}
	if owner.child != nil && !owner.childJoined {
		if err := owner.child.Close(ctx); err != nil {
			return err
		}
		owner.childJoined = true
	}
	if owner.waiter != nil && !owner.waiterClosed {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-owner.waitDone:
		}
		if err := owner.waiter.Close(); err != nil {
			return err
		}
		owner.waiterClosed = true
	}
	for index := len(owner.pins) - 1; index >= 0; index-- {
		if owner.pins[index] != nil {
			if err := owner.pins[index].Close(); err != nil {
				return err
			}
			owner.pins[index] = nil
		}
	}
	owner.closed = true
	return nil
}

// Only the sealed ordinary Node command enters this adapter. The public argv
// contains bounded identities, never an executable selector or credentials.
func validateDesktopNodeProcessArguments(arguments []string, directory string) ([]string, error) {
	invalid := errors.New("the native Node process requires its exact captured command")
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(directory) > 32760 || strings.ContainsAny(directory, "\x00\r\n") ||
		(len(arguments) != 11 && len(arguments) != 13) || arguments[0] != "routervpn-node" {
		return nil, invalid
	}
	values := make(map[string]string, 6)
	for index := 1; index < len(arguments); index += 2 {
		name, value := arguments[index], arguments[index+1]
		if _, exists := values[name]; exists || value == "" || strings.ContainsAny(value, "\x00\r\n") || len(value) > 32760 {
			return nil, invalid
		}
		switch name {
		case "--runtime-dir":
			if !sameDesktopNodeProcessPath(value, directory) {
				return nil, invalid
			}
		case "--session":
			if !desktopNodeProcessHex(value, 16) {
				return nil, invalid
			}
		case "--config-sha256", "--physical-source-sha256", "--imported-source-sha256", "--physical-transfer-sha256":
			if !desktopNodeProcessHex(value, 32) {
				return nil, invalid
			}
		case "--physical-mtu":
			mtu, err := strconv.Atoi(value)
			if err != nil || mtu < 1280 || mtu > 9000 || strconv.Itoa(mtu) != value {
				return nil, invalid
			}
		default:
			return nil, invalid
		}
		values[name] = value
	}
	if (values["--physical-source-sha256"] == "") == (values["--imported-source-sha256"] == "") {
		return nil, invalid
	}
	for _, name := range []string{"--runtime-dir", "--session", "--config-sha256", "--physical-transfer-sha256"} {
		if values[name] == "" {
			return nil, invalid
		}
	}
	return append([]string(nil), arguments...), nil
}

// The external command shares bounded public digest syntax, never Router
// readiness or its optional MTU argument. This is not a generic CLI selector.
func validateDesktopExternalProcessArguments(arguments []string, directory string) ([]string, error) {
	if len(arguments) != 11 || arguments[0] != "routervpn-external" {
		return nil, errors.New("native external process requires its exact captured command")
	}
	for _, argument := range arguments {
		if argument == "--imported-source-sha256" {
			return nil, errors.New("native external process cannot borrow imported-entry authority")
		}
	}
	copied := append([]string(nil), arguments...)
	copied[0] = "routervpn-node"
	validated, err := validateDesktopNodeProcessArguments(copied, directory)
	if err != nil {
		return nil, err
	}
	validated[0] = "routervpn-external"
	return validated, nil
}

func desktopNodeProcessHex(value string, size int) bool {
	if len(value) != size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size
}

func sameDesktopNodeProcessPath(actual, expected string) bool {
	if filepath.Clean(actual) != actual {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(actual, expected)
	}
	return actual == expected
}
