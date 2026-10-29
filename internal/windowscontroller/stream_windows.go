//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"io"
	"runtime"
	"syscall"
)

// ReadContext reads one bounded binary chunk after the caller has completed the
// independent public hello and native peer verification. It never changes the
// newline bootstrap or ObserveLifetime protocol. The outer bridge owns exact
// frame lengths and must retire its channel after any partial-frame failure.
func (p *Pipe) ReadContext(ctx context.Context, buffer []byte) (int, error) {
	if p == nil {
		return 0, ErrClosed
	}
	p.readMu.Lock()
	defer p.readMu.Unlock()
	return p.read(ctx, buffer)
}

// WriteContext preserves operation's cancellation/OVERLAPPED join before the
// caller may reuse its bytes or close its captured pipe. A request cancellation
// must not be passed here: a complete binary frame uses its channel deadline.
func (p *Pipe) WriteContext(ctx context.Context, buffer []byte) (int, error) {
	if p == nil {
		return 0, ErrClosed
	}
	if len(buffer) == 0 || len(buffer) > maxFrame {
		return 0, errors.New("Windows controller binary chunk is unbounded")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	count, err := p.operation(ctx, true, func(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
		var count uint32
		err := syscall.WriteFile(handle, buffer, &count, overlapped)
		return count, err
	})
	runtime.KeepAlive(buffer)
	if err != nil {
		return 0, err
	}
	if count == 0 || count > uint32(len(buffer)) {
		return 0, io.ErrShortWrite
	}
	return int(count), nil
}
