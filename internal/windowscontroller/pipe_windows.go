//go:build windows

package windowscontroller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const pipePrefix = `\\.\pipe\RouterVPN-Controller-v1-`
const maxFrame = 4096

type Pipe struct {
	mu                                      sync.Mutex
	readMu, writeMu                         sync.Mutex
	handle                                  syscall.Handle
	name                                    string
	server, connected, readMessage, closing bool
	closed                                  chan struct{}
	operations                              sync.WaitGroup
	closeOnce                               sync.Once
	closeErr                                error
}

func validPipeName(name string) bool {
	if !strings.HasPrefix(name, pipePrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, pipePrefix)
	if len(suffix) != 32 {
		return false
	}
	for _, value := range suffix {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return false
		}
	}
	return true
}

// NewPipe creates exactly one local, non-inheritable pipe instance. Its random
// name is only a rendezvous address, never an authentication credential.
func NewPipe() (*Pipe, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return createPipe(pipePrefix + hex.EncodeToString(nonce[:]))
}

func createPipe(name string) (*Pipe, error) {
	if !validPipeName(name) {
		return nil, errors.New("Windows controller pipe name is invalid")
	}
	api, err := native()
	if err != nil {
		return nil, err
	}
	identity, err := currentIdentity()
	if err != nil {
		return nil, err
	}
	encoded, _ := syscall.UTF16PtrFromString(name)
	var handle syscall.Handle
	err = withDescriptor(identity.SID, func(attributes *syscall.SecurityAttributes) error {
		value, _, callErr := api.createPipe.Call(uintptr(unsafe.Pointer(encoded)),
			3|0x40000000|0x00080000, /* DUPLEX | OVERLAPPED | FIRST_PIPE_INSTANCE */
			8 /* byte stream, PIPE_REJECT_REMOTE_CLIENTS */, 1, maxFrame, maxFrame, 0,
			uintptr(unsafe.Pointer(attributes)))
		handle = syscall.Handle(value)
		if handle == 0 || handle == syscall.InvalidHandle {
			return nativeError("private named pipe creation", callErr)
		}
		return nil
	})
	runtime.KeepAlive(encoded)
	if err != nil {
		return nil, err
	}
	return &Pipe{handle: handle, name: name, server: true, closed: make(chan struct{})}, nil
}

func (p *Pipe) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}

func (p *Pipe) borrow(requireConnected bool) (syscall.Handle, func(), error) {
	if p == nil {
		return 0, nil, ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.handle == 0 {
		return 0, nil, ErrClosed
	}
	if requireConnected && !p.connected {
		return 0, nil, errors.New("Windows controller pipe is not connected")
	}
	p.operations.Add(1)
	return p.handle, p.operations.Done, nil
}

// operation never releases its OVERLAPPED/event/buffer until the kernel has
// completed or acknowledged cancellation. Close joins all entered operations
// before closing the underlying pipe handle.
func (p *Pipe) operation(ctx context.Context, requireConnected bool, start func(syscall.Handle, *syscall.Overlapped) (uint32, error)) (uint32, error) {
	if ctx == nil {
		return 0, errors.New("Windows controller pipe requires a bounded caller")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	api, err := native()
	if err != nil {
		return 0, err
	}
	handle, release, err := p.borrow(requireConnected)
	if err != nil {
		return 0, err
	}
	defer release()
	value, _, callErr := api.event.Call(0, 1, 0, 0)
	if value == 0 {
		return 0, nativeError("pipe operation event", callErr)
	}
	event := syscall.Handle(value)
	defer syscall.CloseHandle(event)
	overlapped := syscall.Overlapped{HEvent: event}
	count, err := start(handle, &overlapped)
	if !errors.Is(err, syscall.ERROR_IO_PENDING) {
		if err == nil {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			select {
			case <-p.closed:
				return 0, ErrClosed
			default:
			}
		}
		return count, err
	}
	var interrupted error
	for {
		if interrupted == nil {
			interrupted = ctx.Err()
			if interrupted == nil {
				select {
				case <-p.closed:
					interrupted = ErrClosed
				default:
				}
			}
			if interrupted != nil {
				cancelErr := syscall.CancelIoEx(handle, &overlapped)
				if cancelErr != nil && !errors.Is(cancelErr, syscall.Errno(1168)) {
					interrupted = errors.Join(interrupted, cancelErr)
				}
			}
		}
		status, waitErr := syscall.WaitForSingleObject(event, 25)
		if waitErr != nil || status != syscall.WAIT_TIMEOUT && status != syscall.WAIT_OBJECT_0 {
			interrupted = errors.Join(interrupted, waitErr, errors.New("Windows controller pipe wait returned an unknown state"))
			_ = syscall.CancelIoEx(handle, &overlapped)
			break
		}
		if status == syscall.WAIT_OBJECT_0 {
			break
		}
	}
	var transferred uint32
	ok, _, callErr := api.overlappedResult.Call(uintptr(handle), uintptr(unsafe.Pointer(&overlapped)), uintptr(unsafe.Pointer(&transferred)), 1)
	runtime.KeepAlive(overlapped)
	if interrupted != nil {
		return 0, interrupted
	}
	if ok == 0 {
		return 0, nativeError("joined pipe operation", callErr)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-p.closed:
		return 0, ErrClosed
	default:
	}
	return transferred, nil
}

func (p *Pipe) Accept(ctx context.Context) error {
	if p == nil {
		return ErrClosed
	}
	p.readMu.Lock()
	defer p.readMu.Unlock()
	p.mu.Lock()
	valid := p.server && !p.connected && !p.closing
	p.mu.Unlock()
	if !valid {
		return errors.New("Windows controller pipe accepts only its first captured client")
	}
	api, err := native()
	if err != nil {
		return err
	}
	_, err = p.operation(ctx, false, func(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
		ok, _, callErr := api.connectPipe.Call(uintptr(handle), uintptr(unsafe.Pointer(overlapped)))
		if ok != 0 || errors.Is(callErr, syscall.Errno(535)) {
			return 0, nil
		} // ERROR_PIPE_CONNECTED
		return 0, callErr
	})
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return ErrClosed
	}
	p.connected = true
	return nil
}

// DialPipe deliberately requests identification-only SQOS. The pipe server may
// inspect the writer's token but never gains impersonation/delegation authority.
func DialPipe(ctx context.Context, name string) (*Pipe, error) {
	if ctx == nil || !validPipeName(name) {
		return nil, errors.New("Windows controller requires its exact local pipe address")
	}
	api, err := native()
	if err != nil {
		return nil, err
	}
	encoded, _ := syscall.UTF16PtrFromString(name)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		handle, err := syscall.CreateFile(encoded, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING,
			0x40000000|0x00100000|0x00010000 /* OVERLAPPED | SQOS_PRESENT | IDENTIFICATION */, 0)
		if err == nil {
			return &Pipe{handle: handle, name: name, connected: true, closed: make(chan struct{})}, nil
		}
		if !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) && !errors.Is(err, syscall.Errno(231)) {
			return nil, err
		}
		// This wait is bounded even if a named pipe never appears or another
		// already-connected owner keeps the single instance occupied.
		if errors.Is(err, syscall.Errno(231)) {
			api.waitPipe.Call(uintptr(unsafe.Pointer(encoded)), 20)
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *Pipe) read(ctx context.Context, buffer []byte) (int, error) {
	if len(buffer) == 0 || len(buffer) > maxFrame {
		return 0, errors.New("Windows controller pipe read is unbounded")
	}
	count, err := p.operation(ctx, true, func(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
		var count uint32
		err := syscall.ReadFile(handle, buffer, &count, overlapped)
		return count, err
	})
	runtime.KeepAlive(buffer)
	if err != nil {
		if errors.Is(err, syscall.ERROR_BROKEN_PIPE) {
			return 0, io.EOF
		}
		return 0, err
	}
	if count == 0 {
		return 0, io.EOF
	}
	if count > uint32(len(buffer)) {
		return 0, errors.New("Windows controller pipe returned an invalid read length")
	}
	p.mu.Lock()
	p.readMessage = true
	p.mu.Unlock()
	return int(count), nil
}

// ReadFrame consumes only one bounded frame, retaining all subsequent bytes for
// the exact session's lifetime observer. No buffered read can swallow its EOF
// or a later cancellation byte.
func (p *Pipe) ReadFrame(ctx context.Context) ([]byte, error) {
	if p == nil {
		return nil, ErrClosed
	}
	p.readMu.Lock()
	defer p.readMu.Unlock()
	frame := make([]byte, 0, 384)
	var next [1]byte
	for len(frame) < maxFrame {
		_, err := p.read(ctx, next[:])
		if err != nil {
			return nil, err
		}
		frame = append(frame, next[0])
		if next[0] == '\n' {
			return frame, nil
		}
	}
	return nil, errors.New("Windows controller pipe frame is oversized")
}

func (p *Pipe) WriteFrame(ctx context.Context, frame []byte) error {
	if p == nil {
		return ErrClosed
	}
	if len(frame) == 0 || len(frame) > maxFrame || frame[len(frame)-1] != '\n' || bytes.Count(frame, []byte{'\n'}) != 1 {
		return errors.New("Windows controller requires one exact bounded pipe frame")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	for len(frame) > 0 {
		count, err := p.operation(ctx, true, func(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
			var count uint32
			err := syscall.WriteFile(handle, frame, &count, overlapped)
			return count, err
		})
		runtime.KeepAlive(frame)
		if err != nil {
			return err
		}
		if count == 0 || count > uint32(len(frame)) {
			return io.ErrShortWrite
		}
		frame = frame[count:]
	}
	return nil
}

// ObserveLifetime returns only after the connected writer closes, this pipe is
// cancelled, or a protocol-invalid extra byte arrives. Callers revoke admission
// before beginning their owned controller/runtime drain.
func (p *Pipe) ObserveLifetime(ctx context.Context) error {
	if p == nil {
		return ErrClosed
	}
	p.readMu.Lock()
	defer p.readMu.Unlock()
	var next [1]byte
	_, err := p.read(ctx, next[:])
	if err != nil {
		return err
	}
	return errors.New("Windows controller lifetime channel received an unexpected frame")
}

type Peer struct {
	Process  *Process
	Identity TokenIdentity
}

func (p *Pipe) Peer() (*Peer, error) { return p.peer(nil) }

func (p *Pipe) peer(expected *Process) (_ *Peer, resultErr error) {
	if p == nil {
		return nil, ErrClosed
	}
	p.readMu.Lock()
	defer p.readMu.Unlock()
	api, err := native()
	if err != nil {
		return nil, err
	}
	handle, release, err := p.borrow(true)
	if err != nil {
		return nil, err
	}
	defer release()
	p.mu.Lock()
	server, readMessage := p.server, p.readMessage
	p.mu.Unlock()
	if server && !readMessage {
		return nil, errors.New("Windows controller must read its public client hello before token identification")
	}
	proc := api.pipeServerPID
	if server {
		proc = api.pipeClientPID
	}
	var pid uint32
	ok, _, callErr := proc.Call(uintptr(handle), uintptr(unsafe.Pointer(&pid)))
	if ok == 0 || pid == 0 {
		return nil, nativeError("actual named-pipe peer PID", callErr)
	}
	var process *Process
	if expected != nil {
		if pid != expected.PID() {
			return nil, errors.New("Windows controller pipe belongs to a different retained process")
		}
		process, err = expected.retain()
	} else {
		process, err = OpenProcess(pid)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, process.Close())
		}
	}()
	var identity TokenIdentity
	if server {
		identity, err = inspectWriter(handle)
	} else {
		identity, err = process.Identity()
	}
	if err != nil {
		return nil, err
	}
	if err := process.Alive(); err != nil {
		return nil, err
	}
	return &Peer{Process: process, Identity: identity}, nil
}

// VerifyPeer binds the kernel pipe peer to the retained launch process and
// pinned executable before the caller may transmit any access/owner secret.
// Token policy is deliberately separate: a different administrator SID can be
// the valid result of a standard user's explicit UAC consent.
func (p *Pipe) VerifyPeer(expected *Process, image *Image) (_ *Peer, resultErr error) {
	if expected == nil || image == nil {
		return nil, errors.New("Windows controller peer has no captured launch owner")
	}
	peer, err := p.peer(expected)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, peer.Process.Close())
		}
	}()
	if peer.Process.PID() != expected.PID() {
		return nil, errors.New("Windows controller pipe belongs to a different retained process")
	}
	if err := expected.Alive(); err != nil {
		return nil, err
	}
	if err := expected.VerifyImage(image); err != nil {
		return nil, err
	}
	if err := peer.Process.VerifyImage(image); err != nil {
		return nil, err
	}
	return peer, nil
}

func (p *Pipe) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closing = true
		close(p.closed)
		handle := p.handle
		p.mu.Unlock()
		cancelErr := syscall.CancelIoEx(handle, nil)
		if errors.Is(cancelErr, syscall.Errno(1168)) {
			cancelErr = nil
		}
		p.operations.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()
		closeErr := syscall.CloseHandle(handle)
		p.closeErr = errors.Join(cancelErr, closeErr)
		if closeErr == nil {
			p.handle = 0
		}
	})
	return p.closeErr
}
