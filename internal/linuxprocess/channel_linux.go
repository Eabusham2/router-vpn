//go:build linux

package linuxprocess

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const MessageLimit = 16384

// Channel owns the actual inherited SOCK_SEQPACKET connection. Its per-message
// peer PID is supplied by actual process creation or a retained parent witness;
// the connection's creation-time SO_PEERCRED is not a substitute for SCM_CREDENTIALS.
type Channel struct {
	gate         chan struct{}
	file         *os.File
	conn         *net.UnixConn
	creator      syscall.Ucred
	identity     Object
	peerIdentity Object
	unnamed      bool
	createdPair  bool
	stopping     atomic.Bool
	closeMu      sync.Mutex
	closeErr     error
}

// Packet retains every received descriptor even if message validation fails.
// Callers must Close the returned packet on both success and error, after
// transferring its one permitted descriptor with TakeFile if appropriate.
type Packet struct {
	Payload []byte
	gate    sync.Mutex
	files   []*os.File
	valid   bool
	closed  bool
	err     error
}

// ChannelPair returns the parent endpoint and the exact child endpoint to pass
// with exec.Cmd.ExtraFiles. Both partial owners are returned on failure.
func ChannelPair() (*Channel, *os.File, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	first := os.NewFile(uintptr(pair[0]), "linux-parent-channel")
	second := os.NewFile(uintptr(pair[1]), "linux-child-inherited-channel")
	if err := syscall.SetsockoptInt(pair[1], syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
		return &Channel{gate: readyGate(), file: first}, second, err
	}
	channel, err := CaptureChannel(first)
	if err != nil {
		return channel, second, err
	}
	info, statErr := second.Stat()
	channel.peerIdentity, err = objectOf(info)
	if statErr != nil || err != nil || !channel.unnamed || !socketObject(channel.peerIdentity) {
		return channel, second, errors.Join(statErr, err, errors.New("Linux parent lost its original unnamed socketpair identities"))
	}
	channel.createdPair = true
	return channel, second, nil
}

func socketObject(value Object) bool {
	return value.Inode != 0 && value.Mode&0170000 == 0140000 && value.UID == 0 && value.GID == 0
}

func readyGate() chan struct{} {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return gate
}

// CaptureChannel consumes the exact inherited file, including on error. It
// accepts neither a pathname listener nor an arbitrary stream connection.
func CaptureChannel(file *os.File) (*Channel, error) {
	c := &Channel{gate: readyGate(), file: file}
	if file == nil {
		return c, errors.New("Linux child channel has no inherited descriptor")
	}
	// ExtraFiles clears CLOEXEC for the initial child. net.FileConn owns a
	// separate duplicate; marking that duplicate cannot protect this original
	// socket retained for authentication and joined cleanup.
	if err := SetCloseOnExec(file); err != nil {
		return c, err
	}
	info, statErr := file.Stat()
	var err error
	c.identity, err = objectOf(info)
	if statErr != nil || err != nil || !socketObject(c.identity) {
		return c, errors.Join(statErr, err, errors.New("Linux child channel has no original native socket object"))
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return c, err
	}
	var nativeErr error
	err = raw.Control(func(fd uintptr) {
		kind, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil || kind != syscall.SOCK_SEQPACKET {
			nativeErr = errors.Join(err, errors.New("Linux child channel requires native sequenced packets"))
			return
		}
		c.unnamed = true
		for _, peer := range []bool{false, true} {
			unnamed, err := capturedPairAddress(fd, peer)
			if err != nil {
				nativeErr = err
				return
			}
			c.unnamed = c.unnamed && unnamed
		}
		peer, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil || peer == nil || peer.Pid < 1 || peer.Uid != 0 || peer.Gid != 0 {
			nativeErr = errors.Join(err, errors.New("Linux child channel lost its privileged native creator"))
			return
		}
		c.creator = *peer
		nativeErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
	})
	if err != nil || nativeErr != nil {
		return c, errors.Join(err, nativeErr)
	}
	connection, err := net.FileConn(file)
	if err != nil {
		return c, err
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		// SOCK_SEQPACKET + AF_UNIX above makes this a net invariant. Preserve
		// any cleanup failure rather than treating it as a captured channel.
		return c, errors.Join(connection.Close(), errors.New("Linux child channel changed its native family"))
	}
	c.conn = unix
	return c, nil
}

func (c *Channel) CreatorPID() int {
	if c == nil {
		return 0
	}
	return int(c.creator.Pid)
}

func (c *Channel) currentIdentity() (Object, error) {
	if c == nil || c.file == nil || c.conn == nil || c.stopping.Load() {
		return Object{}, errors.New("Linux child channel has no live captured socket")
	}
	info, err := c.file.Stat()
	identity, identityErr := objectOf(info)
	if err != nil || identityErr != nil || identity != c.identity {
		return Object{}, errors.Join(err, identityErr, errors.New("Linux child channel changed its original socket object"))
	}
	return identity, nil
}

func (c *Channel) enter(ctx context.Context) error {
	if c == nil || ctx == nil || c.gate == nil {
		return errors.New("Linux child channel has no captured owner")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.gate:
		return nil
	}
}

func (c *Channel) operation(ctx context.Context, operation func() error) (failure error) {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { c.gate <- struct{}{} }()
	if ctx.Err() != nil || c.stopping.Load() || c.conn == nil {
		return errors.Join(ctx.Err(), errors.New("Linux child channel is incomplete or retired"))
	}
	deadline := time.Now().Add(5 * time.Second)
	if earlier, ok := ctx.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		c.stopping.Store(true)
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		// Join the exact cancellation callback before clearing its deadline;
		// an old operation can never interrupt a replacement operation.
		if err := c.conn.SetDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) {
			failure = errors.Join(failure, err)
		}
		failure = errors.Join(failure, ctx.Err())
		if c.stopping.Load() {
			failure = errors.Join(failure, errors.New("Linux child channel retired during its entered operation"))
		}
		if failure != nil {
			c.stopping.Store(true)
		}
	}()
	return operation()
}

func (c *Channel) Send(ctx context.Context, body []byte, file *os.File) error {
	if len(body) == 0 || len(body) > MessageLimit {
		return errors.New("Linux child message exceeds its bounded frame")
	}
	return c.operation(ctx, func() error {
		write := func(oob []byte) error {
			n, control, err := c.conn.WriteMsgUnix(body, oob, nil)
			if err != nil || n != len(body) || control != len(oob) {
				return errors.Join(err, errors.New("Linux child did not send its complete native frame"))
			}
			return nil
		}
		if file == nil {
			return write(nil)
		}
		raw, err := file.SyscallConn()
		if err != nil {
			return err
		}
		var sendErr error
		err = raw.Control(func(fd uintptr) { sendErr = write(syscall.UnixRights(int(fd))) })
		return errors.Join(err, sendErr)
	})
}

func (c *Channel) Receive(ctx context.Context, expectedPID int, wantFile bool) (*Packet, error) {
	p := &Packet{}
	if expectedPID < 1 || uint64(expectedPID) > 1<<31-1 {
		return p, errors.New("Linux child receiver requires its actually captured peer PID")
	}
	err := c.operation(ctx, func() error {
		body := make([]byte, MessageLimit+1)
		control := make([]byte, syscall.CmsgSpace(syscall.SizeofUcred)+syscall.CmsgSpace(16))
		n, oob, flags, address, readErr := c.conn.ReadMsgUnix(body, control)
		messages, parseErr := syscall.ParseSocketControlMessage(control[:oob])
		var credentials *syscall.Ucred
		var ancillaryErr error
		for _, message := range messages {
			switch {
			case message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_RIGHTS:
				if len(message.Data) == 0 || len(message.Data)%4 != 0 {
					ancillaryErr = errors.New("Linux child received malformed native descriptor data")
					continue
				}
				descriptors, err := syscall.ParseUnixRights(&message)
				ancillaryErr = errors.Join(ancillaryErr, err)
				for _, descriptor := range descriptors {
					p.files = append(p.files, os.NewFile(uintptr(descriptor), "authenticated-linux-child-task"))
				}
			case message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_CREDENTIALS:
				if credentials != nil {
					ancillaryErr = errors.New("Linux child repeated its native credential witness")
					continue
				}
				var err error
				credentials, err = syscall.ParseUnixCredentials(&message)
				ancillaryErr = errors.Join(ancillaryErr, err)
			default:
				ancillaryErr = errors.New("Linux child received an unknown native ancillary object")
			}
		}
		if readErr != nil || parseErr != nil || ancillaryErr != nil || n == 0 || n > MessageLimit ||
			flags & ^syscall.MSG_CMSG_CLOEXEC != 0 || (address != nil && address.Name != "" && address.Name[0] != '@') ||
			credentials == nil || int(credentials.Pid) != expectedPID || credentials.Uid != 0 || credentials.Gid != 0 ||
			(wantFile && len(p.files) != 1) || (!wantFile && len(p.files) != 0) {
			return errors.Join(readErr, parseErr, ancillaryErr, errors.New("Linux child rejected its native sender, descriptor inventory or complete frame"))
		}
		p.Payload = body[:n]
		return nil
	})
	p.valid = err == nil
	return p, err
}

func (p *Packet) TakeFile() (*os.File, error) {
	if p == nil {
		return nil, errors.New("Linux child packet has no native descriptor")
	}
	p.gate.Lock()
	defer p.gate.Unlock()
	if !p.valid || p.closed || len(p.files) != 1 || p.files[0] == nil {
		return nil, errors.New("Linux child packet has no single accepted native descriptor")
	}
	file := p.files[0]
	p.files[0] = nil
	return file, nil
}

func (p *Packet) Close() error {
	if p == nil {
		return nil
	}
	p.gate.Lock()
	defer p.gate.Unlock()
	p.valid = false
	clear(p.Payload)
	p.Payload = nil
	for i, file := range p.files {
		if file != nil {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				p.err = errors.Join(p.err, err)
				return err
			}
			p.files[i] = nil
		}
	}
	p.closed = p.err == nil
	return p.err
}

// Close first interrupts the real connection, then joins its entered operation.
// A cancelled join retains both the owner and any prior native close failure.
func (c *Channel) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux child channel close requires its live cleanup context")
	}
	c.stopping.Store(true)
	c.closeMu.Lock()
	if c.conn != nil {
		if err := c.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.closeErr = errors.Join(c.closeErr, err)
		}
	}
	if c.file != nil {
		if err := c.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			c.closeErr = errors.Join(c.closeErr, err)
		}
	}
	failure := c.closeErr
	c.closeMu.Unlock()
	if err := c.enter(ctx); err != nil {
		return errors.Join(failure, err)
	}
	c.gate <- struct{}{}
	return failure
}
