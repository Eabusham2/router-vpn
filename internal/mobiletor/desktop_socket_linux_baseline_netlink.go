//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	desktopLinuxNFTSubsystem     = 10
	desktopLinuxNFTInet          = 1
	desktopLinuxNFTDeleteTable   = 0x0a02
	desktopLinuxNFTNewGeneration = 0x0a0f
	desktopLinuxNFTGetGeneration = 0x0a10
	desktopLinuxNFTBatchBegin    = 0x10
	desktopLinuxNFTBatchEnd      = 0x11
)

// This retained endpoint can only observe a ruleset generation and delete an
// original table handle conditional on that generation. It cannot flush a
// ruleset, delete by name, or create/adopt a replacement owner. Linux's UAPI
// uses native-endian headers and network-endian attribute payloads.
type desktopLinuxBaselineNetlink struct {
	mu        sync.Mutex
	file      *os.File
	port      uint32
	seq       uint32
	uncertain error
}

func desktopLinuxOpenBaselineNetlink() (_ *desktopLinuxBaselineNetlink, failure error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	n := &desktopLinuxBaselineNetlink{file: os.NewFile(uintptr(fd), "routervpn-owned-baseline-netlink")}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, n.close())
		}
	}()
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	address, err := syscall.Getsockname(fd)
	local, ok := address.(*syscall.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, errors.Join(err, errors.New("Linux baseline lost its original netlink endpoint"))
	}
	n.port = local.Pid
	var seed [4]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	n.seq = binary.NativeEndian.Uint32(seed[:]) & 0x3fffffff
	return n, nil
}

func desktopLinuxBaselineAttribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	result := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(result[:2], uint16(length))
	binary.NativeEndian.PutUint16(result[2:4], kind)
	copy(result[4:], value)
	return result
}

func desktopLinuxBaselineMessage(kind, flags uint16, seq, port uint32, family byte, subsystem uint16, attributes []byte) []byte {
	result := make([]byte, 20+len(attributes))
	binary.NativeEndian.PutUint32(result[:4], uint32(len(result)))
	binary.NativeEndian.PutUint16(result[4:6], kind)
	binary.NativeEndian.PutUint16(result[6:8], flags)
	binary.NativeEndian.PutUint32(result[8:12], seq)
	binary.NativeEndian.PutUint32(result[12:16], port)
	result[16] = family
	binary.BigEndian.PutUint16(result[18:20], subsystem)
	copy(result[20:], attributes)
	return result
}

func desktopLinuxBaselineReply(data []byte, source syscall.Sockaddr, flags int, port uint32, expected ...uint32) (*syscall.NetlinkMessage, error) {
	kernel, ok := source.(*syscall.SockaddrNetlink)
	if !ok || kernel.Family != syscall.AF_NETLINK || kernel.Pid != 0 || kernel.Groups != 0 || flags != 0 || len(data) < 16 || port == 0 || len(expected) == 0 || len(expected) > 3 {
		return nil, errors.New("Linux baseline did not receive a complete kernel reply")
	}
	length := int(binary.NativeEndian.Uint32(data[:4]))
	if length < 16 || length > len(data) || (length+3)&^3 != len(data) || !bytes.Equal(data[length:], make([]byte, len(data)-length)) {
		return nil, errors.New("Linux baseline received an incomplete or trailing native message")
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil || len(messages) != 1 || messages[0].Header.Pid != port || messages[0].Header.Flags&syscall.NLM_F_MULTI != 0 {
		return nil, errors.Join(err, errors.New("Linux baseline received an unrelated or ambiguous netlink reply"))
	}
	for _, sequence := range expected {
		if messages[0].Header.Seq == sequence {
			return &messages[0], nil
		}
	}
	return nil, errors.New("Linux baseline reply belongs to another native sequence")
}

// The caller holds mu, so cancellation cannot reset another operation's
// deadline. Keep a complete receipt even if cancellation races with delivery;
// an acknowledged mutation must never be replayed after a late failure.
func (n *desktopLinuxBaselineNetlink) exchange(ctx context.Context, request []byte, expected ...uint32) (reply *syscall.NetlinkMessage, sent bool, failure error) {
	if n.file == nil || n.port == 0 || n.uncertain != nil || ctx == nil || ctx.Err() != nil || len(request) == 0 || len(request) > 4096 {
		return nil, false, errors.Join(n.uncertain, errors.New("Linux baseline netlink operation lost its live original endpoint"))
	}
	deadline := time.Now().Add(2 * time.Second)
	if earlier, ok := ctx.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	if err := n.file.SetDeadline(deadline); err != nil {
		return nil, false, err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = n.file.SetDeadline(time.Now()); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
		reset := n.file.SetDeadline(time.Time{})
		failure = errors.Join(failure, ctx.Err(), reset)
		if sent && reply == nil || reset != nil {
			n.uncertain = errors.Join(failure, errors.New("Linux baseline retained an unacknowledged native operation"))
		}
	}()
	raw, err := n.file.SyscallConn()
	if err != nil {
		return nil, false, err
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
		sent = nativeErr == nil
		return true
	})
	if err != nil || nativeErr != nil {
		return nil, sent, errors.Join(err, nativeErr)
	}
	buffer := make([]byte, 64<<10)
	var size, flags int
	var source syscall.Sockaddr
	err = raw.Read(func(fd uintptr) bool {
		size, _, flags, source, nativeErr = syscall.Recvmsg(int(fd), buffer, nil, 0)
		return !errors.Is(nativeErr, syscall.EAGAIN) && !errors.Is(nativeErr, syscall.EINTR)
	})
	if err != nil || nativeErr != nil || size < 0 || size > len(buffer) {
		return nil, sent, errors.Join(err, nativeErr, errors.New("Linux baseline has no complete native receipt"))
	}
	reply, err = desktopLinuxBaselineReply(buffer[:size], source, flags, n.port, expected...)
	return reply, sent, err
}

func (n *desktopLinuxBaselineNetlink) nextSequence() (uint32, error) {
	if n.seq > ^uint32(0)-4 {
		return 0, errors.New("Linux baseline exhausted its original native sequence")
	}
	n.seq += 3
	return n.seq, nil
}

func desktopLinuxBaselineKernelError(message *syscall.NetlinkMessage, request []byte) error {
	if message == nil || message.Header.Type != syscall.NLMSG_ERROR || len(message.Data) < 20 || len(request) < 16 {
		return errors.New("Linux baseline did not receive a complete native acknowledgement")
	}
	if !bytes.Equal(message.Data[4:20], request[:16]) || message.Header.Seq != binary.NativeEndian.Uint32(request[8:12]) || message.Header.Pid != binary.NativeEndian.Uint32(request[12:16]) {
		return errors.New("Linux baseline acknowledgement belongs to another request")
	}
	code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
	if code > 0 || code < -4095 {
		return errors.New("Linux baseline acknowledgement has a malformed native error")
	}
	if code != 0 {
		return fmt.Errorf("Linux baseline kernel transaction rejected: %w", syscall.Errno(-int64(code)))
	}
	return nil
}

func desktopLinuxBaselineGeneration(message *syscall.NetlinkMessage) (uint32, error) {
	if message == nil || message.Header.Type != desktopLinuxNFTNewGeneration || len(message.Data) < 12 || message.Data[0] != syscall.AF_UNSPEC || message.Data[1] != 0 {
		return 0, errors.New("Linux baseline generation has an unexpected native shape")
	}
	var generation uint32
	seen := make(map[uint16]bool)
	for data := message.Data[4:]; len(data) != 0; {
		if len(data) < 4 {
			return 0, errors.New("Linux baseline generation has a truncated attribute")
		}
		length, rawKind := int(binary.NativeEndian.Uint16(data[:2])), binary.NativeEndian.Uint16(data[2:4])
		kind, aligned := rawKind&0x3fff, (length+3)&^3
		if length < 4 || aligned > len(data) || kind < 1 || kind > 3 || seen[kind] || rawKind&0x8000 != 0 {
			return 0, errors.New("Linux baseline generation has an ambiguous attribute")
		}
		seen[kind] = true
		switch kind {
		case 1, 2:
			if length != 8 {
				return 0, errors.New("Linux baseline generation metadata is not an exact native integer")
			}
			if kind == 1 {
				generation = binary.BigEndian.Uint32(data[4:8])
			}
		case 3:
			if length < 5 || length > 68 || data[length-1] != 0 || bytes.IndexByte(data[4:length-1], 0) >= 0 {
				return 0, errors.New("Linux baseline generation has malformed process metadata")
			}
		}
		data = data[aligned:]
	}
	if generation == 0 || binary.BigEndian.Uint16(message.Data[2:4]) != uint16(generation) {
		return 0, errors.New("Linux baseline has no exact nonzero ruleset generation")
	}
	return generation, nil
}

func (n *desktopLinuxBaselineNetlink) generation(ctx context.Context) (uint32, error) {
	if n == nil {
		return 0, errors.New("Linux baseline has no retained netlink endpoint")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	seq, err := n.nextSequence()
	if err != nil {
		return 0, err
	}
	request := desktopLinuxBaselineMessage(desktopLinuxNFTGetGeneration, syscall.NLM_F_REQUEST, seq, n.port, 0, 0, nil)
	reply, _, err := n.exchange(ctx, request, seq)
	if reply == nil {
		return 0, err
	}
	generation, receiptErr := n.generationReceipt(reply, request)
	if failure := errors.Join(err, receiptErr); failure != nil {
		return 0, failure
	}
	return generation, nil
}

// The caller holds the endpoint's operation lock. A parsed datagram is only
// transport evidence; malformed semantic contents still retire that stream.
func (n *desktopLinuxBaselineNetlink) generationReceipt(reply *syscall.NetlinkMessage, request []byte) (uint32, error) {
	if reply.Header.Type == syscall.NLMSG_ERROR {
		err := errors.Join(desktopLinuxBaselineKernelError(reply, request), errors.New("Linux baseline received no generation identity"))
		n.retainUncertainReceipt(err)
		return 0, err
	}
	generation, err := desktopLinuxBaselineGeneration(reply)
	n.retainUncertainReceipt(err)
	return generation, err
}

func desktopLinuxBaselineDeleteReceipt(reply *syscall.NetlinkMessage, requests [3][]byte) (bool, error) {
	if reply == nil {
		return false, errors.New("Linux baseline has no native transaction receipt")
	}
	for index, request := range requests {
		if len(request) < 16 || reply.Header.Seq != binary.NativeEndian.Uint32(request[8:12]) {
			continue
		}
		if err := desktopLinuxBaselineKernelError(reply, request); err != nil {
			return false, err
		}
		// A command ACK can precede transaction commit failure. Only the
		// kernel's successful BATCH_END receipt proves the complete commit.
		if index != 2 {
			return false, errors.New("Linux baseline received no committed batch acknowledgement")
		}
		return true, nil
	}
	return false, errors.New("Linux baseline receipt belongs to another transaction")
}

func (n *desktopLinuxBaselineNetlink) retainUncertainReceipt(err error) {
	var rejection syscall.Errno
	if err != nil && !errors.As(err, &rejection) {
		// Only an exactly attributed kernel negative is a known unchanged
		// transaction. Other replies cannot authorize another native send.
		n.uncertain = err
	}
}

func (n *desktopLinuxBaselineNetlink) deleteReceipt(reply *syscall.NetlinkMessage, requests [3][]byte) (bool, error) {
	acknowledged, err := desktopLinuxBaselineDeleteReceipt(reply, requests)
	n.retainUncertainReceipt(err)
	return acknowledged, err
}

func (n *desktopLinuxBaselineNetlink) delete(ctx context.Context, generation uint32, handle uint64) (acknowledged, sent bool, failure error) {
	if n == nil || generation == 0 || handle == 0 || handle > 1<<53-1 {
		return false, false, errors.New("Linux baseline deletion requires its original exact handle and generation")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	seq, err := n.nextSequence()
	if err != nil {
		return false, false, err
	}
	var gen [4]byte
	binary.BigEndian.PutUint32(gen[:], generation)
	var object [8]byte
	binary.BigEndian.PutUint64(object[:], handle)
	requests := [3][]byte{
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchBegin, syscall.NLM_F_REQUEST, seq, n.port, 0, desktopLinuxNFTSubsystem, desktopLinuxBaselineAttribute(1, gen[:])),
		desktopLinuxBaselineMessage(desktopLinuxNFTDeleteTable, syscall.NLM_F_REQUEST, seq+1, n.port, desktopLinuxNFTInet, 0, desktopLinuxBaselineAttribute(4, object[:])),
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq+2, n.port, 0, desktopLinuxNFTSubsystem, nil),
	}
	request := append(append(append([]byte{}, requests[0]...), requests[1]...), requests[2]...)
	reply, sent, err := n.exchange(ctx, request, seq, seq+1, seq+2)
	if reply == nil {
		return false, sent, err
	}
	acknowledged, receiptErr := n.deleteReceipt(reply, requests)
	return acknowledged, sent, errors.Join(err, receiptErr)
}

func (n *desktopLinuxBaselineNetlink) close() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.file == nil {
		return nil
	}
	if err := n.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	n.file = nil
	return nil
}
