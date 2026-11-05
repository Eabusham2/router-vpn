//go:build linux

package desktopnetwork

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"
)

// Unlike syscall.NetlinkRIB's blocking Recvfrom, this private dump socket is
// nonblocking and belongs to the original operation. Cancellation closes that
// exact descriptor, wakes the runtime poller and joins the close callback.
func linuxDumpRequest(ctx context.Context, request int) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("Linux network dump lost its original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "original-network-dump")
	defer file.Close()
	destination := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err = syscall.Bind(fd, destination); err != nil {
		return nil, err
	}
	address, err := syscall.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	local, ok := address.(*syscall.SockaddrNetlink)
	if !ok || local.Pid == 0 {
		return nil, errors.New("Linux network dump lost its original port")
	}
	message := make([]byte, 17)
	binary.LittleEndian.PutUint32(message, uint32(len(message)))
	binary.LittleEndian.PutUint16(message[4:], uint16(request))
	binary.LittleEndian.PutUint16(message[6:], syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST)
	binary.LittleEndian.PutUint32(message[8:], 1)
	message[16] = syscall.AF_UNSPEC
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// SOCK_NONBLOCK makes a full send queue an explicit failed observation;
	// it cannot block beyond the caller's deadline or silently retry policy.
	if err = syscall.Sendto(fd, message, 0, destination); err != nil {
		return nil, err
	}
	return linuxReceiveDump(ctx, file, local.Pid)
}

func linuxDumpDatagram(data []byte, flags int, sender syscall.Sockaddr, port uint32) (bool, error) {
	from, ok := sender.(*syscall.SockaddrNetlink)
	if !ok || from.Pid != 0 || len(data) < syscall.NLMSG_HDRLEN || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return false, errors.New("Linux network dump lost its complete original kernel datagram")
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return false, err
	}
	if err := linuxNetworkFraming(data, messages); err != nil {
		return false, err
	}
	done := false
	for _, message := range messages {
		if done || message.Header.Seq != 1 || message.Header.Pid != port || message.Header.Flags&0x10 != 0 || message.Header.Type == syscall.NLMSG_ERROR || message.Header.Type == syscall.NLMSG_OVERRUN {
			return false, errors.New("Linux network dump lost its exact request or native continuity")
		}
		if message.Header.Type == syscall.NLMSG_DONE {
			done = true
		}
	}
	return done, nil
}

// ParseNetlinkMessage permits a short trailing fragment. Neither a dump nor
// the subscribed event stream may turn that incomplete datagram into proof.
func linuxNetworkFraming(data []byte, messages []syscall.NetlinkMessage) error {
	if len(messages) == 0 {
		return errors.New("Linux network datagram omitted complete messages")
	}
	consumed := 0
	for _, message := range messages {
		aligned := (int(message.Header.Len) + 3) &^ 3
		if aligned < syscall.NLMSG_HDRLEN || aligned > len(data)-consumed {
			return errors.New("Linux network datagram contains incomplete aligned framing")
		}
		consumed += aligned
	}
	if consumed != len(data) {
		return errors.New("Linux network datagram contains trailing unframed bytes")
	}
	return nil
}

func linuxReceiveDump(ctx context.Context, file *os.File, port uint32) (result []byte, failure error) {
	if ctx == nil || file == nil || port == 0 {
		return nil, errors.New("Linux network dump has no original bounded socket")
	}
	var once sync.Once
	var closeErr error
	joined := make(chan struct{})
	closeOriginal := func() { once.Do(func() { closeErr = file.Close(); close(joined) }) }
	stop := context.AfterFunc(ctx, closeOriginal)
	defer func() {
		if !stop() {
			<-joined
		}
		closeOriginal()
		failure = errors.Join(failure, closeErr, ctx.Err())
	}()
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 256<<10)
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var size, flags int
		var sender syscall.Sockaddr
		var received error
		err = raw.Read(func(fd uintptr) bool {
			size, _, flags, sender, received = syscall.Recvmsg(int(fd), buffer, nil, syscall.MSG_DONTWAIT)
			return received != syscall.EAGAIN && received != syscall.EWOULDBLOCK && received != syscall.EINTR
		})
		if err == nil {
			err = received
		}
		if err != nil {
			return nil, err
		}
		if size <= 0 || size > len(buffer) || len(result)+size > 4<<20 {
			return nil, errors.New("Linux network dump exceeds its bounded native inventory")
		}
		done, err := linuxDumpDatagram(buffer[:size], flags, sender, port)
		if err != nil {
			return nil, err
		}
		result = append(result, buffer[:size]...)
		if done {
			return result, nil
		}
	}
}

func linuxDump(ctx context.Context, request int, response uint16) ([]syscall.NetlinkMessage, error) {
	raw, err := linuxDumpRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, errors.New("Linux network dump is empty or exceeds its bound")
	}
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, err
	}
	var rows []syscall.NetlinkMessage
	done := false
	for _, message := range messages {
		if done || message.Header.Flags&0x10 != 0 {
			return nil, errors.New("Linux network dump is interrupted or has trailing records")
		}
		if message.Header.Type == syscall.NLMSG_DONE {
			if len(message.Data) != 0 && (len(message.Data) < 4 || int32(binary.LittleEndian.Uint32(message.Data)) != 0) {
				return nil, errors.New("Linux network dump ended with an incomplete native result")
			}
			done = true
			continue
		}
		if message.Header.Type != response {
			return nil, errors.New("Linux network dump returned an unrequested record")
		}
		rows = append(rows, message)
	}
	if !done {
		return nil, errors.New("Linux network dump has no complete ending")
	}
	return rows, nil
}
