//go:build darwin

package mobiletor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

type desktopDarwinRequest struct {
	Operation string
	Sequence  uint64
	Capture   DesktopSocketCapture
	Options   DesktopDarwinSocketOptions
	Creation  DesktopSocketCreation
	Grant     DesktopSocketGrant
	Tunnel    string
	Index     uint32
}

type desktopDarwinReply struct {
	Sequence uint64
	Capture  DesktopSocketCapture
	Owner    DesktopSocketKernelOwner
	Creation DesktopSocketCreation
	UID      uint32
	Account  string
	PF       *desktopDarwinPF
	Receipt  DesktopSocketReceipt
	Error    string
}

var desktopDarwinIdle = errors.New("Darwin physical control has no pending frame")

// Darwin does not implement Linux's SCM_CREDENTIALS protocol. The anonymous
// inherited stream has a single exec-owned peer; LOCAL_PEERPID is checked after
// each bounded frame, and descriptor creator UID is checked independently.
// Transfer/finish acknowledgments keep the peer alive until that observation.
func desktopDarwinSocketPair() (*net.UnixConn, *os.File, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, fd := range pair {
		syscall.CloseOnExec(fd)
	}
	first, second := os.NewFile(uintptr(pair[0]), "routervpn-physical-control"), os.NewFile(uintptr(pair[1]), "routervpn-physical-helper")
	connection, err := net.FileConn(first)
	first.Close()
	if err != nil {
		second.Close()
		return nil, nil, err
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		second.Close()
		return nil, nil, errors.New("Darwin physical channel is not Unix")
	}
	return unix, second, nil
}

func desktopDarwinHelperChannel() (*net.UnixConn, error) {
	file := os.NewFile(3, "routervpn-physical-inherited-channel")
	defer file.Close()
	var stat syscall.Stat_t
	kind, err := syscall.GetsockoptInt(3, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil || kind != syscall.SOCK_STREAM || syscall.Fstat(3, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK || stat.Uid != 0 {
		return nil, errors.New("Darwin physical helper requires its inherited root-created stream")
	}
	for _, query := range []func(int) (syscall.Sockaddr, error){syscall.Getsockname, syscall.Getpeername} {
		address, err := query(3)
		unix, ok := address.(*syscall.SockaddrUnix)
		if err != nil || !ok || unix.Name != "" {
			return nil, errors.New("Darwin physical helper cannot use a named or unconnected channel")
		}
	}
	connection, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, errors.New("Darwin physical inherited stream changed family")
	}
	return unix, nil
}

func desktopDarwinSend(channel *net.UnixConn, value any, file *os.File) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > 32<<10 {
		return errors.New("Darwin physical control frame exceeds its bound")
	}
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame, uint32(len(raw)))
	copy(frame[4:], raw)
	var rights []byte
	if file != nil {
		rights = syscall.UnixRights(int(file.Fd()))
	}
	n, oob, err := channel.WriteMsgUnix(frame, rights, nil)
	if err != nil {
		return err
	}
	if n != len(frame) || oob != len(rights) {
		return io.ErrShortWrite
	}
	return nil
}

func desktopDarwinReceive(channel *net.UnixConn, value any, pid, uid uint32) (file *os.File, failure error) {
	var header [4]byte
	control := make([]byte, syscall.CmsgSpace(4*8))
	n, oob, flags, _, err := channel.ReadMsgUnix(header[:], control)
	if desktopSocketIdleReceive(n, oob, flags, err) {
		return nil, desktopDarwinIdle
	}
	messages, parseErr := syscall.ParseSocketControlMessage(control[:oob])
	var files []*os.File
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET || message.Header.Type != syscall.SCM_RIGHTS {
			parseErr = errors.New("unexpected Darwin helper ancillary control")
			continue
		}
		rights, e := syscall.ParseUnixRights(&message)
		if e != nil {
			parseErr = e
		}
		for _, fd := range rights {
			syscall.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "routervpn-physical-transferred"))
		}
	}
	defer func() {
		if failure != nil {
			for _, f := range files {
				f.Close()
			}
		}
	}()
	if err != nil || parseErr != nil || flags != 0 || n == 0 || len(files) > 1 {
		return nil, errors.Join(err, parseErr, errors.New("Darwin physical channel lost its bounded frame"))
	}
	// Read every fragment with recvmsg. Ordinary Read/ReadFull would discard
	// an unexpected descriptor attached to a later byte of this stream.
	readRemainder := func(buffer []byte) error {
		for len(buffer) != 0 {
			n, oob, flags, _, readErr := channel.ReadMsgUnix(buffer, control)
			messages, parseErr := syscall.ParseSocketControlMessage(control[:oob])
			for _, message := range messages {
				if message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_RIGHTS {
					rights, err := syscall.ParseUnixRights(&message)
					parseErr = errors.Join(parseErr, err)
					for _, descriptor := range rights {
						syscall.Close(descriptor)
					}
				}
			}
			if readErr != nil || parseErr != nil || flags != 0 || oob != 0 || n == 0 {
				return errors.Join(readErr, parseErr, errors.New("Darwin physical frame has a truncated fragment or late descriptor"))
			}
			buffer = buffer[n:]
		}
		return nil
	}
	if err := readRemainder(header[n:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 32<<10 {
		return nil, errors.New("Darwin physical frame length is invalid")
	}
	data := make([]byte, length)
	if err := readRemainder(data); err != nil {
		return nil, err
	}
	raw, err := channel.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer int
	var peerErr error
	if err = raw.Control(func(fd uintptr) {
		peer, peerErr = syscall.GetsockoptInt(int(fd), 0 /* SOL_LOCAL */, 2 /* LOCAL_PEERPID */)
	}); err != nil || peerErr != nil || peer <= 1 || uint32(peer) != pid {
		return nil, errors.Join(err, peerErr, fmt.Errorf("Darwin physical channel has another actual peer PID %d, expected %d", peer, pid))
	}
	// A creator reply must include the actual descriptor made under its UID.
	// Guardian replies have no borrowed user identity; their child PID and
	// private inherited root-created stream establish the control owner.
	if uid != 0 {
		if len(files) != 1 {
			return nil, errors.New("Darwin isolated creator supplied no kernel descriptor")
		}
		var stat syscall.Stat_t
		if syscall.Fstat(int(files[0].Fd()), &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK || stat.Uid != uid {
			return nil, errors.New("Darwin isolated creator descriptor has another kernel UID")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("Darwin physical channel has trailing JSON data")
	}
	if len(files) == 1 {
		return files[0], nil
	}
	return nil, nil
}
