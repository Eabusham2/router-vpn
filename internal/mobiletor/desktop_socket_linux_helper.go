//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type desktopLinuxRequest struct {
	Operation  string
	Sequence   uint64
	Capture    DesktopSocketCapture
	Options    DesktopLinuxSocketOptions
	NodeScoped bool `json:",omitempty"`
	Creation   DesktopSocketCreation
	Grant      DesktopSocketGrant
}

type desktopLinuxReply struct {
	Sequence uint64
	Capture  DesktopSocketCapture
	Owner    DesktopSocketKernelOwner
	Creation DesktopSocketCreation
	UID      uint32
	Account  string
	NFT      *desktopLinuxNFT
	Receipt  DesktopSocketReceipt
	Error    string
}

func desktopLinuxSocketPair() (*net.UnixConn, *os.File, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	first, second := os.NewFile(uintptr(pair[0]), "routervpn-physical-control"), os.NewFile(uintptr(pair[1]), "routervpn-physical-helper")
	if err = syscall.SetsockoptInt(pair[0], syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
		first.Close()
		second.Close()
		return nil, nil, err
	}
	if err = syscall.SetsockoptInt(pair[1], syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
		first.Close()
		second.Close()
		return nil, nil, err
	}
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
		return nil, nil, errors.New("Linux physical helper channel is not Unix")
	}
	return unix, second, nil
}

func desktopLinuxHelperChannel() (*net.UnixConn, error) {
	file := os.NewFile(3, "routervpn-physical-inherited-channel")
	defer file.Close()
	typeValue, err := syscall.GetsockoptInt(3, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil || typeValue != syscall.SOCK_SEQPACKET {
		return nil, errors.New("Linux physical helper requires an inherited private sequenced channel")
	}
	if _, err = syscall.Getsockname(3); err != nil {
		return nil, err
	}
	if err = syscall.SetsockoptInt(3, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
		return nil, err
	}
	connection, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, errors.New("Linux physical helper channel changed family")
	}
	return unix, nil
}

func desktopLinuxSend(channel *net.UnixConn, value any, file *os.File) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 32<<10 {
		return errors.New("Linux physical control message exceeds its bound")
	}
	var rights []byte
	if file != nil {
		rights = syscall.UnixRights(int(file.Fd()))
	}
	n, oob, err := channel.WriteMsgUnix(raw, rights, nil)
	if err != nil {
		return err
	}
	if n != len(raw) || oob != len(rights) {
		return io.ErrShortWrite
	}
	return nil
}

func desktopLinuxReceive(channel *net.UnixConn, value any, pid, uid uint32) (file *os.File, failure error) {
	data, control := make([]byte, 32<<10), make([]byte, syscall.CmsgSpace(4*8)+syscall.CmsgSpace(syscall.SizeofUcred))
	n, oob, flags, _, err := channel.ReadMsgUnix(data, control)
	messages, parseErr := syscall.ParseSocketControlMessage(control[:oob])
	var files []*os.File
	var credential *syscall.Ucred
	for _, message := range messages {
		if message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_RIGHTS {
			rights, e := syscall.ParseUnixRights(&message)
			if e != nil {
				parseErr = e
			}
			for _, fd := range rights {
				syscall.CloseOnExec(fd)
				files = append(files, os.NewFile(uintptr(fd), "routervpn-physical-transferred"))
			}
		} else if message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_CREDENTIALS {
			if credential != nil {
				parseErr = errors.New("duplicate helper credentials")
			}
			credential, err = syscall.ParseUnixCredentials(&message)
		} else {
			parseErr = errors.New("unexpected helper ancillary control")
		}
	}
	defer func() {
		if failure != nil {
			for _, f := range files {
				f.Close()
			}
		}
	}()
	if err != nil || parseErr != nil || flags & ^syscall.MSG_CMSG_CLOEXEC != 0 || n == 0 || len(files) > 1 || credential == nil || uint32(credential.Pid) != pid || credential.Uid != uid {
		return nil, errors.Join(err, parseErr, fmt.Errorf("Linux physical channel lost its actual process/credential owner (flags=%d size=%d credentials=%v want PID=%d UID=%d)", flags, n, credential, pid, uid))
	}
	decoder := json.NewDecoder(bytes.NewReader(data[:n]))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(value); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("Linux physical channel has trailing data")
	}
	if len(files) == 1 {
		return files[0], nil
	}
	return nil, nil
}

type desktopLinuxKernelSocket struct {
	inode   uint64
	cookie  uint64
	uid     uint32
	network string
}

func desktopLinuxSocketIdentity(file *os.File) (desktopLinuxKernelSocket, error) {
	var st syscall.Stat_t
	if file == nil {
		return desktopLinuxKernelSocket{}, errors.New("Linux physical socket handle is missing")
	}
	if err := syscall.Fstat(int(file.Fd()), &st); err != nil {
		return desktopLinuxKernelSocket{}, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return desktopLinuxKernelSocket{}, errors.New("Linux physical descriptor is not a socket")
	}
	typeValue, err := syscall.GetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return desktopLinuxKernelSocket{}, err
	}
	network := "tcp"
	if typeValue == syscall.SOCK_DGRAM {
		network = "udp"
	} else if typeValue != syscall.SOCK_STREAM {
		return desktopLinuxKernelSocket{}, errors.New("Linux physical socket is not TCP/UDP")
	}
	var cookie uint64
	length := uint32(8)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, file.Fd(), syscall.SOL_SOCKET, 57, uintptr(unsafe.Pointer(&cookie)), uintptr(unsafe.Pointer(&length)), 0)
	if errno != 0 || length != 8 || cookie == 0 {
		return desktopLinuxKernelSocket{}, errors.New("Linux physical socket has no kernel cookie")
	}
	return desktopLinuxKernelSocket{inode: st.Ino, cookie: cookie, uid: st.Uid, network: network}, nil
}

func desktopLinuxCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("Linux privileged helper executable is not root owned")
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err = command.Run()
	if output.Len() > 2<<20 {
		return nil, errors.New("Linux privileged helper output exceeds its bound")
	}
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", filepath.Base(path), err)
	}
	return output.Bytes(), nil
}

const desktopLinuxIdentities = "/run/router-vpn-owned-sockets"

func desktopLinuxIdentityDirectory() error {
	if err := os.Mkdir(desktopLinuxIdentities, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(desktopLinuxIdentities)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("Linux physical identity directory is not private root ownership")
	}
	return nil
}

func desktopLinuxVerifyAccount(account string, uid uint32) error {
	if !strings.HasPrefix(account, "rvpnt_") || !desktopSocketHex(strings.TrimPrefix(account, "rvpnt_"), 20) || uid < 0x40000000 || uid >= 0x80000000 {
		return errors.New("Linux physical account identity is invalid")
	}
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return err
	}
	matches := 0
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		value, e := strconv.ParseUint(fields[2], 10, 32)
		if fields[0] == account || e == nil && uint32(value) == uid {
			if fields[0] != account || e != nil || uint32(value) != uid || fields[5] != "/nonexistent" || fields[6] != "/usr/sbin/nologin" {
				return errors.New("Linux physical account identity was reused")
			}
			matches++
		}
	}
	if matches != 1 {
		return errors.New("Linux physical account has no exclusive retained UID")
	}
	shadow, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return err
	}
	matches = 0
	for _, line := range strings.Split(string(shadow), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 0 && fields[0] == account {
			if len(fields) != 9 || fields[1] != "!" || fields[7] != "1" {
				return errors.New("Linux physical account lost its locked expired identity")
			}
			matches++
		}
	}
	if matches != 1 {
		return errors.New("Linux physical account has no exclusive locked identity")
	}
	return nil
}

func desktopLinuxAllocateAccount(c DesktopSocketCapture) (string, uint32, error) {
	if err := desktopLinuxIdentityDirectory(); err != nil {
		return "", 0, err
	}
	for attempts := 0; attempts < 16; attempts++ {
		var random [14]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", 0, err
		}
		uid := uint32(0x40000000) | (binary.BigEndian.Uint32(random[:4]) & 0x3fffffff)
		account := "rvpnt_" + hex.EncodeToString(random[4:])
		record, err := os.OpenFile(filepath.Join(desktopLinuxIdentities, account), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", 0, err
		}
		encoded, _ := json.Marshal(struct {
			Capture     DesktopSocketCapture
			UID         uint32
			GuardianPID int
		}{c, uid, os.Getpid()})
		_, writeErr := record.Write(encoded)
		syncErr := record.Sync()
		closeErr := record.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return "", 0, err
		}
		// Capture recovery ownership before the account tool can mutate anything.
		// A timeout or unknown outcome retains this private record; no guessed
		// success or broad account deletion can recycle an unacknowledged UID.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err = desktopLinuxCommand(ctx, "/usr/sbin/useradd", "--no-log-init", "--no-create-home", "--password", "!", "--expiredate", "1", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--user-group", "--uid", strconv.FormatUint(uint64(uid), 10), account)
		cancel()
		if err != nil {
			continue
		}
		if err = desktopLinuxVerifyAccount(account, uid); err != nil {
			return "", 0, err
		}
		return account, uid, nil
	}
	return "", 0, errors.New("Linux physical guardian could not allocate its locked identity")
}

func desktopLinuxRetireAccount(account string, uid uint32) error {
	if err := desktopLinuxVerifyAccount(account, uid); err != nil {
		return err
	}
	// The sole UID child was synchronously joined before transfer. Still reject
	// unexpected processes before releasing the managed account for any reuse.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, e := strconv.ParseUint(entry.Name(), 10, 32); e != nil {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				for _, value := range strings.Fields(line)[1:] {
					if value == strconv.FormatUint(uint64(uid), 10) {
						return errors.New("Linux physical creator identity still has a live process")
					}
				}
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := desktopLinuxCommand(ctx, "/usr/sbin/userdel", account); err != nil {
		return err
	}
	// userdel normally deletes the matching private group. If configured not
	// to, keeping that unused group is safer than removing an unrelated group.
	return os.Remove(filepath.Join(desktopLinuxIdentities, account))
}

type desktopLinuxOwnedSocket struct {
	creation DesktopSocketCreation
	file     *os.File
	identity desktopLinuxKernelSocket
	bound    bool
	grants   map[string]DesktopSocketGrant
}

type desktopLinuxGuardian struct {
	capture DesktopSocketCapture
	options DesktopLinuxSocketOptions
	owner   DesktopSocketKernelOwner
	account string
	uid     uint32
	nft     *desktopLinuxNFT
	sockets map[string]*desktopLinuxOwnedSocket
}

// RunDesktopLinuxSocketHelper is called only by the packaged native command.
// An inherited channel and kernel sender credentials, rather than CLI JSON or
// stdout receipts, authenticate every operation and transferred descriptor.
func RunDesktopLinuxSocketHelper(role string) error {
	channel, err := desktopLinuxHelperChannel()
	if err != nil {
		return err
	}
	defer channel.Close()
	parent := uint32(os.Getppid())
	if parent <= 1 {
		return errors.New("Linux physical helper has no retained parent")
	}
	if role == "creator" {
		return desktopLinuxCreator(channel, parent)
	}
	if role != "guardian" || os.Geteuid() != 0 {
		return errors.New("Linux physical guardian requires its privileged role")
	}
	var request desktopLinuxRequest
	channel.SetDeadline(time.Now().Add(3 * time.Second))
	file, err := desktopLinuxReceive(channel, &request, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("Linux prepare included an unexpected descriptor")
	}
	if err != nil || request.Operation != "prepare" || request.Sequence != 1 || !request.Capture.valid() || request.Options.validate() != nil {
		return errors.Join(err, errors.New("Linux physical preparation rejected"))
	}
	baselineCtx, baselineCancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = desktopLinuxValidateNFTBaseline(baselineCtx, request.Capture, request.Options, request.NodeScoped)
	baselineCancel()
	if err != nil {
		return err
	}
	account, uid, err := desktopLinuxAllocateAccount(request.Capture)
	if err != nil {
		return err
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	generation := binary.BigEndian.Uint64(nonce[:])
	if generation == 0 {
		return errors.New("Linux physical generation is empty")
	}
	g := &desktopLinuxGuardian{capture: request.Capture, options: request.Options, account: account, uid: uid, owner: desktopLinuxOwner(request.Capture, uid, account, generation), sockets: make(map[string]*desktopLinuxOwnedSocket)}
	// Every exceptional exit quarantines the managed account. Cleanup first
	// proves exact rules/sets absent, then closes retained sockets. It cannot
	// release UID ownership on an unacknowledged native crash.
	defer g.cleanup(false)
	g.nft, err = desktopLinuxNewNFT(g.capture, g.uid, g.options, request.NodeScoped)
	if err != nil {
		return err
	}
	reply := desktopLinuxReply{Sequence: request.Sequence, Capture: g.capture, Owner: g.owner, UID: uid, Account: account, NFT: g.nft}
	if err = desktopLinuxSend(channel, reply, nil); err != nil {
		return err
	}
	sequence := request.Sequence
	for {
		channel.SetDeadline(time.Now().Add(6 * time.Second))
		var next desktopLinuxRequest
		file, err := desktopLinuxReceive(channel, &next, parent, 0)
		if err != nil {
			if file != nil {
				file.Close()
			}
			return err
		}
		if next.Sequence != sequence+1 || next.Capture != g.capture {
			if file != nil {
				file.Close()
			}
			return errors.New("Linux physical operation changed its capture or sequence")
		}
		sequence = next.Sequence
		reply := desktopLinuxReply{Sequence: sequence, Capture: g.capture}
		var transferred *os.File
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		switch next.Operation {
		case "probe":
			if file != nil {
				err = errors.New("probe descriptor rejected")
			} else {
				err = g.nft.verify(ctx, true)
				if err == nil {
					err = desktopLinuxVerifyAccount(g.account, g.uid)
				}
			}
		case "create":
			transferred, err = g.create(ctx, next.Creation)
			reply.Creation = next.Creation
		case "bind":
			err = g.bind(next.Creation, file)
		case "grant":
			reply.Receipt, err = g.grant(ctx, next.Grant)
		case "revoke":
			err = g.revoke(ctx, next.Grant)
		case "release":
			err = g.release(next.Creation)
		case "finish":
			err = g.cleanup(true)
		default:
			err = errors.New("unknown Linux physical operation")
		}
		cancel()
		if file != nil {
			file.Close()
		}
		if err != nil {
			reply.Error = err.Error()
		}
		if sendErr := desktopLinuxSend(channel, reply, transferred); sendErr != nil {
			return sendErr
		}
		if next.Operation == "finish" && err == nil {
			return nil
		}
	}
}

func (g *desktopLinuxGuardian) release(c DesktopSocketCreation) error {
	if c.Capture != g.capture || c.Binding.Owner != g.owner || !desktopSocketHex(c.SocketID, 32) {
		return errors.New("Linux physical release changed its owner")
	}
	owned := g.sockets[c.SocketID]
	if owned == nil {
		return nil
	}
	if c != owned.creation || len(owned.grants) != 0 {
		return errors.New("Linux physical release precedes exact permit cleanup")
	}
	if err := owned.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	delete(g.sockets, c.SocketID)
	return nil
}

func desktopLinuxCreator(channel *net.UnixConn, parent uint32) error {
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		return errors.New("Linux socket creator has no isolated identity")
	}
	channel.SetDeadline(time.Now().Add(3 * time.Second))
	var request desktopLinuxRequest
	file, err := desktopLinuxReceive(channel, &request, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("creator received an unexpected descriptor")
	}
	c := request.Creation
	if err != nil || request.Operation != "create" || !c.Capture.valid() || !c.Binding.Owner.valid() || !desktopSocketHex(c.SocketID, 32) || c.Network != "tcp" && c.Network != "udp" {
		return errors.Join(err, errors.New("Linux isolated creation rejected"))
	}
	family, kind := syscall.AF_INET6, syscall.SOCK_STREAM
	if c.Binding.LocalAddress.Is4() {
		family = syscall.AF_INET
	}
	if c.Network == "udp" {
		kind = syscall.SOCK_DGRAM
	}
	fd, err := syscall.Socket(family, kind|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	socket := os.NewFile(uintptr(fd), "routervpn-isolated-physical")
	defer socket.Close()
	return desktopLinuxSend(channel, desktopLinuxReply{Sequence: request.Sequence, Capture: c.Capture, Creation: c}, socket)
}

func (g *desktopLinuxGuardian) create(ctx context.Context, c DesktopSocketCreation) (*os.File, error) {
	if c.Capture != g.capture || c.Binding.Owner != g.owner || !desktopSocketHex(c.SocketID, 32) || c.Network != "tcp" && c.Network != "udp" || len(g.sockets) >= DesktopSocketLimit || g.sockets[c.SocketID] != nil {
		return nil, errors.New("Linux creator request changed ownership")
	}
	want, err := g.options.binding(g.owner, netip.AddrPortFrom(c.Binding.LocalAddress, 1))
	if err != nil || !desktopLinuxBindingEqual(want, c.Binding) {
		return nil, errors.New("Linux creator binding changed")
	}
	channel, child, err := desktopLinuxSocketPair()
	if err != nil {
		return nil, err
	}
	defer channel.Close()
	defer child.Close()
	command := exec.CommandContext(ctx, "/proc/self/exe", "routervpn-owned-socket-helper", "creator")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
	command.Stderr = os.Stderr
	command.ExtraFiles = []*os.File{child}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: g.uid, Gid: g.uid, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL}
	if err = command.Start(); err != nil {
		return nil, err
	}
	child.Close()
	channel.SetDeadline(time.Now().Add(2 * time.Second))
	request := desktopLinuxRequest{Operation: "create", Sequence: 1, Capture: g.capture, Creation: c}
	err = desktopLinuxSend(channel, request, nil)
	var reply desktopLinuxReply
	var file *os.File
	if err == nil {
		file, err = desktopLinuxReceive(channel, &reply, uint32(command.Process.Pid), g.uid)
	}
	if err != nil {
		command.Process.Kill()
	}
	joinErr := command.Wait()
	if err != nil || joinErr != nil || file == nil || reply.Sequence != 1 || reply.Capture != g.capture || reply.Creation != c {
		if file != nil {
			file.Close()
		}
		return nil, errors.Join(err, joinErr, errors.New("Linux isolated transfer did not join"))
	}
	identity, err := desktopLinuxSocketIdentity(file)
	if err != nil || identity.uid != g.uid || identity.network != c.Network {
		file.Close()
		return nil, errors.New("Linux creator changed its actual kernel socket owner")
	}
	g.sockets[c.SocketID] = &desktopLinuxOwnedSocket{creation: c, file: file, identity: identity, grants: make(map[string]DesktopSocketGrant)}
	return file, nil
}

func (g *desktopLinuxGuardian) bind(c DesktopSocketCreation, file *os.File) error {
	if c.Capture != g.capture || c.Binding.Owner != g.owner || file == nil {
		return errors.New("Linux bind has no captured socket")
	}
	identity, err := desktopLinuxSocketIdentity(file)
	if err != nil || identity.uid != g.uid {
		return errors.New("Linux bind has another kernel creator")
	}
	var owned *desktopLinuxOwnedSocket
	for _, candidate := range g.sockets {
		if candidate.identity == identity {
			owned = candidate
			break
		}
	}
	if owned == nil || owned.bound || owned.creation.Binding != c.Binding || c.Network != identity.network+map[bool]string{true: "4", false: "6"}[c.Binding.LocalAddress.Is4()] {
		return errors.New("Linux bind has another captured socket identity")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	if _, _, err = desktopSocketSourceRaw(file, identity.network, c.Binding.LocalAddress); err != nil {
		return err
	}
	if err = desktopLinuxCheckInterface(DesktopLinuxSocketInterface{Name: c.Binding.InterfaceName, Index: c.Binding.InterfaceIndex, Address: c.Binding.LocalAddress}); err != nil {
		return err
	}
	var failure error
	err = raw.Control(func(fd uintptr) {
		failure = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, c.Binding.InterfaceName)
		if failure != nil {
			return
		}
		var actual string
		actual, failure = desktopLinuxBoundDevice(int(fd))
		if failure == nil && actual != c.Binding.InterfaceName {
			failure = errors.New("Linux physical bind device did not read back")
		}
	})
	if err != nil || failure != nil {
		return errors.Join(err, failure)
	}
	owned.bound = true
	return nil
}

func (g *desktopLinuxGuardian) grant(ctx context.Context, grant DesktopSocketGrant) (DesktopSocketReceipt, error) {
	owned := g.sockets[grant.SocketID]
	if owned == nil || !owned.bound || grant.Capture != g.capture || grant.Binding != owned.creation.Binding || grant.Network != owned.creation.Network || grant.Sequence == 0 || !g.options.permits(grant.Network, grant.Remote) {
		return DesktopSocketReceipt{}, errors.New("Linux grant has no exact source owner")
	}
	identity, err := desktopLinuxSocketIdentity(owned.file)
	if err != nil || identity != owned.identity {
		return DesktopSocketReceipt{}, errors.New("Linux grant lost its retained kernel socket")
	}
	local, err := desktopSocketLocal(int(owned.file.Fd()))
	if err != nil || local != grant.Local || local.Addr() != grant.Binding.LocalAddress {
		return DesktopSocketReceipt{}, errors.New("Linux grant changed its actual bound tuple")
	}
	if err = desktopLinuxCheckInterface(DesktopLinuxSocketInterface{Name: grant.Binding.InterfaceName, Index: grant.Binding.InterfaceIndex, Address: grant.Binding.LocalAddress}); err != nil {
		return DesktopSocketReceipt{}, err
	}
	bound, err := desktopLinuxBoundDevice(int(owned.file.Fd()))
	if err != nil || bound != grant.Binding.InterfaceName {
		return DesktopSocketReceipt{}, errors.New("Linux grant lost its device binding")
	}
	for _, option := range []int{syscall.SO_REUSEADDR, 15 /* SO_REUSEPORT */} {
		value, err := syscall.GetsockoptInt(int(owned.file.Fd()), syscall.SOL_SOCKET, option)
		if err != nil || value != 0 {
			return DesktopSocketReceipt{}, errors.New("Linux grant socket permits address/port reuse")
		}
	}
	key := grant.Remote.String()
	previous, exists := owned.grants[key]
	if exists && grant.Sequence <= previous.Sequence || !exists && len(owned.grants) >= DesktopSocketPeerLimit {
		return DesktopSocketReceipt{}, errors.New("Linux grant sequence/peer limit rejected")
	}
	// Retain unknown application outcomes before touching the kernel. Revoke
	// remains possible when acknowledgment/readback fails.
	owned.grants[key] = grant
	return g.nft.grant(ctx, grant)
}

func (g *desktopLinuxGuardian) revoke(ctx context.Context, grant DesktopSocketGrant) error {
	owned := g.sockets[grant.SocketID]
	if owned == nil || grant.Capture != g.capture || grant.Binding != owned.creation.Binding || grant.Network != owned.creation.Network {
		return errors.New("Linux revoke changed its retained owner")
	}
	previous, exists := owned.grants[grant.Remote.String()]
	if !exists {
		return g.nft.absent(ctx, grant)
	}
	if previous != grant {
		return errors.New("Linux revoke changed its exact operation")
	}
	if err := g.nft.revoke(ctx, grant); err != nil {
		return err
	}
	delete(owned.grants, grant.Remote.String())
	return nil
}

func (g *desktopLinuxGuardian) cleanup(release bool) error {
	if release && len(g.sockets) != 0 {
		return errors.New("Linux physical finish precedes native descriptor retirement")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if g.nft != nil {
		if err := g.nft.close(ctx); err != nil {
			return err
		}
	}
	for id, owned := range g.sockets {
		if err := owned.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
		delete(g.sockets, id)
	}
	if release && g.account != "" {
		if err := desktopLinuxRetireAccount(g.account, g.uid); err != nil {
			return err
		}
		g.account = ""
	}
	return nil
}

func desktopLinuxBoundDevice(fd int) (string, error) {
	var buffer [16]byte
	size := uint32(len(buffer))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return "", errno
	}
	if size > uint32(len(buffer)) {
		return "", errors.New("oversized physical interface readback")
	}
	return strings.TrimRight(string(buffer[:size]), "\x00"), nil
}
