//go:build linux || darwin

// Package installcap retains the original installer's exclusive description
// during its one protected reassert transaction. It cannot select another root.
package installcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const Root = "/opt/router-vpn-client"
const Lock = Root + ".install.lock"
const frameLimit = 1024

var generationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type record struct {
	Schema      int    `json:"schema"`
	Generation  string `json:"generation"`
	Operation   string `json:"operation"`
	Phase       string `json:"phase"`
	Sequence    uint32 `json:"sequence"`
	PID         int    `json:"pid"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	RootDevice  uint64 `json:"root_device"`
	RootInode   uint64 `json:"root_inode"`
	LeaseDevice uint64 `json:"lease_device"`
	LeaseInode  uint64 `json:"lease_inode"`
}

func validRecord(value record) bool {
	if value.Schema != 1 || !generationPattern.MatchString(value.Generation) || value.Sequence > 64 || value.PID <= 0 || value.PID > 1<<31-1 {
		return false
	}
	switch value.Phase {
	case "reassert", "plan", "apply", "reference":
	default:
		return false
	}
	switch value.Operation {
	case "adopt", "grant", "ready", "ack", "done", "mutation":
		return true
	}
	return false
}

func decodeRecord(raw []byte) (record, error) {
	var value record
	// Disallow both duplicate and unknown keys. A second parser alone would
	// silently accept a later duplicate identity field.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return value, errors.New("installer capability is not one object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return value, errors.New("installer capability repeats an identity field")
		}
		seen[name] = true
		var ignored json.RawMessage
		if err := decoder.Decode(&ignored); err != nil {
			return value, err
		}
		if bytes.Equal(ignored, []byte("null")) {
			return value, errors.New("installer capability contains a null identity field")
		}
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') || len(seen) != 12 {
		return value, errors.New("installer capability has another field count")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || !validRecord(value) {
		return value, errors.New("installer capability has another bounded transaction")
	}
	return value, nil
}

func send(channel *net.UnixConn, value record) error {
	if !validRecord(value) {
		return errors.New("installer capability has invalid outbound identity")
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > frameLimit {
		return errors.New("installer capability exceeds its private bound")
	}
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame, uint32(len(raw)))
	copy(frame[4:], raw)
	n, err := channel.Write(frame)
	if n != len(frame) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	return err
}

func receive(channel *net.UnixConn, wanted int) (_ record, files []*os.File, failure error) {
	var value record
	defer func() {
		if failure != nil {
			for _, file := range files {
				file.Close()
			}
			files = nil
		}
	}()
	// Reserve bounded space for a complete local credential record as well as
	// rights. A foreign record is rejected after every received fd is owned.
	header, control := make([]byte, 4), make([]byte, syscall.CmsgSpace(4*4)+syscall.CmsgSpace(76))
	n, count, flags, _, err := channel.ReadMsgUnix(header, control)
	if err != nil {
		return value, files, err
	}
	messages, err := syscall.ParseSocketControlMessage(control[:count])
	if err != nil {
		return value, files, err
	}
	var ancillaryError error
	for _, message := range messages {
		fds, err := syscall.ParseUnixRights(&message)
		if err != nil {
			// Credentials or another foreign record can precede real rights.
			// Capture all rights before rejection so none escape the deferred
			// close. Never interpret foreign payload bytes as descriptors.
			ancillaryError = errors.Join(ancillaryError, errors.New("installer capability contains foreign ancillary authority"))
			continue
		}
		for _, fd := range fds {
			syscall.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "routervpn-installer-borrowed-authority"))
		}
	}
	if ancillaryError != nil {
		return value, files, ancillaryError
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || len(files) != wanted || n == 0 {
		return value, files, errors.New("installer capability descriptor/frame count differs")
	}
	if _, err := io.ReadFull(channel, header[n:]); err != nil {
		return value, files, err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > frameLimit {
		return value, files, errors.New("installer capability frame exceeds its bound")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(channel, raw); err != nil {
		return value, files, err
	}
	value, err = decodeRecord(raw)
	return value, files, err
}

func protected(path string, private, directory bool, acl func(string) error) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0022 != 0 ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 ||
		(directory && !info.IsDir()) || (!directory && (!info.Mode().IsRegular() || stat.Nlink != 1)) ||
		(private && info.Mode().Perm() != map[bool]os.FileMode{true: 0700, false: 0600}[directory]) {
		return nil, errors.New("installer capability path is not its protected original object")
	}
	if acl == nil {
		return nil, errors.New("installer capability has no native ACL verifier")
	}
	if err := acl(path); err != nil {
		return nil, err
	}
	return info, nil
}

func identity(info os.FileInfo) (uint64, uint64) {
	stat := info.Sys().(*syscall.Stat_t)
	return uint64(stat.Dev), uint64(stat.Ino)
}

func originalLock(file *os.File, path string, device, inode uint64, acl func(string) error) error {
	actual, err := file.Stat()
	named, namedErr := protected(path, true, false, acl)
	if err != nil || namedErr != nil || !os.SameFile(actual, named) {
		return errors.New("installer transferred another original locked object")
	}
	actualDevice, actualInode := identity(actual)
	if device != actualDevice || inode != actualInode {
		return errors.New("installer lock differs from its captured transaction")
	}
	probe, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer probe.Close()
	probed, err := probe.Stat()
	if err != nil || !os.SameFile(actual, probed) {
		return errors.New("installer lock changed before its independent probe")
	}
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
		return errors.New("installer capability was released or downgraded")
	} else if !errors.Is(err, syscall.EWOULDBLOCK) {
		return err
	}
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// Borrowed owns only received descriptions. Close never calls LOCK_UN.
type Borrowed struct {
	channel     *net.UnixConn
	channelFile *os.File
	lock        *os.File
	lease       *os.File
	ready       record
	adopted     bool
	closed      bool
}

func channelForProcess(channel *net.UnixConn) (*os.File, error) {
	raw, err := channel.SyscallConn()
	if err != nil {
		return nil, err
	}
	descriptor := -1
	var duplicateError error
	err = raw.Control(func(fd uintptr) {
		flags, _, failure := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if failure != 0 || flags&syscall.O_NONBLOCK == 0 {
			duplicateError = errors.New("installer channel lost its bounded nonblocking mode")
			return
		}
		// Dup plus CLOEXEC is protected against another concurrent fork.
		// os.NewFile preserves an already-nonblocking descriptor when exec
		// later calls Fd. net.UnixConn.File returns kindSock instead, whose
		// Fd silently makes the shared Python/Go description blocking.
		syscall.ForkLock.RLock()
		descriptor, duplicateError = syscall.Dup(int(fd))
		if duplicateError == nil {
			syscall.CloseOnExec(descriptor)
			flags, _, failure = syscall.Syscall(syscall.SYS_FCNTL, uintptr(descriptor), syscall.F_GETFD, 0)
			if failure != 0 || flags&syscall.FD_CLOEXEC == 0 {
				duplicateError = errors.New("installer channel duplicate did not retain close-on-exec")
			}
		}
		syscall.ForkLock.RUnlock()
	})
	if failure := errors.Join(err, duplicateError); failure != nil {
		if descriptor >= 0 {
			syscall.Close(descriptor)
		}
		return nil, failure
	}
	return os.NewFile(uintptr(descriptor), "routervpn-original-installer-channel-lifetime"), nil
}

// Acquire requires the existing root helper, fixed protected installation,
// original kernel peer, captured generation, and both retained locked objects.
func Acquire(ctx context.Context, descriptor int, generation string, issuer int, phase string, acl func(string) error) (_ *Borrowed, failure error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || descriptor < 3 || descriptor > 1<<31-1 ||
		issuer <= 0 || issuer > 1<<31-1 || !generationPattern.MatchString(generation) || (phase != "plan" && phase != "apply" && phase != "reference") {
		return nil, errors.New("native installer reassert lacks its exact inherited capability")
	}
	file := os.NewFile(uintptr(descriptor), "routervpn-original-installer-channel")
	defer file.Close()
	if err := checkPeer(descriptor, issuer); err != nil {
		return nil, err
	}
	connection, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, errors.New("installer capability changed socket family")
	}
	owner := &Borrowed{channel: channel}
	defer func() {
		if failure != nil {
			owner.Close()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := channel.SetDeadline(deadline); err != nil {
		return nil, err
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = channel.Close()
		close(canceled)
	})
	callbackJoined := false
	defer func() {
		if !callbackJoined && !stop() {
			<-canceled
		}
	}()
	for path := filepath.Dir(Root); ; path = filepath.Dir(path) {
		if _, err := protected(path, false, true, acl); err != nil {
			return nil, err
		}
		if path == "/" {
			break
		}
	}
	root, err := protected(Root, false, true, acl)
	if err != nil {
		return nil, err
	}
	named, err := protected(Lock, true, false, acl)
	if err != nil {
		return nil, err
	}
	request := record{Schema: 1, Generation: generation, Operation: "adopt", Phase: phase, PID: os.Getpid()}
	request.Device, request.Inode = identity(named)
	request.RootDevice, request.RootInode = identity(root)
	if err := send(channel, request); err != nil {
		return nil, err
	}
	grant, received, err := receive(channel, 2)
	if err != nil {
		return nil, err
	}
	owner.lock, owner.lease = received[0], received[1]
	expected := request
	expected.Operation, expected.Sequence, expected.PID = "grant", grant.Sequence, issuer
	expected.LeaseDevice, expected.LeaseInode = grant.LeaseDevice, grant.LeaseInode
	if grant != expected || grant.Sequence == 0 || grant.LeaseInode == 0 {
		return nil, errors.New("installer grant changed its original capture")
	}
	if err := originalLock(owner.lock, Lock, grant.Device, grant.Inode, acl); err != nil {
		return nil, err
	}
	leaseDirectory := filepath.Join(Root, "run", "install-"+generation)
	for _, path := range []string{filepath.Join(Root, "run"), leaseDirectory} {
		if _, err := protected(path, true, true, acl); err != nil {
			return nil, err
		}
	}
	leasePath := filepath.Join(leaseDirectory, "lease-"+strconv.FormatUint(uint64(grant.Sequence), 10))
	if err := originalLock(owner.lease, leasePath, grant.LeaseDevice, grant.LeaseInode, acl); err != nil {
		return nil, err
	}
	owner.ready = grant
	owner.ready.Operation, owner.ready.PID = "ready", os.Getpid()
	if err := send(channel, owner.ready); err != nil {
		return nil, err
	}
	ack, _, err := receive(channel, 0)
	expected.Operation = "ack"
	if err != nil || ack != expected || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err(), errors.New("installer did not acknowledge the original retained description"))
	}
	if err := checkPeer(descriptor, issuer); err != nil {
		return nil, err
	}
	current, err := os.Lstat(Root)
	if err != nil || !os.SameFile(root, current) {
		return nil, errors.New("installed generation changed during capability admission")
	}
	owner.channelFile, err = channelForProcess(channel)
	if err != nil {
		return nil, err
	}
	if err := channel.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	stopped := stop()
	callbackJoined = true
	if !stopped {
		<-canceled
		return nil, errors.Join(ctx.Err(), errors.New("installer acquisition was canceled before its owner could return"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owner.adopted = true
	return owner, nil
}

// Files retain every descendant until its real exit, including after the
// Python or Go parent dies. The issuer independently probes the exact lease.
func (owner *Borrowed) Files() []*os.File {
	if owner == nil || owner.closed || !owner.adopted {
		return nil
	}
	return []*os.File{owner.lock, owner.lease, owner.channelFile}
}

func (owner *Borrowed) Close() error {
	if owner == nil || owner.closed {
		return nil
	}
	owner.closed = true
	var failure error
	if owner.adopted {
		failure = owner.channel.SetWriteDeadline(time.Now().Add(3 * time.Second))
		finished := owner.ready
		finished.Operation = "done"
		failure = errors.Join(failure, send(owner.channel, finished))
	}
	for _, file := range []*os.File{owner.lock, owner.lease, owner.channelFile} {
		if file != nil {
			failure = errors.Join(failure, file.Close())
		}
	}
	return errors.Join(failure, owner.channel.Close())
}
