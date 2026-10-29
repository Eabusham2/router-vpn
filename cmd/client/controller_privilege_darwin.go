//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"router-vpn/internal/common"
)

const macOSOwnedControllerRoot = "/opt/router-vpn-client"
const macOSOwnedControllerSocketDirectory = "/opt/router-vpn-client.control"
const macOSOwnedControllerSocket = macOSOwnedControllerSocketDirectory + "/controller.sock"
const macOSOwnedControllerRecord = macOSOwnedControllerRoot + "/controller-owner.json"
const macOSOwnedInstallLock = "/opt/router-vpn-client.install.lock"
const macOSOwnedProcessLock = "/opt/router-vpn-client.controller.lock"
const macOSOwnedSupervisorLock = "/opt/router-vpn-client.supervisor.lock"

func macOSOwnedExecutable() string {
	return filepath.Join(macOSOwnedControllerRoot, "router-vpn-client")
}

func validateNativeOwnedStartup(owned *ownedDesktopController) error {
	if owned != nil {
		if os.Getuid() != 0 || os.Geteuid() != 0 || owned.processID != os.Getpid() || owned.callerUID == 0 ||
			!validLocalControllerSecret(owned.accessToken) || !validControllerOwnerToken(owned.ownerToken) ||
			owned.input == nil || owned.installLock == nil || owned.processLock == nil || owned.ownerDone == nil {
			return errors.New("the installed controller lost its captured privileged launch")
		}
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 && executable == macOSOwnedExecutable() {
		return errors.New("open the installed Router VPN desktop app to authorize its owned controller")
	}
	return nil
}

func validateNativeOwnedConfiguration(config common.ClientConfig) error {
	if config.Listen != "" && config.Listen != linuxOwnedControllerAddress {
		return errors.New("the installed native controller must use its fixed loopback listener")
	}
	for name, supplied := range map[string]string{
		"modes.json": config.ModesFile, "modes": config.ScriptsDir,
		"routers.json": config.ProfilesFile, "state.json": config.StateFile,
	} {
		if supplied == "" {
			continue
		}
		path := supplied
		if !filepath.IsAbs(path) {
			path = filepath.Join(macOSOwnedControllerRoot, path)
		}
		if filepath.Clean(path) != filepath.Join(macOSOwnedControllerRoot, name) || strings.ContainsRune(supplied, '\x00') {
			return errors.New("the native controller configuration escaped its fixed installed paths")
		}
	}
	return nil
}

func macOSOwnedInstallIdentity() (uint32, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return 0, errors.New("the macOS controller supervisor requires root")
	}
	executable, err := os.Executable()
	if err != nil || executable != macOSOwnedExecutable() {
		return 0, errors.New("only the fixed installed Router VPN controller can be elevated")
	}
	if err = ownedDesktopInstall(macOSOwnedControllerRoot); err != nil {
		return 0, err
	}
	info, err := os.Lstat(macOSOwnedControllerRecord)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedDesktopInfo(info) {
		return 0, errors.New("the installed desktop owner record is not private and root-owned")
	}
	data, err := readPrivateRegular(macOSOwnedControllerRecord, 256)
	if err != nil {
		return 0, err
	}
	var record struct {
		Schema    int    `json:"schema"`
		CallerUID uint32 `json:"caller_uid"`
	}
	var fields map[string]json.RawMessage
	if decodeRelayControlJSON(data, &record) != nil || json.Unmarshal(data, &fields) != nil || len(fields) != 2 ||
		fields["schema"] == nil || fields["caller_uid"] == nil || record.Schema != 1 || record.CallerUID == 0 || record.CallerUID == ^uint32(0) {
		return 0, errors.New("the installed desktop owner record is invalid")
	}
	if _, err = user.LookupId(strconv.FormatUint(uint64(record.CallerUID), 10)); err != nil {
		return 0, errors.New("the authorized desktop user no longer exists")
	}
	config, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, "client.json"), maxPrivateStoreBytes)
	if err != nil {
		return 0, errors.New("the installed controller configuration cannot be read safely")
	}
	var captured common.ClientConfig
	if decodeRelayControlJSON(config, &captured) != nil {
		return 0, errors.New("the installed controller configuration is invalid")
	}
	if err = validateNativeOwnedConfiguration(captured); err != nil {
		return 0, err
	}
	return record.CallerUID, nil
}

// Darwin's pipe_stat reports the observing process's UID, not its creator.
// It therefore cannot authenticate the desktop. The retained connected Unix
// socket supplies that authority; stdin is only the bounded private frame.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_pipe.c
func macOSOwnedInput(input *os.File) (*os.File, error) {
	if input == nil {
		return nil, errors.New("the native controller requires anonymous launch input")
	}
	info, err := input.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeNamedPipe == 0 || stat.Nlink != 0 || stat.Dev != 0 {
		return nil, errors.New("the native controller launch identity must arrive on an anonymous pipe")
	}
	return macOSOwnedDuplicate(input)
}

func macOSOwnedDuplicate(input *os.File) (*os.File, error) {
	raw, err := input.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var result error
	err = raw.Control(func(value uintptr) { fd, result = syscall.Dup(int(value)) })
	if err != nil || result != nil {
		return nil, errors.Join(err, result)
	}
	syscall.CloseOnExec(fd)
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "routervpn-owned-controller-channel"), nil
}

type macOSOwnedPeerIdentity struct {
	UID uint32
	PID int
}

func macOSOwnedPeer(raw syscall.RawConn) (macOSOwnedPeerIdentity, error) {
	var identity macOSOwnedPeerIdentity
	var result error
	err := raw.Control(func(value uintptr) {
		fd := int(value)
		kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil || kind != syscall.SOCK_STREAM {
			result = errors.New("the desktop lifetime is not a stream socket")
			return
		}
		peer, err := syscall.Getpeername(fd)
		if _, ok := peer.(*syscall.SockaddrUnix); err != nil || !ok {
			result = errors.New("the desktop lifetime has no connected local peer")
			return
		}
		// Apple's public xucred layout is version, uid, short group count,
		// alignment and sixteen gids. LOCAL_PEERCRED is SOL_LOCAL option 1.
		// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ucred.h
		// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h
		var credential struct {
			Version uint32
			UID     uint32
			Groups  int16
			Padding uint16
			GIDs    [16]uint32
		}
		size := uint32(unsafe.Sizeof(credential))
		_, _, callErr := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), 0, 1, uintptr(unsafe.Pointer(&credential)), uintptr(unsafe.Pointer(&size)), 0)
		if callErr != 0 || size != 76 || credential.Version != 0 || credential.Groups < 1 || credential.Groups > 16 || credential.UID == ^uint32(0) {
			result = errors.New("the desktop kernel peer credentials could not be verified")
			return
		}
		pid, err := syscall.GetsockoptInt(fd, 0, 2) // LOCAL_PEERPID
		if err != nil || pid <= 0 {
			result = errors.New("the desktop kernel peer process could not be verified")
			return
		}
		identity = macOSOwnedPeerIdentity{UID: credential.UID, PID: pid}
	})
	return identity, errors.Join(err, result)
}

func macOSOwnedAdoptLock(fd uintptr, path string, exclusive bool) (*os.File, error) {
	file := os.NewFile(fd, path)
	if file == nil {
		return nil, errors.New("the supervisor did not retain its installation lock")
	}
	info, err := file.Stat()
	entry, entryErr := os.Lstat(path)
	if err != nil || entryErr != nil || !info.Mode().IsRegular() || !ownedDesktopInfo(info) || info.Mode().Perm() != 0600 ||
		!ownedDesktopInfo(entry) || !os.SameFile(info, entry) {
		file.Close()
		return nil, errors.New("the supervisor transferred a different installation lock")
	}
	if err = ownedPathACL(path); err != nil {
		file.Close()
		return nil, err
	}
	operation := syscall.LOCK_SH
	if exclusive {
		operation = syscall.LOCK_EX
	}
	if err = syscall.Flock(int(fd), operation|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	syscall.CloseOnExec(int(fd))
	return file, nil
}

func macOSOwnedEnvironment() []string {
	return []string{
		"HOME=/var/root", "LANG=en_US.UTF-8", "PATH=" + macOSOwnedControllerRoot + "/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"HOMEVPN_ROOT=" + macOSOwnedControllerRoot, "HOMEVPN_CLIENT_CONFIG=" + macOSOwnedControllerRoot + "/client.json",
		"HOMEVPN_NATIVE_APP=macos-appkit-product",
		"DYLD_FALLBACK_LIBRARY_PATH=/usr/lib", "DYLD_FALLBACK_FRAMEWORK_PATH=/System/Library/Frameworks",
	}
}

func prepareNativeOwnedController(arguments []string) (_ *ownedDesktopController, failure error) {
	requested := false
	for _, argument := range arguments {
		if argument == linuxOwnedControllerArgument {
			return nil, errors.New("the fixed Linux controller launcher requires Linux")
		}
		if argument == macOSOwnedControllerArgument {
			requested = true
		}
	}
	if !requested {
		return nil, nil
	}
	if len(arguments) != 1 || arguments[0] != macOSOwnedControllerArgument || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errors.New("the installed native controller requires its authorized fixed launch")
	}
	owned := &ownedDesktopController{processID: os.Getpid()}
	defer func() {
		if failure != nil {
			owned.close()
		}
	}()
	if err := ownedDesktopAncestors(filepath.Dir(macOSOwnedControllerRoot)); err != nil {
		return nil, err
	}
	var err error
	owned.installLock, err = macOSOwnedAdoptLock(4, macOSOwnedInstallLock, false)
	if err != nil {
		return nil, err
	}
	owned.processLock, err = macOSOwnedAdoptLock(5, macOSOwnedProcessLock, true)
	if err != nil {
		return nil, err
	}
	uid, err := macOSOwnedInstallIdentity()
	if err != nil {
		return nil, err
	}
	lifetime := os.NewFile(3, "routervpn-macos-desktop-lifetime")
	if lifetime == nil {
		return nil, errors.New("the native controller requires its authenticated desktop lifetime")
	}
	defer lifetime.Close()
	raw, err := lifetime.SyscallConn()
	if err != nil {
		return nil, err
	}
	peer, err := macOSOwnedPeer(raw)
	if err != nil || peer.UID != uid {
		return nil, errors.New("the native controller lifetime belongs to another desktop user")
	}
	var socketAddressError error
	err = raw.Control(func(fd uintptr) {
		address, readErr := syscall.Getsockname(int(fd))
		local, ok := address.(*syscall.SockaddrUnix)
		if readErr != nil || !ok || local.Name != macOSOwnedControllerSocket {
			socketAddressError = errors.New("the native controller lifetime was not accepted by its installed supervisor")
		}
	})
	if err != nil || socketAddressError != nil {
		return nil, errors.Join(err, socketAddressError)
	}
	owned.input, err = macOSOwnedDuplicate(lifetime)
	if err != nil {
		return nil, err
	}
	input, err := macOSOwnedInput(os.Stdin)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	if err = input.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	frame, err := readOwnedControllerFrame(input)
	if err != nil {
		return nil, errors.New("the native controller launch identity is missing or oversized")
	}
	owned.accessToken, owned.ownerToken, err = decodeOwnedControllerHandshake(frame)
	if err != nil {
		return nil, err
	}
	owned.callerUID = uid
	os.Clearenv()
	for _, item := range macOSOwnedEnvironment() {
		key, value, _ := strings.Cut(item, "=")
		if err = os.Setenv(key, value); err != nil {
			return nil, err
		}
	}
	if err = os.Chdir(macOSOwnedControllerRoot); err != nil {
		return nil, err
	}
	syscall.Umask(0077)
	done := make(chan struct{})
	owned.ownerDone = done
	go func() { var byte [1]byte; _, _ = owned.input.Read(byte[:]); close(done) }()
	return owned, nil
}

func macOSControllerSupervisorUtility(arguments []string) (bool, error) {
	requested := false
	for _, argument := range arguments {
		if argument == macOSControllerSupervisorArgument {
			requested = true
		}
	}
	if !requested {
		return false, nil
	}
	if len(arguments) != 1 || arguments[0] != macOSControllerSupervisorArgument || os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, errors.New("the installed supervisor requires its fixed privileged launch")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return true, runMacOSControllerSupervisor(ctx)
}

func macOSOwnedSocketDirectory() error {
	// Use the protected installation prefix. /private/var/run can be writable
	// by the daemon group, so it cannot supply the required immutable ancestry.
	// Read-only non-wheel groups still do not grant mutation authority.
	for path := filepath.Dir(macOSOwnedControllerSocketDirectory); ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return errors.New("the supervisor runtime ancestor is not a real directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("the supervisor runtime ancestor is not exclusively root-owned")
		}
		if err = ownedPathACL(path); err != nil {
			return err
		}
		if path == "/" {
			break
		}
	}
	if err := os.Mkdir(macOSOwnedControllerSocketDirectory, 0755); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	} else {
		if err := os.Chmod(macOSOwnedControllerSocketDirectory, 0755); err != nil {
			return err
		}
	}
	info, err := os.Lstat(macOSOwnedControllerSocketDirectory)
	if err != nil || !info.IsDir() || !ownedDesktopInfo(info) || info.Mode().Perm() != 0755 {
		return errors.New("the installed supervisor socket directory is not exclusively root-owned")
	}
	return ownedPathACL(macOSOwnedControllerSocketDirectory)
}

func runMacOSControllerSupervisor(ctx context.Context) error {
	ownedContext, cancelOwned := context.WithCancel(ctx)
	defer cancelOwned()
	if err := ownedDesktopAncestors(filepath.Dir(macOSOwnedControllerRoot)); err != nil {
		return err
	}
	install, err := ownedDesktopLock(macOSOwnedInstallLock, false)
	if err != nil {
		return errors.New("Router VPN installation or upgrade is in progress")
	}
	defer install.Close()
	uid, err := macOSOwnedInstallIdentity()
	if err != nil {
		return err
	}
	supervisor, err := ownedDesktopLock(macOSOwnedSupervisorLock, true)
	if err != nil {
		return errors.New("an installed Router VPN supervisor is already running")
	}
	defer supervisor.Close()
	startupProcess, err := ownedDesktopLock(macOSOwnedProcessLock, true)
	if err != nil {
		return errors.New("a previous owned controller still retains its protected connection")
	}
	defer startupProcess.Close()
	if err = macOSOwnedReassert(ownedContext); err != nil {
		return err
	}
	if err = macOSOwnedSocketDirectory(); err != nil {
		return err
	}
	if info, statErr := os.Lstat(macOSOwnedControllerSocket); statErr == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || stat.Uid != uid || stat.Nlink != 1 {
			return errors.New("an unrelated file occupies the installed supervisor socket")
		}
		if err = ownedPathACL(macOSOwnedControllerSocket); err != nil {
			return err
		}
		if err = os.Remove(macOSOwnedControllerSocket); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	oldMask := syscall.Umask(0077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: macOSOwnedControllerSocket, Net: "unix"})
	syscall.Umask(oldMask)
	if err != nil {
		return err
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if err = os.Chmod(macOSOwnedControllerSocket, 0600); err != nil {
		return err
	}
	if err = os.Chown(macOSOwnedControllerSocket, int(uid), 0); err != nil {
		return err
	}
	if err = ownedPathACL(macOSOwnedControllerSocket); err != nil {
		return err
	}
	identity, err := os.Lstat(macOSOwnedControllerSocket)
	if err != nil {
		return err
	}
	defer func() {
		if current, err := os.Lstat(macOSOwnedControllerSocket); err == nil && os.SameFile(identity, current) {
			_ = os.Remove(macOSOwnedControllerSocket)
		}
	}()
	// Idle supervisors do not block installation. Every launch reacquires and
	// transfers its shared lock before exec, with no unlocked startup window.
	if err = startupProcess.Close(); err != nil {
		return err
	}
	if err = install.Close(); err != nil {
		return err
	}
	stop := context.AfterFunc(ownedContext, func() { _ = listener.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer func() { cancelOwned(); workers.Wait() }()
	capacity := make(chan struct{}, 4)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case capacity <- struct{}{}:
		default:
			connection.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-capacity }()
			defer connection.Close()
			if err := runMacOSOwnedChild(ownedContext, connection, uid); err != nil {
				fmt.Fprintln(os.Stderr, "Router VPN owned controller launch or join failed:", err)
			}
		}()
	}
}

func macOSOwnedReassert(ctx context.Context) error {
	// Reinstall the exact saved Always policy before admitting a desktop. This
	// is the existing policy compiler, with its fixed root-owned Python wrapper;
	// no profile, environment-selected helper or public resolver is substituted.
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, filepath.Join(macOSOwnedControllerRoot, "bin", "python3"),
		filepath.Join(macOSOwnedControllerRoot, "modes", "kill-switch-platform.py"), "reassert")
	command.Dir, command.Env = macOSOwnedControllerRoot, macOSOwnedEnvironment()
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("the saved macOS protection policy could not be reasserted: %w", err)
	}
	return nil
}

func runMacOSOwnedChild(ctx context.Context, connection *net.UnixConn, registeredUID uint32) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	peer, err := macOSOwnedPeer(raw)
	if err != nil || peer.UID != registeredUID || registeredUID == 0 {
		return errors.New("the supervisor rejected a foreign local peer")
	}
	if err = connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	frame, err := readOwnedControllerFrame(connection)
	if err != nil {
		return errors.New("the supervisor requires a bounded launch identity")
	}
	secret, owner, err := decodeOwnedControllerHandshake(frame)
	if err != nil {
		return err
	}
	if err = connection.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	install, err := ownedDesktopLock(macOSOwnedInstallLock, false)
	if err != nil {
		return errors.New("Router VPN installation or upgrade is in progress")
	}
	defer install.Close()
	process, err := ownedDesktopLock(macOSOwnedProcessLock, true)
	if err != nil {
		return errors.New("another desktop already owns the installed controller")
	}
	defer process.Close()
	uid, err := macOSOwnedInstallIdentity()
	if err != nil || uid != registeredUID {
		return errors.New("the installed desktop authorization changed")
	}
	fd := -1
	var duplicateErr error
	if err = raw.Control(func(value uintptr) { fd, duplicateErr = syscall.Dup(int(value)) }); err != nil || duplicateErr != nil {
		return errors.Join(err, duplicateErr)
	}
	syscall.CloseOnExec(fd)
	lifetime := os.NewFile(uintptr(fd), "routervpn-macos-desktop-lifetime")
	defer lifetime.Close()
	input, output, err := os.Pipe()
	if err != nil {
		return err
	}
	defer input.Close()
	defer output.Close()
	child := exec.Command(macOSOwnedExecutable(), macOSOwnedControllerArgument)
	child.Dir = macOSOwnedControllerRoot
	child.Env = macOSOwnedEnvironment()
	child.Stdin = input
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{lifetime, install, process}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err = child.Start(); err != nil {
		return errors.New("the fixed installed controller could not start")
	}
	// Parent copies close immediately. The exact child owns all three inherited
	// capabilities even before its Go bootstrap can run or an installer races.
	_ = input.Close()
	_ = lifetime.Close()
	_ = install.Close()
	_ = process.Close()
	retire := context.AfterFunc(ctx, func() { _ = connection.CloseRead() })
	defer retire()
	_, frameErr := output.Write(frame)
	_ = output.Close()
	_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	startErr := writeOwnedControllerSupervisorReceipt(connection, "started", child.Process.Pid, 0, secret, owner)
	if frameErr != nil || startErr != nil {
		_ = connection.CloseRead()
	}
	// Wait is the only source of joined evidence. EOF or a signal is not a
	// fabricated success, and no timeout kills a child still draining ownership.
	joinErr := child.Wait()
	if child.ProcessState == nil {
		return errors.Join(joinErr, errors.New("the owned controller has no actual process-join result"))
	}
	exitCode := child.ProcessState.ExitCode()
	_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	receiptErr := writeOwnedControllerSupervisorReceipt(connection, "joined", child.Process.Pid, exitCode, secret, owner)
	if frameErr != nil || startErr != nil || joinErr != nil || receiptErr != nil {
		return errors.Join(frameErr, startErr, joinErr, receiptErr)
	}
	return nil
}
