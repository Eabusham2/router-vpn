//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"router-vpn/internal/common"
)

const linuxOwnedControllerRoot = "/opt/router-vpn-client"
const linuxOwnedInstallLock = "/opt/router-vpn-client.install.lock"
const linuxOwnedProcessLock = "/opt/router-vpn-client.controller.lock"

func validateLinuxOwnedStartup(owned *linuxOwnedController) error {
	if owned != nil {
		if os.Geteuid() != 0 || owned.processID != os.Getpid() || owned.callerUID == 0 ||
			!validLocalControllerSecret(owned.accessToken) || !validControllerOwnerToken(owned.ownerToken) ||
			owned.input == nil || owned.installLock == nil || owned.processLock == nil || owned.ownerDone == nil {
			return errors.New("the installed controller lost its captured privileged launch")
		}
		parent, ok := owned.nodeParent.(*desktopLinuxNodeParent)
		if !ok || parent == nil || parent.controller != owned {
			return errors.New("the installed controller lost its retained Linux parent")
		}
		return parent.Current(context.Background())
	}
	if os.Geteuid() != 0 {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if executable == filepath.Join(linuxOwnedControllerRoot, "router-vpn-client") {
		return errors.New("open the installed Router VPN desktop app to authorize its owned controller")
	}
	return nil
}

func prepareLinuxOwnedController(arguments []string) (_ *linuxOwnedController, failure error) {
	if !containsOwnedControllerArgument(arguments) {
		return nil, nil
	}
	if len(arguments) != 1 || arguments[0] != linuxOwnedControllerArgument || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, errors.New("the installed native controller requires its authorized fixed launch")
	}
	uid, err := strconv.ParseUint(os.Getenv("PKEXEC_UID"), 10, 32)
	if err != nil || uid == 0 || uid >= uint64(^uint32(0)) || strconv.FormatUint(uid, 10) != os.Getenv("PKEXEC_UID") {
		return nil, errors.New("the native controller requires the authenticated desktop user")
	}
	if _, err = user.LookupId(strconv.FormatUint(uid, 10)); err != nil {
		return nil, errors.New("the authenticated desktop user no longer exists")
	}
	owned := &linuxOwnedController{processID: os.Getpid(), callerUID: uint32(uid)}
	defer func() {
		if failure != nil {
			owned.close()
		}
	}()
	if err = linuxOwnedAncestors(filepath.Dir(linuxOwnedControllerRoot)); err != nil {
		return nil, err
	}
	owned.installLock, err = linuxOwnedLock(linuxOwnedInstallLock, false)
	if err != nil {
		return nil, errors.New("Router VPN installation or upgrade is in progress")
	}
	owned.processLock, err = linuxOwnedLock(linuxOwnedProcessLock, true)
	if err != nil {
		return nil, errors.New("an installed Router VPN controller already owns this launch")
	}
	executable, err := os.Executable()
	if err != nil || executable != filepath.Join(linuxOwnedControllerRoot, "router-vpn-client") {
		return nil, errors.New("only the fixed installed Router VPN controller can be elevated")
	}
	if err = linuxOwnedInstall(linuxOwnedControllerRoot); err != nil {
		return nil, err
	}
	actual, err := os.Stat("/proc/self/exe")
	installed, installedErr := os.Lstat(executable)
	if err != nil || installedErr != nil || !os.SameFile(actual, installed) {
		return nil, errors.New("the running controller no longer matches the installed executable")
	}
	config, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "client.json"), maxPrivateStoreBytes)
	if err != nil {
		return nil, errors.New("the installed controller configuration cannot be read safely")
	}
	var captured common.ClientConfig
	if err = decodeRelayControlJSON(config, &captured); err != nil {
		return nil, errors.New("the installed controller configuration is invalid")
	}
	if err = validateLinuxOwnedConfiguration(captured); err != nil {
		return nil, err
	}
	owned.input, err = linuxOwnedInput(os.Stdin, uint32(uid))
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(owned.input, 512)
	if err = owned.input.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, errors.New("the native controller input cannot be bounded")
	}
	frame, err := reader.ReadSlice('\n')
	if err != nil || len(frame) > 384 {
		return nil, errors.New("the native controller launch identity is missing or oversized")
	}
	owned.accessToken, owned.ownerToken, err = decodeLinuxOwnedHandshake(frame)
	if err != nil {
		return nil, err
	}
	if err = owned.input.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// pkexec documents a minimal environment and PKEXEC_UID. Apply a fixed
	// controller environment as well; no caller-selected script/config/runtime,
	// proxy, loader or catalog environment is inherited by privileged children.
	// https://polkit.pages.freedesktop.org/polkit/pkexec.1.html
	os.Clearenv()
	for key, value := range map[string]string{
		"HOME": "/root", "LANG": "C.UTF-8",
		"PATH":                  linuxOwnedControllerRoot + "/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOMEVPN_ROOT":          linuxOwnedControllerRoot,
		"HOMEVPN_CLIENT_CONFIG": filepath.Join(linuxOwnedControllerRoot, "client.json"),
		"HOMEVPN_NATIVE_APP":    "linux-gtk-product",
	} {
		if err = os.Setenv(key, value); err != nil {
			return nil, err
		}
	}
	if err = os.Chdir(linuxOwnedControllerRoot); err != nil {
		return nil, err
	}
	syscall.Umask(0077)
	done := make(chan struct{})
	owned.ownerDone = done
	parent, err := newDesktopLinuxNodeParent(owned)
	owned.nodeParent = parent // Retain every returned partial native owner for teardown.
	if err != nil {
		return nil, err
	}
	go func() {
		// EOF (desktop death) or any second message permanently retires this
		// owner. The HTTP lifecycle drains all native work before process exit.
		_, _ = reader.ReadByte()
		close(done)
	}()
	return owned, nil
}

func containsOwnedControllerArgument(arguments []string) bool {
	for _, argument := range arguments {
		if argument == linuxOwnedControllerArgument {
			return true
		}
	}
	return false
}

func decodeLinuxOwnedHandshake(frame []byte) (string, string, error) {
	return decodeOwnedControllerHandshake(frame)
}

func validateLinuxOwnedConfiguration(config common.ClientConfig) error {
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
			path = filepath.Join(linuxOwnedControllerRoot, path)
		}
		if filepath.Clean(path) != filepath.Join(linuxOwnedControllerRoot, name) || strings.ContainsRune(supplied, '\x00') {
			return errors.New("the native controller configuration escaped its fixed installed paths")
		}
	}
	return nil
}

func linuxOwnedInfo(info fs.FileInfo) bool  { return ownedDesktopInfo(info) }
func linuxOwnedAncestors(path string) error { return ownedDesktopAncestors(path) }
func linuxOwnedInstall(root string) error   { return ownedDesktopInstall(root) }
func linuxOwnedLock(path string, exclusive bool) (*os.File, error) {
	return ownedDesktopLock(path, exclusive)
}

func linuxOwnedInput(input *os.File, uid uint32) (*os.File, error) {
	if input == nil {
		return nil, errors.New("the native controller requires its inherited anonymous input")
	}
	info, err := input.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	link, linkErr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", input.Fd()))
	if !ok || info.Mode()&os.ModeNamedPipe == 0 || stat.Uid != uid || info.Mode().Perm()&0077 != 0 ||
		linkErr != nil || !strings.HasPrefix(link, "pipe:[") || !strings.HasSuffix(link, "]") {
		return nil, errors.New("the native controller requires its authenticated user's anonymous input pipe")
	}
	// Duplicate the retained descriptor so bootstrap cleanup never closes an
	// unrelated os.Stdin wrapper reused by a test or utility caller.
	fd, err := syscall.Dup(int(input.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "routervpn-controller-lifetime"), nil
}
