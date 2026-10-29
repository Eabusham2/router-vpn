//go:build darwin

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

func macOSInstallerUtility(arguments []string) (bool, error) {
	requested := false
	for _, value := range arguments {
		requested = requested || value == "--install-macos-native"
	}
	if !requested {
		return false, nil
	}
	if len(arguments) != 3 || arguments[0] != "--install-macos-native" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, errors.New("run the native package installer from your normal Mac account and approve its sudo request")
	}
	caller, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil || caller == 0 || caller >= uint64(^uint32(0)) || strconv.FormatUint(caller, 10) != os.Getenv("SUDO_UID") {
		return true, errors.New("native installation requires the captured non-root installing user")
	}
	if _, err = user.LookupId(strconv.FormatUint(caller, 10)); err != nil {
		return true, err
	}
	python, _, err := macOSPythonTrustRoot(arguments[2])
	if err != nil {
		return true, err
	}
	source, err := filepath.EvalSymlinks(arguments[1])
	if err != nil || !filepath.IsAbs(source) {
		return true, errors.New("the native package requires a canonical absolute source")
	}
	executable, err := os.Executable()
	actual, statErr := os.Stat(executable)
	supplied, sourceErr := os.Lstat(filepath.Join(source, "router-vpn-client"))
	if err != nil || statErr != nil || sourceErr != nil || !supplied.Mode().IsRegular() || !os.SameFile(actual, supplied) {
		return true, errors.New("run the controller belonging to this exact extracted native package")
	}
	if err = os.MkdirAll("/opt", 0755); err != nil {
		return true, err
	}
	if err = trustedMacToolAncestors("/opt"); err != nil {
		return true, err
	}
	private, err := os.MkdirTemp("/opt", ".router-vpn-bootstrap-")
	if err != nil {
		return true, err
	}
	defer os.RemoveAll(private)
	// Snapshot installer code into a root-owned private directory before Python
	// imports it. Application/runtime inputs have their own descriptor-based
	// capture, verification and transaction inside the installer.
	for _, name := range []string{"install-macos-native.py", "install-linux-native.py"} {
		if err = copyMacInstallerModule(filepath.Join(source, "client", name), filepath.Join(private, name)); err != nil {
			return true, err
		}
	}
	command := exec.Command(python, "-EsS", filepath.Join(private, "install-macos-native.py"), source, "--caller-uid", strconv.FormatUint(caller, 10), "--python", python)
	command.Env = macOSPythonEnvironment()
	command.Dir = private
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return true, command.Run()
}

func copyMacInstallerModule(source, destination string) error {
	fd, err := syscall.Open(source, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), source)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 2<<20 {
		return errors.New("unsafe native installer module")
	}
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil || int64(len(data)) != before.Size() {
		return errors.New("native installer module changed while reading")
	}
	after, err := file.Stat()
	named, namedErr := os.Lstat(source)
	if err != nil || namedErr != nil || !named.Mode().IsRegular() || !os.SameFile(before, named) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("native installer module changed during capture")
	}
	if err = os.WriteFile(destination, data, 0600); err != nil {
		return fmt.Errorf("capture native installer: %w", err)
	}
	return nil
}
