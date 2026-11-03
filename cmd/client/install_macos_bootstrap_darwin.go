//go:build darwin

package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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
	entry, err := captureMacInstallerPackage(source, private)
	if err != nil {
		return true, err
	}
	// Replace this package's native image before the installer inventories the
	// incoming generation. The protected Python supervisor owns cleanup in the
	// same PID; no still-live incoming bootstrap needs an image/PID exemption.
	return true, execMacInstallerPackage(python, private, entry,
		[]string{source, "--caller-uid", strconv.FormatUint(caller, 10), "--python", python}, macOSPythonEnvironment())
}
