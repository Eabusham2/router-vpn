//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The installer must establish interpreter trust before executing Python as
// root. A Homebrew interpreter or library writable by the desktop user is not
// a durable privileged runtime. The normal-user launcher may discover a
// candidate, but only these fixed system/installer-owned roots confer trust.
func macOSPythonTrustRoot(candidate string) (string, string, error) {
	if !filepath.IsAbs(candidate) {
		return "", "", errors.New("the installation Python must have an absolute path")
	}
	canonical, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", "", err
	}
	const commandLineTools = "/Library/Developer/CommandLineTools"
	var framework string
	if strings.HasPrefix(canonical, commandLineTools+"/") {
		framework = commandLineTools + "/Library/Frameworks/Python3.framework"
	} else if strings.HasPrefix(canonical, "/Library/Frameworks/Python.framework/Versions/") {
		framework = "/Library/Frameworks/Python.framework"
	}
	if framework == "" {
		return "", "", errors.New("install a root-owned Python.org framework or Apple Command Line Tools Python before native installation; user-owned Homebrew runtimes cannot execute privileged helpers")
	}
	root, err := validateMacPythonRuntime(canonical, framework)
	if err != nil {
		return "", "", err
	}
	return canonical, root, nil
}

func trustedMacToolInfo(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode()&0022 == 0 && info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) == 0 && (info.IsDir() || info.Mode().IsRegular())
}

func trustedMacToolAncestors(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("noncanonical privileged tool path")
	}
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || !trustedMacToolInfo(info) {
			return fmt.Errorf("privileged tool parent is not exclusively root-owned: %s", path)
		}
		if err := ownedPathACL(path); err != nil {
			return err
		}
		if path == string(filepath.Separator) {
			return nil
		}
		path = filepath.Dir(path)
	}
}

// Rejected library links must identify the actual failure on the native host.
// Keep untrusted names quoted, preserve both ends of long paths, and bound the
// diagnostic without changing which owner or target the trust gate accepts.
func macPythonDiagnosticValue(value string) string {
	const limit = 256
	if len(value) > limit {
		value = value[:limit/2] + "...[truncated]..." + value[len(value)-limit/2:]
	}
	return strconv.QuoteToASCII(value)
}

func macPythonRejectedLink(path, target string, owner *syscall.Stat_t, resolutionErr error) error {
	link, readErr := os.Readlink(path)
	uid := "unavailable"
	if owner != nil {
		uid = strconv.FormatUint(uint64(owner.Uid), 10)
	}
	detail := "privileged Python contains a foreign or escaping link: path=" + macPythonDiagnosticValue(path) +
		" link=" + macPythonDiagnosticValue(link) + " resolved=" + macPythonDiagnosticValue(target) + " owner_uid=" + uid
	if resolutionErr != nil {
		detail += " resolution_error=" + macPythonDiagnosticValue(resolutionErr.Error())
	}
	if readErr != nil {
		detail += " readlink_error=" + macPythonDiagnosticValue(readErr.Error())
	}
	return errors.New(detail)
}
