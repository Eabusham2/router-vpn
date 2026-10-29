//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
	var root string
	if strings.HasPrefix(canonical, commandLineTools+"/") {
		root = commandLineTools
	} else {
		root = regexp.MustCompile(`^/Library/Frameworks/Python\.framework/Versions/[0-9]+\.[0-9]+/`).FindString(canonical)
		root = strings.TrimSuffix(root, "/")
	}
	if root == "" {
		return "", "", errors.New("install a root-owned Python.org framework or Apple Command Line Tools Python before native installation; user-owned Homebrew runtimes cannot execute privileged helpers")
	}
	if err = validateMacPythonTree(root, canonical); err != nil {
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

func validateMacPythonTree(root, executable string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(executable, root+string(filepath.Separator)) {
		return errors.New("the privileged interpreter escaped its captured installation")
	}
	if err := trustedMacToolAncestors(root); err != nil {
		return err
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || !trustedMacToolInfo(info) || info.Mode()&0111 == 0 {
		return errors.New("the privileged interpreter is not a trusted executable")
	}
	count := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, failure error) error {
		count++
		if failure != nil || count > 300000 {
			return errors.New("the complete privileged Python installation cannot be bounded and inspected")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			target, failure := filepath.EvalSymlinks(path)
			if !ok || stat.Uid != 0 || failure != nil || !strings.HasPrefix(target, root+string(filepath.Separator)) {
				return macPythonRejectedLink(path, target, stat, failure)
			}
			info, err = os.Stat(target)
			if err != nil {
				return err
			}
			if err := ownedPathACL(target); err != nil {
				return err
			}
		}
		if !trustedMacToolInfo(info) {
			return errors.New("privileged Python code or libraries are writable by another user")
		}
		return ownedPathACL(path)
	})
}
