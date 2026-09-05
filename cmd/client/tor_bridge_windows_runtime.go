package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const torWindowsRuntimeWalkLimit = 4096

func safePinnedRuntimeExecutable(path, label string) (string, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" || strings.ContainsAny(path, "\r\n\x00") {
		return "", fmt.Errorf("%s path is empty or unsafe", label)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("%s is unavailable: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular non-symlink file", label)
	}
	return path, nil
}

func findUniquePinnedRuntimeExecutable(root, name, label string) (string, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || root == "" || strings.ContainsAny(root, "\r\n\x00") {
		return "", fmt.Errorf("%s runtime root is empty or unsafe", label)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("%s runtime root is unavailable: %w", label, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", fmt.Errorf("%s runtime root must be a real directory", label)
	}

	visited := 0
	matches := make([]string, 0, 1)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > torWindowsRuntimeWalkLimit {
			return errors.New("Tor Expert Bundle runtime tree exceeds safety limit")
		}
		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return fmt.Errorf("Tor Expert Bundle runtime contains symlink %q", path)
		}
		if entry.IsDir() || !strings.EqualFold(entry.Name(), name) {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s candidate is not a regular file", label)
		}
		matches = append(matches, path)
		if len(matches) > 1 {
			return fmt.Errorf("Tor Expert Bundle contains more than one %s", name)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("Tor Expert Bundle must contain exactly one %s; found %d", name, len(matches))
	}
	return safePinnedRuntimeExecutable(matches[0], label)
}

func windowsTorRuntimeExecutable(root, name string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", errors.New("Windows Tor runtime requested on a non-Windows platform")
	}
	if runtime.GOARCH != "amd64" {
		return "", errors.New("native Tor bridge runtime is unavailable on Windows ARM64 because the pinned Tor Project Expert Bundle has no Windows ARM64 build")
	}
	windowsRoot := filepath.Join(filepath.Clean(root), "runtime", "windows")
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sing-box.exe":
		return safePinnedRuntimeExecutable(filepath.Join(windowsRoot, "sing-box.exe"), "pinned Windows sing-box")
	case "tor.exe":
		return findUniquePinnedRuntimeExecutable(filepath.Join(windowsRoot, "tor-expert"), "tor.exe", "pinned Windows Tor")
	case "lyrebird.exe":
		return findUniquePinnedRuntimeExecutable(filepath.Join(windowsRoot, "tor-expert"), "lyrebird.exe", "pinned Windows Lyrebird")
	default:
		return "", fmt.Errorf("unsupported Windows Tor runtime executable %q", name)
	}
}
