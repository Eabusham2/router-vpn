//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

type macInstallerPackageSource struct {
	name        string
	root        *os.Root
	identity    fs.FileInfo
	directories map[string]*os.Root
	identities  map[string]fs.FileInfo
}

func openMacInstallerPackageSource(source string) (*macInstallerPackageSource, error) {
	before, err := os.Lstat(source)
	if err != nil || !before.IsDir() {
		return nil, errors.New("native installer source is not its original directory")
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return nil, err
	}
	owned := &macInstallerPackageSource{name: source, root: root, identity: before,
		directories: make(map[string]*os.Root), identities: make(map[string]fs.FileInfo)}
	complete := false
	defer func() {
		if !complete {
			owned.close()
		}
	}()
	if err := owned.current(); err != nil {
		return nil, err
	}
	for _, name := range []string{"client", "modes"} {
		named, err := root.Lstat(name)
		if err != nil || !named.IsDir() {
			return nil, errors.New("native installer package directory is missing or linked")
		}
		directory, err := root.OpenRoot(name)
		if err != nil {
			return nil, err
		}
		owned.directories[name], owned.identities[name] = directory, named
		if err := owned.current(); err != nil {
			return nil, err
		}
	}
	complete = true
	return owned, nil
}

func (s *macInstallerPackageSource) close() {
	for _, directory := range s.directories {
		_ = directory.Close()
	}
	_ = s.root.Close()
}

func (s *macInstallerPackageSource) current() error {
	actual, err := s.root.Stat(".")
	named, nameErr := os.Lstat(s.name)
	if err != nil || nameErr != nil || !named.IsDir() || !os.SameFile(s.identity, actual) || !os.SameFile(s.identity, named) {
		return errors.New("native installer source directory changed during capture")
	}
	for name, directory := range s.directories {
		actual, err := directory.Stat(".")
		named, nameErr := s.root.Lstat(name)
		if err != nil || nameErr != nil || !named.IsDir() || !os.SameFile(s.identities[name], actual) || !os.SameFile(s.identities[name], named) {
			return errors.New("native installer package directory changed during capture")
		}
	}
	return nil
}

// captureMacInstallerPackage retains the exact source directories while taking
// the private snapshot. Python's explicit sibling and parent-relative imports
// require the original package layout. No ambient modules or private state are
// included, and a replaced directory cannot redirect a later module read.
func captureMacInstallerPackage(source, private string) (string, error) {
	owned, err := openMacInstallerPackageSource(source)
	if err != nil {
		return "", err
	}
	defer owned.close()
	return owned.capture(private)
}

func (s *macInstallerPackageSource) capture(private string) (string, error) {
	info, err := os.Lstat(private)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("native installer capture requires its new private directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return "", errors.New("native installer capture lost its directory owner")
	}
	for _, name := range []string{"client", "modes"} {
		if err := os.Mkdir(filepath.Join(private, name), 0700); err != nil {
			return "", fmt.Errorf("create native installer package: %w", err)
		}
	}
	for _, relative := range []string{
		"client/install-macos-native.py",
		"client/install-linux-native.py",
		"client/install-macos-generation.py",
		"client/install-macos-image.py",
		"modes/darwin_install_capability.py",
	} {
		if err := copyMacInstallerModule(s.directories[filepath.Dir(relative)], filepath.Base(relative), filepath.Join(private, relative)); err != nil {
			return "", err
		}
	}
	if err := s.current(); err != nil {
		return "", err
	}
	return filepath.Join(private, "client", "install-macos-native.py"), nil
}

func copyMacInstallerModule(source *os.Root, name, destination string) error {
	// os.Root confines lookup to the retained parent but may resolve internal
	// links. Require the named leaf itself to be regular, and bind its original
	// identity to the opened descriptor before reading any bytes.
	original, err := source.Lstat(name)
	if err != nil || !original.Mode().IsRegular() {
		return errors.New("unsafe native installer module name")
	}
	file, err := source.OpenFile(name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(original, before) || before.Size() < 1 || before.Size() > 2<<20 {
		return errors.New("unsafe native installer module")
	}
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil || int64(len(data)) != before.Size() {
		return errors.New("native installer module changed while reading")
	}
	after, err := file.Stat()
	named, namedErr := source.Lstat(name)
	if err != nil || namedErr != nil || !named.Mode().IsRegular() || !os.SameFile(before, named) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("native installer module changed during capture")
	}
	if err = os.WriteFile(destination, data, 0600); err != nil {
		return fmt.Errorf("capture native installer: %w", err)
	}
	return nil
}
