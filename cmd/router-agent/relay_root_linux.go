//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
)

// The production ARM64 agent retains Go 1.24. Both operands are resolved from
// an open descriptor for the captured root, even after its pathname is moved
// and replaced. No /proc alias or unchecked absolute-path fallback is used.
func renameRelayRootFileLegacy(root *os.Root, oldName, newName string) error {
	if root == nil || !validRelayRootName(oldName) || !validRelayRootName(newName) {
		return errors.New("invalid owned relay mailbox name")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	fd := int(directory.Fd())
	return syscall.Renameat(fd, oldName, fd, newName)
}
