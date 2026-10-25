package main

import (
	"errors"
	"os"
	"strings"
)

// All relay mailbox names are single components chosen by this process. Keep
// that boundary before either the newer Root method or the pinned Go 1.24
// Linux descriptor-relative implementation; neither may resolve the old path.
func validRelayRootName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && !strings.ContainsAny(name, "/\\\x00")
}

func renameRelayRootFile(root *os.Root, oldName, newName string) error {
	if root == nil || !validRelayRootName(oldName) || !validRelayRootName(newName) {
		return errors.New("invalid owned relay mailbox name")
	}
	if atomic, ok := any(root).(interface{ Rename(string, string) error }); ok {
		return atomic.Rename(oldName, newName)
	}
	return renameRelayRootFileLegacy(root, oldName, newName)
}

// Go 1.24 supplies rooted OpenRoot/Remove but not RemoveAll. Traverse only the
// captured tree and remove symlinks themselves. A replacement at the launch
// pathname is checked by the caller and never used for this traversal.
func removeRelayRootContents(root *os.Root) error {
	if root == nil {
		return errors.New("owned relay directory is unavailable")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !validRelayRootName(name) {
			return errors.New("invalid owned relay directory entry")
		}
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			child, err := root.OpenRoot(name)
			if err != nil {
				return err
			}
			opened, statErr := child.Stat(".")
			if statErr != nil || !os.SameFile(info, opened) {
				_ = child.Close()
				return errors.New("owned relay child directory changed")
			}
			removeErr := removeRelayRootContents(child)
			closeErr := child.Close()
			if removeErr != nil || closeErr != nil {
				return errors.Join(removeErr, closeErr)
			}
			current, statErr := root.Lstat(name)
			if statErr != nil || !os.SameFile(info, current) {
				return errors.New("owned relay child directory was replaced")
			}
		}
		if err := root.Remove(name); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
