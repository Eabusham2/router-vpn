//go:build !linux

package main

import "os"

// Non-Linux native builds use the newer pinned toolchain and the Root.Rename
// interface above. An older toolchain without that rooted primitive must not
// replace it with a pathname operation that could follow a replacement owner.
func renameRelayRootFileLegacy(_ *os.Root, _, _ string) error {
	return os.ErrInvalid
}
