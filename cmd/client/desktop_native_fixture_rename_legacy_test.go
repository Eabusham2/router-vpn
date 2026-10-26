//go:build !go1.25

package main

import (
	"os"
	"path/filepath"
)

// Keep the controller's Go 1.24 minimum buildable. The separately built native
// engine and actual Windows native gates use pinned Go 1.26, including Root's
// Windows POSIX replacement. Older POSIX controller fixtures retain Rename's
// equivalent held-snapshot behavior; no test is skipped on either toolchain.
func desktopNativeFixtureRename(root *os.Root, oldname, newname string) error {
	return os.Rename(filepath.Join(root.Name(), oldname), filepath.Join(root.Name(), newname))
}
