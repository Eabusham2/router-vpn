//go:build go1.25

package main

import "os"

func desktopNativeFixtureRename(root *os.Root, oldname, newname string) error {
	return root.Rename(oldname, newname)
}
