//go:build !windows

package main

import "os"

func replacePrivateStoreFile(source, target string) error {
	return os.Rename(source, target)
}
