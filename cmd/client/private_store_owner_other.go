//go:build !windows

package main

import "os"

func validateOwnedPrivateStoreFile(string, os.FileInfo) (bool, error) { return false, nil }
func readOwnedPrivateStoreFile(string, int64) ([]byte, bool, error)   { return nil, false, nil }
