//go:build windows

package main

import "os"

// Once an elevated controller captured its original desktop owner, private
// reads/replacements must preserve that owner and reject hardlink/reparse
// substitution before even the ordinary upgrade-time permission adjustment.
func validateOwnedPrivateStoreFile(path string, info os.FileInfo) (bool, error) {
	if windowsRuntimeOriginalOwnerCapture.Load() == nil {
		return false, nil
	}
	// The captured Windows ACL is authoritative. Do not follow the path again
	// for chmod after checking its handle; another name could replace it.
	return true, validatePrivateRuntimePathPermissions(path, info)
}

func readOwnedPrivateStoreFile(path string, limit int64) ([]byte, bool, error) {
	if windowsRuntimeOriginalOwnerCapture.Load() == nil {
		return nil, false, nil
	}
	body, err := readPrivateRuntimeSnapshot(path, limit)
	return body, true, err
}
