//go:build !linux && !darwin

package main

// Preserve the existing native permission preparation on other platforms,
// including the captured Windows owner and protected DACL checks.
func preparePrivateRuntimeRoot(path string) error {
	return ensurePrivateRuntimeDirectory(path)
}
