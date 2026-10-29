//go:build linux

package common

// Linux POSIX ACL effective write grants are represented by the group mask
// checked by the existing root ownership/mode validation. Darwin requires an
// additional independent extended ACL readback.
func OwnedPathACL(string) error { return nil }
