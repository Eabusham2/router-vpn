//go:build linux

package main

// Linux POSIX ACL effective write grants are represented by the group mask
// checked by the existing root ownership/mode validation. Darwin requires an
// additional independent extended ACL readback.
func ownedPathACL(string) error { return nil }
