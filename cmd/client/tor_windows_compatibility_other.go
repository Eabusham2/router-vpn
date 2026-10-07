//go:build !windows

package main

import "errors"

func windowsTorHostCompatibility() (string, error) {
	return "", errors.New("Windows Tor compatibility requested on a non-Windows platform")
}
