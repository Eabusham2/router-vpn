//go:build linux || darwin

package main

import "router-vpn/internal/common"

func validateOwnedDarwinACL(data []byte, private bool) error {
	return common.ValidateOwnedDarwinACL(data, private)
}
