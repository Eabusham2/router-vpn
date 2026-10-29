//go:build linux

package main

import "router-vpn/internal/common"

func ownedPathACL(path string) error { return common.OwnedPathACL(path) }
