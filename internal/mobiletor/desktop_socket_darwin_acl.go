//go:build darwin

package mobiletor

import "router-vpn/internal/common"

func desktopDarwinPathACL(path string) error { return common.OwnedPathACL(path) }
