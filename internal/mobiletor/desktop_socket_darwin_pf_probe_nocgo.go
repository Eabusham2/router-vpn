//go:build darwin && !cgo && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"errors"
	"net/netip"
)

func desktopDarwinPFProbeTransaction(context.Context, string, netip.Addr, int) error {
	return errors.New("Darwin single-filter transaction probe requires the actual native Apple SDK")
}
