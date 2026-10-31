//go:build linux

package mobiletor

import (
	"context"
	"errors"
)

// ReadDesktopLinuxProtectionAbsence independently reads the kernel. A missing
// state file, an nft command error, a closed source or a decoded empty record
// cannot establish initial absence. This function mutates no native policy.
func ReadDesktopLinuxProtectionAbsence(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux protection absence requires a live native readback")
	}
	rows, err := desktopLinuxNFTRead(ctx)
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		return errors.New("Linux protection still has an existing native table")
	}
	return ctx.Err()
}
