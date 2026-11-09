//go:build !linux && !darwin && !windows

package main

import (
	"context"
	"errors"
)

func bindDesktopImportedMTUKernel(context.Context, string, uintptr, desktopNodeMTURecord) error {
	return errors.New("imported MTU probes require a supported native interface binding")
}
