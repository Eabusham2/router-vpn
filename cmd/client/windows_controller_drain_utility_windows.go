//go:build windows

package main

import (
	"context"
	"os"
	"time"

	"router-vpn/internal/windowscontroller"
)

func windowsControllerDrainUtility(args []string) (bool, error) {
	pid, pin, handled, err := parseWindowsControllerDrainUtility(args)
	if !handled || err != nil {
		return handled, err
	}
	// Open once and retain the actual kernel process for every TLS/receipt
	// readback. A reused PID cannot substitute the old session's TLS leaf.
	owner, err := windowscontroller.OpenProcess(pid)
	if err != nil {
		return true, err
	}
	defer owner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	return true, writeCapturedControllerDrain(ctx, owner, pin, os.Stdout)
}
