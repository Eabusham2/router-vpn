//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"router-vpn/internal/mobiletor"
)

// This standalone entry never opens client configuration or starts a tunnel.
// It addresses only the native managed BFE identity; no pathname, PID, profile,
// interface or firewall object can be supplied by a caller.
func windowsPhysicalProtectionUtility(args []string) (bool, error) {
	prepared, handled, err := parseWindowsPreparedProtectionUtility(args)
	if handled {
		if err != nil {
			return true, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		capture := mobiletor.DesktopSocketCapture{SessionID: prepared.SessionID, SourceSHA256: prepared.SourceSHA256, NetworkID: prepared.NetworkID}
		if err := mobiletor.ReadDesktopWindowsPreparedProtection(ctx, capture, prepared.Policy, prepared.BaselineSHA256); err != nil {
			return true, err
		}
		prepared.Prepared = true
		return true, json.NewEncoder(os.Stdout).Encode(prepared)
	}
	operation, handled, err := parseWindowsProtectionUtility(args)
	if !handled || err != nil {
		return handled, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if operation == "probe" {
		absent, err := mobiletor.ProbeDesktopWindowsProtectionAbsent(ctx)
		if err != nil {
			return true, err
		}
		// This distinct output cannot be confused with authoritative status.
		return true, json.NewEncoder(os.Stdout).Encode(struct {
			Schema int  `json:"schema"`
			Absent bool `json:"absent"`
		}{1, absent})
	}
	if operation != "status" {
		var owner *mobiletor.DesktopWindowsProtectionRecovery
		if operation == "force-off" {
			owner, err = mobiletor.NewDesktopWindowsProtectionRecovery(ctx)
		} else {
			owner, err = mobiletor.NewDesktopWindowsProtectionRelease(ctx)
		}
		if owner != nil {
			// A timed-out preparation may retain entered native work. Cleanup
			// receives its own bounded join; an error is never success output.
			cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
			err = errors.Join(err, owner.Close(cleanup))
			stop()
		}
		if err != nil {
			return true, err
		}
	}
	state, err := mobiletor.ReadDesktopWindowsProtection(ctx)
	if err != nil {
		return true, err
	}
	return true, json.NewEncoder(os.Stdout).Encode(state)
}
