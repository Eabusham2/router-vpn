//go:build darwin

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"router-vpn/internal/mobiletor"
)

// This is a fixed private operation leaf within the existing protected
// installation. The outer Python state lock covers plan/journal/apply; this
// lock also serializes independently invoked native kernel transactions.
const macOSOwnedPFOperationLock = macOSOwnedControllerRoot + "/pf-operation.lock"

func macOSOwnedPFUtility(args []string) (bool, error) {
	handled, apply, err := darwinPFUtilityPhase(args)
	if !handled || err != nil {
		return handled, err
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, errors.New("the installed Darwin PF utility requires its existing root helper")
	}
	if err := ownedDesktopAncestors(filepath.Dir(macOSOwnedControllerRoot)); err != nil {
		return true, err
	}
	install, err := ownedDesktopLock(macOSOwnedInstallLock, false)
	if err != nil {
		return true, errors.New("Router VPN installation or upgrade is in progress")
	}
	defer install.Close()
	if _, err := macOSOwnedInstallIdentity(); err != nil {
		return true, err
	}
	operation, err := ownedDesktopLock(macOSOwnedPFOperationLock, true)
	if err != nil {
		return true, errors.New("another exact Darwin PF transaction is still owned")
	}
	defer operation.Close()
	input, err := macOSOwnedInput(os.Stdin)
	if err != nil {
		return true, err
	}
	defer input.Close()
	if err := input.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return true, err
	}
	raw, err := io.ReadAll(io.LimitReader(input, mobiletor.DesktopDarwinPFBaselineLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > mobiletor.DesktopDarwinPFBaselineLimit {
		return true, errors.Join(err, errors.New("Darwin PF utility did not receive one bounded private request"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var result []byte
	if args[1] == "reference" {
		result, err = mobiletor.RunDesktopDarwinPFReference(ctx, raw)
	} else {
		result, err = mobiletor.RunDesktopDarwinPFBaseline(ctx, raw, apply)
	}
	if err != nil {
		return true, err
	}
	if len(result) == 0 || len(result) > mobiletor.DesktopDarwinPFBaselineLimit {
		return true, errors.New("Darwin PF utility produced an invalid proof size")
	}
	_, err = os.Stdout.Write(result)
	return true, err
}
