//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"
)

// ReadDesktopLinuxNodeAbsence observes one strictly derived candidate name in
// a generation-bracketed native namespace. Other retained sessions can remain
// installed. It grants no creation, removal, adoption or process authority;
// an unknown original create/delete cannot be repaired with this readback.
func ReadDesktopLinuxNodeAbsence(ctx context.Context, sessionID string) (failure error) {
	if ctx == nil || ctx.Err() != nil || !desktopSocketHex(sessionID, 32) || os.Geteuid() != 0 {
		return errors.New("Linux Node absence requires its live captured native query")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	namespace, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, namespace.Close()) }()
	identity, err := namespace.Stat()
	if err != nil {
		return err
	}
	endpoint, err := desktopLinuxOpenBaselineNetlink()
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, endpoint.close()) }()
	before, err := endpoint.generation(ctx)
	if err != nil {
		return err
	}
	raw, err := desktopLinuxNFTCommand(ctx, []string{"-j", "-n", "list", "tables"}, "")
	if err != nil {
		return err
	}
	rows, err := desktopLinuxNFTRows(raw)
	if err != nil {
		return err
	}
	name := desktopLinuxNodeTablePrefix + sessionID
	if err := desktopLinuxTableListAbsent(rows, func(candidate string) bool { return candidate == name }); err != nil {
		return err
	}
	after, err := endpoint.generation(ctx)
	if err != nil || before != after {
		return errors.Join(err, errors.New("Linux Node absence changed during its original native snapshot"))
	}
	retained, retainedErr := namespace.Stat()
	current, currentErr := os.Stat("/proc/thread-self/ns/net")
	if retainedErr != nil || currentErr != nil || !os.SameFile(identity, retained) || !os.SameFile(identity, current) || ctx.Err() != nil {
		return errors.Join(retainedErr, currentErr, ctx.Err(), errors.New("Linux Node absence left its captured native namespace"))
	}
	return nil
}
