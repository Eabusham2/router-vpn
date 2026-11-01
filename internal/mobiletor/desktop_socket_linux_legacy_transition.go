//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"
)

// ReadDesktopLinuxLegacyTransitionAbsence is a read-only preflight for a
// transition that cannot yet succeed an existing fixed legacy guard. It
// prevents stopping that legacy connection before the unsupported transition
// is discovered. Retained Node-family guards are outside this query; their
// original session must independently prove any later succession. This result
// grants no creation, adoption, removal, global absence or admission authority.
func ReadDesktopLinuxLegacyTransitionAbsence(ctx context.Context) (failure error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return errors.New("Linux legacy transition requires its live privileged native query")
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
	if err := desktopLinuxTableListAbsent(rows, func(name string) bool { return name == desktopLinuxNFTTable }); err != nil {
		return err
	}
	after, err := endpoint.generation(ctx)
	if err != nil || before != after {
		return errors.Join(err, errors.New("Linux legacy transition changed during its original native snapshot"))
	}
	retained, retainedErr := namespace.Stat()
	current, currentErr := os.Stat("/proc/thread-self/ns/net")
	if retainedErr != nil || currentErr != nil || !os.SameFile(identity, retained) || !os.SameFile(identity, current) || ctx.Err() != nil {
		return errors.Join(retainedErr, currentErr, ctx.Err(), errors.New("Linux legacy transition left its captured native namespace"))
	}
	return nil
}
