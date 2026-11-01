//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"
)

// ReadDesktopLinuxNodeStopAbsence is only a read-only legacy Stop dispatch
// boundary. A previously released original Node session must independently
// find no Node-family table before deferring to another connection's Stop.
// Its fixed Tor/global guard remains owned by that legacy path. This result
// must never authorize admission, global absence, table creation or removal.
func ReadDesktopLinuxNodeStopAbsence(ctx context.Context) (failure error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return errors.New("Linux Node Stop absence requires its live privileged native query")
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
	if err := desktopLinuxTableListAbsent(rows, func(name string) bool { return strings.HasPrefix(name, desktopLinuxNodeTablePrefix) }); err != nil {
		return err
	}
	after, err := endpoint.generation(ctx)
	if err != nil || before != after {
		return errors.Join(err, errors.New("Linux Node Stop absence changed during its original native snapshot"))
	}
	retained, retainedErr := namespace.Stat()
	current, currentErr := os.Stat("/proc/thread-self/ns/net")
	if retainedErr != nil || currentErr != nil || !os.SameFile(identity, retained) || !os.SameFile(identity, current) || ctx.Err() != nil {
		return errors.Join(retainedErr, currentErr, ctx.Err(), errors.New("Linux Node Stop absence left its captured native namespace"))
	}
	return nil
}
