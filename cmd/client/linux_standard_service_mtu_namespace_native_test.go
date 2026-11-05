//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
)

// Invoked only by the installed namespace scenario with the actual generated
// native bundle, private authenticated SOCKS/DNS peer and retained root service.
// It proves native MTU mutation/readback/restore/Stop, not public HTTPS speed.
func linuxStandardServiceNativeMTUFixture(a *app, launch *linuxStandardServiceLaunch) error {
	ctx, cancel, err := mobilemtu.WithOperationContext(context.Background(), 35*time.Second, 10*time.Second)
	if err != nil {
		return err
	}
	defer cancel()
	owner, err := newLinuxStandardServiceMTUOwner(ctx, launch)
	if err != nil {
		return err
	}
	if err := owner.PrepareRetestContext(ctx); err != nil {
		return err
	}
	original, err := owner.CaptureContext(ctx)
	if err != nil {
		return err
	}
	epoch := launch.prepared.requestEpoch
	observer, monitor := epoch.observer, owner.activation
	current := original
	first, second := 1280, 1360
	if original.MTU == first {
		first = 1320
	}
	if original.MTU == second {
		second = 1340
	}
	for _, mtu := range []int{first, second, original.MTU} {
		before, err := desktopnetwork.ParseDesktopNetworkReceipt(epoch.mtuReceipt)
		if err != nil {
			return err
		}
		changed, err := owner.ChangeMTU(ctx, current, mtu)
		if err != nil {
			return fmt.Errorf("installed original MTU transaction: %w", err)
		}
		actual, err := owner.CaptureContext(ctx)
		if err != nil || actual != changed || actual.MTU != mtu || actual.Session != original.Session || actual.Path != original.Path {
			return errors.Join(err, errors.New("installed MTU did not match its actual retained TUN readback"))
		}
		after, err := desktopnetwork.ParseDesktopNetworkReceipt(epoch.mtuReceipt)
		if err != nil || before.Incarnation == after.Incarnation || epoch.observer != observer || owner.activation != monitor || epoch.mtuTransition != nil || owner.pending != nil {
			return errors.New("installed MTU replaced its original observer or omitted joined reader succession")
		}
		if err := mobilemtu.LockContext(ctx, &launch.mu); err != nil {
			return err
		}
		binding := epoch.mtuBinding
		resolved, resolveErr := owner.rpcLocked(ctx, "mtu-resolve", &linuxStandardServiceMTURequest{Expected: &binding})
		launch.mu.Unlock()
		if resolveErr != nil || resolved == nil || resolved.Current != binding || len(resolved.Addresses) != 1 || resolved.Addresses[0] != "203.0.113.20" {
			return errors.Join(resolveErr, errors.New("installed MTU lost its real selected-DNS exchange after mutation"))
		}
		current = actual
	}
	// A cancelled next request cannot construct another reader after restore.
	restored := epoch.mtuReceipt
	stopped, stop := context.WithCancel(ctx)
	stop()
	if _, err := owner.ChangeMTU(stopped, current, first); !errors.Is(err, context.Canceled) {
		return errors.New("cancelled installed MTU admission did not preserve its original deadline")
	}
	if epoch.mtuReceipt != restored || epoch.observer != observer || current.MTU != original.MTU || owner.pending != nil {
		return errors.New("cancelled installed MTU admission changed the restored original owner")
	}
	if actual, err := owner.CaptureContext(ctx); err != nil || actual != current {
		return errors.Join(err, errors.New("installed MTU original restore was not retained"))
	}
	// The caller now exercises the existing actual Stop and native protection
	// absence checks over every retained reader retirement, including this history.
	return ctx.Err()
}
