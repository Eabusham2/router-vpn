package main

import (
	"context"
	"errors"
	"runtime"
	"sync"

	"router-vpn/internal/desktopnetwork"
)

type desktopExternalComparisonNetwork interface {
	IdentityContext(context.Context) (string, error)
	CurrentContext(context.Context) error
	BeforeTransition(context.Context, speedLabPathIdentity) error
	AfterTransition(context.Context, speedLabPathIdentity) error
	RecordTransient(context.Context, *desktopNodeLaunch) error
	Close() error
}

type desktopExternalCohortNetwork struct {
	mu         sync.Mutex
	app        *app
	owner      *speedLabTemporaryOwner
	tracker    *desktopnetwork.Tracker
	current    speedLabPathIdentity
	old        speedLabPathIdentity
	transition bool
	transient  map[*desktopNodeLaunch]string
}

func openDesktopExternalComparisonNetwork(ctx context.Context, a *app, initial speedLabPathIdentity) (desktopExternalComparisonNetwork, error) {
	if a == nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("external comparison network requires its captured application and caller")
	}
	raw, ok := speedLabTemporaryOwners.Load(a)
	owner, typed := raw.(*speedLabTemporaryOwner)
	if !ok || !typed || owner == nil {
		return nil, errors.New("external comparison network requires the original Speed Lab transaction")
	}
	o := &desktopExternalCohortNetwork{app: a, owner: owner, current: initial, transient: make(map[*desktopNodeLaunch]string)}
	if err := o.ownerCurrent(ctx); err != nil {
		return nil, err
	}
	receipt, err := o.capture(ctx, initial)
	if err != nil {
		return nil, err
	} // Refuse unknown originals before any Stop.
	tracker, err := desktopnetwork.Open(ctx, receipt)
	o.tracker = tracker
	if err != nil {
		if tracker != nil {
			return o, err
		}
		return nil, err
	}
	if err = o.ownerCurrent(ctx); err == nil {
		var again *desktopnetwork.DesktopNetworkReceipt
		again, err = o.capture(ctx, initial)
		if err == nil && networkReceiptIdentity(again) != networkReceiptIdentity(receipt) {
			err = errors.New("original native routing receipt changed while installing the observer")
		}
	}
	if err != nil {
		if closeErr := o.Close(); closeErr != nil {
			return o, errors.Join(err, closeErr)
		}
		return nil, err
	}
	return o, nil
}

func networkReceiptIdentity(receipt *desktopnetwork.DesktopNetworkReceipt) string {
	if receipt == nil {
		return ""
	}
	raw, _ := desktopnetwork.CanonicalDesktopNetworkReceipt(*receipt)
	return raw
}

func parseDesktopCohortReceipt(raw, name string, index, mtu int) (*desktopnetwork.DesktopNetworkReceipt, error) {
	receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(raw)
	if err != nil || receipt.TargetOS != runtime.GOOS || name != "" && receipt.Name != name || index != 0 && receipt.Index != uint32(index) || mtu != 0 && receipt.MTU != mtu {
		return nil, errors.New("comparison requires the exact current native TUN and routing receipt")
	}
	return &receipt, nil
}

func (o *desktopExternalCohortNetwork) ownerCurrent(ctx context.Context) error {
	if o == nil || o.app == nil || o.owner == nil {
		return errors.New("comparison network lost its original transaction")
	}
	a := o.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if !a.speedLabOwnerCurrentLocked(o.owner) || a.cmd != o.owner.runtime {
		return errors.New("comparison network belongs to a replacement application session")
	}
	return nil
}

func (o *desktopExternalCohortNetwork) capture(ctx context.Context, identity speedLabPathIdentity) (*desktopnetwork.DesktopNetworkReceipt, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("native routing capture lost its caller")
	}
	if err := o.ownerCurrent(ctx); err != nil {
		return nil, err
	}
	a := o.app
	if identity == (speedLabPathIdentity{}) {
		if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
			return nil, err
		}
		off := a.cmd == nil && !a.state.Connected && o.owner.runtime == nil && a.speedLabOwnerCurrentLocked(o.owner)
		a.mu.Unlock()
		_, native := desktopNodeOwners.Load(a)
		if !off || native {
			return nil, errors.New("comparison off boundary contains an unknown or retained native runtime")
		}
		if err := desktopCohortLinuxOff(ctx, a); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
		return nil, err
	}
	var receipt *desktopnetwork.DesktopNetworkReceipt
	var err error
	switch {
	case identity.External != nil:
		proof, e := a.readDesktopExternalProofContext(ctx, identity.External)
		err = e
		if err == nil {
			receipt, err = parseDesktopCohortReceipt(proof.NetworkReceipt, "", 0, 0)
		}
	case identity.Tor != nil:
		proof, e := a.readDesktopTorProofContext(ctx, identity.Tor)
		err = e
		if err == nil {
			receipt, err = parseDesktopCohortReceipt(proof.NetworkReceipt, proof.InterfaceName, proof.InterfaceIndex, proof.EffectiveMTU)
		}
	case identity.Node != nil:
		_, err = a.readDesktopOwnedNodeReadyContext(ctx, identity.Node, false)
		if err == nil {
			var live desktopNodeMTURecord
			live, err = readDesktopNodeMTUContext(ctx, identity.Node)
			if err == nil {
				receipt, err = parseDesktopCohortReceipt(live.NetworkReceipt, live.Interface, live.Index, live.MTU)
			}
		}
	case identity.Linux != nil:
		receipt, err = desktopCohortLinuxReceipt(ctx, a, identity.Linux)
	default:
		err = errors.New("comparison original path has no captured native routing receipt")
	}
	if err != nil {
		return nil, err
	}
	if err = validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
		return nil, err
	}
	if err = o.ownerCurrent(ctx); err != nil {
		return nil, err
	}
	return receipt, nil
}

func (o *desktopExternalCohortNetwork) IdentityContext(ctx context.Context) (string, error) {
	if o == nil || o.tracker == nil {
		return "", errors.New("comparison network observer identity is missing")
	}
	return o.tracker.IdentityContext(ctx)
}

// No app.mu or native-owner recapture here: the final selection guard calls
// CurrentContext while holding its exact source/decision transaction locks.
func (o *desktopExternalCohortNetwork) CurrentContext(ctx context.Context) error {
	if o == nil || o.tracker == nil {
		return errors.New("comparison network observer is missing")
	}
	return o.tracker.CurrentContext(ctx)
}

func (o *desktopExternalCohortNetwork) BeforeTransition(ctx context.Context, identity speedLabPathIdentity) error {
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if o.transition || identity != o.current {
		return errors.New("network transition replaced its last exact path checkpoint")
	}
	receipt, err := o.capture(ctx, identity)
	if err != nil {
		return err
	}
	if err = o.tracker.Begin(ctx, receipt); err != nil {
		return err
	}
	o.old, o.transition, o.transient = identity, true, make(map[*desktopNodeLaunch]string)
	return nil
}

func (o *desktopExternalCohortNetwork) RecordTransient(ctx context.Context, launch *desktopNodeLaunch) error {
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if !o.transition || ctx == nil || ctx.Err() != nil || launch == nil || launch.tor == nil || launch.external != nil || launch.ownedNode != nil {
		return errors.New("transient routing receipt has no exact Tor comparison transition")
	}
	if err := o.ownerCurrent(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &o.app.mu); err != nil {
		return err
	}
	current := o.app.cmd == launch.command && o.owner.runtime == launch.command
	o.app.mu.Unlock()
	if !current {
		return errors.New("transient routing receipt belongs to another native process")
	}
	proof, err := o.app.readDesktopTorProofContext(ctx, launch)
	if err != nil {
		return err
	}
	receipt, err := parseDesktopCohortReceipt(proof.NetworkReceipt, proof.InterfaceName, proof.InterfaceIndex, proof.EffectiveMTU)
	if err != nil {
		return err
	}
	key := networkReceiptIdentity(receipt)
	if previous := o.transient[launch]; previous != "" && previous != key {
		return errors.New("transient native routing receipt changed after its first proof")
	}
	if err = o.ownerCurrent(ctx); err != nil {
		return err
	}
	if err = o.tracker.RecordContext(ctx, *receipt); err != nil {
		return err
	}
	o.transient[launch] = key
	return nil
}

func desktopCohortLaunchJoined(ctx context.Context, launch *desktopNodeLaunch) error {
	if launch == nil {
		return nil
	}
	acknowledged := false
	switch {
	case launch.tor != nil:
		if err := desktopnetwork.LockContext(ctx, &launch.tor.mu); err != nil {
			return err
		}
		acknowledged = launch.tor.stopAcknowledged
		launch.tor.mu.Unlock()
	case launch.external != nil:
		if err := desktopnetwork.LockContext(ctx, &launch.external.mu); err != nil {
			return err
		}
		acknowledged = launch.external.stopAcknowledged
		launch.external.mu.Unlock()
	case launch.ownedNode != nil:
		if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
			return err
		}
		acknowledged = launch.ownedNode.retired
		launch.workspaceMu.Unlock()
	default:
		return errors.New("retired routing receipt has no original native runtime")
	}
	if !acknowledged {
		return errors.New("routing transition has no acknowledged original native drain and join")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Ordinary external runtimes own their own Wait channel. Opening the
	// Router/Tor waiter here could reap the same process a second time.
	var done <-chan struct{}
	if launch.external != nil {
		if launch.external.retained != nil {
			observer, ok := launch.external.retained.(interface {
				ProcessDoneContext(context.Context) (<-chan struct{}, error)
			})
			if !ok {
				return errors.New("retired external process has no contextual join observation")
			}
			var err error
			done, err = observer.ProcessDoneContext(ctx)
			if err != nil {
				return err
			}
		} else {
			done = desktopExternalProcessDone(launch)
		}
	} else {
		done = desktopNodeProcessDone(launch)
	}
	select {
	case <-done:
		return ctx.Err()
	default:
		return errors.New("routing transition has no acknowledged original native drain and join")
	}
}

func (o *desktopExternalCohortNetwork) AfterTransition(ctx context.Context, identity speedLabPathIdentity) error {
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if !o.transition {
		return errors.New("network completion has no original transition window")
	}
	receipt, err := o.capture(ctx, identity)
	if err != nil {
		return err
	}
	current := identity.External
	if current == nil {
		current = identity.Tor
	}
	if current == nil {
		current = identity.Node
	}
	for launch := range o.transient {
		if launch != current {
			if err := desktopCohortLaunchJoined(ctx, launch); err != nil {
				return err
			}
		}
	}
	for _, launch := range []*desktopNodeLaunch{o.old.External, o.old.Tor, o.old.Node} {
		if launch != nil && launch != current {
			if err := desktopCohortLaunchJoined(ctx, launch); err != nil {
				return err
			}
		}
	}
	if o.old.Linux != nil && o.old.Linux != identity.Linux {
		if err := desktopCohortLinuxJoined(ctx, o.old.Linux); err != nil {
			return err
		}
	}
	if err = o.tracker.End(ctx, receipt); err != nil {
		return err
	}
	o.current, o.old, o.transition = identity, speedLabPathIdentity{}, false
	o.transient = make(map[*desktopNodeLaunch]string)
	return nil
}

func (o *desktopExternalCohortNetwork) Close() error {
	if o == nil || o.tracker == nil {
		return nil
	}
	return o.tracker.Close()
}
