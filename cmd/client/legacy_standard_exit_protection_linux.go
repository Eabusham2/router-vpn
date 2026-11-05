//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"router-vpn/internal/mobiletor"
)

// A standard engine owns a closed endpoint policy, not a Router Node guardian.
// The native object cannot be reconstructed from the persisted comparison row.
type legacyExitKernelProtection interface {
	Receipt(context.Context) (mobiletor.DesktopLinuxStandardProtectionReceipt, error)
	Current(context.Context, *os.File) error
	Release(context.Context, *os.File) error
	Supersede(context.Context, legacyExitKernelProtection, *os.File) error
	Close(context.Context) error
}
type legacyExitNativeProtection struct {
	*mobiletor.DesktopLinuxStandardProtection
}

func (p *legacyExitNativeProtection) Supersede(ctx context.Context, next legacyExitKernelProtection, lease *os.File) error {
	other, ok := next.(*legacyExitNativeProtection)
	if !ok || p == nil || other == nil {
		return errors.New("standard succession substituted its original native creator")
	}
	return p.DesktopLinuxStandardProtection.Supersede(ctx, other.DesktopLinuxStandardProtection, lease)
}

type legacyExitProtectionFactory func(context.Context, string, string, []netip.Addr, bool, *os.File) (legacyExitKernelProtection, error)

func createLegacyExitNativeProtection(ctx context.Context, session, digest string, endpoints []netip.Addr, lan bool, lease *os.File) (legacyExitKernelProtection, error) {
	created, err := mobiletor.NewDesktopLinuxStandardProtection(ctx, session, digest, endpoints, lan, lease)
	if created == nil {
		return nil, err
	}
	return &legacyExitNativeProtection{created}, err
}

var legacyStandardProtectionOwners sync.Map // map[*app]*legacyExitProtectionSlot

type legacyExitProtectionMarker struct {
	Schema  int                                             `json:"schema"`
	BootID  string                                          `json:"boot_id"`
	Receipt mobiletor.DesktopLinuxStandardProtectionReceipt `json:"creation"`
}
type legacyExitProtectionState struct {
	Policy          string                                `json:"policy"`
	ProfileID       string                                `json:"profile_id"`
	PolicyProfileID string                                `json:"policy_profile_id"`
	Endpoint        string                                `json:"endpoint"`
	EndpointIPs     []string                              `json:"endpoint_ips"`
	HomeLAN         bool                                  `json:"home_lan_access"`
	Platform        string                                `json:"platform"`
	Enforced        bool                                  `json:"enforced"`
	Transfer        *linuxStandardServiceTransferResponse `json:"standard_node_transfer,omitempty"`
	Owner           legacyExitProtectionMarker            `json:"linux_standard_owner"`
}
type legacyExitProtectionSlot struct {
	app                                                            *app
	root, policy, profileID, endpoint, boot                        string
	namespace                                                      os.FileInfo
	homeLAN                                                        bool
	kernel                                                         legacyExitKernelProtection
	receipt                                                        mobiletor.DesktopLinuxStandardProtectionReceipt
	expected, saved                                                *legacyExitStateToken
	prior                                                          *legacyExitProtectionSlot
	body                                                           []byte
	superseded, persisted, detached, removed, stateRemoved, closed bool
}

func (p *legacyExitProtectionSlot) scope(l *legacyExitMutationLease) error {
	if p == nil || l == nil || p.root != l.rootPath || p.namespace == nil {
		return errors.New("standard protection lost its original installation or namespace")
	}
	current, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(current, p.namespace) {
		return errors.New("standard protection left its captured namespace")
	}
	return l.Current()
}
func (p *legacyExitProtectionSlot) selected() error {
	actual, ok := legacyStandardProtectionOwners.Load(p.app)
	if !ok || actual != p {
		return errors.New("standard protection belongs to a replacement owner")
	}
	return nil
}
func (p *legacyExitProtectionSlot) finishPrior(ctx context.Context) error {
	if p.prior == nil || p.prior.closed {
		return nil
	}
	if !p.persisted || !p.superseded || !p.prior.removed {
		return errors.New("standard predecessor has no acknowledged completed handover")
	}
	if err := p.prior.kernel.Close(ctx); err != nil {
		return err
	}
	if err := p.prior.saved.Close(); err != nil {
		return err
	}
	p.prior.closed = true
	return nil
}

func (p *legacyExitProtectionSlot) current(ctx context.Context, l *legacyExitMutationLease) error {
	if err := p.finishPrior(ctx); err != nil {
		return err
	}
	if err := p.scope(l); err != nil {
		return err
	}
	if err := p.selected(); err != nil {
		return err
	}
	if !p.persisted || p.removed || p.closed || p.kernel == nil {
		return errors.New("standard protection has no live acknowledged original creation")
	}
	if err := p.saved.Current(l); err != nil {
		return err
	}
	if err := p.kernel.Current(ctx, l.lock); err != nil {
		return err
	}
	if err := p.saved.Current(l); err != nil {
		return err
	}
	return p.scope(l)
}

// A failed persistence/succession step keeps both actual objects in this slot.
// Retries use their original capabilities; reading JSON can never refill them.
func (p *legacyExitProtectionSlot) publish(ctx context.Context, l *legacyExitMutationLease, validate func() error) error {
	if err := p.scope(l); err != nil {
		return err
	}
	if err := validate(); err != nil {
		return err
	}
	if p.persisted {
		if p.prior != nil && !p.prior.closed {
			if err := p.prior.kernel.Close(ctx); err != nil {
				return err
			}
			if err := p.prior.saved.Close(); err != nil {
				return err
			}
			p.prior.closed = true
		}
		return p.current(ctx, l)
	}
	if p.kernel == nil {
		return errors.New("standard protection has no original native creation")
	}
	if p.prior != nil {
		if err := p.prior.selected(); err != nil {
			return err
		}
	} else if _, exists := legacyStandardProtectionOwners.Load(p.app); exists {
		return errors.New("new standard protection cannot replace another saved owner")
	}
	if p.saved == nil {
		if err := p.expected.Current(l); err != nil {
			return err
		}
		receipt, err := p.kernel.Receipt(ctx)
		if err != nil {
			return err
		}
		p.receipt = receipt
		if err := p.kernel.Current(ctx, l.lock); err != nil {
			return err
		}
		if p.prior != nil && !p.superseded {
			if err := validate(); err != nil {
				return err
			}
			if err := p.expected.Current(l); err != nil {
				return err
			}
			if err := p.prior.kernel.Supersede(ctx, p.kernel, l.lock); err != nil {
				return err
			}
			p.superseded = true
		}
		if err := validate(); err != nil {
			return err
		}
		state := legacyExitProtectionState{Policy: p.policy, ProfileID: p.profileID, PolicyProfileID: p.profileID, Endpoint: p.endpoint, EndpointIPs: []string{p.endpoint}, HomeLAN: p.homeLAN, Platform: "linux", Enforced: true, Owner: legacyExitProtectionMarker{Schema: 1, BootID: p.boot, Receipt: receipt}}
		p.body, err = json.Marshal(state)
		if err != nil {
			return err
		}
		p.saved, err = legacyExitWriteState(ctx, l, p.expected, p.body)
		if err != nil {
			return err
		}
	} else {
		if err := p.saved.Current(l); err != nil {
			return err
		}
		if err := l.run.Sync(); err != nil {
			return err
		}
	}
	if err := validate(); err != nil {
		return err
	}
	if p.prior == nil {
		if _, loaded := legacyStandardProtectionOwners.LoadOrStore(p.app, p); loaded {
			return errors.New("standard protection publication lost its original vacant owner")
		}
	} else if !legacyStandardProtectionOwners.CompareAndSwap(p.app, p.prior, p) {
		return errors.New("standard protection publication cannot overwrite its replacement")
	}
	p.persisted = true
	if p.prior != nil {
		p.prior.removed = true
		if err := p.prior.kernel.Close(ctx); err != nil {
			return err
		}
		if err := p.prior.saved.Close(); err != nil {
			return err
		}
		p.prior.closed = true
	}
	return p.current(ctx, l)
}
func (p *legacyExitProtectionSlot) release(ctx context.Context, l *legacyExitMutationLease) error {
	if err := p.finishPrior(ctx); err != nil {
		return err
	}
	if p.closed {
		return nil
	}
	if err := p.scope(l); err != nil {
		return err
	}
	if err := p.selected(); err != nil {
		return err
	}
	if !p.persisted || p.kernel == nil {
		return errors.New("standard protection cannot release an incomplete original creation")
	}
	if !p.stateRemoved {
		if err := p.saved.Current(l); err != nil {
			return err
		}
	}
	if !p.removed {
		if err := p.kernel.Release(ctx, l.lock); err != nil {
			return err
		}
		p.removed = true
	}
	if !p.stateRemoved {
		removed, err := legacyExitRemoveState(ctx, l, p.saved)
		p.stateRemoved = removed
		if err != nil {
			return err
		}
	} else {
		if err := legacyExitStateAbsent(l); err != nil {
			return err
		}
		if err := l.run.Sync(); err != nil {
			return err
		}
	}
	if err := p.kernel.Close(ctx); err != nil {
		return err
	}
	if err := p.saved.Close(); err != nil {
		return err
	}
	if !legacyStandardProtectionOwners.CompareAndDelete(p.app, p) {
		return errors.New("retired standard protection cannot remove replacement ownership")
	}
	p.closed = true
	return nil
}
func (o *linuxLegacyStandardExitOwner) applyProtection(ctx context.Context) error {
	if o.protectionPolicy == "off" {
		if raw, exists := legacyStandardProtectionOwners.Load(o.app); exists {
			prior, ok := raw.(*legacyExitProtectionSlot)
			if !ok || prior == nil || !prior.detached {
				return errors.New("Off requires the retained retired protection creator")
			}
			o.offInherited = prior
			runtime.LockOSThread()
			l, err := acquireLegacyExitMutationLease(ctx, o.protectionRoot)
			if err == nil {
				err = prior.release(ctx, l)
				l.Close()
			}
			runtime.UnlockOSThread()
			if err != nil {
				return err
			}
		}
		if o.offProtectionCheck == nil {
			return errors.New("legacy Off lost its original absence check")
		}
		return o.offProtectionCheck(ctx)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	l, err := acquireLegacyExitMutationLease(ctx, o.protectionRoot)
	if err != nil {
		return err
	}
	defer l.Close()
	if err = o.current(o.command); err != nil {
		return err
	}
	if o.protection == nil {
		expected, err := legacyExitCaptureState(l)
		if err != nil {
			return err
		}
		var prior *legacyExitProtectionSlot
		if raw, exists := legacyStandardProtectionOwners.Load(o.app); exists {
			var ok bool
			prior, ok = raw.(*legacyExitProtectionSlot)
			if !ok || prior == nil || !prior.detached {
				_ = expected.Close()
				return errors.New("standard successor requires its original joined predecessor")
			}
			_ = expected.Close()
			expected = prior.saved
			if err = prior.current(ctx, l); err != nil {
				return err
			}
		} else {
			if !expected.absent {
				_ = expected.Close()
				return errors.New("existing cold protection has no retained creator; refusing state-based adoption")
			}
			if o.protectionAbsence == nil {
				return errors.New("standard creation lost native absence query")
			}
			if err = o.protectionAbsence(ctx); err != nil {
				return err
			}
		}
		boot, err := readDesktopLinuxNodeBootID()
		if err != nil {
			return err
		}
		endpoint, err := netip.ParseAddr(strings.Trim(o.protectionEndpoint, "[]"))
		if err != nil || endpoint.Zone() != "" || endpoint.Is4In6() || endpoint.IsUnspecified() || endpoint.IsMulticast() {
			return errors.New("protected standard exit requires a captured unicast literal endpoint without pre-tunnel DNS")
		}
		p := &legacyExitProtectionSlot{app: o.app, root: o.protectionRoot, namespace: o.namespaceInfo, policy: o.protectionPolicy, profileID: o.protectionProfileID, endpoint: endpoint.String(), homeLAN: o.protectionLAN, boot: boot, expected: expected, prior: prior}
		o.protection = p
		if o.protectionFactory == nil {
			return errors.New("standard protection lost its original native factory")
		}
		p.kernel, err = o.protectionFactory(ctx, o.session, o.digest, []netip.Addr{endpoint}, o.protectionLAN, l.lock)
		if p.kernel == nil {
			// The native factory returns no object only before any creation
			// attempt. Preserve any predecessor and discard this unstarted slot.
			o.protection = nil
			if p.prior == nil {
				_ = p.expected.Close()
			}
			return errors.Join(err, errors.New("standard protection was not created"))
		}
		if err != nil {
			return err
		}
	}
	return o.protection.publish(ctx, l, func() error { return o.current(o.command) })
}
func (o *linuxLegacyStandardExitOwner) currentProtection(ctx context.Context) error {
	if o.protectionPolicy == "off" {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	l, err := acquireLegacyExitMutationLease(ctx, o.protectionRoot)
	if err != nil {
		return err
	}
	defer l.Close()
	if o.protection == nil {
		return errors.New("standard engine lost its original protection creator")
	}
	return o.protection.current(ctx, l)
}
func (o *linuxLegacyStandardExitOwner) retireProtection(ctx context.Context, release bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	if o.protection == nil && o.offInherited == nil {
		return nil
	}
	l, err := acquireLegacyExitMutationLease(ctx, o.protectionRoot)
	if err != nil {
		return err
	}
	defer l.Close()
	if o.protectionPolicy == "off" {
		return o.offInherited.release(ctx, l)
	}
	p := o.protection
	if !p.persisted {
		if err = p.publish(ctx, l, func() error { return o.current(o.command) }); err != nil {
			return err
		}
	}
	if release && p.policy == "on-connect" {
		return p.release(ctx, l)
	}
	if err = p.current(ctx, l); err != nil {
		return err
	}
	p.detached = true
	return nil
}

type legacyExitDetachedProtectionStop struct {
	slot      *legacyExitProtectionSlot
	operation context.Context
}

func captureLegacyExitDetachedProtectionStop(a *app) (desktopRetainedStopCapture, error) {
	raw, ok := legacyStandardProtectionOwners.Load(a)
	if !ok {
		return nil, nil
	}
	p, ok := raw.(*legacyExitProtectionSlot)
	if !ok || p == nil || !p.detached {
		return nil, errors.New("standard protection has no original joined source")
	}
	a.mu.Lock()
	s := &legacyExitDetachedProtectionStop{slot: p, operation: a.connectionContext}
	idle := a.cmd == nil
	a.mu.Unlock()
	if !idle {
		return nil, errors.New("detached standard protection cannot retire a replacement command")
	}
	return s, nil
}
func (s *legacyExitDetachedProtectionStop) Retire(ctx context.Context, command *exec.Cmd, release bool) error {
	p := s.slot
	p.app.mu.Lock()
	same := command == nil && p.app.cmd == nil && p.app.connectionContext == s.operation
	p.app.mu.Unlock()
	if !same {
		return errors.New("detached standard Stop lost its captured operation")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l, err := acquireLegacyExitMutationLease(ctx, p.root)
	if err != nil {
		return err
	}
	defer l.Close()
	if release && p.policy == "on-connect" {
		return p.release(ctx, l)
	}
	return p.current(ctx, l)
}
