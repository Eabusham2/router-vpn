//go:build linux

package main

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"time"
)

// This executes inside the retained service against its actual original
// process and measured listener receipt. No listener or pidfd is serialized to
// a restarted GUI controller, and reconnect never refreshes network identity.
func linuxStandardServiceDNSReceiptCurrent(ctx context.Context, owner *linuxLegacyStandardExitOwner) error {
	if owner == nil || owner.dns == nil {
		return errors.New("standard service lost original selected DNS")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	owner.dns.mu.Lock()
	proof := owner.dns.proof
	owner.dns.mu.Unlock()
	if proof == nil || proof.owner != owner || proof.session != owner.session || proof.config != owner.digest {
		return errors.New("standard service has no matching original DNS proof receipt")
	}
	if err := owner.legacyDNSCurrent(ctx); err != nil {
		return err
	}
	member, err := legacyDNSDuplicateChildFD(owner.originalPIDFD, proof.fd)
	if err != nil {
		return err
	}
	identity, readErr := legacyDNSListenerSnapshot(member, netip.MustParseAddrPort("127.0.0.1:1099"))
	closeErr := member.Close()
	if readErr != nil || closeErr != nil || identity != proof.listener {
		return errors.Join(readErr, closeErr, errors.New("standard service selected DNS listener changed its original runtime"))
	}
	return owner.legacyDNSCurrent(ctx)
}

func (o *linuxStandardServiceLaunch) ProveSelectedDNS(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.joined || ctx == nil || ctx.Err() != nil {
		return errors.New("standard service DNS launch was cancelled or retired")
	}
	if err := o.currentIntent(ctx, o.Command()); err != nil {
		return err
	}
	if err := o.prepared.legacyDNSNetworkCurrent(); err != nil {
		return err
	}
	if err := o.call(ctx, linuxStandardServiceRequest{Schema: 1, Action: "prove-dns", Session: o.request.Session}, nil); err != nil {
		return err
	}
	if err := o.currentIntent(ctx, o.Command()); err != nil {
		return err
	}
	if err := o.prepared.legacyDNSNetworkCurrent(); err != nil {
		return err
	}
	o.dnsProved = true
	return nil
}

func proveLinuxServiceStandardDNS(ctx context.Context, a *app, observed observedConnection, runtimeID string, selected dnsSelection) (dnsProofState, bool) {
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	raw, exists := linuxStandardServiceOwners.Load(a)
	if !exists {
		return result, false
	}
	fail := func(err error) (dnsProofState, bool) { result.Reason = err.Error(); return result, true }
	owner, ok := raw.(*linuxStandardServiceLaunch)
	if !ok || owner == nil || ctx == nil || ctx.Err() != nil {
		return fail(errors.New("standard service DNS observation lost original owner"))
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.joined || !owner.dnsProved || owner.prepared.dns == nil || owner.prepared.dns.selection != selected {
		return fail(errors.New("standard service DNS has no original pre-activation receipt"))
	}
	current := func() error {
		actual, present := linuxStandardServiceOwners.Load(a)
		a.mu.Lock()
		defer a.mu.Unlock()
		st := a.state
		if !present || actual != owner || a.cmd != owner.Command() || !observed.Connected || observed.Phase != "connected" || !st.Connected || st.Phase != "connected" ||
			st.Mode != observed.Mode || st.LogicalMode != observed.LogicalMode || st.RuntimeMode != runtimeID || observed.RuntimeMode != runtimeID || st.RouterID != observed.RouterID || st.Base != observed.Base ||
			observed.RouterID != owner.prepared.routerID || runtimeID != owner.prepared.runtimeMode || observed.Base != owner.prepared.base || asyncMeasurementProfileToken(observed.Profile) != owner.prepared.dns.profileToken {
			return errors.New("standard service DNS observation belongs to a replaced connection")
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return fail(err)
	}
	if err := owner.prepared.legacyDNSNetworkCurrent(); err != nil {
		return fail(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := owner.call(bounded, linuxStandardServiceRequest{Schema: 1, Action: "dns-current", Session: owner.request.Session}, nil); err != nil {
		return fail(err)
	}
	if err := current(); err != nil {
		return fail(err)
	}
	if err := owner.prepared.legacyDNSNetworkCurrent(); err != nil {
		return fail(err)
	}
	result.Status = "passed"
	result.Reason = "the retained service proved selected DNS through its original engine and retained the same process, listener, configuration and network"
	return result, true
}
