//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"router-vpn/internal/common"
)

type legacyStandardDNS struct {
	selection               dnsSelection
	profileID, profileToken string
	network                 func() string
	networkID               string
	digest                  [32]byte
	size                    int
	source, sealed          *os.File
	mu                      sync.Mutex
	proof                   *legacyStandardDNSReceipt
}

type legacyStandardDNSReceipt struct {
	owner           *linuxLegacyStandardExitOwner
	session, config string
	fd              int
	listener        legacyDNSListenerIdentity
}

func captureLegacyStandardDNS(profile common.RouterProfile, raw []byte, network func() string) (*legacyStandardDNS, error) {
	selected, err := expectedDNSSelection(profile)
	if err != nil {
		return nil, err
	}
	if err := validateLegacyStandardDNSGraph(raw, selected); err != nil {
		return nil, err
	}
	if network == nil {
		return nil, errors.New("legacy DNS preparation has no physical network observer")
	}
	original := network()
	if original == "" {
		return nil, errors.New("legacy DNS preparation cannot capture the physical network")
	}
	return &legacyStandardDNS{selection: selected, profileID: profile.ID, profileToken: asyncMeasurementProfileToken(profile), network: network, networkID: original, digest: sha256.Sum256(raw), size: len(raw)}, nil
}

// networkID is immutable from preparation. A later successful observation can
// never replace that identity, including the first DNS proof after Start.
func (o *linuxLegacyStandardExitOwner) legacyDNSNetworkCurrent() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := o.namespaceCurrent(); err != nil {
		return err
	}
	if o.dns == nil || o.dns.network == nil || o.dns.networkID == "" || o.dns.network() != o.dns.networkID {
		return errors.New("legacy DNS proof physical network changed since preparation")
	}
	return o.namespaceCurrent()
}

// The caller pins its current OS thread so this namespace check also covers
// listener transfer and the subsequent loopback exchange.
func (o *linuxLegacyStandardExitOwner) legacyDNSCurrent(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.dns == nil || !o.started || o.pidFile == nil || o.pidFile != o.originalPIDFD || o.command == nil || o.command.Process == nil {
		return errors.New("legacy DNS proof has no original started owner")
	}
	if err := o.currentRuntimeLocked(ctx); err != nil {
		return err
	}
	if o.sourceConfig == nil || o.sourceConfig != o.dns.source || o.config == nil || o.config != o.dns.sealed {
		return errors.New("legacy DNS proof configuration capability was replaced")
	}
	sourceInfo, sourceErr := o.dns.source.Stat()
	namedInfo, namedErr := o.launch.directoryRoot.Lstat("sing-box.json")
	if sourceErr != nil || namedErr != nil || !namedInfo.Mode().IsRegular() || !os.SameFile(sourceInfo, namedInfo) {
		return errors.New("legacy DNS proof configuration inode was replaced")
	}
	raw, err := readDesktopRuntimeFile(o.launch, "sing-box.json", 8<<20)
	if err != nil || sha256.Sum256(raw) != o.dns.digest || o.digest != hex.EncodeToString(o.dns.digest[:]) {
		return errors.Join(err, errors.New("legacy DNS proof configuration changed"))
	}
	sealed := make([]byte, o.dns.size+1)
	n, err := o.config.ReadAt(sealed, 0)
	if err != nil && !errors.Is(err, io.EOF) || n != o.dns.size || sha256.Sum256(sealed[:n]) != o.dns.digest {
		return errors.New("legacy DNS proof lost its exact sealed child configuration")
	}
	o.app.mu.Lock()
	profile, found := o.app.profileByIDLocked(o.dns.profileID)
	o.app.mu.Unlock()
	if !found || asyncMeasurementProfileToken(profile) != o.dns.profileToken {
		return errors.New("legacy DNS proof source policy changed")
	}
	return o.legacyDNSNetworkCurrent()
}

func (o *linuxLegacyStandardExitOwner) legacyDNSOperationCurrent(operation context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.currentOperationLocked(operation)
}

func (o *linuxLegacyStandardExitOwner) ProveSelectedDNS(operation context.Context) (failure error) {
	if operation == nil || operation.Err() != nil || o == nil || o.dns == nil {
		return errors.New("legacy DNS proof requires its captured operation")
	}
	ctx, cancel := context.WithTimeout(operation, 4*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	o.dns.mu.Lock()
	o.dns.proof = nil
	o.dns.mu.Unlock()
	if err := o.legacyDNSOperationCurrent(operation); err != nil {
		return err
	}
	if err := o.legacyDNSCurrent(ctx); err != nil {
		return err
	}
	var listener *legacyDNSListener
	for {
		var err error
		listener, err = captureLegacyDNSListener(ctx, o.originalPIDFD, netip.MustParseAddrPort("127.0.0.1:1099"))
		if err == nil {
			break
		}
		if !errors.Is(err, errLegacyDNSListenerNotFound) {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if err := o.legacyDNSOperationCurrent(operation); err != nil {
			return err
		}
		if err := o.legacyDNSCurrent(ctx); err != nil {
			return err
		}
	}
	defer func() { failure = errors.Join(failure, listener.Close()) }()
	if err := exchangeLegacyStandardDNS(ctx, "127.0.0.1:1099"); err != nil {
		return err
	}
	if err := listener.Current(); err != nil {
		return err
	}
	if err := o.legacyDNSOperationCurrent(operation); err != nil {
		return err
	}
	if err := o.legacyDNSCurrent(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	receipt := &legacyStandardDNSReceipt{owner: o, session: o.session, config: o.digest, fd: listener.targetFD, listener: listener.identity}
	if err := listener.Close(); err != nil {
		return err
	}
	o.dns.mu.Lock()
	o.dns.proof = receipt
	o.dns.mu.Unlock()
	return nil
}

func proveLegacyStandardDNS(ctx context.Context, a *app, observed observedConnection, runtimeID string, selected dnsSelection) (dnsProofState, bool) {
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	if a == nil {
		return result, false
	}
	if remote, owned := proveLinuxServiceStandardDNS(ctx, a, observed, runtimeID, selected); owned {
		return remote, true
	}
	raw, exists := legacyStandardExitOwners.Load(a)
	if !exists {
		return result, false
	}
	fail := func(err error) (dnsProofState, bool) { result.Reason = err.Error(); return result, true }
	o, ok := raw.(*linuxLegacyStandardExitOwner)
	if !ok || o == nil || o.dns == nil || ctx == nil || ctx.Err() != nil {
		return fail(errors.New("legacy selected DNS lost its captured owner"))
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	o.dns.mu.Lock()
	proof := o.dns.proof
	o.dns.mu.Unlock()
	if proof == nil || proof.owner != o || proof.session != o.session || proof.config != o.digest || selected != o.dns.selection {
		return fail(errors.New("legacy selected DNS has no matching pre-activation proof"))
	}
	if !observed.Connected || observed.Phase != "connected" || observed.RouterID != o.routerID || observed.RuntimeMode != o.runtimeMode || runtimeID != o.runtimeMode || observed.Base != o.base || asyncMeasurementProfileToken(observed.Profile) != o.dns.profileToken {
		return fail(errors.New("legacy selected DNS observation belongs to another source"))
	}
	if err := o.legacyDNSCurrent(ctx); err != nil {
		return fail(err)
	}
	member, err := legacyDNSDuplicateChildFD(o.originalPIDFD, proof.fd)
	if err != nil {
		return fail(err)
	}
	identity, readErr := legacyDNSListenerSnapshot(member, netip.MustParseAddrPort("127.0.0.1:1099"))
	closeErr := member.Close()
	if readErr != nil || closeErr != nil || identity != proof.listener {
		return fail(errors.Join(readErr, closeErr, errors.New("legacy selected DNS listener no longer belongs to its original runtime")))
	}
	a.mu.Lock()
	st := a.state
	current := a.cmd == o.command && st.Connected && st.Phase == "connected" && st.RouterID == observed.RouterID && st.RuntimeMode == runtimeID && st.Mode == observed.Mode && st.LogicalMode == observed.LogicalMode && st.Base == observed.Base
	a.mu.Unlock()
	if !current || ctx.Err() != nil {
		return fail(errors.New("legacy selected DNS observation lost its current connected runtime"))
	}
	if err := o.legacyDNSCurrent(ctx); err != nil {
		return fail(err)
	}
	result.Status = "passed"
	result.Reason = "the original retained stock runtime proved its uncached selected DNS before public-exit activation; original process, listener, configuration and network remain current"
	return result, true
}
