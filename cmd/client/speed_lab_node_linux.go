//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

// This identity retains the original active owners without owning their
// lifetime. It creates no process waiter, source copy, or legacy registration.
// Only a real current native observation admits it; presentation state and
// decoded readiness alone cannot supply a Linux Speed Lab path.
type desktopLinuxNodePath struct {
	app           *app
	session       *desktopLinuxNodeSession
	host          *desktopLinuxNodeHost
	sessionParent *desktopLinuxNodeParentCapture
	hostParent    *desktopLinuxNodeParentCapture
	activation    *desktopLinuxNodeActivation
	process       *desktopLinuxNodeProcess
	transaction   *desktopLinuxNodeTransaction
	journal       *desktopLinuxNodeJournal
	policy        *mobilemultihop.DesktopNodePolicy
	launch        *desktopNodeLaunch
	command       *exec.Cmd
	processJoined <-chan struct{}
	lifetime      context.Context
	selection     linuxprotection.NodeSelection
	ready         mobilemultihop.DesktopNodeReadyRecord
	network       string
	revision      string
	options       [3]bool
	savedOptions  [3]bool
}

func readDesktopLinuxNodePathReady(ctx context.Context, h *desktopLinuxNodeHost) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error) {
	return h.readReadyLocked(ctx, false)
}

func captureDesktopLinuxNodePath(ctx context.Context, a *app, command *exec.Cmd) (*desktopLinuxNodePath, bool, error) {
	return captureDesktopLinuxNodePathWith(ctx, a, command, readDesktopLinuxNodePathReady)
}

// The only modeled boundary in focused tests is the actual native readReady
// operation. Shipping capture always supplies the original policy/TUN reader.
func captureDesktopLinuxNodePathWith(ctx context.Context, a *app, command *exec.Cmd,
	readReady func(context.Context, *desktopLinuxNodeHost) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error)) (*desktopLinuxNodePath, bool, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || readReady == nil {
		return nil, true, errors.New("Linux Speed Lab path requires its original bounded caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return nil, false, nil
	}
	p, ok := controller.nodeParent.(*desktopLinuxNodeParent)
	if !ok || p == nil || p.gate == nil {
		return nil, true, errors.New("Linux Speed Lab path has another original native parent")
	}
	select {
	case <-ctx.Done():
		return nil, true, ctx.Err()
	case <-p.gate:
	}
	s := p.session
	retained := len(p.dependents) != 0
	p.gate <- struct{}{}
	if s == nil {
		if retained {
			return nil, true, errors.New("Linux Speed Lab path lost the session for its retained native owners")
		}
		return nil, false, nil
	}
	if err := s.enter(ctx); err != nil {
		return nil, true, err
	}
	defer func() { s.gate <- struct{}{} }()
	if s.parent == nil || s.parent.app != a || s.parent.controller != controller || s.parent.parent != p {
		return nil, true, errors.New("Linux Speed Lab path lost its original application session")
	}
	h := s.active
	if h == nil {
		// Only a current original empty session may defer to another path.
		if err := s.currentLocked(ctx); err != nil {
			return nil, true, err
		}
		return nil, false, nil
	}
	if err := h.enter(ctx); err != nil {
		return nil, true, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.imported != nil {
		if h.activation == nil || h.launch == nil || h.launch.command != command || h.launch.importedPlatform == nil {
			return nil, true, errors.New("Linux imported Speed Lab path has no original activated command")
		}
		if err := h.observeLocked(ctx); err != nil {
			return nil, true, err
		}
		// The imported graph keeps both independently saved nodes in its
		// multihop owner; a NodeProfile cannot replace that source identity.
		return nil, false, nil
	}
	if h.external != nil {
		if h.activation == nil || h.launch == nil || h.launch.command != command {
			return nil, true, errors.New("Linux external Speed Lab path has no original activated command")
		}
		if err := h.observeLocked(ctx); err != nil {
			return nil, true, err
		}
		// Ordinary external identities retain their native proof and measurement
		// contract; the lookup below will recheck this same session before use.
		return nil, false, nil
	}
	if h.activation == nil || h.process == nil || h.transaction == nil || h.launch == nil || h.ready == nil {
		return nil, true, errors.New("Linux Speed Lab path has no original proved active owner")
	}
	path := &desktopLinuxNodePath{app: a, session: s, host: h, sessionParent: s.parent, hostParent: h.parent,
		activation: h.activation, process: h.process, transaction: h.transaction, journal: s.journal,
		policy: h.policy, launch: h.launch, command: command, processJoined: h.process.joined,
		lifetime: h.activation.lifetime, selection: h.selection, ready: *h.ready,
		network: h.network, revision: h.revision, options: h.options, savedOptions: h.savedOptions}
	if _, _, err := path.currentLockedWith(ctx, readReady); err != nil {
		return nil, true, err
	}
	return path, true, nil
}

// Both original session.gate and host.gate are held, in that order. This is
// owner comparison, not native readiness; currentLocked performs that proof.
// Sealed restoration can reuse this comparison while copying its own inputs.
func (path *desktopLinuxNodePath) selectedLocked(ctx context.Context) error {
	if path == nil || ctx == nil || ctx.Err() != nil || path.app == nil || path.session == nil || path.host == nil ||
		path.sessionParent == nil || path.hostParent == nil || path.activation == nil || path.process == nil ||
		path.transaction == nil || path.journal == nil || path.policy == nil || path.launch == nil || path.command == nil {
		return errors.New("Linux Speed Lab path lost its captured active owners")
	}
	s, h := path.session, path.host
	if s.closed || s.released || s.active != h || s.parent != path.sessionParent || s.journal != path.journal ||
		h.closing || h.closed || h.released || h.parent != path.hostParent || h.activation != path.activation ||
		h.process != path.process || h.transaction != path.transaction || h.policy != path.policy || h.launch != path.launch ||
		h.selection != path.selection || h.network != path.network || h.revision != path.revision ||
		h.options != path.options || h.savedOptions != path.savedOptions || h.ready == nil || *h.ready != path.ready ||
		path.ready.SessionID == "" || path.ready.SourceSHA256 == "" || path.ready.SessionID != path.selection.SessionID ||
		path.ready.SourceSHA256 != path.selection.SourceSHA256 || path.activation.lifetime != path.lifetime ||
		path.process.command != path.command || path.process.joined != path.processJoined || h.launch.command != path.command ||
		path.transaction.journal != path.journal || path.journal.parent == nil ||
		!sameDesktopLinuxParentCapture(path.sessionParent, path.journal.parent) ||
		!sameDesktopLinuxParentCapture(path.sessionParent, path.hostParent) || path.sessionParent.app != path.app {
		return errors.New("Linux Speed Lab path belongs to a replaced retained session")
	}
	if err := path.activation.matches(h); err != nil {
		return err
	}
	p := path.sessionParent.parent
	if p == nil || p.gate == nil {
		return errors.New("Linux Speed Lab path lost its original parent registration")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	_, retainedSession := p.dependents[s]
	_, retainedHost := p.dependents[h]
	selected := p.complete && !p.closed && !p.stopping && p.session == s && retainedSession && retainedHost
	p.gate <- struct{}{}
	if !selected || path.network == "" || physicalNetworkIdentity() != path.network {
		return errors.New("Linux Speed Lab path changed its original parent or physical network")
	}
	path.app.mu.Lock()
	defer path.app.mu.Unlock()
	a := path.app
	profile, exists := a.profileByIDLocked(path.launch.profileID)
	_, duplicate := desktopNodeOwners.Load(a)
	if ctx.Err() != nil || duplicate || path.sessionParent.currentAppLocked(false) != nil ||
		a.cmd != path.command ||
		a.state.RouterID != path.launch.profileID || a.state.RuntimeMode != path.launch.mode ||
		a.state.Mode == "external-node" || a.state.Mode == "multihop" || !exists ||
		strings.EqualFold(profile.NodeKind, "external") || profile.External != nil || desktopOwnedNodeProfileToken(profile) != path.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != path.savedOptions ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != path.options {
		return errors.New("Linux Speed Lab path changed its selected command, private node or policy")
	}
	return nil
}

func (path *desktopLinuxNodePath) currentLocked(ctx context.Context) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error) {
	return path.currentLockedWith(ctx, readDesktopLinuxNodePathReady)
}

func (path *desktopLinuxNodePath) currentLockedWith(ctx context.Context,
	readReady func(context.Context, *desktopLinuxNodeHost) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error)) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error) {
	var empty mobilemultihop.DesktopNodeReadyRecord
	var noLive desktopNodeMTURecord
	if err := path.selectedLocked(ctx); err != nil {
		return empty, noLive, err
	}
	if readReady == nil {
		return empty, noLive, errors.New("Linux Speed Lab path omitted its actual native observation")
	}
	record, live, err := readReady(ctx, path.host)
	if err != nil || record != path.ready {
		return empty, noLive, errors.Join(err, errors.New("Linux Speed Lab path lost its captured native readiness"))
	}
	if err := path.selectedLocked(ctx); err != nil {
		return empty, noLive, err
	}
	return record, live, nil
}

func validateDesktopLinuxNodePath(ctx context.Context, a *app, path *desktopLinuxNodePath) error {
	return validateDesktopLinuxNodePathWith(ctx, a, path, readDesktopLinuxNodePathReady)
}

func validateDesktopLinuxNodePathWith(ctx context.Context, a *app, path *desktopLinuxNodePath,
	readReady func(context.Context, *desktopLinuxNodeHost) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error)) error {
	if path == nil {
		// A removed typed identity must not turn a retained Linux path into an
		// ordinary Connected/state-only measurement. A nil command deliberately
		// cannot capture any active native owner in this absence check.
		_, handled, err := captureDesktopLinuxNodePathWith(ctx, a, nil, readReady)
		if handled {
			return errors.Join(err, errors.New("Speed Lab omitted its retained Linux path identity"))
		}
		return err
	}
	if ctx == nil || ctx.Err() != nil || path.app != a {
		return errors.New("Linux Speed Lab result belongs to another application or caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := path.session.enter(ctx); err != nil {
		return err
	}
	defer func() { path.session.gate <- struct{}{} }()
	if err := path.host.enter(ctx); err != nil {
		return err
	}
	defer func() { path.host.gate <- struct{}{} }()
	_, _, err := path.currentLockedWith(ctx, readReady)
	return err
}
