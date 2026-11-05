//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
	"strings"
	"sync/atomic"
	"time"
)

// Both original owners retain this object. Before Bind it is only a captured
// pointer/intent; joining the old engine cannot resolve an unmade reservation.
type linuxStandardNodeReverseTransfer struct {
	plannedArgs, plannedEnv                                                    []string
	plannedRoot                                                                string
	plannedRootInfo                                                            os.FileInfo
	command                                                                    *exec.Cmd
	planning                                                                   *desktopNodeLaunch
	plannedConfig                                                              string
	planningAdopted                                                            bool
	session                                                                    *desktopLinuxNodeSession
	source                                                                     *desktopLinuxNodeTransaction
	owner                                                                      *linuxStandardServiceLaunch
	operation                                                                  context.Context
	deadline                                                                   time.Time
	profile                                                                    common.RouterProfile
	exitRaw                                                                    string
	request                                                                    linuxStandardServiceReverseRequest
	native                                                                     *mobiletor.DesktopLinuxNodeStandardTransfer
	destination                                                                *mobiletor.DesktopLinuxClosedTransferSnapshot
	original                                                                   linuxprotection.JournalState
	staged, serviceAttempted, nativeFinished, nativeCommitted, journalFinished bool
	committed, resolved                                                        atomic.Bool
}

func captureStandardReverse(operation context.Context, a *app, profile common.RouterProfile, exit standardExit, eligible bool) (standardReversePreparation, error) {
	if operation == nil {
		return nil, errors.New("reverse transfer omitted original operation")
	}
	if !eligible || a == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(operation, 120*time.Second)
	defer cancel()
	parent, err := captureStandardReverseParent(ctx, a)
	if err != nil || parent == nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-parent.parent.gate:
	}
	session := parent.parent.session
	parent.parent.gate <- struct{}{}
	if session == nil {
		return nil, nil
	}
	if err = session.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { session.gate <- struct{}{} }()
	if err = session.currentLocked(ctx); err != nil {
		return nil, err
	}
	if session.reverse != nil && !session.reverse.resolved.Load() {
		return nil, errors.New("finish the original Node-to-standard transfer before another connection")
	}
	source := session.predecessor
	if session.active != nil {
		source = session.active.transaction
	}
	if source == nil {
		return nil, nil
	}
	if err = source.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { source.gate <- struct{}{} }()
	if source.closed || source.superseded || source.successor != nil || source.off != nil || !source.complete || !source.nativeCommitted || source.baseline == nil || source.prepared == nil || source.pending != nil {
		return nil, errors.New("reverse transfer has no complete original Node creator")
	}
	if source.selection.Policy != "always" && source.selection.Policy != "on-connect" {
		return nil, errors.New("reverse source has no protected native policy")
	}
	if profile.KillSwitchPolicy != "always" && profile.KillSwitchPolicy != "on-connect" {
		return nil, errors.New("choose a protected standard destination before transferring retained Node protection")
	}
	raw, err := json.Marshal(exit)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	return &linuxStandardNodeReverseTransfer{session: session, source: source, operation: operation, deadline: deadline, profile: common.CloneRouterProfile(profile), exitRaw: string(raw)}, nil
}

// Capture uses the same original bootstrap and Current proof as Node admission,
// but carries this connection's context through the application lock and proof.
func captureStandardReverseParent(ctx context.Context, a *app) (*desktopLinuxNodeParentCapture, error) {
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	owner := a.localController
	a.mu.Unlock()
	if owner == nil {
		return nil, nil
	}
	parent, ok := owner.nodeParent.(*desktopLinuxNodeParent)
	if !ok || parent == nil || parent.controller != owner {
		return nil, errors.New("reverse transfer lost original installed Node parent")
	}
	capture := &desktopLinuxNodeParentCapture{app: a, controller: owner, parent: parent, record: parent.record, lifetime: parent.ctx}
	if err := capture.Current(ctx); err != nil {
		return nil, err
	}
	return capture, nil
}

func (t *linuxStandardNodeReverseTransfer) Bind(launch legacyStandardExitLaunch) error {
	o, ok := launch.(*linuxStandardServiceLaunch)
	if !ok || o == nil || o.prepared == nil || o.reverse != nil {
		return errors.New("reverse destination is not its original installed service launch")
	}
	ctx, cancel := context.WithDeadline(t.operation, t.deadline)
	defer cancel()
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if err := t.adoptPlanning(ctx, o); err != nil {
		return err
	}
	digest, err := linuxStandardProfileDigest(t.profile)
	if err != nil || o.request.ProfileID != t.profile.ID || o.request.ProfileSHA256 != digest || o.prepared.protectionPolicy != t.profile.KillSwitchPolicy || o.prepared.protectionLAN != t.profile.HomeLANAccess {
		return errors.Join(err, errors.New("reverse destination changed captured policy"))
	}
	if err = t.session.enter(ctx); err != nil {
		return err
	}
	defer func() { t.session.gate <- struct{}{} }()
	if err = t.session.currentLocked(ctx); err != nil {
		return err
	}
	if t.session.active != nil || t.session.predecessor != t.source || t.session.reverse != nil && !t.session.reverse.resolved.Load() {
		return errors.New("reverse source was replaced before original join")
	}
	if _, err = t.session.selectedPredecessorLocked(ctx, t.source); err != nil {
		return err
	}
	if err = t.source.enter(ctx); err != nil {
		return err
	}
	defer func() { t.source.gate <- struct{}{} }()
	if err = t.source.checkHead(ctx); err != nil {
		return err
	}
	if err = desktopnetwork.LockContext(ctx, &o.app.mu); err != nil {
		return err
	}
	intentErr := o.app.checkCapturedConnectionOperationLocked(t.operation)
	profile, exists := o.app.profileByIDLocked(t.source.profileID)
	o.app.mu.Unlock()
	if intentErr != nil || !exists || desktopOwnedNodeProfileToken(profile) != t.source.revision {
		return errors.Join(intentErr, errors.New("reverse source policy changed before transfer"))
	}
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	t.owner = o
	o.reverse = t
	t.session.reverse = t
	t.native, err = t.source.baseline.ReserveStandardTransfer(ctx, id)
	if err != nil {
		return err
	}
	snapshot, err := t.native.Snapshot(ctx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	t.request = linuxStandardServiceReverseRequest{Parent: t.source.parent.record, Source: snapshot, Intent: linuxprotection.NodeStandardTransfer{ID: id, DeadlineNS: t.deadline.UnixNano(), Source: t.source.selection, SourceProfileID: t.source.profileID, SourceProfileRevision: t.source.revision, SourceReceiptSHA256: standardengine.SHA256(raw), DestinationSession: o.request.Session, DestinationConfigSHA256: o.request.ConfigSHA256, DestinationProfileID: o.request.ProfileID, DestinationProfileSHA256: o.request.ProfileSHA256, Endpoint: o.request.Endpoint, Policy: o.prepared.protectionPolicy, HomeLAN: o.prepared.protectionLAN}}
	if err = t.request.Intent.Validate(); err != nil {
		return err
	}
	t.original = linuxprotection.CloneState(t.source.head.Record.Committed)
	next := t.source.nextRecord()
	intent := t.request.Intent
	next.ReverseTransfer = &intent
	next.Phase = "intent"
	next.Intent = &linuxprotection.JournalIntent{Action: "standard-transfer", RequestID: id, ProfileID: t.source.profileID, ProfileRevision: t.source.revision, ResultProfileRevision: t.source.revision}
	t.staged = true
	return t.source.appendRecord(ctx, next)
}

// owner.mu serializes messages/evidence. Source/session gates never cover RPC.
func (t *linuxStandardNodeReverseTransfer) rpcLocked(ctx context.Context, action string) (*linuxStandardServiceReverseResponse, error) {
	o := t.owner
	if o == nil || o.reverse != t || t.request.Intent.Validate() != nil {
		return nil, errors.New("reverse call lost retained original intent")
	}
	q := linuxStandardServiceRequest{Schema: 1, Action: action, Session: o.request.Session, Reverse: &t.request}
	var directory *os.File
	if action == "reverse-prepare" {
		q = o.request
		q.Action = action
		q.Reverse = &t.request
		directory = o.prepared.directory
	}
	exchange := o.exchange
	if exchange == nil {
		exchange = func(call context.Context, q linuxStandardServiceRequest, d *os.File, before func()) (linuxStandardServiceResponse, error) {
			return linuxStandardServiceRPC(call, o.image, o.prepared.namespaceInfo, &o.peer, q, d, before)
		}
	}
	response, err := exchange(ctx, q, directory, func() {
		if action == "reverse-prepare" {
			t.serviceAttempted = true
			o.attempted = true
		}
	})
	if err != nil && response.authenticatedPeer == nil {
		return nil, err
	}
	if response.authenticatedPeer == nil || response.authenticatedPeer != o.peer || response.Startup != nil || response.MTU != nil || response.Transfer != nil || response.Protection != nil {
		return nil, errors.Join(err, errors.New("reverse response lost original authenticated service"))
	}
	out := response.Reverse
	if out == nil || out.Intent != t.request.Intent || out.Committed != (out.Phase == "committed") || (out.Phase != "retained" && out.Phase != "prepared" && out.Phase != "committed" && out.Phase != "aborting" && out.Phase != "aborted") {
		return nil, errors.Join(err, errors.New("reverse response changed original transaction"))
	}
	if out.Destination != nil {
		s := out.Destination
		endpoint, e := netip.ParseAddr(strings.Trim(t.request.Intent.Endpoint, "[]"))
		if e != nil || s.Validate() != nil || !s.Standard || s.Capture.SessionID != o.request.Session || s.Capture.SourceSHA256 != o.request.ConfigSHA256 || s.HomeLAN != t.request.Intent.HomeLAN || len(s.Endpoints) != 1 || s.Endpoints[0] != endpoint || s.NamespaceDevice != t.request.Source.NamespaceDevice || s.NamespaceInode != t.request.Source.NamespaceInode {
			return nil, errors.New("reverse successor changed original native policy")
		}
		if t.destination != nil && !reflect.DeepEqual(*t.destination, *s) {
			return nil, errors.New("reverse response replaced pinned successor")
		}
		if t.destination == nil {
			copy := *s
			copy.Inventory = append([]byte(nil), s.Inventory...)
			copy.Endpoints = append([]netip.Addr(nil), s.Endpoints...)
			t.destination = &copy
		}
	}
	if (out.Phase == "prepared" || out.Phase == "committed") && t.destination == nil {
		return nil, errors.New("reverse response omitted actual successor pin")
	}
	if out.Committed && !t.nativeCommitted {
		return nil, errors.New("reverse service claimed unproved source removal")
	}
	return out, errors.Join(err, o.peer.Current(ctx), ctx.Err())
}
func (t *linuxStandardNodeReverseTransfer) startLocked(parent context.Context) error {
	if t == nil || t.owner == nil || t.owner.reverse != t || t.resolved.Load() {
		return errors.New("reverse start lost original reservation")
	}
	ctx, cancel := context.WithDeadline(parent, t.deadline)
	defer cancel()
	if err := t.owner.currentIntentContext(ctx, t.operation, t.owner.Command()); err != nil {
		return err
	}
	if t.native == nil || !t.staged || t.owner.mtuExitRaw != t.exitRaw {
		return errors.New("reverse source reservation or captured exit did not complete")
	}
	if err := t.source.enter(ctx); err != nil {
		return err
	}
	err := t.source.flushPending(ctx)
	if err == nil {
		err = t.source.checkHead(ctx)
	}
	t.source.gate <- struct{}{}
	if err != nil {
		return err
	}
	response, err := t.rpcLocked(ctx, "reverse-prepare")
	if err != nil {
		return err
	}
	if response.Phase != "prepared" {
		return errors.New("reverse destination did not retain its prepared guard")
	}
	if err = t.owner.currentIntentContext(ctx, t.operation, t.owner.Command()); err != nil {
		return err
	}
	if err = t.source.enter(ctx); err != nil {
		return err
	}
	err = t.source.checkHead(ctx)
	if err == nil {
		err = t.native.Commit(ctx, *t.destination)
	}
	t.source.gate <- struct{}{}
	if err != nil {
		return err
	}
	return t.resolveLocked(ctx)
}
func (t *linuxStandardNodeReverseTransfer) resolveLocked(ctx context.Context) error {
	if t.resolved.Load() {
		return nil
	}
	if t.native == nil {
		t.resolved.Store(true)
		return nil
	}
	if !t.nativeFinished {
		committed, err := t.native.Result(ctx)
		if err != nil {
			return err
		}
		t.nativeCommitted = committed
	}
	if !t.journalFinished {
		if err := t.source.enter(ctx); err != nil {
			return err
		}
		err := t.source.flushPending(ctx)
		if err == nil && t.staged {
			next := t.source.nextRecord()
			next.Phase = "settled"
			next.Intent = nil
			next.Committed = linuxprotection.CloneState(t.original)
			if t.nativeCommitted {
				next.Committed = linuxprotection.JournalState{}
			}
			err = t.source.appendRecord(ctx, next)
		}
		if err == nil {
			t.journalFinished = true
			if t.nativeCommitted {
				t.source.superseded = true
				t.source.baselineReleased = true
			}
		}
		t.source.gate <- struct{}{}
		if err != nil {
			return err
		}
	}
	if t.serviceAttempted {
		action := "reverse-abort"
		if t.nativeCommitted {
			action = "reverse-commit"
		}
		result, err := t.rpcLocked(ctx, action)
		if err != nil {
			return err
		}
		if result.Committed != t.nativeCommitted || !result.Committed && result.Phase != "aborted" {
			return errors.New("reverse settlement differs from actual source outcome")
		}
	}
	if !t.nativeFinished {
		committed, err := t.native.Finish(ctx)
		if err != nil {
			return err
		}
		if committed != t.nativeCommitted {
			return errors.New("reverse final source acknowledgement changed actual outcome")
		}
		t.nativeFinished = true
	}
	if t.nativeCommitted {
		if err := t.source.Close(ctx); err != nil {
			return err
		}
		if err := t.session.enter(ctx); err != nil {
			return err
		}
		if t.session.predecessor != t.source {
			t.session.gate <- struct{}{}
			return errors.New("reverse completion replaced original predecessor")
		}
		t.session.predecessor = nil
		t.session.gate <- struct{}{}
		t.committed.Store(true)
	}
	t.resolved.Store(true)
	return ctx.Err()
}
func (s *desktopLinuxNodeSession) drainStandardReverse(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	t := s.reverse
	s.gate <- struct{}{}
	if t == nil || t.resolved.Load() {
		return nil
	}
	if t.owner == nil {
		return errors.New("reverse cleanup lost original destination owner")
	}
	if err := desktopnetwork.LockContext(ctx, &t.owner.mu); err != nil {
		return err
	}
	defer t.owner.mu.Unlock()
	return t.resolveLocked(ctx)
}
func (t *linuxStandardNodeReverseTransfer) current(ctx context.Context) error {
	if t == nil || !t.resolved.Load() || !t.committed.Load() || t.owner == nil {
		return errors.New("reverse checkpoint has no completed original successor")
	}
	if err := desktopnetwork.LockContext(ctx, &t.owner.mu); err != nil {
		return err
	}
	defer t.owner.mu.Unlock()
	result, err := t.rpcLocked(ctx, "reverse-current")
	if err == nil && !result.Committed {
		err = errors.New("reverse checkpoint lost actual successor")
	}
	return err
}
