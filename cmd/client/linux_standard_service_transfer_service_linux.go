//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

type linuxStandardServiceTransfer struct {
	peer           *linuxStandardServicePeer
	session        *linuxStandardServiceSession
	slot           *legacyExitProtectionSlot
	native         *mobiletor.DesktopLinuxStandardNodeTransfer
	request        linuxStandardServiceTransferRequest
	result         linuxStandardServiceTransferResponse
	requestSession string
	bootPeerClosed bool
	nativeFinished bool
	pendingPhase   string
	snapshot       *mobiletor.DesktopLinuxNodeTransferSnapshot
	prepared       *linuxprotection.NodePreparedRecord
}

func (t *linuxStandardServiceTransfer) persist(ctx context.Context, lease *legacyExitMutationLease, phase string) error {
	if t.pendingPhase != "" && t.pendingPhase != phase {
		return errors.New("transfer retains another original durable phase")
	}
	t.pendingPhase = phase
	var state legacyExitProtectionState
	if err := json.Unmarshal(t.slot.body, &state); err != nil {
		return err
	}
	next := t.result
	next.Phase = phase
	state.Transfer = &next
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if !bytes.Equal(t.slot.body, body) {
		before := t.slot.saved
		saved, writeErr := legacyExitWriteState(ctx, lease, before, body)
		if saved != nil {
			t.slot.saved = saved
			t.slot.body = append([]byte(nil), body...)
			if err := before.Close(); err != nil {
				return errors.Join(writeErr, err)
			}
		}
		if writeErr != nil {
			return writeErr
		}
	}
	if err := t.slot.saved.Current(lease); err != nil {
		return err
	}
	if err := lease.run.Sync(); err != nil {
		return err
	}
	t.result = next
	t.pendingPhase = ""
	return nil
}

func (s *linuxStandardService) transferRequest(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest) (out *linuxStandardServiceTransferResponse, failure error) {
	q := request.Transfer
	switch request.Action {
	case "transfer-reserve", "transfer-current", "transfer-held", "transfer-commit", "transfer-resolve":
	default:
		return nil, errors.New("standard transfer action is unavailable")
	}
	if ctx == nil || ctx.Err() != nil || q == nil || request.BudgetMS < 1 || request.BudgetMS > 120000 || request.DeadlineNS <= time.Now().UnixNano() || request.Schema != 1 || !validControllerOwnerToken(request.Session) || !validControllerOwnerToken(q.ID) || request.Reverse != nil || request.MTU != nil || request.Release || request.Directory != "" || request.ConfigSHA256 != "" || request.ProfileSHA256 != "" || request.ProfileID != "" || request.Endpoint != "" || request.RuntimeMode != "" || request.Base != "" || request.NetworkID != "" || request.RouterID != "" || request.ProfileRevision != "" || request.ResultRevision != "" {
		return nil, errors.New("standard transfer request changed its fixed original scope")
	}
	if q.DeadlineNS <= 0 || q.Destination.Validate() != nil || !validProfileID(q.ProfileID) || len(q.ProfileRevision) != 64 {
		return nil, errors.New("standard transfer omitted its destination selection")
	}
	if err := peer.Current(ctx); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
	}
	defer func() {
		if out != nil {
			copy := *out
			out = &copy
		}
		s.gate <- struct{}{}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(ns, s.namespace) {
		return nil, errors.Join(err, errors.New("standard transfer changed its original namespace"))
	}
	if s.reversePending() {
		return nil, errors.New("reverse transfer must resolve before forward transfer")
	}
	t := s.transfer
	if old, exists := s.transferHistory[q.ID]; exists {
		if q.Boot || old.Boot {
			original := *q
			original.Snapshot = nil
			original.Prepared = nil
			if !q.Boot || !old.Boot || old.history == nil || old.history.Peer != peer.record || old.history.Session != request.Session || !reflect.DeepEqual(old.history.Request, original) || q.Snapshot != nil || q.Prepared != nil {
				return nil, errors.New("retired boot transfer changed original peer or intent")
			}
			if request.Action != "transfer-resolve" && request.Action != "transfer-held" {
				return &old, errors.New("boot transfer ID was already retired")
			}
			return &old, nil
		}
		if old.Intent.SourceSession != request.Session || old.Intent.Destination != q.Destination || old.Intent.ProfileID != q.ProfileID || old.Intent.ProfileRevision != q.ProfileRevision || old.Intent.DeadlineNS != q.DeadlineNS || s.session == nil || s.session.peer.record != peer.record {
			return nil, errors.New("retired transfer request changed its original intent")
		}
		if request.Action != "transfer-resolve" && request.Action != "transfer-held" {
			return &old, errors.New("transfer ID was already retired")
		}
		if request.Action == "transfer-resolve" {
			return &old, nil
		}
	}
	if q.Boot && (s.boot == nil || s.boot.closed) && (t == nil || t.request.ID != q.ID) {
		if s.quiescing {
			return nil, errors.New("boot service is retiring")
		}
		if s.bootFailure != nil {
			return nil, errors.Join(s.bootFailure, errors.New("boot transfer cannot infer recovery from a failed boot"))
		}
		if t != nil && !t.terminal() {
			return nil, errors.New("original boot transfer remains unresolved")
		}
		if raw, exists := legacyStandardProtectionOwners.Load(s.app); exists {
			if slot, ok := raw.(*legacyExitProtectionSlot); !ok || slot == nil || !slot.closed {
				return nil, errors.New("service retains another original protection source")
			}
		}
		if s.session != nil && (!s.session.joined || s.session.cleanupPending) {
			return nil, errors.New("service still owns an original engine")
		}
		if q.Snapshot != nil || q.Prepared != nil || request.Action != "transfer-reserve" && request.Action != "transfer-resolve" {
			return nil, errors.New("missing boot creator cannot settle another phase")
		}
		return &linuxStandardServiceTransferResponse{Boot: true, NoBoot: true, Phase: "no-boot"}, nil
	}
	if t != nil && t.terminal() && t.result.Phase == "aborted" && q.ID != t.request.ID && request.Action == "transfer-reserve" && (q.Boot && t.request.Boot && t.sourceStillCaptured(s) || !q.Boot && !t.request.Boot && t.peer.record == peer.record && t.sourceRequestSession() == request.Session) {
		t = nil
	}
	if t == nil {
		if (request.Action != "transfer-reserve" && request.Action != "transfer-resolve") || q.Snapshot != nil || q.Prepared != nil || s.quiescing || !q.Boot && (s.session == nil || s.session.cleanupPending || s.session.request.Session != request.Session || s.session.peer.record != peer.record) || q.Boot && (s.boot == nil || s.boot.closed || s.bootFailure != nil || s.session != nil && (!s.session.joined || s.session.cleanupPending)) {
			return nil, errors.New("standard transfer has no live original source to reserve")
		}
		if len(s.transferHistory) >= 128 {
			return nil, errors.New("standard transfer history is full; retain original protection")
		}
		// Cleanup of an overtaken unsent request cannot depend on a still-selected
		// destination. It only seals this ID against later admission.
		if request.Action == "transfer-reserve" {
			if err := s.loadProfiles(); err != nil {
				return nil, err
			}
			s.app.mu.Lock()
			profile, exists := s.app.profileByIDLocked(q.ProfileID)
			s.app.mu.Unlock()
			if !exists || desktopOwnedNodeProfileToken(profile) != q.ProfileRevision || desktopOwnedNodeProtectionPolicy(profile) != q.Destination.Policy || profile.HomeLANAccess != q.Destination.HomeLAN {
				return nil, errors.New("standard transfer destination profile changed")
			}
		}
		var slot *legacyExitProtectionSlot
		if q.Boot {
			slot = s.boot
		} else {
			slot = s.session.owner.protection
		}
		native, ok := func() (*legacyExitNativeProtection, bool) {
			if slot == nil {
				return nil, false
			}
			v, ok := slot.kernel.(*legacyExitNativeProtection)
			return v, ok
		}()
		if !ok || native == nil || slot.removed || slot.closed {
			return nil, errors.New("standard transfer has no original native protection creator")
		}
		lease, err := acquireLegacyExitMutationLease(ctx, s.root)
		if err != nil {
			return nil, err
		}
		defer lease.Close()
		if err = slot.current(ctx, lease); err != nil {
			return nil, err
		}
		receipt, err := native.Receipt(ctx)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(receipt)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		sourceSession, sourceConfig := receipt.Session, receipt.ConfigSHA256
		if !q.Boot {
			sourceSession, sourceConfig = request.Session, s.session.request.ConfigSHA256
		}
		intent := linuxprotection.StandardNodeTransfer{ID: q.ID, DeadlineNS: q.DeadlineNS, SourceSession: sourceSession, SourceConfigSHA256: sourceConfig, SourceReceiptSHA256: hex.EncodeToString(sum[:]), Destination: q.Destination, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision}
		if err = intent.Validate(); err != nil {
			return nil, err
		}
		original := *q
		original.Snapshot = nil
		original.Prepared = nil
		t = &linuxStandardServiceTransfer{peer: peer, slot: slot, request: original, requestSession: request.Session, result: linuxStandardServiceTransferResponse{Intent: intent, Boot: q.Boot}}
		if q.Boot {
			t.result.history = &linuxStandardServiceTransferHistory{Peer: peer.record, Session: request.Session, Request: original}
		} else {
			t.peer = s.session.peer
			t.session = s.session
		}
		if request.Action == "transfer-reserve" {
			deadline, bounded := ctx.Deadline()
			if !bounded || q.DeadlineNS > deadline.UnixNano() || time.Now().UnixNano() >= q.DeadlineNS {
				return nil, context.DeadlineExceeded
			}
		}
		t.native, err = native.ReserveNodeTransfer(ctx, q.ID, lease.lock)
		if err != nil {
			return nil, err
		}
		if s.transferHistory == nil {
			s.transferHistory = make(map[string]linuxStandardServiceTransferResponse)
		}
		s.transfer = t // Retain original creator before persistence can fail.
		if request.Action == "transfer-resolve" {
			_, err = t.native.Finish(ctx)
			if err == nil {
				t.nativeFinished = true

				err = t.persist(ctx, lease, "aborted")
			}
			if err == nil {
				err = t.finishBootPeer()
			}
			if err == nil {
				s.transferHistory[q.ID] = t.result
			}
			return &t.result, err
		}
		if err = t.native.Exclusive(ctx); err != nil {
			return &t.result, err
		}
		err = t.persist(ctx, lease, "reserved")
		return &t.result, err
	}
	original := *q
	original.Snapshot = nil
	original.Prepared = nil
	if !t.sourceStillCaptured(s) || t.peer.record != peer.record || request.Session != t.sourceRequestSession() || !reflect.DeepEqual(original, t.request) {
		return nil, errors.New("standard transfer request replaced its exact original reservation")
	}
	if request.Action == "transfer-reserve" || request.Action == "transfer-current" || request.Action == "transfer-commit" {
		if time.Now().UnixNano() >= t.request.DeadlineNS {
			return &t.result, context.DeadlineExceeded
		}
	}
	if t.native == nil {
		return &t.result, errors.New("standard transfer admission retained incomplete native creation")
	}
	if request.Action != "transfer-commit" && (q.Snapshot != nil || q.Prepared != nil) {
		return nil, errors.New("standard transfer supplied unexpected destination evidence")
	}
	if t.terminal() && request.Action != "transfer-held" {
		if request.Action == "transfer-reserve" || request.Action == "transfer-current" || request.Action == "transfer-commit" {
			return &t.result, errors.New("standard transfer reservation is terminal")
		}
		return &t.result, nil
	}
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return &t.result, err
	}
	defer lease.Close()
	if err = t.slot.scope(lease); err != nil {
		return &t.result, err
	}
	// A positively finished original release removes its registry entry and
	// closes its own descriptors. Retry only the retained cleanup milestone;
	// do not select a new owner or reread deliberately retired native handles.
	if t.slot.closed {
		if request.Action != "transfer-resolve" || !t.nativeFinished || !t.result.Committed || t.result.Phase != "settled" || t.pendingPhase != "" || !t.slot.removed || !t.slot.stateRemoved {
			return &t.result, errors.New("transfer has no completed original release milestone")
		}
	} else if err = t.slot.selected(); err != nil {
		return &t.result, err
	}
	if !t.slot.stateRemoved {
		if err = t.slot.saved.Current(lease); err != nil {
			return &t.result, err
		}
	}
	switch request.Action {
	case "transfer-reserve":
		if t.result.Phase != "" && t.result.Phase != "reserved" {
			return &t.result, errors.New("standard transfer cannot reserve entered work")
		}
		err = t.persist(ctx, lease, "reserved")
	case "transfer-current":
		if time.Now().UnixNano() >= t.request.DeadlineNS {
			return &t.result, context.DeadlineExceeded
		}
		if t.result.Phase != "reserved" || t.pendingPhase != "" {
			return &t.result, errors.New("standard transfer is no longer an unentered predecessor")
		}
		err = t.slot.current(ctx, lease)
		if err == nil {
			err = t.native.Exclusive(ctx)
		}
	case "transfer-held":
		err = t.native.Exclusive(ctx)
	case "transfer-commit":
		if err = s.loadProfiles(); err != nil {
			return &t.result, err
		}
		s.app.mu.Lock()
		target, found := s.app.profileByIDLocked(t.request.ProfileID)
		s.app.mu.Unlock()
		if !found || desktopOwnedNodeProfileToken(target) != t.request.ProfileRevision || desktopOwnedNodeProtectionPolicy(target) != t.request.Destination.Policy || target.HomeLANAccess != t.request.Destination.HomeLAN {
			return &t.result, errors.New("transfer destination changed before original admission")
		}
		if time.Now().UnixNano() >= t.request.DeadlineNS {
			return &t.result, context.DeadlineExceeded
		}
		call, cancel := context.WithDeadline(ctx, time.Unix(0, t.request.DeadlineNS))
		defer cancel()
		ctx = call
		if !t.sourceJoined(s) || !t.slot.detached || q.Snapshot == nil || q.Prepared == nil || q.Prepared.Validate() != nil || q.Prepared.Protection != q.Snapshot.Record || q.Prepared.Policy != q.Destination.Policy || q.Prepared.Guardian.Engine.BootID != peer.record.BootID || q.Prepared.Guardian.Engine.ProcParentID != peer.record.ProcProcessID || q.Prepared.Guardian.Engine.NetworkNamespace != peer.record.NetworkNamespace || q.Prepared.Guardian.Engine.PIDNamespace != peer.record.PIDNamespace || q.Snapshot.Record.Capture.SessionID != q.Destination.SessionID || q.Snapshot.Record.Capture.SourceSHA256 != q.Destination.SourceSHA256 || q.Snapshot.HomeLAN != q.Destination.HomeLAN {
			return &t.result, errors.New("standard transfer preceded source join or changed destination")
		}
		if t.snapshot != nil && (!reflect.DeepEqual(*t.snapshot, *q.Snapshot) || !reflect.DeepEqual(*t.prepared, *q.Prepared)) {
			return &t.result, errors.New("transfer cannot replace its first captured successor inventory")
		}
		if t.snapshot == nil {
			copy := *q.Snapshot
			copy.Inventory = append([]byte(nil), q.Snapshot.Inventory...)
			t.snapshot = &copy
			prepared := *q.Prepared
			t.prepared = &prepared
			raw, _ := json.Marshal(struct {
				Snapshot mobiletor.DesktopLinuxNodeTransferSnapshot
				Prepared linuxprotection.NodePreparedRecord
			}{copy, prepared})
			digest := sha256.Sum256(raw)
			t.result.DestinationSHA256 = hex.EncodeToString(digest[:])
		}
		if t.result.Phase == "reserved" || t.pendingPhase == "entered" {
			if err = t.persist(ctx, lease, "entered"); err != nil {
				return &t.result, err
			}
		}
		if t.result.Phase != "entered" && t.result.Phase != "committed" {
			return &t.result, errors.New("standard transfer omitted its durable removal intent")
		}
		if err = t.native.Commit(ctx, *q.Snapshot, lease.lock); err != nil {
			return &t.result, err
		}
		t.result.Committed = true
		err = t.persist(ctx, lease, "committed")
	case "transfer-resolve":
		// Once Finish has positively joined the original native result, later
		// retries only finish that exact durable cleanup. The creator may have
		// intentionally closed some/all descriptors in slot.release already.
		if !t.nativeFinished {
			committed, resultErr := t.native.Result(ctx)
			if resultErr != nil {
				return &t.result, resultErr
			}
			t.result.Committed = committed
			phase := "aborted"
			if committed {
				phase = "committed"
			}
			if t.pendingPhase != "" {
				if err = t.persist(ctx, lease, t.pendingPhase); err != nil {
					return &t.result, err
				}
			}
			if !t.slot.stateRemoved {
				if err = t.persist(ctx, lease, phase); err != nil {
					return &t.result, err
				}
			}
			if _, err = t.native.Finish(ctx); err != nil {
				return &t.result, err
			}
			t.nativeFinished = true
		} else if t.pendingPhase != "" {
			if err = t.persist(ctx, lease, t.pendingPhase); err != nil {
				return &t.result, err
			}
		}
		if t.result.Committed {
			t.slot.removed = true
			if err = t.slot.release(ctx, lease); err != nil {
				return &t.result, err
			}
			t.result.Phase = "settled"
		}
		// Validate the replying peer before intentionally retiring the original
		// boot conversation. An overtaken unsent resolve may own this same peer.
		if err = errors.Join(ctx.Err(), peer.Current(ctx)); err != nil {
			return &t.result, err
		}
		if err = t.finishBootPeer(); err != nil {
			return &t.result, err
		}
		if q.Boot && t.result.Committed && s.boot == t.slot {
			s.boot = nil
		}
		s.transferHistory[q.ID] = t.result
	default:
		return nil, errors.New("standard transfer action is unavailable")
	}
	if request.Action == "transfer-resolve" && t.request.Boot && t.bootPeerClosed {
		return &t.result, errors.Join(err, ctx.Err())
	}
	return &t.result, errors.Join(err, ctx.Err(), peer.Current(ctx))
}

func (s *linuxStandardService) transferPending() bool {
	return s.transfer != nil && !s.transfer.terminal()
}
func standardTransferAction(action string) bool { return strings.HasPrefix(action, "transfer-") }

func (t *linuxStandardServiceTransfer) terminal() bool {
	return t != nil && (!t.request.Boot || t.bootPeerClosed) && t.nativeFinished && t.pendingPhase == "" && (t.result.Phase == "settled" || t.result.Phase == "aborted")
}

func (t *linuxStandardServiceTransfer) sourceRequestSession() string {
	if t.requestSession != "" {
		return t.requestSession
	}
	return t.result.Intent.SourceSession
}
func (t *linuxStandardServiceTransfer) sourceStillCaptured(s *linuxStandardService) bool {
	if t.request.Boot {
		return t.session == nil && s.boot == t.slot && t.slot != nil
	}
	return t.session == s.session
}
func (t *linuxStandardServiceTransfer) sourceJoined(s *linuxStandardService) bool {
	if t.request.Boot {
		return t.sourceStillCaptured(s) && (s.session == nil || s.session.joined && !s.session.cleanupPending)
	}
	return t.session != nil && t.session == s.session && t.session.joined && !t.session.cleanupPending
}
func (t *linuxStandardServiceTransfer) finishBootPeer() error {
	if !t.request.Boot || t.bootPeerClosed {
		return nil
	}
	if t.peer == nil {
		return errors.New("boot transfer lost retained authenticated peer")
	}
	if err := t.peer.Close(); err != nil {
		return err
	}
	t.bootPeerClosed = true
	return nil
}
