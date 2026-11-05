//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

// One original connection operation retains this object from preflight through
// source join, native transfer and any later bounded cleanup. Neither journal
// records nor service replies can construct this controller-side capability.
type linuxStandardServiceNodeTransfer struct {
	owner               *linuxStandardServiceLaunch
	host                *desktopLinuxNodeHost
	operation           context.Context
	request             linuxStandardServiceTransferRequest
	intent              atomic.Pointer[linuxprotection.StandardNodeTransfer]
	pin                 *mobiletor.DesktopLinuxNodeTransferPin
	destinationSHA256   string
	serviceSettled      bool
	mu                  sync.Mutex // Serializes RPC, pin and successor digest; acquired before owner.mu.
	attempted           bool
	committed, resolved atomic.Bool
}

func captureLinuxStandardServiceNodeTransfer(ctx context.Context, h *desktopLinuxNodeHost) (*linuxStandardServiceNodeTransfer, error) {
	if h == nil || h.external != nil {
		return nil, nil
	}
	raw, exists := linuxStandardServiceOwners.Load(h.parent.app)
	if !exists {
		return nil, nil
	}
	o, ok := raw.(*linuxStandardServiceLaunch)
	if !ok || o == nil || o.app != h.parent.app {
		return nil, errors.New("Node transfer found a foreign standard service owner")
	}
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return nil, err
	}
	defer o.mu.Unlock()
	if o.transfer != nil && !o.transfer.resolved.Load() {
		return nil, errors.New("finish the original service-to-Node transfer first")
	}
	if !o.attempted || o.peer == nil || o.prepared == nil || o.prepared.protectionPolicy == "off" {
		return nil, errors.New("Node transfer requires its actual protected installed service")
	}
	if err := desktopnetwork.LockContext(ctx, &o.app.mu); err != nil {
		return nil, err
	}
	selected := o.app.cmd == o.prepared.command && !o.joined || o.app.cmd == nil && o.joined
	current := o.app.checkCapturedConnectionOperationLocked(h.operation)
	o.app.mu.Unlock()
	if !selected || current != nil {
		return nil, errors.Join(current, errors.New("Node transfer replaced its original service runtime"))
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("Node transfer omitted its original startup deadline")
	}
	if bound := time.Now().Add(120 * time.Second); bound.Before(deadline) {
		deadline = bound
	}
	deadline = deadline.Add(-2 * time.Millisecond)
	t := &linuxStandardServiceNodeTransfer{owner: o, host: h, operation: h.operation, request: linuxStandardServiceTransferRequest{ID: id, DeadlineNS: deadline.UnixNano(), Destination: h.selection, ProfileID: desktopExternalPathProfileID(h.launch), ProfileRevision: h.revision}}
	t.mu.Lock() // New object is unpublished; no other transfer caller can hold it.
	defer t.mu.Unlock()
	o.transfer = t
	h.standardTransfer = t // retained before a lost reservation response
	_, err = t.rpcLocked(ctx, "transfer-reserve", nil, nil)
	return t, err
}

func (t *linuxStandardServiceNodeTransfer) rpcLocked(ctx context.Context, action string, snapshot *mobiletor.DesktopLinuxNodeTransferSnapshot, prepared *linuxprotection.NodePreparedRecord) (*linuxStandardServiceTransferResponse, error) {
	o := t.owner
	raw, ok := linuxStandardServiceOwners.Load(o.app)
	if !ok || raw != o || o.transfer != t || o.peer == nil {
		return nil, errors.New("transfer lost its original controller/service owner")
	}
	q := t.request
	q.Snapshot = snapshot
	q.Prepared = prepared
	request := linuxStandardServiceRequest{Schema: 1, Action: action, Session: o.request.Session, Transfer: &q}
	exchange := o.exchange
	if exchange == nil {
		exchange = func(ctx context.Context, r linuxStandardServiceRequest, directory *os.File, before func()) (linuxStandardServiceResponse, error) {
			return linuxStandardServiceRPC(ctx, o.image, o.prepared.namespaceInfo, &o.peer, r, directory, before)
		}
	}
	response, err := exchange(ctx, request, nil, func() { t.attempted = true })
	result := response.Transfer
	if result != nil {
		expected := result.Intent
		if expected.Validate() != nil || expected.ID != q.ID || expected.DeadlineNS != q.DeadlineNS || expected.SourceSession != o.request.Session || expected.SourceConfigSHA256 != o.request.ConfigSHA256 || expected.Destination != q.Destination || expected.ProfileID != q.ProfileID || expected.ProfileRevision != q.ProfileRevision || t.intent.Load() != nil && *t.intent.Load() != expected {
			return nil, errors.Join(err, errors.New("transfer response changed its immutable original intent"))
		}
		if t.intent.Load() == nil {
			copy := expected
			t.intent.Store(&copy)
		}
		if result.Committed {
			if t.destinationSHA256 == "" || result.DestinationSHA256 != t.destinationSHA256 {
				return nil, errors.New("transfer completion substituted its captured successor inventory")
			}
			t.committed.Store(true)
		}
	}
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, errors.New("transfer omitted authenticated original completion")
	}
	return result, nil
}

func (t *linuxStandardServiceNodeTransfer) current(ctx context.Context, admission bool) error {
	if t == nil || t.owner == nil || t.host == nil {
		return errors.New("transfer lost its actual original capture")
	}
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if admission && (t.operation.Err() != nil || t.resolved.Load() || time.Now().UnixNano() >= t.request.DeadlineNS) {
		return errors.Join(t.operation.Err(), errors.New("transfer admission passed its original operation deadline"))
	}
	if err := t.host.parent.retirementCurrent(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &t.owner.mu); err != nil {
		return err
	}
	defer t.owner.mu.Unlock()
	action := "transfer-held"
	if admission {
		action = "transfer-current"
	}
	_, err := t.rpcLocked(ctx, action, nil, nil)
	return err
}
func (t *linuxStandardServiceNodeTransfer) journalIntent() *linuxprotection.StandardNodeTransfer {
	if t == nil || t.intent.Load() == nil {
		return nil
	}
	copy := *t.intent.Load()
	return &copy
}

func (t *linuxStandardServiceNodeTransfer) commit(ctx context.Context, tx *desktopLinuxNodeTransaction, prepared linuxprotection.NodePreparedRecord) error {
	if t == nil {
		return errors.New("Node transfer lost its original capture")
	}
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if t == nil || tx == nil || tx.baseline == nil || tx.standardTransfer != t || t.intent.Load() == nil || t.resolved.Load() || t.operation.Err() != nil || tx.selection != t.request.Destination || !reflect.DeepEqual(tx.head.Record.Transfer, t.intent.Load()) {
		return errors.New("Node transfer lost its original prepared transaction")
	}
	call, cancel := context.WithDeadline(ctx, time.Unix(0, t.request.DeadlineNS))
	defer cancel()
	if t.pin == nil {
		pin, err := tx.baseline.PinStandardTransfer(call, t.request.ID)
		if err != nil {
			return err
		}
		t.pin = pin
	}
	if err := desktopnetwork.LockContext(call, &t.owner.mu); err != nil {
		return err
	}
	defer t.owner.mu.Unlock()
	err := t.pin.WithSnapshot(call, func(snapshot mobiletor.DesktopLinuxNodeTransferSnapshot) error {
		raw, _ := json.Marshal(struct {
			Snapshot mobiletor.DesktopLinuxNodeTransferSnapshot
			Prepared linuxprotection.NodePreparedRecord
		}{snapshot, prepared})
		digest := sha256.Sum256(raw)
		t.destinationSHA256 = hex.EncodeToString(digest[:])
		_, err := t.rpcLocked(call, "transfer-commit", &snapshot, &prepared)
		return err
	})
	if err != nil {
		return err
	}
	if !t.committed.Load() {
		return errors.New("service did not acknowledge original source removal")
	}
	return t.resolveLocked(call)
}

func (t *linuxStandardServiceNodeTransfer) resolveLocked(ctx context.Context) error {
	if t.resolved.Load() {
		return nil
	}
	if !t.serviceSettled {
		result, err := t.rpcLocked(ctx, "transfer-resolve", nil, nil)
		if err != nil {
			return err
		}
		if result.Phase != "aborted" && result.Phase != "settled" {
			return errors.New("transfer cleanup did not settle its original native result")
		}
		t.committed.Store(result.Committed)
		t.serviceSettled = true
	}
	if t.pin != nil {
		if err := t.pin.Resolve(ctx); err != nil {
			return err
		}
	}
	if t.committed.Load() {
		if t.owner.peer != nil {
			if err := t.owner.peer.Close(); err != nil {
				return err
			}
			t.owner.peer = nil
		}
		// The old service launch no longer owns protection. Its old Stop/callback
		// can never select or clear the current Node command.
		if !linuxStandardServiceOwners.CompareAndDelete(t.owner.app, t.owner) {
			return errors.New("transfer settlement replaced the original service owner")
		}
	}
	t.resolved.Store(true)
	return nil
}
func (t *linuxStandardServiceNodeTransfer) resolve(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if err := desktopnetwork.LockContext(ctx, &t.mu); err != nil {
		return err
	}
	defer t.mu.Unlock()
	if t.resolved.Load() {
		return nil
	}
	if err := desktopnetwork.LockContext(ctx, &t.owner.mu); err != nil {
		return err
	}
	defer t.owner.mu.Unlock()
	return t.resolveLocked(ctx)
}

func (j *desktopLinuxNodeJournal) bindStandardTransfer(ctx context.Context, t *linuxStandardServiceNodeTransfer) error {
	if j.transfer == t {
		return nil
	}
	if t == nil || t.intent.Load() == nil || !sameDesktopLinuxParentCapture(t.host.parent, j.parent) || j.transfer != nil && (!j.transfer.resolved.Load() || j.transfer.committed.Load()) {
		return errors.New("journal cannot replace an unresolved original service transfer")
	}
	if err := t.current(ctx, true); err != nil {
		return err
	}
	selected, err := j.Snapshot(ctx)
	if err != nil {
		return err
	}
	if selected.Incomplete || selected.Record.Phase != "settled" || selected.Record.Committed != (linuxprotection.JournalState{}) {
		return errors.New("new service reservation requires its exact empty joined checkpoint")
	}
	next := linuxprotection.CloneRecord(selected.Record)
	next.Sequence++
	next.PreviousSHA256 = selected.SHA256
	next.Transfer = t.journalIntent()
	saved, err := j.Append(ctx, selected.SHA256, next)
	if sameDesktopLinuxJournalSelection(saved, next) {
		j.transfer = t
	}
	return err
}
