//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
)

// This is a read-only presentation of already retained owners. It never opens
// a journal, reconstructs an nft creator or creates a controller/session. Its
// token compares a UI request; only the original native transaction can remove
// protection. Failed capture is represented as pending, never as absence.
type desktopPlatformProtectionCapture struct {
	standard                                             *linuxStandardServiceProtectionCapture
	standardProfilePath                                  string
	controller                                           *ownedDesktopController
	parent                                               *desktopLinuxNodeParent
	session                                              *desktopLinuxNodeSession
	active                                               *desktopLinuxNodeHost
	predecessor                                          *desktopLinuxNodeTransaction
	journal                                              *desktopLinuxNodeJournal
	off                                                  *desktopLinuxNodeProtectionOff
	head                                                 linuxprotection.JournalSelection
	profileID                                            string
	policy                                               string
	failure                                              error
	removed, absenceProved, profileWritten, profileSaved bool
	originalRevision, resultRevision, pendingToken       string
}

func (a *app) captureDesktopParentProfileProtection() *desktopPlatformProtectionCapture {
	return a.captureDesktopParentProfileProtectionContext(context.Background())
}

func (a *app) captureDesktopParentProfileProtectionContext(caller context.Context) *desktopPlatformProtectionCapture {
	if caller == nil {
		return &desktopPlatformProtectionCapture{failure: errors.New("Linux protection observation requires its original caller")}
	}
	ctx, cancel := context.WithTimeout(caller, 2*time.Second)
	defer cancel()
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return &desktopPlatformProtectionCapture{failure: err}
	}
	controller := a.localController
	a.mu.Unlock()
	if controller == nil || controller.nodeParent == nil {
		return nil
	}
	parent, ok := controller.nodeParent.(*desktopLinuxNodeParent)
	if !ok || parent == nil {
		return &desktopPlatformProtectionCapture{controller: controller, failure: errors.New("Linux protection has another original parent")}
	}
	capture := &desktopPlatformProtectionCapture{controller: controller, parent: parent}
	select {
	case <-ctx.Done():
		capture.failure = ctx.Err()
		return capture
	case <-parent.gate:
	}
	session := parent.session
	parent.gate <- struct{}{}
	if session == nil {
		return nil
	}
	capture.session = session
	if err := session.enter(ctx); err != nil {
		capture.failure = err
		return capture
	}
	defer func() { session.gate <- struct{}{} }()
	capture.active, capture.predecessor, capture.journal, capture.off = session.active, session.predecessor, session.journal, session.off
	if session.parent == nil || session.parent.app != a || session.parent.parent != parent || session.parent.controller != controller ||
		session.closed || session.released || session.journalErr != nil {
		capture.failure = errors.New("Linux protection lost its original retained session or journal")
		return capture
	}
	if session.active == nil && session.predecessor == nil && session.off == nil {
		// A never-used session has no native claim. A completed Off/Disconnect
		// must retain its exact empty journal and independently observed absence.
		if err := session.unclaimedStopLocked(ctx); err != nil {
			capture.failure = err
			return capture
		}
		return nil
	}
	transaction := session.predecessor
	if host := session.active; host != nil {
		if err := host.enter(ctx); err != nil {
			capture.failure = err
			return capture
		}
		transaction = host.transaction
		host.gate <- struct{}{}
	}
	if transaction == nil {
		capture.failure = errors.New("Linux protection preparation has not joined its original transaction")
		return capture
	}
	if err := transaction.enter(ctx); err != nil {
		capture.failure = err
		return capture
	}
	defer func() { transaction.gate <- struct{}{} }()
	if !sameDesktopLinuxParentCapture(transaction.parent, session.parent) || transaction.journal != session.journal {
		capture.failure = errors.New("Linux protection belongs to a replaced source or journal")
		return capture
	}
	capture.head = transaction.head
	capture.head.Record = linuxprotection.CloneRecord(transaction.head.Record)
	capture.profileID, capture.policy = transaction.profileID, transaction.selection.Policy
	if off := session.off; off != nil {
		if off.session != session || off.transaction != transaction || transaction.off != off {
			capture.failure = errors.New("Linux protection lost its accepted Off owner")
			return capture
		}
		capture.removed, capture.absenceProved = transaction.baselineReleased, off.absenceProved
		capture.profileWritten, capture.profileSaved = off.profileWritten, off.profileSaved
		capture.originalRevision, capture.resultRevision, capture.pendingToken = off.profileRevision, off.resultRevision, off.token
	}
	return capture
}

func (c *desktopPlatformProtectionCapture) token(revision string) string {
	if c.standard != nil {
		return c.standardToken(revision)
	}
	if c.off != nil && c.pendingToken != "" && (revision == c.originalRevision || revision == c.resultRevision) {
		return c.pendingToken
	}
	var parent linuxprotection.ParentRecord
	if c.parent != nil {
		parent = c.parent.record
	}
	raw, _ := json.Marshal(struct {
		Kind, Revision, Profile, Policy string
		Parent                          linuxprotection.ParentRecord
		Head                            linuxprotection.JournalSelection
		Active, Unavailable             bool
	}{"routervpn-linux-protection-revision-v1", revision, c.profileID, c.policy, parent, c.head, c.active != nil, c.failure != nil})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (c *desktopPlatformProtectionCapture) settings(value profileProtectionSettings) profileProtectionSettings {
	if c.standard != nil {
		return c.standardSettings(value)
	}
	value.ProtectionProfileID = c.profileID
	switch {
	case c.failure != nil:
		value.ProtectionStatus, value.EffectivePolicy = "pending", "unknown"
		value.Message = "Linux protection still has an unresolved original owner. Finish its cleanup before changing protection."
	case c.off != nil:
		value.ProtectionStatus, value.EffectivePolicy = "off-pending", "unknown"
		value.Message = "Turning the kill switch off is pending. Retry Off to finish the same change."
		if c.removed && c.absenceProved {
			value.ProtectionStatus, value.EffectivePolicy = "off-unsaved", "off"
			value.Message = errDesktopProtectionOffUnsaved.Error()
			if c.profileWritten {
				value.Message = "The kill switch is off. Its saved preference still needs verification; retry Off to finish."
			}
			if c.profileSaved {
				value.ProtectionStatus = "off-pending"
				value.Message = "The kill switch is off and its preference is saved. Retry Off to finish protection cleanup."
			}
		}
	default:
		value.ProtectionStatus, value.EffectivePolicy = "retained", c.policy
		if c.active != nil {
			value.ProtectionStatus = "active"
		}
		if c.profileID != value.ProfileID {
			value.Message = "Protection still belongs to another node. Select that node to turn its kill switch off."
		}
	}
	return value
}

// The common handler holds app.mu here, after the platform's gated comparison
// and before persistence. operationMu prevents a legitimate session succession.
func (c *desktopPlatformProtectionCapture) currentAppLocked(a *app) bool {
	if c != nil && c.standard != nil {
		return c.failure == nil && c.standardProfilePath == a.cfg.ProfilesFile && c.standard.currentAppLocked(a)
	}
	return c == nil || c.failure == nil && c.controller != nil && a.localController == c.controller &&
		c.controller.nodeParent == c.parent && c.session != nil && c.session.parent.currentAppLocked(false) == nil && a.nodeProtection == nil
}

func samePlatformProtectionCapture(a, b *desktopPlatformProtectionCapture) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.standard != nil || b.standard != nil {
		return a.failure == nil && b.failure == nil && a.standard != nil && b.standard != nil && a.standardProfilePath == b.standardProfilePath && a.standard.same(b.standard)
	}
	return a.failure == nil && b.failure == nil && a.controller == b.controller && a.parent == b.parent && a.session == b.session &&
		a.active == b.active && a.predecessor == b.predecessor && a.journal == b.journal && a.off == b.off &&
		a.profileID == b.profileID && a.policy == b.policy && reflect.DeepEqual(a.head, b.head)
}

func (a *app) handlePlatformProfileProtection(w http.ResponseWriter, r *http.Request, profile common.RouterProfile, capture profileProtectionCapture, policy string) bool {
	if capture.slot != nil { // Explicit other-platform fixtures retain their original backend.
		return false
	}
	current := a.capturePlatformProfileProtection()
	if !samePlatformProtectionCapture(capture.platform, current) {
		http.Error(w, "Linux protection ownership changed; refresh before changing protection", http.StatusConflict)
		return true
	}
	if current == nil {
		return false
	}
	if current.standard != nil {
		return a.handleStandardServiceProfileProtection(w, r, profile, capture, current, policy)
	}
	if current.off != nil && policy != "off" || current.active != nil || current.profileID != profile.ID {
		http.Error(w, "select the retained disconnected node and finish its pending Off change before changing protection", http.StatusConflict)
		return true
	}
	if policy != "off" {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	updated, err := current.session.applyProtectionOff(ctx, current, capture)
	if err != nil {
		a.mu.Lock()
		if latest, exists := a.profileByIDLocked(profile.ID); exists {
			profile = cloneRouterProfile(latest)
		}
		a.mu.Unlock()
		value := protectionSettingsWithCapture(profile, a.captureProfileProtection(profile))
		if value.Message == "" {
			value.Message = "The protection change did not finish. Refresh and retry Off."
		}
		status := http.StatusServiceUnavailable
		if errors.Is(err, errDesktopProtectionOffUnsaved) {
			status = http.StatusInternalServerError
		}
		writeProfileProtectionValue(w, status, value)
		return true
	}
	cancelPendingStartupPolicy(a)
	writeProfileProtectionValue(w, http.StatusOK, protectionSettingsWithCapture(updated, a.captureProfileProtection(updated)))
	return true
}

func (a *app) guardPlatformProtectionOffPending() error {
	return a.guardPlatformProtectionOffPendingContext(context.Background())
}

func (a *app) guardPlatformProtectionOffPendingContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Linux protection admission requires its original live caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	capture := a.capturePlatformProfileProtectionContext(ctx)
	if capture != nil && capture.standard != nil {
		if capture.failure != nil || capture.standard.Failure != nil || capture.standard.Pending || capture.standard.Active {
			return errors.Join(errors.New("finish the pending original standard-service protection change before another operation"), capture.failure, capture.standard.Failure, ctx.Err())
		}
		return ctx.Err()
	}
	if capture != nil && (capture.off != nil || capture.failure != nil) {
		return errors.Join(errors.New("finish the pending Linux Kill Switch Off change or original protection cleanup before another operation"), capture.failure, ctx.Err())
	}
	return ctx.Err()
}

func (a *app) guardPlatformProtectionPreference(policy string) error {
	if strings.EqualFold(strings.TrimSpace(policy), "off") && a.capturePlatformProfileProtection() != nil {
		return errors.New("use the Kill switch control to finish turning retained Linux protection off before saving Off here")
	}
	return nil
}
