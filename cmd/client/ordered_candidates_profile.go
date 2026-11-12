package main

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

type orderedCandidateSaveRequest struct {
	RequestID    string                         `json:"request_id"`
	ViewToken    string                         `json:"view_token"`
	CandidateID  string                         `json:"candidate_id"`
	Name         string                         `json:"name"`
	ProposedPath []common.MultihopNodeSelection `json:"proposed_path"`
}

// This endpoint saves a complete draft for the next connection. It neither
// replaces active profile records nor alters the retained native runtime.
func (a *app) saveOrderedCandidateProfile(w http.ResponseWriter, r *http.Request) {
	var q orderedCandidateSaveRequest
	if !viaEntryDecode(w, r, &q) {
		return
	}
	q.Name = strings.TrimSpace(q.Name)
	if !validViaEntryRequestID(q.RequestID) || !validProfileID(q.CandidateID) || q.ViewToken == "" || validateConnectionProfileName(q.Name) != nil {
		http.Error(w, "an exact receipt, candidate and explicit profile name are required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if !a.operationMu.TryLock() {
		http.Error(w, "another operation owns the active path", 409)
		return
	}
	defer a.operationMu.Unlock()
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	owner := c.owner
	if !orderedCandidateAdoptable(owner, q, time.Now()) {
		c.mu.Unlock()
		http.Error(w, "candidate receipt is expired, cancelled or not drained; retest", 409)
		return
	}
	job := owner.ordered
	c.mu.Unlock()
	// Completed measurements release their hold so Auto can resume while rows
	// are displayed. Reacquire the exact launch before observing the original
	// reader, and keep it through publication. A reader changed by Auto during
	// that interval is rejected, never adopted as the measured reader.
	finishHold, err := beginDesktopNodeChainMeasurementHold(ctx, a, job.catalog.launch)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	defer finishHold(true)
	if err := job.observeAdoption(ctx); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	candidate, found := a.profileByIDLocked(q.CandidateID)
	profiles := make([]common.RouterProfile, len(a.profiles.Profiles))
	for i, p := range a.profiles.Profiles {
		profiles[i] = cloneRouterProfile(p)
	}
	revision, err := a.candidateCatalogRevisionLocked()
	a.mu.Unlock()
	if !found || err != nil || revision != job.catalog.revision {
		http.Error(w, "original saved candidate catalog changed", 409)
		return
	}
	control, nodes, err := orderedCandidateProposal(job.view.identity.Ordered.launch.chain.selection.Nodes, job.view.position, candidate, profiles)
	if err != nil || !reflect.DeepEqual(nodes, q.ProposedPath) {
		http.Error(w, "proposed path differs from the exact supported replacement or insertion", 409)
		return
	}
	for i := range profiles {
		if profiles[i].ID == control.ID {
			profiles[i] = control
		}
	}
	compiled, err := captureDesktopNodeChain(ctx, job.catalog.launch.root, control, profiles, nodes, "local", nil)
	if err != nil {
		http.Error(w, "proposed full path failed original source compilation: "+err.Error(), 409)
		return
	}
	if err = job.observeAdoption(ctx); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	// The existing admission lock includes the public Stop/shutdown transaction.
	// Receipt/source checks and atomic profile-store publication share this lock.
	release, err := a.lockCandidatePublicationContext(ctx, c)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	defer release()
	if c.owner != owner || !orderedCandidateAdoptable(owner, q, time.Now()) {
		http.Error(w, "original candidate receipt changed before profile save", 409)
		return
	}
	revision, err = a.candidateCatalogRevisionLocked()
	if err != nil || revision != job.catalog.revision || !orderedCandidateOwnerStillLocked(a, job.view.identity) {
		http.Error(w, "original owner or source catalog changed during profile save", 409)
		return
	}
	if err = compiled.validate(ctx, control, profiles); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	record, err := a.orderedCandidateProfileRecordLocked(control, q.Name)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if len(store.Profiles) >= connectionProfileStoreMaxEntries {
		http.Error(w, "connection profile limit reached", 409)
		return
	}
	if ctx.Err() != nil {
		http.Error(w, ctx.Err().Error(), 408)
		return
	}
	if err = compiled.validate(ctx, control, profiles); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	store.Profiles = append(store.Profiles, record)
	if err = persistConnectionProfileStore(a, store); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	job.accepted = false // one explicit save per receipt, no duplicate retries
	viaEntryJSON(w, map[string]any{"ok": true, "profile_id": record.ID, "profile_name": record.Name, "proposed_path": nodes, "active_path_changed": false, "note": "Saved for the next connection. Disconnect before loading this complete profile."})
}

// Caller holds the original publication locks. No callback or native observer
// runs under app.mu; catalog.current already proved the protected owner.
func orderedCandidateOwnerStillLocked(a *app, id speedLabPathIdentity) bool {
	raw, ok := nativeMultihopOwners.Load(a)
	graph, exists := getActiveMultihopGraph(a)
	tracker, registered := sessionTrackers.Load(a)
	if !registered || tracker != id.Tracker || id.Tracker == nil || id.Tracker.session == nil {
		return false
	}
	session := id.Tracker.session
	if session.ID != id.SessionID || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" {
		return false
	}
	return ok && raw == id.Ordered && exists && graph == id.Graph && a.cmd == id.Command && a.state.Connected && a.state.Phase == "connected" && mtuStateSnapshotToken(a.state) == id.StateToken
}
func orderedCandidateAdoptable(owner *viaEntryOwner, q orderedCandidateSaveRequest, now time.Time) bool {
	if owner == nil || owner.id != q.RequestID || owner.running || !owner.drained || owner.cancelled || owner.ordered == nil {
		return false
	}
	job := owner.ordered
	if !job.accepted || job.invalidated || job.lost.Load() || job.catalog == nil || job.observation == nil || job.view.token != q.ViewToken {
		return false
	}
	for _, row := range job.results {
		if row.CandidateID == q.CandidateID && validateDesktopNodeChainCandidateStatus(job.catalog.plan, q.CandidateID, row, now) == nil {
			return true
		}
	}
	return false
}
func (a *app) orderedCandidateProfileRecordLocked(control common.RouterProfile, name string) (connectionProfileRecord, error) {
	var record connectionProfileRecord
	prefs, err := snapshotConnectionPreferences(control, control.CustomLayers)
	if err != nil {
		return record, err
	}
	captures, err := a.snapshotConnectionNodeChainLocked(control, prefs)
	if err != nil {
		return record, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record = connectionProfileRecord{ID: newID(), Name: name, NodeID: control.ID, NodeProofID: control.NodeProofID, Mode: "shadowsocks", Prefs: prefs, NodeChain: captures, CreatedAt: now, UpdatedAt: now}
	if len(captures) == 0 {
		return record, errors.New("next-connection profile lost its complete ordered path")
	}
	return record, validateSavedNodeChain(record)
}

func (job *orderedCandidateJob) observeAdoption(ctx context.Context) error {
	if job == nil || job.observation == nil || job.lost.Load() {
		return errors.New("candidate receipt has no retained original proof")
	}
	err := job.observation.current(ctx, job.catalog)
	if err == nil {
		err = job.catalog.current(ctx)
	}
	err = errors.Join(err, ctx.Err())
	if err != nil {
		job.lost.Store(true)
	}
	return err
}
