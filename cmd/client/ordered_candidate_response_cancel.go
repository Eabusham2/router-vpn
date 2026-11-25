package main

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

// A connected cancellation retains only the original public view identities.
// It grants no native capability, and cannot revive a request after cancellation.
type orderedCandidateResponseAdmission struct {
	token               string
	position            int
	epoch               uint64
	nodes               []orderedCandidateResponseSourceNode
	owners              []string
	selected, requested string
	created             time.Time
	started             bool
	drained             bool
}

func rememberOrderedCandidateResponseViewLocked(c *viaEntryControl, view *orderedCandidateView) error {
	if len(view.responseNodes) == 0 {
		return nil
	}
	c.pruneNoncesLocked()
	if len(c.orderedResponseViews) >= 1024 {
		return errors.New("connected source view history is full; retry shortly")
	}
	if c.orderedResponseViews == nil {
		c.orderedResponseViews = map[string]*orderedCandidateResponseAdmission{}
	}
	c.orderedResponseViews[view.token] = &orderedCandidateResponseAdmission{
		token: view.token, position: view.position, epoch: view.responseEpoch,
		owners: slices.Clone(view.responseOwners), requested: view.responseRequested, selected: view.responseSelected, nodes: slices.Clone(view.responseNodes), created: time.Now(), drained: true,
	}
	return nil
}

func reserveOrderedCandidateResponseAdmissionLocked(c *viaEntryControl, id string, view *orderedCandidateView) error {
	if len(view.responseNodes) == 0 {
		return nil
	}
	recorded := c.orderedResponseViews[view.token]
	if recorded == nil || c.orderedResponseAdmissions[id] != nil || len(c.orderedResponseAdmissions) >= 1024 {
		return errors.New("connected response request lost its original issued view")
	}
	if c.orderedResponseAdmissions == nil {
		c.orderedResponseAdmissions = map[string]*orderedCandidateResponseAdmission{}
	}
	record := *recorded
	record.created, record.started, record.drained = time.Now(), true, false
	c.orderedResponseAdmissions[id] = &record
	return nil
}

func (c *viaEntryControl) pruneOrderedCandidateResponseNoncesLocked() {
	for token, record := range c.orderedResponseViews {
		if time.Since(record.created) > 5*time.Minute {
			delete(c.orderedResponseViews, token)
		}
	}
	for id, record := range c.orderedResponseAdmissions {
		if time.Since(record.created) > 5*time.Minute && (c.owner == nil || c.owner.id != id) {
			delete(c.orderedResponseAdmissions, id)
		}
	}
}

func (a *app) orderedCandidateConnectedCancel(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestID string `json:"request_id"`
		ViewToken string `json:"view_token"`
	}
	if !viaEntryDecode(w, r, &q) {
		return
	}
	if !validViaEntryRequestID(q.RequestID) {
		http.Error(w, "invalid candidate request identity", 400)
		return
	}
	if q.ViewToken == "" {
		a.cancelViaEntryCandidate(w, r, q.RequestID, nil)
		return
	}
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(r.Context(), &c.mu); err != nil {
		http.Error(w, "candidate cancellation could not enter its original control", 408)
		return
	}
	c.pruneNoncesLocked()
	admission := c.orderedResponseAdmissions[q.RequestID]
	if admission == nil {
		recorded := c.orderedResponseViews[q.ViewToken]
		_, used := c.seen[q.RequestID]
		if recorded == nil || used || len(c.orderedResponseAdmissions) >= 1024 || len(c.seen) >= 1024 {
			c.mu.Unlock()
			http.Error(w, "connected cancellation lost its original bounded view", 409)
			return
		}
		if c.orderedResponseAdmissions == nil {
			c.orderedResponseAdmissions = map[string]*orderedCandidateResponseAdmission{}
		}
		record := *recorded
		record.created = time.Now()
		c.orderedResponseAdmissions[q.RequestID], admission = &record, &record
		// Reserve the nonce in the same snapshot so a delayed start cannot
		// enter another candidate purpose before this cancellation joins.
		c.seen[q.RequestID] = time.Now()
	}
	if admission.token != q.ViewToken {
		c.mu.Unlock()
		http.Error(w, "connected cancellation cannot adopt another view", 409)
		return
	}
	c.mu.Unlock()
	a.cancelViaEntryCandidateWithResponse(w, r, q.RequestID, nil, admission)
}

func writeOrderedCandidateResponseCancel(w http.ResponseWriter, c *viaEntryControl, owner *viaEntryOwner, id string, admission *orderedCandidateResponseAdmission, failure error) {
	if !c.mu.TryLock() {
		http.Error(w, "Original candidate cleanup is still joining; Cancel retries the same owner.", 503)
		return
	}
	running, drained := false, admission.drained
	if owner != nil {
		running, drained = owner.running, owner.drained
	}
	cleanup := ""
	if failure != nil || !drained {
		cleanup = "Original candidate cleanup is pending; Cancel retries the same owner."
	}
	response := map[string]any{
		"schema": 1, "request_id": id, "view_token": admission.token,
		"prefix_position": admission.position, "response_source_nodes": admission.nodes,
		"requested_execution": "auto", "required_selected_execution": "local",
		"selected_execution": "local", "selection_epoch": admission.epoch,
		"measurement": hopmeasure.CandidatePrivateResponseMeasurement,
		"started":     admission.started, "admission_cancelled": !admission.started,
		"running": running, "drained": drained, "cancelled": true,
		"accepted": false, "reviewing": false, "cleanup_pending": !drained,
		"cleanup_error": cleanup, "failure": "", "saved_profile_id": "",
		"results": []hopmeasure.CandidateStatus{}, "errors": []viaEntryCandidateError{},
		"active_path_changed": false, "ok": failure == nil && drained,
	}
	if len(admission.owners) > 0 {
		response["requested_execution"], response["selected_execution"] = admission.requested, admission.selected
		publishCandidateResponseOwners(response, admission.owners, admission.selected)
	}
	c.mu.Unlock()
	viaEntryJSON(w, response)
}
