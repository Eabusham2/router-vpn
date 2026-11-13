package main

import (
	"errors"
	"net/http"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

// This bounded record binds a request to its original source-only view before
// admission. It carries no native or source capability. Its lifetime exceeds
// the view's 120 seconds, so pruning cannot revive a delayed original POST.
type orderedCandidatePreparedAdmission struct {
	token    string
	position int
	created  time.Time
}

// Issued view identities also outlive the UI view's admission window. A
// second window may refresh the current catalog while an older POST is in
// transit; that cannot strand the older window's cancellation reservation.
func rememberOrderedCandidatePreparedViewLocked(control *viaEntryControl, view *orderedCandidatePreparedView) error {
	control.pruneNoncesLocked()
	if len(control.preparedViews) >= 1024 {
		return errors.New("saved source view history is full; retry shortly")
	}
	if control.preparedViews == nil {
		control.preparedViews = map[string]*orderedCandidatePreparedAdmission{}
	}
	control.preparedViews[view.token] = &orderedCandidatePreparedAdmission{view.token, view.position, time.Now()}
	return nil
}

func reserveOrderedCandidatePreparedAdmissionLocked(control *viaEntryControl, id string, view *orderedCandidatePreparedView) error {
	control.pruneNoncesLocked()
	_, used := control.seen[id]
	if used || control.preparedAdmissions[id] != nil || len(control.preparedAdmissions) >= 1024 {
		return errors.New("saved request was already reserved, cancelled or its history is full")
	}
	if control.preparedAdmissions == nil {
		control.preparedAdmissions = map[string]*orderedCandidatePreparedAdmission{}
	}
	control.preparedAdmissions[id] = &orderedCandidatePreparedAdmission{view.token, view.position, time.Now()}
	return nil
}

func (a *app) orderedCandidatePreparedCancel(w http.ResponseWriter, request *http.Request) {
	var q struct {
		RequestID string `json:"request_id"`
		ViewToken string `json:"view_token"`
	}
	if !viaEntryDecode(w, request, &q) {
		return
	}
	if !validViaEntryRequestID(q.RequestID) || q.ViewToken == "" {
		http.Error(w, "saved cancellation requires its exact original request and view", 400)
		return
	}
	control := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(request.Context(), &control.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	control.pruneNoncesLocked()
	admission := control.preparedAdmissions[q.RequestID]
	if admission == nil {
		view := control.preparedView
		if recorded := control.preparedViews[q.ViewToken]; recorded != nil {
			view = &orderedCandidatePreparedView{token: recorded.token, position: recorded.position}
		}
		// Expiry forbids starting work, not cancellation of the exact issued
		// source view. This path creates only a request/view tombstone.
		if view == nil || view.token != q.ViewToken ||
			reserveOrderedCandidatePreparedAdmissionLocked(control, q.RequestID, view) != nil {
			control.mu.Unlock()
			http.Error(w, "saved cancellation lost its original bounded view", 409)
			return
		}
		admission = control.preparedAdmissions[q.RequestID]
	}
	if admission.token != q.ViewToken {
		control.mu.Unlock()
		http.Error(w, "saved request cannot be rebound to another view", 409)
		return
	}
	control.mu.Unlock()
	a.cancelViaEntryCandidate(w, request, q.RequestID, admission)
}

func orderedCandidatePreparedAdmissionCancelResponse(control *viaEntryControl, owner *viaEntryOwner, id string,
	admission *orderedCandidatePreparedAdmission, failure error) map[string]any {
	if response := orderedCandidatePreparedCancelResponse(control, owner, failure); response != nil {
		return response
	}
	// Before worker handoff the admitted preparation already retains its exact
	// cleanup callback. A completed callback, rather than a missing process,
	// supplies its DOWN result. A never-admitted nonce asserts no native DOWN.
	nativeDown := false
	if owner != nil && owner.preparation != nil {
		owner.preparation.mu.Lock()
		nativeDown = owner.preparation.nativeDown
		owner.preparation.mu.Unlock()
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	started, drained, running := owner != nil, true, false
	if owner != nil {
		drained, running = owner.drained, owner.running
	}
	cleanup := ""
	if failure != nil {
		cleanup = "Original temporary cleanup is pending; Cancel retries the same owner."
	}
	return map[string]any{"schema": 1, "scope": "saved-complete-local", "request_id": id,
		"view_token": admission.token, "prefix_position": admission.position, "measurement": "routed-tcp-connect",
		"started": started, "admission_cancelled": !started, "running": running, "cancelled": true,
		"drained": drained, "native_down": nativeDown, "accepted": false, "reviewing": false,
		"cleanup_pending": !drained, "cleanup_error": cleanup, "failure": "",
		"results": []hopmeasure.CandidateStatus{}, "errors": []viaEntryCandidateError{},
		"saved_profile_id": "", "active_path_changed": false, "ok": failure == nil && drained}
}
