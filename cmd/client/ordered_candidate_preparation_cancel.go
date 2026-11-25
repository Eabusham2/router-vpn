package main

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

// This bounded record binds a request to its original source-only view before
// admission. It carries no native or source capability. Its lifetime exceeds
// the view's 120 seconds, so pruning cannot revive a delayed original POST.
type orderedCandidatePreparedAdmission struct {
	token          string
	requested      string
	measurement    string
	scope          string
	position       int
	draft          bool
	created        time.Time
	responseNodes  []orderedCandidateResponseSourceNode
	responseOwners []string
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
	control.preparedViews[view.token] = &orderedCandidatePreparedAdmission{token: view.token, scope: view.scopeValue(), requested: orderedCandidateDraftExecution(view.draft), position: view.position, measurement: candidateViewMetric(view.prefixes, view.position), draft: view.draft != nil, created: time.Now(), responseOwners: slices.Clone(view.responseOwners), responseNodes: slices.Clone(view.responseNodes)}
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
	control.preparedAdmissions[id] = &orderedCandidatePreparedAdmission{token: view.token, scope: view.scopeValue(), requested: orderedCandidateDraftExecution(view.draft), position: view.position, measurement: candidateViewMetric(view.prefixes, view.position), draft: view.draft != nil, created: time.Now(), responseOwners: slices.Clone(view.responseOwners), responseNodes: slices.Clone(view.responseNodes)}
	return nil
}

func (a *app) orderedCandidatePreparedCancel(w http.ResponseWriter, request *http.Request) {
	var q struct {
		RequestID string `json:"request_id"`
		ViewToken string `json:"view_token"`
		Scope     string `json:"scope"`
	}
	if !viaEntryDecode(w, request, &q) {
		return
	}
	scope, scopeErr := normalizedOrderedCandidateSavedScope(q.Scope)
	if scopeErr != nil {
		http.Error(w, scopeErr.Error(), 400)
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
	draft := request.URL.Path == "/api/multihop/draft-candidates/cancel"
	if admission == nil {
		recorded := control.preparedViews[q.ViewToken]
		if recorded == nil && control.preparedView != nil && control.preparedView.token == q.ViewToken {
			view := control.preparedView
			recorded = &orderedCandidatePreparedAdmission{token: view.token, scope: view.scopeValue(), requested: orderedCandidateDraftExecution(view.draft), position: view.position, measurement: candidateViewMetric(view.prefixes, view.position), draft: view.draft != nil, responseOwners: slices.Clone(view.responseOwners), responseNodes: slices.Clone(view.responseNodes)}
		}
		// A late cancel may outlive the catalog. Bind its nonce to the
		// originally issued purpose before any worker can acquire it.
		_, used := control.seen[q.RequestID]
		if recorded == nil || recorded.scope != scope || recorded.draft != draft || used || len(control.preparedAdmissions) >= 1024 {
			control.mu.Unlock()
			http.Error(w, "saved cancellation lost its original bounded view", 409)
			return
		}
		if control.preparedAdmissions == nil {
			control.preparedAdmissions = map[string]*orderedCandidatePreparedAdmission{}
		}
		record := *recorded
		record.created = time.Now()
		control.preparedAdmissions[q.RequestID] = &record
		admission = &record
	}
	if admission.token != q.ViewToken || admission.scope != scope || admission.draft != draft {
		control.mu.Unlock()
		http.Error(w, "saved request cannot be rebound to another view", 409)
		return
	}
	control.mu.Unlock()
	a.cancelViaEntryCandidate(w, request, q.RequestID, admission)
}

func orderedCandidatePreparedAdmissionCancelResponse(control *viaEntryControl, owner *viaEntryOwner, id string,
	admission *orderedCandidatePreparedAdmission, failure error) map[string]any {
	// This reply is also reached after request cancellation or the bounded
	// drain timeout. Observation must not wait on the lifecycle it is reporting.
	// A busy exact snapshot produces a retryable HTTP failure, never a fabricated
	// DOWN result or an empty replacement for an already committed Save.
	if !control.mu.TryLock() {
		return nil
	}
	defer control.mu.Unlock()
	if response := orderedCandidatePreparedCancelResponseLocked(owner, failure); response != nil {
		return response
	}
	// Before worker handoff the admitted preparation already retains its exact
	// cleanup callback. A completed callback, rather than a missing process,
	// supplies its DOWN result. A never-admitted nonce asserts no native DOWN.
	nativeDown := false
	if owner != nil && owner.preparation != nil {
		if !owner.preparation.mu.TryLock() {
			return nil
		}
		nativeDown = owner.preparation.nativeDown
		owner.preparation.mu.Unlock()
	}
	started, drained, running := owner != nil, true, false
	if owner != nil {
		drained, running = owner.drained, owner.running
	}
	cleanup := ""
	if failure != nil {
		cleanup = "Original temporary cleanup is pending; Cancel retries the same owner."
	}
	metric := admission.measurement
	if metric == "" {
		metric = hopmeasure.CandidateTCPMeasurement
	}
	response := orderedCandidatePreparedPurposeResponse(map[string]any{"schema": 1, "request_id": id,
		"view_token": admission.token, "prefix_position": admission.position, "measurement": metric,
		"started": started, "admission_cancelled": !started, "running": running, "cancelled": true,
		"drained": drained, "native_down": nativeDown, "accepted": false, "reviewing": false,
		"cleanup_pending": !drained, "cleanup_error": cleanup, "failure": "",
		"results": []hopmeasure.CandidateStatus{}, "errors": []viaEntryCandidateError{},
		"saved_profile_id": "", "active_path_changed": false, "ok": failure == nil && drained}, admission.scope)
	if admission.draft {
		response["requested_execution"] = admission.requested
		response["origin"] = "editor-draft"
		if len(admission.responseNodes) != 0 {
			response["response_source_nodes"] = admission.responseNodes
			if len(admission.responseOwners) > 0 {
				publishCandidateResponseOwners(response, admission.responseOwners, "")
			} else {
				response["required_selected_execution"] = "local"
			}
		}
	}
	return response
}

func writeOrderedCandidatePreparedAdmissionCancelResponse(w http.ResponseWriter, control *viaEntryControl, owner *viaEntryOwner,
	id string, admission *orderedCandidatePreparedAdmission, failure error) {
	response := orderedCandidatePreparedAdmissionCancelResponse(control, owner, id, admission, failure)
	if response == nil {
		http.Error(w, "Original temporary cleanup is still joining; Cancel retries the same owner.", http.StatusServiceUnavailable)
		return
	}
	viaEntryJSON(w, response)
}
