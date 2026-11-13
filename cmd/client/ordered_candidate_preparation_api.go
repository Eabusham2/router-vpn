package main

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
)

func registerOrderedCandidatePreparedRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/multihop/saved-candidates/catalog", a.orderedCandidatePreparedCatalog)
	h.HandleFunc("/api/multihop/saved-candidates", a.orderedCandidatePreparedRequest)
	h.HandleFunc("/api/multihop/saved-candidates/cancel", a.orderedCandidatePreparedCancel)
	h.HandleFunc("/api/multihop/saved-candidates/save-profile", a.saveOrderedCandidatePreparedProfile)
}

func (a *app) orderedCandidatePreparedCatalog(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if !nativeNodeChainPlatformSupported() {
		http.Error(w, "Temporary saved Local graphs require this platform's accepted native ordered controller.", http.StatusConflict)
		return
	}
	query := request.URL.Query()
	positions := query["prefix_position"]
	text := ""
	if len(positions) == 1 {
		text = positions[0]
	}
	position, err := strconv.Atoi(text)
	if len(query) != 1 || len(positions) != 1 || err != nil || strconv.Itoa(position) != text || position < 0 || position > 7 {
		http.Error(w, "choose an exact saved packet prefix position", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 12*time.Second)
	defer cancel()
	view, err := captureOrderedCandidatePreparedView(ctx, a, position, physicalNetworkIdentityContext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	control := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &control.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	if err := rememberOrderedCandidatePreparedViewLocked(control, view); err != nil {
		control.mu.Unlock()
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	control.preparedView = view
	control.mu.Unlock()
	viaEntryJSON(w, map[string]any{"schema": 1, "scope": "saved-complete-local", "view_token": view.token,
		"expires_at": view.expires.UnixMilli(), "prefix_position": view.position, "prefixes": view.prefixes,
		"candidates": view.candidates, "samples": 50, "measurement": "routed-tcp-connect",
		"note": "Test temporarily proves the complete saved Local graph, measures 50 TCP connection handshakes per candidate through its prefix, then returns Home to DOWN before review. This requires a reachable original final node and does not authenticate candidate credentials. Save creates a separate next-connection profile."})
}

func (a *app) orderedCandidatePreparedRequest(w http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		a.orderedCandidatePreparedStatus(w, request)
		return
	}
	if !nativeNodeChainPlatformSupported() {
		http.Error(w, "Temporary ordered native preparation is unavailable on this platform.", 409)
		return
	}
	var q orderedCandidateRequest
	if !viaEntryDecode(w, request, &q) {
		return
	}
	if !validViaEntryRequestID(q.RequestID) || q.ViewToken == "" || q.Samples != 50 || q.PrefixPosition < 0 || q.PrefixPosition > 7 || len(q.CandidateIDs) < 1 || len(q.CandidateIDs) > hopmeasure.CandidateMaximumTargets {
		http.Error(w, "an exact saved view, distinct candidate IDs and 50 samples are required", 400)
		return
	}
	control := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(request.Context(), &control.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	view := control.preparedView
	valid := view != nil && view.token == q.ViewToken && view.position == q.PrefixPosition && time.Now().Before(view.expires)
	if valid {
		valid = reserveOrderedCandidatePreparedAdmissionLocked(control, q.RequestID, view) == nil
	}
	control.mu.Unlock()
	if !valid {
		http.Error(w, "saved candidate view changed or expired; refresh", 409)
		return
	}
	admission, stopAdmission := context.WithTimeout(request.Context(), 12*time.Second)
	defer stopAdmission()
	lifetime, stopLifetime := context.WithTimeout(context.Background(), viaEntryRequestTimeout)
	p, err := beginOrderedCandidatePreparationWithLifetime(admission, lifetime, a,
		orderedCandidatePreparationRequest{q.RequestID, q.PrefixPosition, q.CandidateIDs, q.Samples}, physicalNetworkIdentityContext)
	if err != nil {
		stopLifetime()
		http.Error(w, err.Error(), 409)
		return
	}
	if !view.matchesPreparation(p, time.Now()) {
		stopLifetime()
		err := p.finish()
		http.Error(w, errors.Join(err, errors.New("saved view no longer matches its exact admitted sources; refresh")).Error(), 409)
		return
	}
	if err := desktopnetwork.LockContext(admission, &control.mu); err != nil {
		stopLifetime()
		_ = p.finish()
		http.Error(w, err.Error(), 408)
		return
	}
	if control.preparedView != view || control.owner != p.owner || p.owner.cancelled || admission.Err() != nil {
		control.mu.Unlock()
		stopLifetime()
		_ = p.finish()
		http.Error(w, "saved view was replaced or cancelled before worker handoff", 409)
		return
	}
	job := &orderedCandidatePreparedJob{view: view, preparation: p}
	p.owner.prepared = job
	response := orderedCandidatePreparedResponseLocked(p.owner, time.Now())
	control.mu.Unlock()
	// The original registered owner, not this response's request context,
	// owns all subsequent native work. Stop/Cancel still waits for its done.
	go runOrderedCandidatePreparedJob(p, job, stopLifetime)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	viaEntryJSON(w, response)
}

func runOrderedCandidatePreparedJob(p *orderedCandidatePreparation, job *orderedCandidatePreparedJob, stopLifetime context.CancelFunc) {
	defer stopLifetime()
	runtime, failure := p.startRuntime(p.operation)
	if failure == nil {
		failure = p.measureRuntime(p.operation, runtime, func(id string, result hopmeasure.CandidateStatus, err error) {
			p.control.mu.Lock()
			defer p.control.mu.Unlock()
			if err != nil {
				job.failures = append(job.failures, viaEntryCandidateError{ID: id, Error: "No complete valid 50-sample TCP receipt."})
			} else {
				job.results = append(job.results, result)
			}
		})
	}
	if failure == nil {
		failure = p.finishForReview(job)
	}
	if failure == nil {
		return
	}
	p.control.mu.Lock()
	job.accepted, job.current = false, ""
	job.failure = "Temporary candidate Test did not complete: " + boundedMTUDetail([]byte(failure.Error()))
	p.control.mu.Unlock()
	cleanup := p.finish()
	p.mu.Lock()
	down := p.nativeDown
	p.mu.Unlock()
	p.control.mu.Lock()
	job.accepted, job.nativeDown, job.current = false, down, ""
	job.failure = "Temporary candidate Test did not complete: " + boundedMTUDetail([]byte(failure.Error()))
	if cleanup != nil {
		job.cleanupError = "Original native or network observer cleanup is pending; Cancel retries the retained owner."
	}
	p.control.mu.Unlock()
}

func orderedCandidatePreparedResponseLocked(owner *viaEntryOwner, now time.Time) map[string]any {
	job := owner.prepared
	reviewing := !owner.running && !owner.cancelled && job.accepted && job.nativeDown &&
		!job.preparation.invalidated.Load() && now.Before(job.expires) && job.saved == nil && !owner.drained
	rows := []hopmeasure.CandidateStatus{}
	if reviewing && job.preparation.runtime != nil && job.preparation.runtime.catalog != nil {
		for _, row := range job.results {
			if validateDesktopNodeChainCandidateStatus(job.preparation.runtime.catalog.plan, row.CandidateID, row, now) == nil {
				rows = append(rows, row)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		left, right := rows[i].Results[0].Benchmark.TrimmedMean, rows[j].Results[0].Benchmark.TrimmedMean
		if left == right {
			return rows[i].CandidateID < rows[j].CandidateID
		}
		return left < right
	})
	cleanupPending := !owner.running && !owner.drained && !reviewing
	response := map[string]any{"schema": 1, "scope": "saved-complete-local", "request_id": owner.id,
		"view_token": job.view.token, "prefix_position": job.view.position, "running": owner.running,
		"drained": owner.drained, "cancelled": owner.cancelled, "native_down": job.nativeDown,
		"accepted": reviewing && len(rows) > 0, "reviewing": reviewing, "cleanup_pending": cleanupPending,
		"current_candidate": job.current, "results": rows, "errors": append([]viaEntryCandidateError{}, job.failures...),
		"failure": job.failure, "cleanup_error": job.cleanupError, "measurement": "routed-tcp-connect",
		"active_path_changed": false, "saved_profile_id": "", "started": true, "admission_cancelled": false}
	if job.saved != nil {
		response["saved_profile_id"], response["profile_id"], response["profile_name"], response["saved"] = job.saved.ID, job.saved.ID, job.saved.Name, true
	}
	return response
}

// A lost Save response followed by Cancel must still expose the already
// committed profile. Legacy/connected cancellation keeps its existing reply.
func orderedCandidatePreparedCancelResponse(control *viaEntryControl, owner *viaEntryOwner, failure error) map[string]any {
	if owner == nil {
		return nil
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if owner.prepared == nil {
		return nil
	}
	if failure != nil {
		owner.prepared.cleanupError = "Original temporary cleanup is pending; Cancel retries the same owner."
	} else if owner.drained && !(owner.prepared.saved != nil && owner.prepared.failure != "") {
		owner.prepared.cleanupError = ""
	}
	response := orderedCandidatePreparedResponseLocked(owner, time.Now())
	response["ok"] = failure == nil && owner.drained
	return response
}

func (a *app) orderedCandidatePreparedStatus(w http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	ids := query["request_id"]
	if len(query) != 1 || len(ids) != 1 || !validViaEntryRequestID(ids[0]) {
		http.Error(w, "exact temporary candidate request identity required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 8*time.Second)
	defer cancel()
	control := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &control.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	owner := control.owner
	if owner == nil || owner.id != ids[0] || owner.prepared == nil {
		control.mu.Unlock()
		http.Error(w, "original temporary candidate job is no longer retained", 409)
		return
	}
	job := owner.prepared
	observe := !owner.running && !owner.cancelled && !owner.drained && job.accepted && job.saved == nil
	control.mu.Unlock()
	if observe {
		if err := desktopnetwork.LockContext(ctx, &owner.closeMu); err != nil {
			http.Error(w, err.Error(), 408)
			return
		}
		if err := desktopnetwork.LockContext(ctx, &control.mu); err != nil {
			owner.closeMu.Unlock()
			http.Error(w, err.Error(), 408)
			return
		}
		observe = control.owner == owner && !owner.running && !owner.cancelled && !owner.drained && job.accepted && job.saved == nil
		control.mu.Unlock()
		var failure error
		if observe {
			failure = job.preparation.reviewCurrent(ctx)
		}
		if failure != nil {
			cleanup := job.preparation.retire(ctx)
			control.mu.Lock()
			job.accepted = false
			job.failure = "Original saved source, Home or physical network changed; retest."
			owner.drained = cleanup == nil
			if cleanup != nil {
				job.cleanupError = "Original observer cleanup remains pending; Cancel retries it."
			}
			control.mu.Unlock()
		}
		owner.closeMu.Unlock()
	}
	if err := desktopnetwork.LockContext(ctx, &control.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	if control.owner != owner {
		control.mu.Unlock()
		http.Error(w, "original temporary candidate owner was replaced", 409)
		return
	}
	response := orderedCandidatePreparedResponseLocked(owner, time.Now())
	control.mu.Unlock()
	viaEntryJSON(w, response)
}
