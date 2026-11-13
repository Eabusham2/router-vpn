package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The lock remains held until the actual reply returns. The timeout is only a
// failure guard; no scheduling delay supplies a successful lifecycle result.
func requireOrderedCancelReplyBeforeUnlock(t *testing.T, done <-chan struct{}, unlock func(), witness string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("cancel reply did not join after releasing its original fixture lock")
		}
		t.Fatal(witness)
	}
}

func TestOrderedPreparedCancelReplyDoesNotWaitForLifecycle(t *testing.T) {
	for _, scope := range []string{orderedCandidateSavedCompleteScope, orderedCandidateSavedPrefixScope} {
		t.Run(scope, func(t *testing.T) {
			a := &app{}
			control := viaEntryControlFor(a)
			t.Cleanup(func() { viaEntryControls.Delete(a) })
			id, token := strings.Repeat("a", 32), strings.Repeat("b", 64)
			admission := &orderedCandidatePreparedAdmission{token: token, scope: scope, created: time.Now()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			preparation := &orderedCandidatePreparation{}
			owner := &viaEntryOwner{id: id, preparation: preparation, running: true, done: make(chan struct{}), cancel: cancel}
			control.owner = owner
			control.preparedAdmissions = map[string]*orderedCandidatePreparedAdmission{id: admission}
			preparation.mu.Lock()
			var once sync.Once
			unlock := func() { once.Do(preparation.mu.Unlock) }
			defer unlock()
			body, err := json.Marshal(map[string]string{"request_id": id, "view_token": token, "scope": scope})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/multihop/saved-candidates/cancel", bytes.NewReader(body)).WithContext(ctx)
			response, done := httptest.NewRecorder(), make(chan struct{})
			go func() {
				// The shipping owner.cancel callback cancels this response only
				// after the handler has captured and cancelled the original owner.
				a.orderedCandidatePreparedCancel(response, request)
				close(done)
			}()
			requireOrderedCancelReplyBeforeUnlock(t, done, unlock, "cancel reply waited for the held preparation lifecycle")
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "same owner") ||
				ctx.Err() == nil || control.owner != owner || control.preparedAdmissions[id] != admission ||
				!owner.cancelled || !owner.running || owner.drained || preparation.nativeDown {
				t.Fatal("busy cancellation reported DOWN or replaced its original pending owner", response.Code, response.Body.String())
			}
			if _, cancelled := control.seen[id]; !cancelled {
				t.Fatal("bounded Cancel lost its original cancellation reservation")
			}
			unlock()
			// This is a DTO/lock test, not native acceptance. Only after release
			// do we model the exact owner's separately acknowledged DOWN state.
			preparation.mu.Lock()
			preparation.nativeDown = true
			preparation.mu.Unlock()
			control.mu.Lock()
			owner.running, owner.drained = false, true
			control.mu.Unlock()
			retry := httptest.NewRecorder()
			writeOrderedCandidatePreparedAdmissionCancelResponse(retry, control, owner, id, admission, nil)
			var result map[string]any
			if retry.Code != http.StatusOK || json.Unmarshal(retry.Body.Bytes(), &result) != nil || result["scope"] != scope ||
				result["request_id"] != id || result["view_token"] != token || result["native_down"] != true ||
				result["drained"] != true || result["ok"] != true || result["accepted"] != false {
				t.Fatal("Cancel retry lost its original joined receipt", retry.Code, retry.Body.String())
			}
			if scope == orderedCandidateSavedPrefixScope && (result["application_open"] != false || result["dns_open"] != false || result["proof_scope"] != "selected-prefix") {
				t.Fatal("Cancel retry upgraded the captured prefix purpose", result)
			}
		})
	}
}

func TestOrderedPreparedCancelReplyDoesNotWaitForCommittedSaveControl(t *testing.T) {
	a := &app{}
	control := viaEntryControlFor(a)
	t.Cleanup(func() { viaEntryControls.Delete(a) })
	id, token := strings.Repeat("a", 32), strings.Repeat("b", 64)
	admission := &orderedCandidatePreparedAdmission{token: token, scope: orderedCandidateSavedPrefixScope, created: time.Now()}
	preparation := &orderedCandidatePreparation{}
	job := &orderedCandidatePreparedJob{view: &orderedCandidatePreparedView{token: token, scope: admission.scope},
		preparation: preparation, nativeDown: true, saved: &connectionProfileRecord{ID: "original-saved-profile", Name: "Original saved profile"}}
	owner := &viaEntryOwner{id: id, cancelled: true, drained: true, prepared: job, preparation: preparation}
	control.owner = owner
	control.preparedAdmissions = map[string]*orderedCandidatePreparedAdmission{id: admission}
	control.mu.Lock()
	var once sync.Once
	unlock := func() { once.Do(control.mu.Unlock) }
	defer unlock()
	response, done := httptest.NewRecorder(), make(chan struct{})
	go func() {
		writeOrderedCandidatePreparedAdmissionCancelResponse(response, control, owner, id, admission, nil)
		close(done)
	}()
	requireOrderedCancelReplyBeforeUnlock(t, done, unlock, "cancel reply waited for the held saved-result control")
	if response.Code != http.StatusServiceUnavailable || control.owner != owner || owner.prepared != job ||
		job.saved == nil || job.saved.ID != "original-saved-profile" || !owner.drained || job.cleanupError != "" {
		t.Fatal("busy saved-result snapshot erased or changed its committed result", response.Code, response.Body.String())
	}
	unlock()
	retry := httptest.NewRecorder()
	writeOrderedCandidatePreparedAdmissionCancelResponse(retry, control, owner, id, admission, nil)
	var result map[string]any
	if retry.Code != http.StatusOK || json.Unmarshal(retry.Body.Bytes(), &result) != nil || result["saved"] != true ||
		result["saved_profile_id"] != "original-saved-profile" || result["profile_name"] != "Original saved profile" ||
		result["native_down"] != true || result["drained"] != true || result["ok"] != true || result["scope"] != admission.scope {
		t.Fatal("Cancel retry erased the original committed Save", retry.Code, retry.Body.String())
	}
}
