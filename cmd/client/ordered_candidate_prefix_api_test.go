//go:build linux || windows

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func TestOrderedCandidatePrefixSourcePurposeCannotUpgrade(t *testing.T) {
	for _, position := range []int{0, 1} {
		t.Run(string(rune('0'+position)), func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			q.Scope, q.Position = orderedCandidateSavedPrefixScope, position
			observe := func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() }
			view, err := captureOrderedCandidatePreparedViewScope(context.Background(), a, position, q.Scope, observe)
			if err != nil {
				t.Fatal(err)
			}
			p := beginOrderedPreparationFixture(t, a, q)
			if !view.matchesPreparation(p, time.Now()) || p.prefixPreparation == nil || view.scopeValue() != q.Scope {
				t.Fatal("prefix view lost its immutable closed purpose")
			}
			wrong := *view
			wrong.scope = orderedCandidateSavedCompleteScope
			if wrong.matchesPreparation(p, time.Now()) {
				t.Fatal("complete view adopted a prefix purpose")
			}
			full, err := newDesktopNodeChainLaunch(p.selection, strings.Repeat("b", 32), "windows")
			if err != nil {
				t.Fatal(err)
			}
			if p.bindLaunch(context.Background(), full) == nil {
				t.Fatal("prefix purpose upgraded to a full-chain launch")
			}
			launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(context.Background(), p.selection, strings.Repeat("c", 32), "windows", p)
			if err != nil {
				t.Fatal(err)
			}
			if validateDesktopNodeChainLaunch(context.Background(), launch) == nil || view.catalog.current(context.Background()) == nil {
				t.Fatal("closed prefix acquired ordinary graph authority")
			}
			budget, err := desktopNodeReadyBudget(launch)
			if err != nil || budget != time.Duration(25+5*(position+1))*time.Second {
				t.Fatal("prefix startup did not retain exact finite proof budget", budget, err)
			}
			if err := p.holdLease(context.Background()); err != nil {
				t.Fatal(err)
			}
			joined, err := p.beginWorker(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			joined(nil)
			if err := p.retireNative(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !p.nativeDown || a.cmd != nil || a.state.Connected || mtuSuspended(a) {
				t.Fatal("unused prefix purpose could not retire independently")
			}
		})
	}
}

func TestOrderedCandidatePrefixCancellationBindsScopeBeforeAdmission(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	view, err := captureOrderedCandidatePreparedViewScope(context.Background(), a, 0, orderedCandidateSavedPrefixScope, func(ctx context.Context) (string, error) { return "physical", ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	c := viaEntryControlFor(a)
	c.mu.Lock()
	c.preparedView = view
	err = rememberOrderedCandidatePreparedViewLocked(c, view)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", orderedCandidateSavedCompleteScope, "foreign"} {
		response := orderedCandidateHTTP(t, a, "/api/multihop/saved-candidates/cancel", map[string]any{"request_id": q.RequestID, "view_token": view.token, "scope": scope})
		if response.Code < 400 {
			t.Fatal("foreign scope cancelled original prefix admission", scope, response.Body.String())
		}
		c.mu.Lock()
		_, seen := c.seen[q.RequestID]
		c.mu.Unlock()
		if seen {
			t.Fatal("foreign scope consumed original nonce")
		}
	}
	response := orderedCandidateHTTP(t, a, "/api/multihop/saved-candidates/cancel", map[string]any{"request_id": q.RequestID, "view_token": view.token, "scope": orderedCandidateSavedPrefixScope})
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	var body map[string]any
	if json.Unmarshal(response.Body.Bytes(), &body) != nil {
		t.Fatal("missing typed prefix tombstone")
	}
	for key, want := range map[string]any{"scope": orderedCandidateSavedPrefixScope, "request_id": q.RequestID, "view_token": view.token, "proof_scope": "selected-prefix", "application_open": false, "dns_open": false, "native_down": false, "started": false, "admission_cancelled": true, "accepted": false, "drained": true, "active_path_changed": false} {
		if body[key] != want {
			t.Fatal("prefix cancellation lost exact never-admitted purpose", key, body)
		}
	}
	c.mu.Lock()
	err = reserveOrderedCandidatePreparedAdmissionLocked(c, q.RequestID, view)
	c.mu.Unlock()
	if err == nil {
		t.Fatal("cancelled prefix nonce revived for a late POST")
	}
	q.Scope = orderedCandidateSavedPrefixScope
	if p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, func(ctx context.Context) (string, error) { return "physical", ctx.Err() }); err == nil {
		_ = p.finish()
		t.Fatal("cancel-before-start allowed a later prefix owner")
	}
}

func TestOrderedCandidatePrefixResultCannotBorrowFullCaptureOrSaveScope(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	q.Scope = orderedCandidateSavedPrefixScope
	p := beginOrderedPreparationFixture(t, a, q)
	result := desktopCandidateStatusFixture(t, p.inventory, q.CandidateIDs[0])
	if validateOrderedCandidatePreparedStatus(p, q.CandidateIDs[0], result, time.Now()) == nil {
		t.Fatal("prefix adopted complete-path candidate capture")
	}
	result.CaptureSHA256 = p.prefixPreparation.CaptureSHA256()
	if err := validateOrderedCandidatePreparedStatus(p, q.CandidateIDs[0], result, time.Now()); err != nil {
		t.Fatal(err)
	}
	job := &orderedCandidatePreparedJob{view: &orderedCandidatePreparedView{token: strings.Repeat("b", 64), scope: q.Scope, position: q.Position}, preparation: p, nativeDown: true, accepted: true, expires: time.Now().Add(time.Minute), results: []hopmeasure.CandidateStatus{result}}
	p.runtime = &orderedCandidatePreparedRuntime{preparation: p, catalog: p.inventory}
	owner := &viaEntryOwner{id: q.RequestID, prepared: job}
	response := orderedCandidatePreparedResponseLocked(owner, time.Now())
	if response["scope"] != q.Scope || response["application_open"] != false || response["dns_open"] != false || response["proof_scope"] != "selected-prefix" || response["accepted"] != true {
		t.Fatal("prefix result lost its distinct closed response", response)
	}
	// This is a DTO/Save-boundary test only; the modeled row grants no positive
	// reviewCurrent or native/kernel acceptance.
	if err := p.finish(); err != nil {
		t.Fatal(err)
	}
	p.control.mu.Lock()
	old := p.control.owner
	p.control.owner = owner
	p.control.mu.Unlock()
	defer func() { p.control.mu.Lock(); p.control.owner = old; p.control.mu.Unlock() }()
	for _, scope := range []string{"", orderedCandidateSavedCompleteScope} {
		reply := orderedCandidateHTTP(t, a, "/api/multihop/saved-candidates/save-profile", map[string]any{"request_id": q.RequestID, "view_token": job.view.token, "candidate_id": q.CandidateIDs[0], "name": "Detached draft", "proposed_path": []any{}, "scope": scope})
		if reply.Code != 409 || !strings.Contains(reply.Body.String(), "original temporary candidate result is unavailable") {
			t.Fatal("foreign Save scope crossed original prefix purpose", reply.Code, reply.Body.String())
		}
	}
}
