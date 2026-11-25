package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"router-vpn/internal/hopmeasure"
	"testing"
	"time"
)

func TestDesktopSelectedServerResponseConnected(t *testing.T) {
	for _, outcome := range [][2]string{{"server", "server"}, {"auto", "server"}, {"auto", "local"}} {
		t.Run(outcome[0]+"/"+outcome[1], func(t *testing.T) {
			f, nodes, id := desktopSelectedResponseParentWithRequest(t, 5, 2, outcome[0], outcome[1])
			identity, _, err := captureSpeedLabIdentityContext(t.Context(), f.a)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := captureDesktopNodeChainCandidates(candidateServerIntent(t.Context(), true), f.a, identity, 2, []string{id})
			if err != nil || catalog.selectedPlan == nil {
				t.Fatal("server response source", err)
			}
			before := httptest.NewRecorder()
			f.a.orderedCandidateCatalog(before, httptest.NewRequest("GET", "/api/multihop/prefix-candidates/catalog?prefix_position=2&server_response=false", nil))
			if before.Code != 400 {
				t.Fatal("invalid Server intent", before.Code)
			}
			view, q := exerciseDesktopSelectedCandidateHTTP(t, f, catalog, id, outcome[1], 2, responseExpectedPositions(5, 2))
			owners := []string{"server"}
			if outcome[0] == "auto" {
				owners = []string{"local", "server"}
			}
			if view.Requested != outcome[0] || view.Required != outcome[1] || view.Selected != outcome[1] || view.Epoch == 0 || !reflect.DeepEqual(view.Owners, owners) || !reflect.DeepEqual(view.ResponseNodes, responseExpectedSourceAt(nodes, 2)) {
				t.Fatal("connected source, server eligibility or actual selected owner changed", view)
			}
			reply := httptest.NewRecorder()
			f.a.orderedCandidates(reply, httptest.NewRequest("GET", "/api/multihop/prefix-candidates?request_id="+q.RequestID, nil))
			var polled desktopSelectedCandidateHTTPTestView
			if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &polled) != nil || !reflect.DeepEqual(polled.Owners, owners) || polled.Required != view.Selected || polled.Requested != view.Requested || polled.Epoch != view.Epoch || polled.Selected != view.Selected || !reflect.DeepEqual(polled.ResponseNodes, view.ResponseNodes) {
				t.Fatal("connected terminal owner changed", reply.Body.String())
			}
		})
	}
}

func TestDesktopSelectedServerResponseDraft(t *testing.T) {
	for _, outcome := range [][2]string{{"server", "server"}, {"auto", "server"}, {"auto", "local"}} {
		t.Run(outcome[0]+"/"+outcome[1], func(t *testing.T) {
			a, nodes, id := selectedResponseAppFixture(t, 3, -1)
			a, draft, q := selectedDraftSourceFixture(t, a, nodes, outcome[0], 1, id)
			q.serverResponse = true
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			view, err := captureOrderedCandidatePreparedSelection(candidateServerIntent(ctx, true), a, 1, q.Scope, draft, func(context.Context) (string, error) { return "physical", nil })
			if err != nil {
				t.Fatal("original draft offered no response source", err)
			}
			owners := []string{"server"}
			if outcome[0] == "auto" {
				owners = []string{"local", "server"}
			}
			if !reflect.DeepEqual(view.responseOwners, owners) || !reflect.DeepEqual(view.responseNodes, responseExpectedSourceAt(nodes, -1)) {
				t.Fatal("triple draft lost original roles or owners", view.responseOwners, view.responseNodes)
			}
			control := viaEntryControlFor(a)
			control.mu.Lock()
			err = rememberOrderedCandidatePreparedViewLocked(control, view)
			admission := control.preparedViews[view.token]
			control.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			before := orderedCandidatePreparedAdmissionCancelResponse(control, nil, q.RequestID, admission, nil)
			if !reflect.DeepEqual(before["response_executions"], owners) || before["selected_execution"] != nil || before["selection_epoch"] != nil || before["native_down"] != false ||
				outcome[0] == "server" && before["required_selected_execution"] != "server" || outcome[0] == "auto" && before["required_selected_execution"] != nil {
				t.Fatal("prestart cancel invented a selected owner or lost its source", before)
			}
			testOriginalSelectedDraftLifecycle(t, a, draft, q, [3]string{outcome[0], outcome[1], "private-measure-only"})
		})
	}
}

func TestDesktopSelectedServerUnregisteredCannotBeSaved(t *testing.T) {
	f, _, id := desktopSelectedResponseParentWithRequest(t, 5, 2, "auto", "server")
	identity, _, err := captureSpeedLabIdentityContext(t.Context(), f.a)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := captureDesktopNodeChainCandidates(candidateServerIntent(t.Context(), true), f.a, identity, 2, []string{id})
	if err != nil {
		t.Fatal(err)
	}
	view, q := exerciseDesktopSelectedCandidateHTTPResult(t, f, catalog, id, "server", 2, responseExpectedPositions(5, 2), true)
	c := viaEntryControlFor(f.a)
	c.mu.Lock()
	job := c.owner.ordered
	if len(job.results) != 1 || len(job.results[0].Results) != 1 {
		t.Fatal("original missing row disappeared")
	}
	status := job.results[0]
	row := status.Results[0]
	c.mu.Unlock()
	if row.CandidateDisposition != hopmeasure.CandidateNotRegistered || row.Ready || row.Benchmark != nil || row.Failure == "" {
		t.Fatal("missing candidate obtained an adoptable score", row)
	}
	for _, key := range []string{"benchmark", "ready", "empty-failure", "wrong-disposition", "wrong-source", "wrong-kind"} {
		foreign := status
		foreign.Results = []hopmeasure.Result{row}
		r := &foreign.Results[0]
		switch key {
		case "benchmark":
			r.Benchmark = &hopmeasure.LatencyBenchmark{}
		case "ready":
			r.Ready = true
		case "empty-failure":
			r.Failure = ""
		case "wrong-disposition":
			r.CandidateDisposition = "other"
		case "wrong-source":
			foreign.CandidateSourceSHA256 = "foreign"
		case "wrong-kind":
			r.Kind = "tcp-connect"
		}
		if validateDesktopSelectedCandidateStatus(job.catalog.selectedPlan, id, foreign, time.Now()) == nil {
			t.Fatal("changed no-score row accepted", key)
		}
	}
	for _, choice := range view.Candidates {
		if choice.ID == id {
			response := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", orderedCandidateSaveRequest{RequestID: q.RequestID, ViewToken: q.ViewToken, CandidateID: id, Name: "missing candidate", ProposedPath: choice.Proposal})
			if response.Code != 409 {
				t.Fatal("unregistered candidate became a saved route", response.Code, response.Body.String())
			}
			return
		}
	}
	t.Fatal("view no longer has tested candidate")
}
