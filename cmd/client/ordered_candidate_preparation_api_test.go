package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
)

func TestOrderedPreparedAdmissionSeparatesResponseAndWorkerLifetimes(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	admission, endResponse := context.WithCancel(context.Background())
	lifetime, stopWorker := context.WithTimeout(context.Background(), viaEntryRequestTimeout)
	defer stopWorker()
	p, err := beginOrderedCandidatePreparationWithLifetime(admission, lifetime, a, q, func(ctx context.Context) (string, error) { return "physical", ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer p.finish()
	endResponse()
	if admission.Err() == nil || p.operation.Err() != nil || p.sourceCurrent(context.Background()) != nil {
		t.Fatal("returning the 202 response revoked its separately owned original worker")
	}
	stopWorker()
	if p.operation.Err() == nil || p.sourceCurrent(context.Background()) == nil {
		t.Fatal("bounded app-owned worker outlived its actual lifetime")
	}
}

func TestOrderedPreparedSavedViewHasNoNativeAuthorityAndBindsOriginalSource(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	observe := func(ctx context.Context) (string, error) { return "physical", ctx.Err() }
	view, err := captureOrderedCandidatePreparedView(context.Background(), a, q.Position, observe)
	if err != nil {
		t.Fatal(err)
	}
	if view.catalog.identity.Ordered != nil || view.catalog.launch.command != nil || view.catalog.launch.chain.ready != nil || view.catalog.current(context.Background()) == nil || a.candidatePreparation != nil {
		t.Fatal("saved UI view created connected/native or operation authority")
	}
	p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.finish()
	if !view.matchesPreparation(p, time.Now()) {
		t.Fatal("fresh admitted graph lost the original saved view")
	}
	for _, fault := range []string{"expired", "network", "position", "catalog", "candidate"} {
		t.Run(fault, func(t *testing.T) {
			copy := *view
			catalog := *view.catalog
			copy.catalog = &catalog
			switch fault {
			case "expired":
				copy.expires = time.Now().Add(-time.Second)
			case "network":
				copy.network += "replacement"
			case "position":
				copy.position++
			case "catalog":
				catalog.revision += "replacement"
			case "candidate":
				catalog.profiles = map[string]string{}
			}
			if copy.matchesPreparation(p, time.Now()) {
				t.Fatal("saved view adopted a replacement original capture", fault)
			}
		})
	}
}

// This tests only the private DOWN admission predicate, using the existing
// socket-free source fixture. No modeled physical observer supplies a positive
// reviewCurrent or native launch result.
func TestOrderedPreparedChoicesRequireActualNativeDownBoundary(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	p := beginOrderedPreparationFixture(t, a, q)
	bindOrderedPreparationFixture(t, p)
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
	check := func() error { a.mu.Lock(); defer a.mu.Unlock(); return p.reviewBoundaryLocked() }
	if err := check(); err != nil {
		t.Fatal("original completed socket-free boundary comparison failed", err)
	}
	for _, fault := range []string{"not-down", "lease", "worker", "pending", "owner", "command", "operation", "connected", "phase", "graph", "home"} {
		t.Run(fault, func(t *testing.T) {
			state, done := a.state, p.workerDone
			switch fault {
			case "not-down":
				p.nativeDown = false
			case "lease":
				p.releaseLease = func() {}
			case "worker":
				p.workerDone = make(chan struct{})
			case "pending":
				p.pending = errors.New("unjoined original child")
			case "owner":
				a.candidatePreparation = &orderedCandidatePreparation{}
			case "command":
				a.cmd = &exec.Cmd{}
			case "operation":
				a.connectionContext = context.Background()
			case "connected":
				a.state.Connected = true
			case "phase":
				a.state.Phase = "candidate:testing"
			case "graph":
				activeMultihopGraphs.Store(a, activeMultihopGraph{})
			case "home":
				a.state.Jumbo = !a.state.Jumbo
			}
			err := check()
			p.nativeDown, p.releaseLease, p.workerDone, p.pending = true, nil, done, nil
			a.candidatePreparation, a.cmd, a.connectionContext, a.state = p, nil, nil, state
			activeMultihopGraphs.Delete(a)
			if err == nil {
				t.Fatal("choices admitted before original native DOWN", fault)
			}
		})
	}
}

func TestOrderedPreparedRouteValidationCannotBorrowConnectedOrAlienJob(t *testing.T) {
	a := &app{}
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, a)
	for _, path := range []string{"/api/multihop/saved-candidates?request_id=bad", "/api/multihop/saved-candidates?request_id=" + strings.Repeat("a", 32), "/api/multihop/saved-candidates/catalog?prefix_position=0&unknown=1"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code < 400 {
			t.Fatal("invalid saved scope acquired another operation", path, w.Code)
		}
	}
	q := orderedCandidateSaveRequest{RequestID: strings.Repeat("a", 32), ViewToken: strings.Repeat("b", 64), CandidateID: "candidate", Name: "Saved draft"}
	w := orderedCandidateHTTP(t, a, "/api/multihop/saved-candidates/save-profile", q)
	if w.Code != 409 {
		t.Fatal("save without retained DOWN result reached profile publication", w.Code)
	}
}

func TestOrderedPreparedCancelPreservesCommittedProfileVisibility(t *testing.T) {
	for _, pending := range []bool{false, true} {
		a := &app{}
		control := viaEntryControlFor(a)
		p := &orderedCandidatePreparation{app: a}
		job := &orderedCandidatePreparedJob{view: &orderedCandidatePreparedView{token: strings.Repeat("b", 64)}, preparation: p, nativeDown: true,
			saved: &connectionProfileRecord{ID: "saved-original", Name: "Explicit draft"}}
		owner := &viaEntryOwner{id: strings.Repeat("a", 32), cancelled: true, drained: !pending, prepared: job}
		var failure error
		if pending {
			failure = errors.New("original observer still joining")
		}
		response := orderedCandidatePreparedCancelResponse(control, owner, failure)
		if response["saved_profile_id"] != "saved-original" || response["profile_name"] != "Explicit draft" || response["saved"] != true || response["cleanup_pending"] != pending || response["ok"] == pending {
			t.Fatal("late Cancel erased a committed Save or claimed an unfinished join", response)
		}
	}
}

func preparedProfileStoreFixture(t *testing.T) (*app, connectionProfileRecord, connectionProfileStore) {
	t.Helper()
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "routers.json")}}
	stamp := "2026-11-13T00:00:00Z"
	before := connectionProfileStore{Version: connectionProfileStoreVersion, Profiles: []connectionProfileRecord{{ID: "old-profile", Name: "Old profile", NodeID: "original-node", Mode: "wg", Prefs: &connectionProfilePreferences{CustomLayers: []string{}}, CreatedAt: stamp, UpdatedAt: stamp}}}
	if err := persistConnectionProfileStore(a, before); err != nil {
		t.Fatal(err)
	}
	// Capture the shipping decoder's normalized legacy defaults before the
	// transaction under test. Later comparisons concern append ownership,
	// not absent preference fields that that decoder intentionally fills.
	var err error
	before, err = loadConnectionProfileStore(a)
	if err != nil {
		t.Fatal(err)
	}
	prefs := *before.Profiles[0].Prefs
	record := connectionProfileRecord{ID: "new-profile", Name: "Explicit saved draft", NodeID: "candidate-node", Mode: "shadowsocks", Prefs: &prefs, CreatedAt: stamp, UpdatedAt: stamp}
	return a, record, before
}

func TestOrderedPreparedProfileAppendKeepsCommitAndRollbackAuthority(t *testing.T) {
	for _, fault := range []string{"success", "final-guard", "post-commit", "precommit-replacement", "postcommit-replacement"} {
		t.Run(fault, func(t *testing.T) {
			a, record, before := preparedProfileStoreFixture(t)
			calls := 0
			replacement := before
			replacement.Profiles = append(append([]connectionProfileRecord(nil), before.Profiles...), connectionProfileRecord{ID: "other-profile", Name: "Other writer", NodeID: "other-node", Mode: "wg", Prefs: record.Prefs, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt})
			publication, err := appendOrderedCandidateProfile(a, record, func() error {
				calls++
				if fault == "final-guard" && calls == 3 || fault == "post-commit" && calls == 4 {
					return errors.New("original physical cohort changed")
				}
				if fault == "precommit-replacement" && calls == 3 {
					return persistConnectionProfileStore(a, replacement)
				}
				return nil
			})
			if fault == "final-guard" || fault == "precommit-replacement" {
				if err == nil || publication != nil {
					t.Fatal("failed pre-rename ownership check committed a candidate profile", err)
				}
				want := before
				if fault == "precommit-replacement" {
					want = replacement
				}
				actual, readErr := loadConnectionProfileStore(a)
				if readErr != nil || !reflect.DeepEqual(actual, want) {
					t.Fatal("refused append erased original or newer writer", readErr)
				}
				return
			}
			if publication == nil || (err != nil) != (fault == "post-commit") {
				t.Fatal("append lost its actual committed identity", err)
			}
			defer clear(publication.before)
			defer clear(publication.after)
			if fault == "postcommit-replacement" {
				if err := persistConnectionProfileStore(a, replacement); err != nil {
					t.Fatal(err)
				}
				if publication.rollback() == nil {
					t.Fatal("rollback overwrote unrelated newer profile store")
				}
				actual, _ := loadConnectionProfileStore(a)
				if !reflect.DeepEqual(actual, replacement) {
					t.Fatal("rollback erased unrelated writer")
				}
				return
			}
			if fault == "post-commit" {
				if err := publication.rollback(); err != nil {
					t.Fatal(err)
				}
				actual, _ := loadConnectionProfileStore(a)
				if !reflect.DeepEqual(actual, before) {
					t.Fatal("owned failed append did not restore only its original store")
				}
				return
			}
			actual, readErr := loadConnectionProfileStore(a)
			if readErr != nil || len(actual.Profiles) != 2 || actual.Profiles[1].ID != record.ID {
				t.Fatal("successful named append was lost", readErr)
			}
			info, _ := os.Stat(connectionProfileStorePath(a))
			if info.Mode().Perm() != 0600 {
				t.Fatal("candidate profile append exposed private store permissions")
			}
		})
	}
}

func TestOrderedPreparedRollbackPreservesOriginalFileBytes(t *testing.T) {
	a, record, before := preparedProfileStoreFixture(t)
	raw, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	raw = append([]byte(" \n"), append(raw, '\n', '\n')...)
	if err := atomicWritePrivate(connectionProfileStorePath(a), raw); err != nil {
		t.Fatal(err)
	}
	publication, err := appendOrderedCandidateProfile(a, record, func() error { return nil })
	if err != nil || publication == nil {
		t.Fatal("original formatted store could not append", err)
	}
	defer clear(publication.before)
	defer clear(publication.after)
	if err := publication.rollback(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(connectionProfileStorePath(a))
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("owned rollback normalized or replaced original store bytes", err)
	}
}

func TestOrderedPreparedStatusRechecksAfterOriginalCloseLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := &app{}
		control := viaEntryControlFor(a)
		p := &orderedCandidatePreparation{app: a, nativeDown: true, cancel: func() {}}
		job := &orderedCandidatePreparedJob{view: &orderedCandidatePreparedView{token: strings.Repeat("b", 64)}, preparation: p, accepted: true, nativeDown: true, expires: time.Now().Add(time.Minute)}
		owner := &viaEntryOwner{id: strings.Repeat("a", 32), prepared: job, cancel: func() {}}
		control.owner = owner
		owner.closeMu.Lock()
		done := make(chan struct{})
		w := httptest.NewRecorder()
		go func() {
			a.orderedCandidatePreparedStatus(w, httptest.NewRequest(http.MethodGet, "/api/multihop/saved-candidates?request_id="+owner.id, nil))
			close(done)
		}()
		synctest.Wait()
		control.mu.Lock()
		job.accepted, job.failure, owner.drained = false, "Candidate results expired; retest before Save.", true
		control.mu.Unlock()
		owner.closeMu.Unlock()
		<-done
		if w.Code != 200 || p.invalidated.Load() || job.failure != "Candidate results expired; retest before Save." {
			t.Fatal("status interpreted completed expiry cleanup as a new source/network loss", w.Code, job.failure)
		}
	})
}

func TestOrderedPreparedEarlyCancellationKeepsOriginalPurposeAndView(t *testing.T) {
	for _, stage := range []string{"before-post", "refused-before-owner", "pre-handoff-owner", "replacement-owner", "expired-view", "replaced-view"} {
		t.Run(stage, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			observe := func(ctx context.Context) (string, error) { return "physical", ctx.Err() }
			view, err := captureOrderedCandidatePreparedView(context.Background(), a, q.Position, observe)
			if err != nil {
				t.Fatal(err)
			}
			control := viaEntryControlFor(a)
			control.preparedView = view
			if err := rememberOrderedCandidatePreparedViewLocked(control, view); err != nil {
				t.Fatal(err)
			}
			if stage == "expired-view" {
				view.expires = time.Now().Add(-time.Second)
			} else if stage == "replaced-view" {
				later := *view
				later.token = strings.Repeat("e", 64)
				control.preparedView = &later
			}
			if stage == "refused-before-owner" || stage == "pre-handoff-owner" {
				if err := reserveOrderedCandidatePreparedAdmissionLocked(control, q.RequestID, view); err != nil {
					t.Fatal(err)
				}
			}
			var original *orderedCandidatePreparation
			var replacement *viaEntryOwner
			if stage == "pre-handoff-owner" {
				original, err = beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe)
				if err != nil {
					t.Fatal(err)
				}
			} else if stage == "replacement-owner" {
				replacement = &viaEntryOwner{id: strings.Repeat("f", 32), running: true, done: make(chan struct{}), cancel: func() { t.Error("early cancellation touched replacement owner") }}
				control.owner = replacement
			}
			body, err := json.Marshal(map[string]string{"request_id": q.RequestID, "view_token": view.token})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				a.orderedCandidatePreparedCancel(w, httptest.NewRequest(http.MethodPost, "/api/multihop/saved-candidates/cancel", bytes.NewReader(body)))
				close(done)
			}()
			if original != nil {
				select {
				case <-original.operation.Done():
				case <-time.After(time.Second):
					t.Fatal("pre-handoff cancellation did not reach original admission")
				}
				if err := original.finish(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("early saved cancellation lost its joined terminal receipt")
			}
			var reply map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply["scope"] != "saved-complete-local" ||
				reply["request_id"] != q.RequestID || reply["view_token"] != view.token || reply["drained"] != true ||
				reply["started"] != (original != nil) || reply["native_down"] != (original != nil) ||
				reply["admission_cancelled"] != (original == nil) || reply["accepted"] != false || reply["active_path_changed"] != false {
				t.Fatal("early saved cancellation claimed another purpose or omitted its typed boundary", w.Code, w.Body.String())
			}
			if replacement != nil && (control.owner != replacement || !replacement.running || replacement.cancelled || replacement.drained) {
				t.Fatal("cancel-before-start mutated or retired the replacement owner")
			}
			// The original nonce cannot gain a late owner or a different view,
			// even when there was no native preparation to shut down.
			if p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe); err == nil || p != nil {
				t.Fatal("cancel-before-start admitted a delayed original POST")
			}
			foreign := *view
			foreign.token = strings.Repeat("0", 64)
			control.preparedView = &foreign
			if reserveOrderedCandidatePreparedAdmissionLocked(control, q.RequestID, &foreign) == nil {
				t.Fatal("saved cancellation nonce was rebound to a later view")
			}
			bad, _ := json.Marshal(map[string]string{"request_id": q.RequestID, "view_token": foreign.token})
			refused := httptest.NewRecorder()
			a.orderedCandidatePreparedCancel(refused, httptest.NewRequest(http.MethodPost, "/api/multihop/saved-candidates/cancel", bytes.NewReader(bad)))
			if refused.Code != 409 {
				t.Fatal("wrong saved view consumed original cancellation", refused.Code)
			}
		})
	}
}
