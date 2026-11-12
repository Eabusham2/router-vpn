package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

func orderedCandidateHTTP(t *testing.T, a *app, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, a)
	mux.ServeHTTP(w, req)
	return w
}

type orderedCandidateSaveWriter struct {
	*httptest.ResponseRecorder
	beforeWrite func()
}

func (w *orderedCandidateSaveWriter) Write(body []byte) (int, error) {
	w.beforeWrite()
	return w.ResponseRecorder.Write(body)
}

func orderedCandidateTestOwner(t *testing.T, catalog *desktopNodeChainCandidateCatalog, id string) *viaEntryOwner {
	t.Helper()
	row := desktopCandidateStatusFixture(t, catalog, id)
	view := &orderedCandidateView{token: strings.Repeat("a", 64), position: 0, catalog: catalog, identity: catalog.identity, expires: time.Now().Add(time.Minute)}
	owner := &viaEntryOwner{id: strings.Repeat("b", 32), drained: true, done: make(chan struct{}), cancel: func() {}, ordered: &orderedCandidateJob{view: view, catalog: catalog, results: []hopmeasure.CandidateStatus{row}, accepted: true}}
	close(owner.done)
	return owner
}
func TestOrderedCandidateStatusPreservesExpiryAndRejectsAlienRows(t *testing.T) {
	a, catalog, id := desktopCandidateSourceTestCatalog(t, "2022-blake3-aes-256-gcm")
	owner := orderedCandidateTestOwner(t, catalog, id)
	c := viaEntryControlFor(a)
	c.owner = owner
	expiry := owner.ordered.results[0].ExpiresAt
	before := orderedCandidateResponseLocked(owner, time.UnixMilli(expiry-1))["results"].([]hopmeasure.CandidateStatus)
	after := orderedCandidateResponseLocked(owner, time.UnixMilli(expiry))["results"].([]hopmeasure.CandidateStatus)
	if len(before) != 1 || len(after) != 0 || owner.ordered.results[0].ExpiresAt != expiry {
		t.Fatal("poll renewed an expired candidate receipt")
	}
	owner.ordered.results[0].Results[0].Benchmark.Attempts = 49
	if len(orderedCandidateResponseLocked(owner, time.Now())["results"].([]hopmeasure.CandidateStatus)) != 0 {
		t.Fatal("partial samples published")
	}
	owner.ordered.results[0] = desktopCandidateStatusFixture(t, catalog, id)
	owner.cancelled = true
	if len(orderedCandidateResponseLocked(owner, time.Now())["results"].([]hopmeasure.CandidateStatus)) != 0 {
		t.Fatal("cancelled result remained selectable")
	}
}
func TestOrderedCandidateRequestsRequireOriginalViewAndSamples(t *testing.T) {
	a := &app{}
	for _, path := range []string{"/api/multihop/prefix-candidates/catalog?prefix_position=0&prefix_position=1", "/api/multihop/prefix-candidates/catalog?prefix_position=01", "/api/multihop/prefix-candidates?request_id=" + strings.Repeat("a", 32) + "&request_id=" + strings.Repeat("b", 32)} {
		mux := http.NewServeMux()
		registerOrderedCandidateRoutes(mux, a)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Fatal("ambiguous candidate query admitted", path, w.Code)
		}
	}
	for _, q := range []orderedCandidateRequest{
		{RequestID: strings.Repeat("a", 32), ViewToken: "view", CandidateIDs: []string{"candidate"}, Samples: 49},
		{RequestID: strings.Repeat("a", 32), ViewToken: "view", CandidateIDs: []string{"candidate", "candidate"}, Samples: 50},
		{RequestID: strings.Repeat("a", 32), ViewToken: "view", CandidateIDs: []string{"candidate"}, Samples: 50},
	} {
		w := orderedCandidateHTTP(t, a, "/api/multihop/prefix-candidates", q)
		if w.Code < 400 {
			t.Fatal("uncaptured request admitted", w.Body.String())
		}
	}
	if c := viaEntryControlFor(a); c.owner != nil {
		t.Fatal("invalid request published a native owner")
	}
}
func TestOrderedCandidateCancelRetainsExactPendingCleanup(t *testing.T) {
	a, catalog, id := desktopCandidateSourceTestCatalog(t, "2022-blake3-aes-256-gcm")
	owner := orderedCandidateTestOwner(t, catalog, id)
	owner.drained = false
	c := viaEntryControlFor(a)
	c.owner = owner
	joined := false
	calls := 0
	owner.cleanup = func(ctx context.Context) error {
		calls++
		if !joined {
			return errors.New("original native worker remains")
		}
		return ctx.Err()
	}
	w := orderedCandidateHTTP(t, a, "/api/multihop/prefix-candidates/cancel", map[string]string{"request_id": owner.id})
	if w.Code != 503 || owner.drained || !owner.cancelled || calls != 1 {
		t.Fatal("cancel released unjoined native owner", w.Code, owner.drained, calls)
	}
	if guardViaEntryDecision(a) == nil {
		t.Fatal("replacement admitted while original cleanup pending")
	}
	joined = true
	w = orderedCandidateHTTP(t, a, "/api/multihop/prefix-candidates/cancel", map[string]string{"request_id": owner.id})
	if w.Code != 200 || !owner.drained || calls != 2 {
		t.Fatal("retry did not join exact original", w.Body.String())
	}
	if err := guardViaEntryDecision(a); err != nil || owner.ordered.accepted {
		t.Fatal("retired receipt survived replacement decision", err)
	}
}
func TestOrderedCandidateNextProfileCapturesSourcesWithoutMutatingActive(t *testing.T) {
	a, catalog, id := desktopCandidateSourceTestCatalog(t, "2022-blake3-chacha20-poly1305")
	original, _ := json.Marshal(a.profiles)
	candidate, _ := a.profileByIDLocked(id)
	control, nodes, err := orderedCandidateProposal(catalog.launch.chain.selection.Nodes, 0, candidate, a.profiles.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	proposed := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	for i := range proposed {
		if proposed[i].ID == control.ID {
			proposed[i] = control
		}
	}
	compiled, err := captureDesktopNodeChain(context.Background(), catalog.launch.root, control, proposed, nodes, "local", nil)
	if err != nil || compiled == nil {
		t.Fatal("actual proposed source compiler", err)
	}
	record, err := a.orderedCandidateProfileRecordLocked(control, "Custom next path")
	if err != nil {
		t.Fatal(err)
	}
	if record.Mode != "shadowsocks" || len(record.NodeChain) != 3 || record.NodeChain[1].NodeKind != "external" || record.NodeChain[1].NodeProofID != "" || !reflect.DeepEqual(record.Prefs.MultihopNodes, nodes) {
		t.Fatal("complete external next-profile capture drifted", record)
	}
	after, _ := json.Marshal(a.profiles)
	if !bytes.Equal(original, after) {
		t.Fatal("saving draft changed active profile inventory")
	}
	if _, _, err := orderedCandidateProposal(catalog.launch.chain.selection.Nodes, 1, candidate, a.profiles.Profiles); err == nil {
		t.Fatal("unsupported custom suffix family admitted")
	}
}
func TestOrderedCandidateSaveHTTPRequiresFreshOriginalOwner(t *testing.T) {
	f, catalog, id := desktopCandidateTestCatalog(t, "2022-blake3-aes-256-gcm")
	owner := orderedCandidateTestOwner(t, catalog, id)
	c := viaEntryControlFor(f.a)
	_, token, _, captureErr := captureOrderedPerformanceContext(context.Background(), f.a)
	if captureErr != nil {
		t.Fatal(captureErr)
	}
	owner.ordered.view.capture = token
	c.orderedView = owner.ordered.view
	// This is the existing native mailbox boundary, not a second candidate
	// implementation: the HTTP handler must publish the actual exact request.
	nativeStatus := desktopCandidateStatusFixture(t, catalog, id)
	producerCtx, stopProducer := context.WithTimeout(context.Background(), 80*time.Second)
	defer stopProducer()
	produced := make(chan error, 1)
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			raw, err := readDesktopRuntimeFile(f.launch, "node-chain-candidate-request.json", 16384)
			if err == nil {
				var request desktopNodeChainCandidateRequest
				if err = json.Unmarshal(raw, &request); err != nil {
					produced <- err
					return
				}
				if !mtuSuspended(f.a) {
					produced <- errors.New("HTTP run did not retain original MTU hold")
					return
				}
				nativeStatus.Request = request.Request
				nativeStatus.MeasuredAt = time.Now().UnixMilli()
				nativeStatus.ExpiresAt = nativeStatus.MeasuredAt + 120000
				result := desktopNodeChainCandidateResult{desktopNodeChainCandidateRequest: request, CompletedAt: time.Now().UnixMilli(), Status: nativeStatus}
				body, _ := json.Marshal(result)
				f.launch.workspaceMu.Lock()
				err = f.launch.directoryRoot.WriteFile(".node-chain-candidate-result.json.pending", body, 0600)
				if err == nil {
					err = f.launch.directoryRoot.Rename(".node-chain-candidate-result.json.pending", "node-chain-candidate-result.json")
				}
				if err == nil {
					err = f.launch.directoryRoot.Remove("node-chain-candidate-request.json")
				}
				f.launch.workspaceMu.Unlock()
				produced <- err
				return
			}
			if !errors.Is(err, os.ErrNotExist) {
				produced <- err
				return
			}
			select {
			case <-tick.C:
			case <-producerCtx.Done():
				produced <- producerCtx.Err()
				return
			}
		}
	}()
	run := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates", orderedCandidateRequest{RequestID: owner.id, ViewToken: owner.ordered.view.token, PrefixPosition: 0, CandidateIDs: []string{id}, Samples: 50})
	if run.Code != 200 {
		t.Fatal("actual HTTP mailbox run", run.Code, run.Body.String())
	}
	if err := <-produced; err != nil {
		t.Fatal("native producer", err)
	}
	c.mu.Lock()
	owner = c.owner
	accepted := owner.ordered.accepted
	drained := owner.drained
	c.mu.Unlock()
	if !accepted || !drained || mtuSuspended(f.a) {
		t.Fatal("HTTP receipt published without joined original hold", run.Body.String())
	}
	candidate, _ := f.a.profileByIDLocked(id)
	_, nodes, err := orderedCandidateProposal(catalog.launch.chain.selection.Nodes, 0, candidate, f.a.profiles.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	q := orderedCandidateSaveRequest{RequestID: owner.id, ViewToken: owner.ordered.view.token, CandidateID: id, Name: "Next connection only", ProposedPath: nodes}
	original, _ := json.Marshal(f.a.profiles)
	command := f.a.cmd
	w := httptest.NewRecorder()
	observedHold := false
	writer := &orderedCandidateSaveWriter{ResponseRecorder: w, beforeWrite: func() {
		suspension := mtuSuspensionFor(f.a)
		suspension.mu.Lock()
		held := suspension.held && suspension.users > 0
		suspension.mu.Unlock()
		lock := mtuRetestLockFor(f.a)
		if lock.TryLock() {
			lock.Unlock()
			t.Error("MTU Retest/Auto could enter during atomic profile publication")
		}
		if !held {
			t.Error("profile publication lost its retained original MTU hold")
		}
		observedHold = held
	}}
	body, _ := json.Marshal(q)
	f.a.saveOrderedCandidateProfile(writer, httptest.NewRequest(http.MethodPost, "/api/multihop/prefix-candidates/save-profile", bytes.NewReader(body)))
	if !observedHold || mtuSuspended(f.a) {
		t.Fatal("save did not retain then release its exact publication hold")
	}
	if w.Code != 200 {
		t.Fatal("save original current receipt", w.Code, w.Body.String())
	}
	store, err := loadConnectionProfileStore(f.a)
	if err != nil || len(store.Profiles) != 1 {
		t.Fatal("complete saved record missing", err)
	}
	after, _ := json.Marshal(f.a.profiles)
	if !bytes.Equal(original, after) || f.a.cmd != command || !f.a.state.Connected {
		t.Fatal("draft save mutated active runtime")
	}
	if w = orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", q); w.Code != 409 {
		t.Fatal("same receipt saved twice", w.Body.String())
	}
	owner.ordered.accepted = true
	owner.ordered.results[0].ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
	if w = orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", q); w.Code != 409 {
		t.Fatal("expired receipt saved", w.Body.String())
	}
}

func TestOrderedCandidateStatusLatchesOriginalSourceSessionAndReaderLoss(t *testing.T) {
	f, initial, id := desktopCandidateTestCatalog(t, "2022-blake3-aes-256-gcm")
	for _, fault := range []string{"session", "source", "reader"} {
		t.Run(fault, func(t *testing.T) {
			catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, initial.identity, 0, []string{id})
			if err != nil {
				t.Fatal(err)
			}
			owner := orderedCandidateTestOwner(t, catalog, id)
			_, owner.ordered.view.capture, _, err = captureOrderedPerformanceContext(context.Background(), f.a)
			if err != nil {
				t.Fatal(err)
			}
			owner.ordered.observation, err = captureOrderedCandidateObservation(context.Background(), owner.ordered)
			if err != nil {
				t.Fatal(err)
			}
			c := viaEntryControlFor(f.a)
			c.mu.Lock()
			c.owner = owner
			c.mu.Unlock()
			poll := func() map[string]any {
				w := httptest.NewRecorder()
				f.a.orderedCandidateStatus(w, httptest.NewRequest("GET", "/api/multihop/prefix-candidates?request_id="+owner.id, nil))
				if w.Code != 200 {
					t.Fatal("bounded original observation", w.Code, w.Body.String())
				}
				var value map[string]any
				if json.Unmarshal(w.Body.Bytes(), &value) != nil {
					t.Fatal(w.Body.String())
				}
				return value
			}
			fresh := poll()
			if fresh["accepted"] != true || len(fresh["results"].([]any)) != 1 {
				t.Fatal("valid original receipt disappeared", fresh)
			}
			restore := func() {}
			switch fault {
			case "session":
				tracker := catalog.identity.Tracker
				tracker.mu.Lock()
				old := tracker.session.ID
				tracker.session.ID = "replacement-session"
				tracker.mu.Unlock()
				restore = func() { tracker.mu.Lock(); tracker.session.ID = old; tracker.mu.Unlock() }
			case "source":
				f.a.mu.Lock()
				index := -1
				for i, p := range f.a.profiles.Profiles {
					if p.ID == id {
						index = i
					}
				}
				old := f.a.profiles.Profiles[index].External.Shadowsocks.Password
				f.a.profiles.Profiles[index].External.Shadowsocks.Password = "changed-original-source"
				f.a.mu.Unlock()
				restore = func() {
					f.a.mu.Lock()
					f.a.profiles.Profiles[index].External.Shadowsocks.Password = old
					f.a.mu.Unlock()
				}
			case "reader":
				f.heartbeat.Lock()
				f.live.Reader++
				err = f.publishHeartbeatLocked()
				f.heartbeat.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				restore = func() {
					f.heartbeat.Lock()
					f.live.Reader--
					err := f.publishHeartbeatLocked()
					f.heartbeat.Unlock()
					if err != nil {
						t.Error(err)
					}
				}
			}
			lost := poll()
			restore()
			if lost["accepted"] != false || len(lost["results"].([]any)) != 0 || !owner.ordered.lost.Load() {
				t.Fatal("source/session/reader loss retained scored rows", fault, lost)
			}
			revived := poll()
			if revived["accepted"] != false || len(revived["results"].([]any)) != 0 {
				t.Fatal("changed-away/back revived original result", fault, revived)
			}
		})
	}
}
