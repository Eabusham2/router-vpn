package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func viaEntryFixture(t *testing.T) (*app, common.RouterProfile, []common.RouterProfile) {
	t.Helper()
	root := desktopAWGPrivateTestRoot(t)
	t.Setenv("HOMEVPN_ROOT", root)
	entry, assets := desktopNodeFixture(t, "198.51.100.8")
	assets["wg-socks.conf"] = []byte(strings.ReplaceAll(string(assets["wg.conf"]), "0.0.0.0/0, ::/0", "10.77.0.0/24"))
	entry.ID, entry.Name = "entry", "Entry"
	candidates := []common.RouterProfile{}
	for i, endpoint := range []string{"candidate.invalid", "198.51.100.22"} {
		p := cloneRouterProfile(entry)
		p.ID, p.Name, p.Endpoint = fmt.Sprintf("exit-%d", i), fmt.Sprintf("Exit %d", i), endpoint
		candidates = append(candidates, p)
	}
	profiles := append([]common.RouterProfile{entry}, candidates...)
	for _, p := range profiles {
		dir := filepath.Join(root, "generated", p.ID, "wg")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for name, body := range assets {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json")}, profiles: common.RouterProfileStore{SelectedID: entry.ID, Profiles: profiles}, state: state{Phase: "off"}}
	t.Cleanup(func() { viaEntryControls.Delete(a) })
	return a, entry, candidates
}

// This controlled lane exercises the actual HTTP identity proof, candidate
// sampling and transaction lifecycle. Wire/protocol behavior is separately
// tested against real sockets and the pinned native SOCKS implementation.
type viaEntryTestLane struct {
	mu             sync.Mutex
	entry          common.RouterProfile
	closed         bool
	failClose      bool
	closeCalls     int
	proofs         int
	wrongLastProof bool
	failHost       string
	block          chan struct{}
	entered        chan struct{}
	enterOnce      sync.Once
	targets        []string
	workers        sync.WaitGroup
}

func (l *viaEntryTestLane) Alive() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.closed
}

func (l *viaEntryTestLane) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	l.mu.Lock()
	l.targets = append(l.targets, address)
	_, proofAddress, _ := viaEntryProofAddress(l.entry)
	if address == proofAddress {
		l.proofs++
		id := l.entry.NodeProofID
		if l.wrongLastProof && l.proofs > 1 {
			id = strings.Repeat("a", 64)
		}
		client, server := net.Pipe()
		l.workers.Add(1)
		l.mu.Unlock()
		go func() {
			defer l.workers.Done()
			defer server.Close()
			request, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil || request.Header.Get("Authorization") != "Bearer "+l.entry.APIToken {
				return
			}
			body := fmt.Sprintf(`{"ok":true,"node_id":%q,"proof":%q}`, id, desktopNodeProofKind)
			_, _ = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		}()
		return client, nil
	}
	block, entered, fail := l.block, l.entered, strings.HasPrefix(address, l.failHost+":") && l.failHost != ""
	l.mu.Unlock()
	if entered != nil {
		l.enterOnce.Do(func() { close(entered) })
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fail {
		return nil, errors.New("fixture routed refusal")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(4 * time.Millisecond):
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (l *viaEntryTestLane) Close(ctx context.Context) error {
	l.mu.Lock()
	l.closeCalls++
	if l.failClose {
		l.mu.Unlock()
		return errors.New("fixture cleanup remains pending")
	}
	l.closed = true
	l.mu.Unlock()
	l.workers.Wait()
	return nil
}

func viaEntryTestRequest(id string, candidates []common.RouterProfile) string {
	ids := []string{}
	for _, p := range candidates {
		ids = append(ids, p.ID)
	}
	data, _ := json.Marshal(viaEntryRequest{RequestID: id, EntryID: "entry", CandidateIDs: ids, Samples: 3})
	return string(data)
}

func runViaEntryTest(a *app, lane *viaEntryTestLane, id string, candidates []common.RouterProfile, network func() string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/multihop/candidates", strings.NewReader(viaEntryTestRequest(id, candidates)))
	a.viaEntryCandidatesWith(w, r, viaEntryDependencies{network: network, start: func(context.Context, string, string, common.RouterProfile, map[string][]byte, map[string][]byte, []common.RouterProfile) (viaEntryLane, error) {
		return lane, nil
	}})
	return w
}

func validateViaEntryTest(a *app, id, exit string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.viaEntryCandidatesValidate(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates/validate", strings.NewReader(fmt.Sprintf(`{"request_id":%q,"entry_id":"entry","exit_id":%q}`, id, exit))))
	return w
}

func cancelViaEntryTest(a *app, id string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.viaEntryCandidatesCancel(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates/cancel", strings.NewReader(fmt.Sprintf(`{"request_id":%q}`, id))))
	return w
}

func TestViaEntryCandidatesReceiptOwnsActualProofAndCleanup(t *testing.T) {
	a, entry, candidates := viaEntryFixture(t)
	beforeProfiles, beforeState := cloneRouterProfileStore(a.profiles), a.state
	lane := &viaEntryTestLane{entry: entry, failHost: candidates[1].Endpoint}
	id := strings.Repeat("1", 32)
	w := runViaEntryTest(a, lane, id, candidates, func() string { return "physical-one" })
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var receipt viaEntryReceipt
	if json.Unmarshal(w.Body.Bytes(), &receipt) != nil || receipt.Schema != 1 || receipt.EntryBase != "wg" || receipt.EntryMode != "wg" || !receipt.Drained || receipt.FastestID != candidates[0].ID || len(receipt.Results) != 1 || len(receipt.Errors) != 1 || receipt.Errors[0].ID != candidates[1].ID {
		t.Fatal("receipt did not separate routed measurements from unavailable candidates", w.Body.String())
	}
	if receipt.Results[0].MedianMs < 3 || receipt.Results[0].Samples != 3 || receipt.Results[0].Failed != 0 || time.Until(receipt.ExpiresAt) > viaEntryReceiptLifetime || time.Until(receipt.ExpiresAt) < 119*time.Second {
		t.Fatal("routed handshake timing or bounded receipt changed")
	}
	if !lane.closed || lane.proofs != 2 || lane.closeCalls != 1 {
		t.Fatal("receipt escaped before both entry proofs and cleanup")
	}
	if !reflect.DeepEqual(beforeProfiles, a.profiles) || !reflect.DeepEqual(beforeState, a.state) || a.cmd != nil {
		t.Fatal("candidate selection changed Home, saved preferences, or durable direct results")
	}
	if result := validateViaEntryTest(a, id, candidates[0].ID); result.Code != 200 || !strings.Contains(result.Body.String(), `"measured":true`) {
		t.Fatal("current measured candidate rejected", result.Body.String())
	}
	if result := validateViaEntryTest(a, id, candidates[1].ID); result.Code != 200 || !strings.Contains(result.Body.String(), `"measured":false`) {
		t.Fatal("explicit unavailable selection mislabeled", result.Body.String())
	}
	if result := validateViaEntryTest(a, id, "not-captured"); result.Code != 409 {
		t.Fatal("uncaptured candidate adopted")
	}
	if result := runViaEntryTest(a, &viaEntryTestLane{entry: entry}, id, candidates, func() string { return "physical-one" }); result.Code != 409 {
		t.Fatal("reused receipt nonce launched another session")
	}
}

func TestViaEntryCandidatesRejectChangedSourcesNetworkExpiryAndDecision(t *testing.T) {
	for _, reason := range []string{"credentials", "assets", "network", "expiry", "decision"} {
		t.Run(reason, func(t *testing.T) {
			a, entry, candidates := viaEntryFixture(t)
			var network atomic.Value
			network.Store("physical-one")
			identity := func() string { return network.Load().(string) }
			id := strings.Repeat("2", 32)
			if w := runViaEntryTest(a, &viaEntryTestLane{entry: entry}, id, candidates, identity); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			switch reason {
			case "credentials":
				a.mu.Lock()
				a.profiles.Profiles[1].APIToken += "-changed"
				a.mu.Unlock()
			case "assets":
				path := filepath.Join(clientRoot(a), "generated", candidates[0].ID, "wg", "wg.conf")
				if err := os.WriteFile(path, []byte("changed captured source"), 0600); err != nil {
					t.Fatal(err)
				}
			case "network":
				network.Store("physical-two")
			case "expiry":
				control := viaEntryControlFor(a)
				control.mu.Lock()
				control.owner.receipt.ExpiresAt = time.Now().Add(-time.Second)
				control.mu.Unlock()
			case "decision":
				release, err := a.beginMutationOperation(httptest.NewRequest(http.MethodPost, "/api/options", nil))
				if err != nil {
					t.Fatal(err)
				}
				release()
			}
			if w := validateViaEntryTest(a, id, candidates[0].ID); w.Code != 409 {
				t.Fatal("stale result remained selectable", reason, w.Body.String())
			}
		})
	}
}

func TestViaEntryCandidatesFinalWrongEntryDiscardsEverySample(t *testing.T) {
	a, entry, candidates := viaEntryFixture(t)
	lane := &viaEntryTestLane{entry: entry, wrongLastProof: true}
	id := strings.Repeat("3", 32)
	w := runViaEntryTest(a, lane, id, candidates, func() string { return "physical-one" })
	if w.Code != 409 || !lane.closed || lane.proofs != 2 || validateViaEntryTest(a, id, candidates[0].ID).Code != 409 {
		t.Fatal("wrong final entry identity retained samples", w.Body.String())
	}
}

func TestViaEntryCandidatesCancelBeforeStartAndDuringProbe(t *testing.T) {
	a, entry, candidates := viaEntryFixture(t)
	id := strings.Repeat("4", 32)
	if w := cancelViaEntryTest(a, id); w.Code != 200 || !strings.Contains(w.Body.String(), `"drained":true`) {
		t.Fatal(w.Body.String())
	}
	if w := runViaEntryTest(a, &viaEntryTestLane{entry: entry}, id, candidates, func() string { return "network" }); w.Code != 409 {
		t.Fatal("cancel-before-start nonce launched a lane")
	}
	id = strings.Repeat("5", 32)
	lane := &viaEntryTestLane{entry: entry, block: make(chan struct{}), entered: make(chan struct{})}
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- runViaEntryTest(a, lane, id, candidates, func() string { return "network" }) }()
	select {
	case <-lane.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("candidate did not enter owned probe")
	}
	if _, release, err := a.beginConnectionOperation(); err == nil {
		release()
		t.Fatal("connection replaced an active candidate owner")
	}
	if w := cancelViaEntryTest(a, id); w.Code != 200 || !strings.Contains(w.Body.String(), `"drained":true`) {
		t.Fatal("cancel did not join owned work", w.Body.String())
	}
	if w := <-finished; w.Code != 409 || !lane.closed {
		t.Fatal("cancelled test published a receipt", w.Body.String())
	}
	newID := strings.Repeat("6", 32)
	newLane := &viaEntryTestLane{entry: entry}
	if w := runViaEntryTest(a, newLane, newID, candidates, func() string { return "network" }); w.Code != 200 {
		t.Fatal("replacement after checked cancellation rejected", w.Body.String())
	}
	if w := cancelViaEntryTest(a, id); w.Code != 200 || validateViaEntryTest(a, newID, candidates[0].ID).Code != 200 {
		t.Fatal("old cancel touched replacement receipt")
	}
}

func TestViaEntryCandidatesFailedCleanupRetainsOwner(t *testing.T) {
	a, entry, candidates := viaEntryFixture(t)
	lane := &viaEntryTestLane{entry: entry, failClose: true}
	id := strings.Repeat("7", 32)
	if w := runViaEntryTest(a, lane, id, candidates, func() string { return "network" }); w.Code != 503 {
		t.Fatal("failed cleanup reported a usable measurement", w.Body.String())
	}
	if validateViaEntryTest(a, id, candidates[0].ID).Code != 409 {
		t.Fatal("unretired candidate became selectable")
	}
	if release, err := a.beginNodeBoundOperation(); err == nil {
		release()
		t.Fatal("new operation replaced failed cleanup")
	}
	if w := cancelViaEntryTest(a, id); w.Code != 503 {
		t.Fatal("cancel forgot failed owner")
	}
	for _, stop := range []http.HandlerFunc{a.disconnect, a.emergencyStop} {
		w := httptest.NewRecorder()
		stop(w, httptest.NewRequest(http.MethodPost, "/stop", nil))
		if w.Code != 503 {
			t.Fatal("global stop acknowledged before owned candidate cleanup", w.Code)
		}
	}
	lane.mu.Lock()
	lane.failClose = false
	lane.mu.Unlock()
	if w := cancelViaEntryTest(a, id); w.Code != 200 || !lane.closed {
		t.Fatal("same-owner cleanup retry failed", w.Body.String())
	}
	if release, err := a.beginNodeBoundOperation(); err != nil {
		t.Fatal("drained owner still blocked new decisions", err)
	} else {
		release()
	}
}

func TestViaEntryCandidatesNetworkChangeCancelsInFlightSocket(t *testing.T) {
	a, entry, candidates := viaEntryFixture(t)
	var network atomic.Value
	network.Store("one")
	lane := &viaEntryTestLane{entry: entry, block: make(chan struct{}), entered: make(chan struct{})}
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		finished <- runViaEntryTest(a, lane, strings.Repeat("8", 32), candidates, func() string { return network.Load().(string) })
	}()
	select {
	case <-lane.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("candidate did not enter probe")
	}
	network.Store("two")
	select {
	case w := <-finished:
		if w.Code != 409 || !lane.closed {
			t.Fatal("network-changed round survived", w.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("network change did not cancel blocked candidate I/O")
	}
}

func TestViaEntryLinuxBaseInferenceAndVariantOwnership(t *testing.T) {
	for _, variant := range []string{"awg2-fast", "awg2-strong"} {
		t.Run(variant, func(t *testing.T) {
			a, entry, candidates := viaEntryFixture(t)
			// The selected control may differ from entry: capture both because
			// actual Linux Connect uses the control preference only as fallback.
			a.profiles.SelectedID = candidates[0].ID
			a.profiles.Profiles[1].BaseTunnel = "awg"
			_, files := viaEntryBaseFixture(t, variant)
			dir := filepath.Join(clientRoot(a), "generated", entry.ID, variant)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			id := strings.Repeat("a", 32)
			var q viaEntryRequest
			_ = json.Unmarshal([]byte(viaEntryTestRequest(id, candidates)), &q)
			q.Base = "auto"
			body, _ := json.Marshal(q)
			lane := &viaEntryTestLane{entry: entry}
			w := httptest.NewRecorder()
			seen := ""
			a.viaEntryCandidatesWith(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates", strings.NewReader(string(body))), viaEntryDependencies{network: func() string { return "physical" }, start: func(ctx context.Context, root, mode string, p common.RouterProfile, captured, start map[string][]byte, nodes []common.RouterProfile) (viaEntryLane, error) {
				seen = mode
				if !reflect.DeepEqual(captured, files) {
					return lane, errors.New("AWG source parameters changed")
				}
				_, _, err := compileViaEntryLane(ctx, p, mode, captured, start, nodes, 27123, "captured", "password")
				return lane, err
			}})
			if w.Code != 200 || seen != variant {
				t.Fatal("candidate did not follow actual Linux AWG source selection", w.Code, w.Body.String(), seen)
			}
			var receipt viaEntryReceipt
			_ = json.Unmarshal(w.Body.Bytes(), &receipt)
			if receipt.EntryBase != "awg" || receipt.EntryMode != variant {
				t.Fatal("AWG variant was mislabeled as WG", receipt)
			}
			if result := validateViaEntryTest(a, id, candidates[0].ID); result.Code != 200 || !strings.Contains(result.Body.String(), `"entry_base":"awg"`) || !strings.Contains(result.Body.String(), `"entry_mode":"`+variant+`"`) {
				t.Fatal("selection validation lost its captured raw entry", result.Body.String())
			}
			if variant == "awg2-fast" {
				a.mu.Lock()
				a.profiles.Profiles[1].BaseTunnel = "wg"
				a.mu.Unlock()
			} else {
				// A new higher-priority fast source changes what Connect would
				// select, even while the measured strong files remain unchanged.
				fast := filepath.Join(clientRoot(a), "generated", entry.ID, "awg2-fast")
				if err := os.MkdirAll(fast, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fast, "awg-socks.conf"), files["awg-socks.conf"], 0600); err != nil {
					t.Fatal(err)
				}
			}
			if result := validateViaEntryTest(a, id, candidates[0].ID); result.Code != 409 {
				t.Fatal("changed Linux base/variant left a stale measurement selectable")
			}
		})
	}
	for _, row := range []struct{ requested, entry, control, expected string }{
		{"wg", "awg", "awg", "wg"}, {"auto", "awg", "wg", "awg"}, {"auto", "auto", "awg", "awg"}, {"auto", "auto", "auto", "wg"},
	} {
		if got := resolveMultihopEntryBase(common.RouterProfile{BaseTunnel: row.control}, common.RouterProfile{BaseTunnel: row.entry}, row.requested); got != row.expected {
			t.Fatal("candidate/Connect shared base precedence changed", row, got)
		}
	}
}

func TestViaEntryCandidateRoutesStrictJSONAndNoFallback(t *testing.T) {
	a, _, candidates := viaEntryFixture(t)
	mux := http.NewServeMux()
	registerTelemetryRoutes(mux, a)
	for _, route := range []string{"/api/multihop/candidates", "/api/multihop/candidates/cancel", "/api/multihop/candidates/validate"} {
		for _, body := range []string{`{"request_id":"one","request_id":"two"}`, `{"unexpected":true}`, `{} {}`} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, route, strings.NewReader(body)))
			if w.Code != 400 {
				t.Fatal("ambiguous API request accepted", route, w.Code)
			}
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != 405 {
			t.Fatal("candidate endpoint is not POST-only", route)
		}
	}
	// A missing private runtime fails the shipping route; it must never call
	// quickProfileLatency or invent a result from the direct-node cache.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates", strings.NewReader(viaEntryTestRequest(strings.Repeat("9", 32), candidates))))
	if w.Code == 200 || strings.Contains(w.Body.String(), `"median_ms"`) {
		t.Fatal("missing entry runtime fell back to direct latency")
	}
}
