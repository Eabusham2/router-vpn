//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/routechoice"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const windowsCONNECTExecutionMarker = "fixture-connect-execution-host"

type windowsCONNECTExecutionCase struct{ Mode, Protocol, Requested, Winner, Fault string }

var windowsCONNECTExecutionCases = []string{
	"http-wg-server",
	"http-awg-fast-auto-local",
	"http-awg-strong-auto-server",
	"https-awg-strong-server",
	"https-wg-auto-local",
	"https-awg-fast-auto-server",
	"http-wrong-auth",
	"https-wrong-auth",
	"https-tls-name",
	"http-wrong-public",
	"https-wrong-final",
	"https-failed-dns",
	"http-replaced-source",
	"https-held-cleanup",
}
var windowsCONNECTExecutionScenarios = map[string]windowsCONNECTExecutionCase{
	"http-wg-server":              {"wg", "http-connect", "server", "server", ""},
	"http-awg-fast-auto-local":    {"awg2-fast", "http-connect", "auto", "local", ""},
	"http-awg-strong-auto-server": {"awg2-strong", "http-connect", "auto", "server", ""},
	"https-awg-strong-server":     {"awg2-strong", "https-connect", "server", "server", ""},
	"https-wg-auto-local":         {"wg", "https-connect", "auto", "local", ""},
	"https-awg-fast-auto-server":  {"awg2-fast", "https-connect", "auto", "server", ""},
	"http-wrong-auth":             {"wg", "http-connect", "server", "server", "wrong-auth"},
	"https-wrong-auth":            {"wg", "https-connect", "server", "server", "wrong-auth"},
	"https-tls-name":              {"wg", "https-connect", "server", "server", "tls-name"},
	"http-wrong-public":           {"wg", "http-connect", "server", "server", "wrong-public"},
	"https-wrong-final":           {"wg", "https-connect", "server", "server", "wrong-final"},
	"https-failed-dns":            {"wg", "https-connect", "server", "server", "failed-dns"},
	"http-replaced-source":        {"wg", "http-connect", "server", "server", "replaced-source"},
	"https-held-cleanup":          {"wg", "https-connect", "server", "server", "held-cleanup"},
}

func windowsCONNECTExecutionScenario(value string) (mode, protocol, requested, winner, fault string, err error) {
	x, found := windowsCONNECTExecutionScenarios[value]
	if !found {
		err = errors.New("uncaptured CONNECT execution case")
		return
	}
	return x.Mode, x.Protocol, x.Requested, x.Winner, x.Fault, nil
}

func windowsCONNECTExecutionEntryLayer(scenario string) string {
	switch scenario {
	case "http-awg-fast-auto-local", "https-awg-strong-server":
		return "aes-256-gcm"
	case "http-awg-strong-auto-server", "https-wg-auto-local":
		return "aes-256-gcm+xor-whitening"
	default:
		return "off"
	}
}

func windowsCONNECTExecutionRequireMeasurements(t *testing.T, result routechoice.Result, winner string, compare bool) {
	t.Helper()
	valid := func(m routechoice.Measurement) bool {
		positive := func(v float64) bool { return v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }
		return m.Candidate.Valid() && m.Eligible && m.Failure == "" && positive(m.LastNodeMS) && positive(m.ExternalMS) && m.ScoreMS != nil && positive(*m.ScoreMS) && math.Abs(*m.ScoreMS-(m.LastNodeMS/2+m.ExternalMS/2)) <= 0.000001
	}
	target := false
	for _, original := range mobilemultihop.Targets {
		target = target || result.Target == original
	}
	if !target || result.Winner == nil || string(result.Winner.Execution) != winner || result.Final == nil || result.Final.Candidate != *result.Winner || !valid(*result.Final) {
		t.Fatal("original chosen path lost its routed final measurement")
	}
	if !compare {
		if len(result.Measurements) != 0 {
			t.Fatal("retained choice reran candidate comparison")
		}
		return
	}
	if len(result.Measurements) != 2 {
		t.Fatal("original Compare omitted a candidate")
	}
	seen := map[routechoice.Execution]bool{}
	for _, m := range result.Measurements {
		if seen[m.Candidate.Execution] || !valid(m) || m.Candidate.Transport != result.Winner.Transport || m.Candidate.EntryID != result.Winner.EntryID || m.Candidate.ExitID != result.Winner.ExitID {
			t.Fatal("original Compare lost a routed candidate or score")
		}
		seen[m.Candidate.Execution] = true
	}
	if !seen[routechoice.Local] || !seen[routechoice.Server] {
		t.Fatal("original Compare replaced a candidate")
	}
}

func windowsCONNECTExecutionRegisterRoutes(mux *http.ServeMux, a *app, original common.RouterProfileStore) (bool, func(), error) {
	root := filepath.Dir(a.cfg.ProfilesFile)
	raw, err := readPrivateRegular(filepath.Join(root, windowsCONNECTExecutionMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, func() {}, nil
	}
	if err != nil {
		return true, nil, err
	}
	scenario := strings.TrimSpace(string(raw))
	_, protocol, requested, _, fault, err := windowsCONNECTExecutionScenario(scenario)
	if err != nil {
		return true, nil, err
	}
	selected, found := a.profileByIDLocked(original.SelectedID)
	if !found || selected.MultihopExecution != requested || len(selected.MultihopNodes) != 3 || !desktopNodeChainHasCONNECT(selected.MultihopNodes) {
		return true, nil, errors.New("original exact CONNECT execution profile changed")
	}
	hold, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	release, err := a.holdCapturedMTU(hold)
	cancel()
	if err != nil {
		return true, nil, err
	}
	var mu sync.Mutex
	var sessions []*desktopNodeChainExecutionSession
	remember := func() error {
		owner, err := a.desktopOrderedExecutionOwner()
		if err != nil {
			return err
		}
		if owner == nil {
			return errors.New("original entered execution owner absent")
		}
		mu.Lock()
		defer mu.Unlock()
		for _, s := range sessions {
			if s == owner.session {
				return nil
			}
		}
		sessions = append(sessions, owner.session)
		return nil
	}
	mux.HandleFunc("/api/native-connect-execution-retired", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		saved := append([]*desktopNodeChainExecutionSession(nil), sessions...)
		mu.Unlock()
		if err := windowsCONNECTExecutionRetired(r.Context(), a, saved); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"native_joined": true, "journal_settled": true, "wfp_absent": true, "tun_absent": true})
	})
	var public, restored atomic.Bool
	mux.HandleFunc("/api/native-connect-execution-source", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		profiles := cloneRouterProfileStore(a.profiles)
		a.mu.Unlock()
		if !found {
			http.Error(w, "original control absent", 409)
			return
		}
		selection, err := resolveDesktopNodeChainSelection(control, profiles.Profiles, control.MultihopNodes, "local")
		if err == nil {
			selection, err = captureNativeMultihopSelection(r.Context(), root, selection, []string{protocol}, nil)
		}
		if err != nil || selection.Native == nil || selection.Native.chain == nil {
			http.Error(w, fmt.Sprint(err), 409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"local_source": selection.Native.chain.input})
	})
	mux.HandleFunc("/api/native-ordered-request", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		tokens, err := a.connectionProfileTokensLocked(control)
		if !found || err != nil {
			http.Error(w, "source changed", 409)
			return
		}
		selected := a.profiles.SelectedID
		_ = json.NewEncoder(w).Encode(multihopConnectRequest{Nodes: append([]common.MultihopNodeSelection(nil), control.MultihopNodes...), Execution: requested, desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: tokens}})
	})
	mux.HandleFunc("/api/multihop/connect", func(w http.ResponseWriter, r *http.Request) {
		public.Store(true)
		a.nativeMultihopConnect(w, r)
	})
	mux.HandleFunc("/api/multihop/status", a.nativeMultihopStatus)
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if err := remember(); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		a.disconnect(w, r)
	})
	mux.HandleFunc("/api/native-connect-execution-observation", func(w http.ResponseWriter, r *http.Request) {
		value, err := windowsCONNECTExecutionObserve(r.Context(), a)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		if err := remember(); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		value.PublicConnect = public.Load()
		value.Restored = restored.Load()
		_ = json.NewEncoder(w).Encode(value)
	})
	// The trigger is test-only. Capture, retained Stop, successor launch and
	// restoration use the real Speed Lab coordinator and its original intent.
	mux.HandleFunc("/api/native-connect-execution-restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "" {
			http.Error(w, "uncaptured restore", 409)
			return
		}
		if err := remember(); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		_, snapshot, finish, err := a.beginSpeedLabTemporaryOperationExpectedContext(r.Context(), nil)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		defer finish()
		if err = a.speedLabSuspendPrevious(snapshot, false); err == nil {
			err = a.speedLabRestoreTemporary(snapshot)
		}
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		if err := remember(); err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		restored.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]bool{"restored": true})
	})
	mux.HandleFunc("/api/native-connect-execution-cleanup-retry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "held-cleanup" {
			http.Error(w, "uncaptured cleanup retry", 409)
			return
		}
		owner, err := a.desktopOrderedExecutionOwner()
		if err != nil || owner == nil || owner.session.Current(r.Context()) != nil {
			http.Error(w, "original live owner absent", 409)
			return
		}
		original, ok := desktopOwnedNodeProcess(owner.session.launch).(*desktopNodeWindowsJournalProcess)
		if !ok || original == nil || original.closeGate == nil {
			http.Error(w, "original journal gate absent", 409)
			return
		}
		select {
		case <-r.Context().Done():
			http.Error(w, r.Context().Err().Error(), 409)
			return
		case <-original.closeGate:
		}
		released := false
		releaseGate := func() {
			if !released {
				original.closeGate <- struct{}{}
				released = true
			}
		}
		defer releaseGate()
		// Hold the actual original host gate, not a replacement cleanup method.
		// The bounded public request must refuse without forgetting this live child.
		call, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		request := httptest.NewRequest(http.MethodPost, "/api/disconnect", strings.NewReader("{}")).WithContext(call)
		result := httptest.NewRecorder()
		a.disconnect(result, request)
		cancel()
		releaseGate()
		if result.Code == http.StatusOK || !strings.Contains(result.Body.String(), context.DeadlineExceeded.Error()) {
			http.Error(w, "held original native cleanup was not bounded", 500)
			return
		}
		original.mu.Lock()
		joined := original.joined
		original.mu.Unlock()
		retained, err := a.desktopOrderedExecutionOwner()
		if err != nil || joined || retained != owner || desktopOwnedNodeProcess(retained.session.launch) != original {
			http.Error(w, "failed cleanup replaced original native owner", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"refused": true, "same_owner": true, "joined": false})
	})
	mux.HandleFunc("/api/native-connect-execution-replace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "replaced-source" {
			http.Error(w, "uncaptured replacement", 409)
			return
		}
		a.mu.Lock()
		if a.profiles.Profiles[1].External.HTTPConnect != nil {
			a.profiles.Profiles[1].External.HTTPConnect.Password += "changed"
		} else {
			a.profiles.Profiles[1].External.HTTPSConnect.Password += "changed"
		}
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"changed": true})
	})
	return true, release, nil
}
