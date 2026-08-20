package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestMeasureRoutedProfileSpeedUsesAuthenticatedExactTransfers(t *testing.T) {
	const token = "hop-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			http.Error(w, "bad auth", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/api/benchmark/download":
			n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
			if err != nil || n < 1<<20 || n > 16<<20 {
				http.Error(w, "bad bytes", http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("Accept-Encoding"); got != "identity" {
				http.Error(w, "compression not disabled", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(n))
			chunk := make([]byte, 64<<10)
			for remaining := n; remaining > 0; {
				size := len(chunk)
				if size > remaining { size = remaining }
				if _, err := w.Write(chunk[:size]); err != nil { return }
				remaining -= size
			}
		case "/api/benchmark/upload":
			n, err := io.Copy(io.Discard, io.LimitReader(r.Body, 16<<20+1))
			if err != nil || n < 1<<20 || n > 16<<20 {
				http.Error(w, "bad upload", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"bytes": n, "server_receive_ms": 1.25})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	profile := common.RouterProfile{ID: "node-a", Name: "Node A", NodeKind: "router-vpn", RouterAPI: server.URL, APIToken: token}
	result, err := measureRoutedProfileSpeed(profile, 1<<20)
	if err != nil { t.Fatal(err) }
	if result.RouterID != profile.ID || result.Bytes != 1<<20 {
		t.Fatalf("unexpected routed result: %+v", result)
	}
	if result.DownloadMbps <= 0 || result.UploadMbps <= 0 || result.DownloadMs <= 0 || result.UploadMs <= 0 {
		t.Fatalf("non-positive real transfer result: %+v", result)
	}
	if !strings.Contains(result.Proof, "not derived from RTT") {
		t.Fatalf("proof does not preserve measurement truth: %q", result.Proof)
	}
}

func TestMeasureRoutedProfileSpeedRejectsUnsupportedProfiles(t *testing.T) {
	if _, err := measureRoutedProfileSpeed(common.RouterProfile{ID: "ext", NodeKind: "external", External: &common.ExternalNodeConfig{}}, 1<<20); err == nil {
		t.Fatal("external-only node unexpectedly accepted")
	}
	if _, err := measureRoutedProfileSpeed(common.RouterProfile{ID: "missing", NodeKind: "router-vpn"}, 1<<20); err == nil {
		t.Fatal("missing private benchmark API/token unexpectedly accepted")
	}
}

func TestValidateActiveMultihopSpeedGraphRequiresExactLivePair(t *testing.T) {
	st := state{Connected: true, Mode: "multihop", RouterID: "exit-a"}
	graph := activeMultihopGraph{EntryID: "entry-a", ExitID: "exit-a", Base: "wg", ExitMode: "shadowsocks"}
	if err := validateActiveMultihopSpeedGraph(st, graph, true, "entry-a", "exit-a"); err != nil {
		t.Fatalf("exact active graph rejected: %v", err)
	}
	if err := validateActiveMultihopSpeedGraph(st, graph, true, "entry-other", "exit-a"); err == nil || !strings.Contains(err.Error(), "does not match active multihop entry") {
		t.Fatalf("wrong entry was not rejected precisely: %v", err)
	}
	if err := validateActiveMultihopSpeedGraph(st, graph, true, "entry-a", "exit-other"); err == nil || !strings.Contains(err.Error(), "does not match active multihop exit") {
		t.Fatalf("wrong exit was not rejected precisely: %v", err)
	}
}

func TestValidateActiveMultihopSpeedGraphFailsClosedWithoutIdentity(t *testing.T) {
	st := state{Connected: true, Mode: "multihop", RouterID: "exit-a"}
	if err := validateActiveMultihopSpeedGraph(st, activeMultihopGraph{}, false, "entry-a", "exit-a"); err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Fatalf("missing graph identity did not fail closed: %v", err)
	}
	graph := activeMultihopGraph{EntryID: "entry-a", ExitID: "exit-a"}
	st.RouterID = "different-exit"
	if err := validateActiveMultihopSpeedGraph(st, graph, true, "entry-a", "exit-a"); err == nil || !strings.Contains(err.Error(), "state and tracked exit identity disagree") {
		t.Fatalf("state/tracker disagreement did not fail closed: %v", err)
	}
}

func TestActiveMultihopGraphTrackerStoresExactSelection(t *testing.T) {
	a := &app{}
	defer clearActiveMultihopGraph(a)
	sel := multihopSelection{
		Entry: common.RouterProfile{ID: "entry-a"},
		Exit: common.RouterProfile{ID: "exit-a"},
		Base: "awg", ExitMode: "hysteria2",
	}
	setActiveMultihopGraph(a, sel)
	graph, ok := getActiveMultihopGraph(a)
	if !ok { t.Fatal("active graph was not stored") }
	if graph.EntryID != "entry-a" || graph.ExitID != "exit-a" || graph.Base != "awg" || graph.ExitMode != "hysteria2" {
		t.Fatalf("active graph changed identity: %+v", graph)
	}
	clearActiveMultihopGraph(a)
	if _, ok := getActiveMultihopGraph(a); ok { t.Fatal("active graph survived explicit invalidation") }
}
