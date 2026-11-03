package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func savedLatencyFixture() common.RouterProfile {
	p := common.RouterProfile{ID: "saved-node", Name: "Saved", NodeKind: "router-vpn", Endpoint: "192.0.2.1", APIToken: "private-original", LatencySamples: 50, LatencyMinMs: 1, LatencyMedianMs: 10, LatencyTrimmedMeanMs: 12, LatencyAverageMs: 14, LatencyP90Ms: 20, LatencyMaxMs: 25, LatencyLastTest: "2026-01-01T00:00:00Z"}
	if err := common.NormalizeRouterProfile(&p); err != nil {
		panic(err)
	}
	p.LatencyReceipt = &common.NodeLatencyReceipt{Schema: 1, Measurement: savedNodeLatencyMeasurement, Attempts: 50, SourceToken: liveMeasurementProfileToken(p), NetworkMetadata: "original-interface-address-metadata"}
	return p
}

func TestSavedNodeLatencyEligibilityPreservesHistoryWithoutInventingEvidence(t *testing.T) {
	base := savedLatencyFixture()
	if !savedNodeLatencyEligible(base) {
		t.Fatal("complete historical source-bound measurement rejected")
	}
	for name, change := range map[string]func(*common.RouterProfile){
		"legacy":          func(p *common.RouterProfile) { p.LatencyReceipt = nil },
		"partial":         func(p *common.RouterProfile) { p.LatencySamples = 49; p.LatencyReceipt.Failed = 1 },
		"short":           func(p *common.RouterProfile) { p.LatencySamples = 5; p.LatencyReceipt.Attempts = 5 },
		"mismatch":        func(p *common.RouterProfile) { p.LatencyReceipt.Attempts = 60 },
		"failure":         func(p *common.RouterProfile) { p.LatencyReceipt.Failed = 1 },
		"missing-network": func(p *common.RouterProfile) { p.LatencyReceipt.NetworkMetadata = "" },
		"routed":          func(p *common.RouterProfile) { p.LatencyReceipt.Measurement = "routed-https-response-after-tls" },
		"credentials":     func(p *common.RouterProfile) { p.APIToken = "replacement" },
		"endpoint":        func(p *common.RouterProfile) { p.Endpoint = "192.0.2.2" },
		"external": func(p *common.RouterProfile) {
			p.NodeKind = "external"
			p.LatencyReceipt.SourceToken = liveMeasurementProfileToken(*p)
		},
		"multihop": func(p *common.RouterProfile) {
			p.MultihopEnabled = true
			p.LatencyReceipt.SourceToken = liveMeasurementProfileToken(*p)
		},
		"nan":          func(p *common.RouterProfile) { p.LatencyTrimmedMeanMs = math.NaN() },
		"infinite":     func(p *common.RouterProfile) { p.LatencyAverageMs = math.Inf(1) },
		"zero":         func(p *common.RouterProfile) { p.LatencyMinMs = 0 },
		"unordered":    func(p *common.RouterProfile) { p.LatencyMaxMs = 2 },
		"future":       func(p *common.RouterProfile) { p.LatencyLastTest = time.Now().Add(time.Hour).Format(time.RFC3339) },
		"missing-time": func(p *common.RouterProfile) { p.LatencyLastTest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			p := cloneRouterProfile(base)
			change(&p)
			if savedNodeLatencyEligible(p) {
				t.Fatal("invalid saved measurement eligible")
			}
			view := publicProfileFor(p)
			if view.LatencyEligible || view.LatencySamples != p.LatencySamples || (name != "nan" && view.LatencyTrimmedMeanMs != p.LatencyTrimmedMeanMs) {
				t.Fatal("eligibility erased historical fields or admitted invalid data")
			}
		})
	}
	clone := cloneRouterProfile(base)
	clone.LatencyReceipt.Attempts = 5
	if base.LatencyReceipt.Attempts != 50 {
		t.Fatal("captured receipt aliases mutable source")
	}
	renamed := cloneRouterProfile(base)
	renamed.Name = "Display rename"
	renamed.UseCount = 90
	if !savedNodeLatencyEligible(renamed) {
		t.Fatal("display metadata arbitrarily invalidated history")
	}
	larger := cloneRouterProfile(base)
	larger.LatencySamples = 200
	larger.LatencyReceipt.Attempts = 200
	if !savedNodeLatencyEligible(larger) {
		t.Fatal("complete original at-least50 benchmark was discarded")
	}
	raw, err := json.Marshal(publicProfileFor(base))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(base.APIToken)) || bytes.Contains(raw, []byte(base.LatencyReceipt.SourceToken)) || bytes.Contains(raw, []byte(base.LatencyReceipt.NetworkMetadata)) {
		t.Fatal("public view leaked private provenance")
	}
}

func TestSavedNodeLatencyAtomicSelectionRanksTrimmedMeanAndRollsBack(t *testing.T) {
	for _, scenario := range []string{"success", "tie", "partial", "legacy", "source-change", "busy", "cancelled", "persist-failure"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			first := savedLatencyFixture()
			first.ID = "a"
			first.LatencyMedianMs = 1
			first.LatencyTrimmedMeanMs = 40
			first.LatencyAverageMs = 45
			first.LatencyP90Ms = 80
			first.LatencyMaxMs = 100
			first.LatencyReceipt.SourceToken = liveMeasurementProfileToken(first)
			second := savedLatencyFixture()
			second.ID = "b"
			second.LatencyMedianMs = 20
			second.LatencyTrimmedMeanMs = 20
			second.LatencyAverageMs = 20
			second.LatencyP90Ms = 20
			second.LatencyReceipt.SourceToken = liveMeasurementProfileToken(second)
			a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "nodes.json")}, profiles: common.RouterProfileStore{SelectedID: "a", Profiles: []common.RouterProfile{first, second}}}
			a.state.RouterID = "a"
			if err := a.persistProfilesLocked(); err != nil {
				t.Fatal(err)
			}
			// Normalization is part of actual persistence; issue the fixture receipt for
			// that stored source, as the production benchmark does for its loaded source.
			for i := range a.profiles.Profiles {
				p := &a.profiles.Profiles[i]
				p.LatencyReceipt.SourceToken = liveMeasurementProfileToken(*p)
			}
			want := http.StatusOK
			expectedID := "b"
			switch scenario {
			case "tie":
				a.profiles.Profiles[0].LatencyTrimmedMeanMs = 20
				expectedID = "a"
			case "partial":
				a.profiles.Profiles[1].LatencySamples = 49
				want = http.StatusConflict
			case "legacy":
				a.profiles.Profiles[1].LatencyReceipt = nil
				want = http.StatusConflict
			case "source-change":
				a.profiles.Profiles[1].APIToken = "new"
				want = http.StatusConflict
			case "busy":
				a.state.Connected = true
				want = http.StatusConflict
			case "cancelled":
				want = http.StatusRequestTimeout
			case "persist-failure":
				a.cfg.ProfilesFile = root
				want = http.StatusInternalServerError
			}
			before := cloneRouterProfileStore(a.profiles)
			routerBefore := a.state.RouterID
			req := httptest.NewRequest(http.MethodPost, "/api/profile/lowest-saved-latency", strings.NewReader(`{}`))
			if scenario == "cancelled" {
				ctx, cancel := context.WithCancel(req.Context())
				cancel()
				req = req.WithContext(ctx)
			}
			out := httptest.NewRecorder()
			a.selectSavedLowestLatency(out, req)
			if out.Code != want {
				t.Fatalf("HTTP%d want%d: %s", out.Code, want, out.Body.String())
			}
			if want != http.StatusOK {
				if !reflect.DeepEqual(before, a.profiles) || a.state.RouterID != routerBefore {
					t.Fatal("refused transaction mutated selection/history")
				}
				return
			}
			if a.profiles.SelectedID != expectedID || a.state.RouterID != expectedID {
				t.Fatal("saved trimmed mean/stable ID ranking was not adopted")
			}
			if !strings.Contains(out.Body.String(), `"scope":"saved"`) || !strings.Contains(out.Body.String(), "different networks and times") {
				t.Fatal("historical result mislabeled current Fastest")
			}
			for i := range before.Profiles {
				if !reflect.DeepEqual(before.Profiles[i], a.profiles.Profiles[i]) {
					t.Fatal("saved selection rewrote benchmark")
				}
			}
		})
	}
}

func TestProfileLatencyPartialActualTCPPreservesSavedBenchmark(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := savedLatencyFixture()
	p.Endpoint = "127.0.0.1"
	p.LatencyReceipt.SourceToken = liveMeasurementProfileToken(p)
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "nodes.json")}, profiles: common.RouterProfileStore{SelectedID: p.ID, Profiles: []common.RouterProfile{p}}}
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	before := cloneRouterProfileStore(a.profiles)
	bytesBefore, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:8388")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for n := 0; n < 7; n++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if n == 6 {
				listener.Close()
			}
			conn.Close()
		}
	}()
	out := httptest.NewRecorder()
	a.profileLatency(out, httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(`{"id":"saved-node","samples":50}`)))
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("owned partial TCP listener did not join")
	}
	if out.Code != http.StatusOK {
		t.Fatalf("partial TCP statistics unavailable: HTTP%d %s", out.Code, out.Body.String())
	}
	var got latencyResponse
	if err := json.Unmarshal(out.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Samples < 5 || got.Samples >= 50 || got.Failed == 0 || got.Samples+got.Failed != 50 || got.Saved || got.Complete {
		t.Fatalf("partial actual counts falsely promoted: %+v", got)
	}
	after, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytesBefore, after) || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("partial result replaced complete saved history")
	}
}
