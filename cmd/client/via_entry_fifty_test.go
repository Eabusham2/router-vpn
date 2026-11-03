package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"router-vpn/internal/common"
)

type viaEntryCountedLane struct {
	*viaEntryTestLane
	host   string
	failAt int32
	calls  atomic.Int32
}

func (l *viaEntryCountedLane) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(address)
	if host == l.host && l.calls.Add(1) == l.failAt {
		return nil, errors.New("one routed candidate handshake failed")
	}
	return l.viaEntryTestLane.DialContext(ctx, network, address)
}

func TestViaEntryFiftyActualDefaultAndPartialFailure(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "complete-default"
		if partial {
			name = "one-real-failed-sample"
		}
		t.Run(name, func(t *testing.T) {
			a, entry, candidates := viaEntryFixture(t)
			candidate := candidates[0]
			base := &viaEntryTestLane{entry: entry}
			lane := &viaEntryCountedLane{viaEntryTestLane: base, host: candidate.Endpoint}
			if partial {
				lane.failAt = 27 // Discovery is call one, followed by fifty samples.
			}
			id := strings.Repeat("e", 32)
			body, _ := json.Marshal(viaEntryRequest{RequestID: id, EntryID: entry.ID, CandidateIDs: []string{candidate.ID}})
			w := httptest.NewRecorder()
			a.viaEntryCandidatesWith(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates", strings.NewReader(string(body))), viaEntryDependencies{
				network: func() string { return "captured-fifty-network" },
				start: func(context.Context, string, string, common.RouterProfile, map[string][]byte, map[string][]byte, []common.RouterProfile) (viaEntryLane, error) {
					return lane, nil
				},
			})
			var receipt viaEntryReceipt
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &receipt) != nil || len(receipt.Results) != 1 || len(receipt.Errors) != 0 {
				t.Fatal("actual candidate transaction failed", w.Code, w.Body.String())
			}
			if lane.calls.Load() != 51 || base.proofs != 2 || !base.closed || base.closeCalls != 1 || !receipt.Drained {
				t.Fatal("sample count, proof or owned drain changed", lane.calls.Load(), base.proofs, base.closeCalls, receipt)
			}
			value := receipt.Results[0]
			if partial {
				if value.Samples != 49 || value.Failed != 1 || value.TrimmedMs <= 0 || value.MedianMs <= 0 || receipt.FastestID != "" || eligibleViaEntryResult(value) {
					t.Fatal("partial real measurement became a comparison score", receipt)
				}
				if validation := validateViaEntryTest(a, id, candidate.ID); validation.Code != 200 || !strings.Contains(validation.Body.String(), `"measured":false`) {
					t.Fatal("partial receipt granted measured adoption", validation.Body.String())
				}
			} else if value.Samples != 50 || value.Failed != 0 || !eligibleViaEntryResult(value) || receipt.FastestID != candidate.ID {
				t.Fatal("default request did not produce fifty complete routed samples", receipt)
			}
		})
	}
}

func TestViaEntryFiftyRejectsShortOrOversizedRequestBeforeOwnership(t *testing.T) {
	for _, samples := range []int{-1, 1, 3, 5, 49, 51, 200} {
		var started, networks int
		a := &app{}
		body, _ := json.Marshal(viaEntryRequest{RequestID: strings.Repeat("b", 32), EntryID: "entry", CandidateIDs: []string{"exit"}, Samples: samples})
		w := httptest.NewRecorder()
		a.viaEntryCandidatesWith(w, httptest.NewRequest(http.MethodPost, "/api/multihop/candidates", strings.NewReader(string(body))), viaEntryDependencies{
			network: func() string { networks++; return "network" },
			start: func(context.Context, string, string, common.RouterProfile, map[string][]byte, map[string][]byte, []common.RouterProfile) (viaEntryLane, error) {
				started++
				return nil, errors.New("must not start")
			},
		})
		_, owned := viaEntryControls.Load(a)
		if w.Code != http.StatusBadRequest || started != 0 || networks != 0 || owned {
			t.Fatal("invalid benchmark size claimed native ownership", samples, w.Code, started, networks, owned)
		}
	}
}

func TestViaEntryFiftyTrimmedRankingAndStableTie(t *testing.T) {
	var spiky, steady []float64
	for i := 0; i < 50; i++ {
		v := 1.0
		if i >= 26 {
			v = 100
		}
		spiky = append(spiky, v)
		steady = append(steady, 20)
	}
	a := profileLatencySummary(common.RouterProfile{ID: "spiky"}, 443, spiky, 0)
	b := profileLatencySummary(common.RouterProfile{ID: "steady"}, 443, steady, 0)
	if a.MedianMs >= b.MedianMs || a.TrimmedMs <= b.TrimmedMs || fastestViaEntryCandidate([]liveLatencyResult{a, b}) != b.ID {
		t.Fatal("median replaced the robust comparison score", a, b)
	}
	c := b
	c.ID = "alpha"
	for _, values := range [][]liveLatencyResult{{b, c}, {c, b}} {
		if fastestViaEntryCandidate(values) != c.ID {
			t.Fatal("tie depends on candidate order", values)
		}
	}
	for _, change := range []func(*liveLatencyResult){
		func(v *liveLatencyResult) { v.Samples = 49 },
		func(v *liveLatencyResult) { v.Samples = 51 },
		func(v *liveLatencyResult) { v.Failed = 1 },
		func(v *liveLatencyResult) { v.TrimmedMs = 0 },
		func(v *liveLatencyResult) { v.TrimmedMs = math.NaN() },
		func(v *liveLatencyResult) { v.TrimmedMs = math.Inf(1) },
		func(v *liveLatencyResult) { v.MedianMs = -1 },
		func(v *liveLatencyResult) { v.MaxMs = 60001 },
		func(v *liveLatencyResult) { v.MinMs = v.MedianMs + 1 },
		func(v *liveLatencyResult) { v.P90Ms = v.MedianMs - 1 },
		func(v *liveLatencyResult) { v.AverageMs = v.MaxMs + 1 },
		func(v *liveLatencyResult) { v.TrimmedMs = v.MaxMs + 1 },
	} {
		invalid := b
		change(&invalid)
		if eligibleViaEntryResult(invalid) || fastestViaEntryCandidate([]liveLatencyResult{invalid}) != "" {
			t.Fatal("invalid or partial statistics received a score", invalid)
		}
	}
}
