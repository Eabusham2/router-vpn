package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/routechoice"
)

type routedClockCaller struct{}
type routedClockLane struct {
	t                  *testing.T
	calls, closed      int
	retired, nilSocket bool
	failAt             int
}

func (l *routedClockLane) AliveContext(ctx context.Context) bool {
	return ctx.Err() == nil && !l.retired
}
func (l *routedClockLane) Close(context.Context) error { l.retired = true; return nil }
func (l *routedClockLane) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	l.calls++
	if ctx.Value(routedClockCaller{}) != "original" || network != "tcp" || !strings.HasPrefix(address, "candidate.invalid:") {
		l.t.Fatal("routed sample escaped original caller/destination", network, address)
	}
	if _, ok := ctx.Deadline(); !ok {
		l.t.Fatal("routed sample lost deadline")
	}
	if l.calls == l.failAt {
		return nil, errors.New("actual routed refusal")
	}
	if l.nilSocket {
		return nil, nil
	}
	client, server := net.Pipe()
	_ = server.Close()
	return &routedClockConnection{Conn: client, lane: l}, nil
}

type routedClockConnection struct {
	net.Conn
	lane *routedClockLane
}

func (c *routedClockConnection) Close() error { c.lane.closed++; return c.Conn.Close() }

func TestRoutedCandidateClockCannotFabricateScoreOrTryAnotherPort(t *testing.T) {
	actual := errors.New("original routed measurement clock failed")
	for _, fault := range []string{"tiny", "ordinary", "start", "read", "zero", "negative", "nan", "infinity", "late-read", "cancel", "retired", "nil-socket", "network-failure"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), routedClockCaller{}, "original"))
			defer cancel()
			lane := &routedClockLane{t: t}
			if fault == "nil-socket" {
				lane.nilSocket = true
			}
			if fault == "network-failure" {
				lane.failAt = 3
			}
			starts, reads := 0, 0
			samples := 5
			if fault == "tiny" || fault == "ordinary" {
				samples = 50
			}
			clock := func() (clientMeasurementInterval, error) {
				starts++
				if fault == "start" {
					return nil, actual
				}
				return clientClockRead(func() (float64, error) {
					reads++
					switch fault {
					case "ordinary":
						return 1.23456, nil
					case "read":
						return 7, actual
					case "zero":
						return 0, nil
					case "negative":
						return -1, nil
					case "nan":
						return math.NaN(), nil
					case "infinity":
						return math.Inf(1), nil
					case "late-read":
						if reads == 4 {
							return 7, actual
						}
					case "cancel":
						cancel()
					case "retired":
						lane.retired = true
					}
					return .000001, nil
				}), nil
			}
			p := common.RouterProfile{ID: "candidate", Endpoint: "candidate.invalid"}
			result, err := measureViaEntryCandidateWithClock(ctx, lane, p, samples, clock)
			if fault == "tiny" || fault == "ordinary" {
				want := .000001
				if fault == "ordinary" {
					want = 1.235
				}
				if err != nil || !eligibleViaEntryResult(result) || result.TrimmedMs != want || starts != 51 || reads != 51 || lane.calls != 51 || lane.closed != 51 || fastestViaEntryCandidate([]liveLatencyResult{result}) != p.ID {
					t.Fatalf("original routed measurements changed: %+v starts=%d reads=%d calls=%d closed=%d err=%v", result, starts, reads, lane.calls, lane.closed, err)
				}
				if !strings.Contains(result.Description, "through captured entry") {
					t.Fatal("routed measurement mislabeled", result.Description)
				}
			} else if fault == "network-failure" {
				if err != nil || result.Samples != 4 || result.Failed != 1 || eligibleViaEntryResult(result) || fastestViaEntryCandidate([]liveLatencyResult{result}) != "" {
					t.Fatal("real network failure became a complete candidate", result, err)
				}
			} else {
				if err == nil || result.Samples != 0 || result.TrimmedMs != 0 || eligibleViaEntryResult(result) {
					t.Fatal("invalid interval acquired candidate score", result, err)
				}
				if fault == "start" || fault == "read" || fault == "late-read" {
					if !errors.Is(err, actual) {
						t.Fatal("original clock failure lost", err)
					}
				}
				if fault == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("clock read lost caller cancellation", err)
				}
				if fault == "start" && (starts != 1 || lane.calls != 0) {
					t.Fatal("failed clock initialization fell back to another port", starts, lane.calls)
				}
				if fault != "start" && fault != "nil-socket" {
					want := 1
					if fault == "late-read" {
						want = 4
					}
					if lane.calls != want || lane.closed != want {
						t.Fatal("invalid clock leaked socket or attempted another port/sample", lane.calls, lane.closed)
					}
				}
			}
		})
	}
}

type routedDurationRead func() (time.Duration, error)

func (r routedDurationRead) Duration() (time.Duration, error) { return r() }

func routedClockExecutionFixture(t *testing.T, ctx context.Context, wrongProof bool) (*desktopExecutionSession, *atomic.Int32) {
	t.Helper()
	a, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	command := &exec.Cmd{}
	a.cmd = command
	selection := multihopSelection{Entry: a.profiles.Profiles[0], Exit: p, Base: "wg", ExitMode: "shadowsocks"}
	d := &desktopExecutionDriver{a: a, selection: selection, network: "captured-physical-network"}
	d.prepared = &speedLabMultihopPreparation{app: a, selection: selection, readNetwork: func(call context.Context) (string, error) {
		if call != ctx {
			t.Error("Compare observer lost original caller")
		}
		return d.network, call.Err()
	}}
	session := &desktopExecutionSession{driver: d, selection: selection, command: command, generation: "captured-generation", candidate: routechoice.Candidate{EntryID: selection.Entry.ID, ExitID: selection.Exit.ID, Execution: routechoice.Local, Transport: selection.ExitMode}}
	count := &atomic.Int32{}
	asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.URL.String() != "http://10.77.0.1:8787/health" || r.Header.Get("Authorization") != "Bearer "+p.APIToken {
			t.Error("Compare response changed captured target/credential", r.URL)
		}
		node := p.NodeProofID
		if wrongProof {
			node = strings.Repeat("0", 64)
		}
		fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, node, desktopNodeProofKind)
	}))
	if session.identityContext(ctx) == "" {
		t.Fatal("Compare fixture has no original identity")
	}
	return session, count
}

func TestCompareResponseUsesOriginalCheckedDurationAndOwner(t *testing.T) {
	actual := errors.New("original Compare clock failure")
	for _, fault := range []string{"nanosecond", "fraction", "start", "read", "zero", "negative", "cancel", "owner", "graph", "wrong-node"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session, requests := routedClockExecutionFixture(t, ctx, fault == "wrong-node")
			starts, reads := 0, 0
			want := time.Nanosecond
			if fault == "fraction" {
				want = 17 * time.Microsecond
			}
			clock := func() (executionMeasurementInterval, error) {
				starts++
				if fault == "start" {
					return nil, actual
				}
				return routedDurationRead(func() (time.Duration, error) {
					reads++
					switch fault {
					case "read":
						return time.Second, actual
					case "zero":
						return 0, nil
					case "negative":
						return -time.Nanosecond, nil
					case "cancel":
						cancel()
					case "owner":
						session.driver.a.mu.Lock()
						session.driver.a.cmd = &exec.Cmd{}
						session.driver.a.mu.Unlock()
					case "graph":
						clearActiveMultihopGraph(session.driver.a)
					}
					return want, nil
				}), nil
			}
			value, err := session.probeWithClock(ctx, "http://10.77.0.1:8787/health", &session.selection.Exit, clock)
			if fault == "nanosecond" || fault == "fraction" {
				if err != nil || value != want {
					t.Fatal("Compare rounded or replaced original duration", value, err)
				}
			} else {
				if err == nil || value != 0 {
					t.Fatal("failed/stale response earned Compare duration", value, err)
				}
				if (fault == "start" || fault == "read") && !errors.Is(err, actual) {
					t.Fatal("Compare clock cause lost", err)
				}
				if fault == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("Compare caller cancellation lost", err)
				}
			}
			expected := 1
			if fault == "start" {
				expected = 0
			}
			if starts != 1 || reads != expected || int(requests.Load()) != expected {
				t.Fatal("Compare clock failure retried or sent unmeasurable proof", starts, reads, requests.Load())
			}
		})
	}
}

func TestCompareResponseProductionClockUsesCheckedDuration(t *testing.T) {
	interval, err := startExecutionMeasurementInterval()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := interval.(hopmeasure.Interval); !ok {
		t.Fatalf("Compare replaced checked native interval with %T", interval)
	}
}
