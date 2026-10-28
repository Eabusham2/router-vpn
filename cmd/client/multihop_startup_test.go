//go:build go1.25

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

func TestDesktopMultihopStartupBudgetsPreserveOrdinaryAndCapturedPhases(t *testing.T) {
	phases := map[string]time.Duration{"wg-pq": 30 * time.Second, "awg2-pq": 30 * time.Second,
		"max-tls-wg": 30 * time.Second, "max-tls-awg": 30 * time.Second,
		"max-quic-wg": 30 * time.Second, "max-quic-awg": 30 * time.Second}
	for _, entry := range mobilemultihop.NodeMultihopEntryModes() {
		for _, exit := range mobilemultihop.NodeMultihopExitModes() {
			selected := multihopSelection{EntryMode: entry, ExitMode: exit}
			for _, execution := range []routechoice.Execution{routechoice.Local, routechoice.Server, "auto"} {
				startup, total := desktopMultihopStartupBudgets(selected, []string{exit}, execution)
				wantTotal := 180 * time.Second
				if execution == "auto" {
					wantTotal += 4 * (phases[entry] + phases[exit])
				}
				if startup != 25*time.Second+phases[entry]+phases[exit] || total != wantTotal || total > 420*time.Second {
					t.Fatalf("captured startup budget differs: %s/%s/%s: %s %s", entry, exit, execution, startup, total)
				}
			}
			if nativeMultihopProofTimeout(selected) != 20*time.Second+phases[entry]+phases[exit] {
				t.Fatal("native Local proof clipped an initial key or extended an ordinary mode", entry, exit)
			}
			owner := &desktopRelayOwner{request: multihoprelay.Request{ExitMode: exit}}
			for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
				for _, renewed := range []bool{false, true} {
					owner.renewed = renewed
					want := 8 * time.Second
					if method == http.MethodPut && !renewed {
						want += phases[exit]
					}
					if owner.controlTimeout(method) != want {
						t.Fatal("lease startup allowance leaked into discovery, renewal or teardown", exit, method, renewed)
					}
				}
			}
		}
		_, total := desktopMultihopStartupBudgets(multihopSelection{EntryMode: entry}, []string{"shadowsocks", "hysteria2"}, "auto")
		if total != 180*time.Second+8*phases[entry] {
			t.Fatal("both automatic exit alternatives lost their captured entry phase", entry, total)
		}
	}
}

func TestDesktopMultihopCapturedDeadlinePrecedesPackageAndSourceWork(t *testing.T) {
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := context.Canceled
		if expired {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
			want = context.DeadlineExceeded
		} else {
			cancel()
		}
		_, err := captureNativeMultihopForAppContext(ctx, &app{}, multihopSelection{}, nil)
		cancel()
		if !errors.Is(err, want) {
			t.Fatal("retired captured startup reached package/source work", err)
		}
	}
}

func TestDesktopMultihopCapturedStartupProvesAfterNativeKeys(t *testing.T) {
	for _, mode := range []string{"wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		t.Run(mode, func(t *testing.T) {
			root, selected := nativeEntryMultihopFixture(t, mode, "off")
			selected.ExitMode = mode
			var err error
			selected, err = captureNativeMultihopSelection(context.Background(), root, selected, []string{mode}, nil)
			if err != nil || selected.Native.validate(selected) != nil {
				t.Fatal("shipping native graph capture failed", err)
			}
			t.Setenv("HOMEVPN_ROOT", root)
			for _, fault := range []string{"", "cancel", "retire"} {
				synctest.Test(t, func(t *testing.T) {
					parent, stop := context.WithCancel(context.Background())
					defer stop()
					command := &exec.Cmd{}
					app := &app{cmd: command, connectionContext: parent}
					start := time.Now()
					var exitProofs atomic.Int32
					var workers sync.WaitGroup
					ordinary := http.DefaultTransport
					transport := ordinary.(*http.Transport).Clone()
					transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
						if ctx.Err() != nil {
							return nil, ctx.Err()
						}
						if network != "tcp" || address != "127.0.0.1:1098" && address != "127.0.0.1:1099" {
							return nil, errors.New("proof tried to bypass its captured local lane")
						}
						client, server := net.Pipe()
						workers.Add(1)
						go func() {
							defer workers.Done()
							defer server.Close()
							request, err := http.ReadRequest(bufio.NewReader(server))
							if err != nil {
								return
							}
							defer request.Body.Close()
							node, ready := selected.Entry, 29*time.Second
							if address == "127.0.0.1:1099" {
								node, ready = selected.Exit, 58*time.Second
								exitProofs.Add(1)
							}
							expected, err := multihopLaneProofURL(node)
							if err != nil || request.URL.String() != expected || node.APIToken != "" && request.Header.Get("Authorization") != "Bearer "+node.APIToken {
								t.Error("native HTTP proof changed its captured node or credential", err)
								return
							}
							status := 503
							body := []byte(`{"pending":true}`)
							if fault == "retire" || time.Since(start) >= ready {
								status = 200
								body, _ = json.Marshal(map[string]any{"ok": true, "node_id": node.NodeProofID, "proof": desktopNodeProofKind})
							}
							if fault == "retire" {
								app.mu.Lock()
								app.cmd = &exec.Cmd{}
								app.mu.Unlock()
							}
							response := http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Close: true}
							_ = response.Write(server)
						}()
						return client, nil
					}
					http.DefaultTransport = transport
					defer func() { http.DefaultTransport = ordinary; transport.CloseIdleConnections() }()
					if fault == "cancel" {
						time.AfterFunc(2*time.Second, stop)
					}
					// Actual wrapper, HTTP clients, private node verification,
					// captured-file identity and ownership checks all execute.
					err := app.proveNativeMultihop(selected, command)
					workers.Wait()
					if fault == "" && (err != nil || exitProofs.Load() == 0 || time.Since(start) < 58*time.Second) {
						t.Fatal("legitimate captured native keys lost Local startup", err, exitProofs.Load(), time.Since(start))
					}
					if fault != "" && (err == nil || time.Since(start) > 2*time.Second || exitProofs.Load() != 0) {
						t.Fatal("extended startup adopted a canceled or retired owner", fault, err, time.Since(start))
					}
				})
			}
		})
	}
}

// Only the native engine/routed measurement boundary is doubled. The captured
// production graph, phase budgets, routechoice score/final-proof/cleanup path,
// and context timers are the shipping code, under Go's virtual clock.
type deadlineCompareDriver struct {
	selected multihopSelection
	opens    map[routechoice.Execution]int
	closed   int
}

type deadlineCompareSession struct {
	driver    *deadlineCompareDriver
	candidate routechoice.Candidate
	identity  string
	failFinal bool
}

func (d *deadlineCompareDriver) Open(ctx context.Context, c routechoice.Candidate) (routechoice.Session, error) {
	if err := d.selected.Native.validate(d.selected); err != nil {
		return nil, err
	}
	d.opens[c.Execution]++
	// Two independent, valid 29-second key phases plus setup/proof overhead.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(62 * time.Second):
	}
	return &deadlineCompareSession{driver: d, candidate: c, identity: fmt.Sprintf("%s/%d", c.Execution, d.opens[c.Execution]), failFinal: c.Execution == routechoice.Server && d.opens[c.Execution] == 2}, nil
}
func (s *deadlineCompareSession) Identity() string                 { return s.identity }
func (s *deadlineCompareSession) Verify(ctx context.Context) error { return ctx.Err() }
func (s *deadlineCompareSession) ProbeLast(ctx context.Context) (time.Duration, error) {
	if s.failFinal {
		return 0, errors.New("candidate lost final routed proof")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.candidate.Execution == routechoice.Server {
		return time.Millisecond, nil
	}
	return 2 * time.Millisecond, nil
}
func (s *deadlineCompareSession) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	if target != "https://203.0.113.9/captured" {
		return 0, errors.New("comparison changed the captured external target")
	}
	return s.ProbeLast(ctx)
}
func (s *deadlineCompareSession) Close(ctx context.Context) error {
	s.driver.closed++
	s.identity = ""
	return ctx.Err()
}

func TestDesktopMultihopCapturedCompareRetainsFinalProofBudget(t *testing.T) {
	root, selected := nativeEntryMultihopFixture(t, "wg-pq", "off")
	selected.ExitMode = "wg-pq"
	var err error
	selected, err = captureNativeMultihopSelection(context.Background(), root, selected, []string{selected.ExitMode}, nil)
	if err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		startup, total := desktopMultihopStartupBudgets(selected, []string{selected.ExitMode}, "auto")
		ctx, cancel := context.WithTimeout(context.Background(), total)
		defer cancel()
		driver := &deadlineCompareDriver{selected: selected, opens: map[routechoice.Execution]int{}}
		candidates := []routechoice.Candidate{}
		for _, execution := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
			candidates = append(candidates, routechoice.Candidate{Execution: execution, Transport: selected.ExitMode, EntryID: selected.Entry.ID, ExitID: selected.Exit.ID})
		}
		result, active, err := routechoice.Compare(ctx, candidates, driver, routechoice.Options{Targets: []string{"https://203.0.113.9/captured"}, StartupTimeout: startup, ProbeTimeout: 2500 * time.Millisecond, CleanupTimeout: 15 * time.Second})
		if err != nil || result.Winner == nil || result.Winner.Execution != routechoice.Local || active == nil || active.Identity() == "" || driver.opens[routechoice.Server] != 2 || driver.opens[routechoice.Local] != 2 || driver.closed != 3 {
			t.Fatal("captured Compare lost a valid final survivor or left another owner", result, driver, err)
		}
		if err := active.Close(context.Background()); err != nil || driver.closed != 4 {
			t.Fatal("final retained owner was not independently drained", err, driver.closed)
		}
	})
}

func TestDesktopRelayInitialHTTPAllowsStartupButRetainsShortRenewal(t *testing.T) {
	cases := []struct {
		name, mode                          string
		renewed, canceled, replaced, wantOK bool
	}{{"initial-pq", "wg-pq", false, false, false, true}, {"initial-max", "max-quic-awg", false, false, false, true}, {"ordinary", "shadowsocks", false, false, false, false}, {"renewal", "wg-pq", true, false, false, false}, {"parent-canceled", "wg-pq", false, true, false, false}, {"owner-replaced", "wg-pq", false, false, true, false}}
	entered := map[string]chan struct{}{}
	for _, test := range cases {
		entered[test.name] = make(chan struct{})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:1098")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "10.77.0.1:8787" || r.URL.Path != "/api/multihop/lease" || r.Header.Get("Authorization") != "Bearer captured-control-token" {
			http.Error(w, "wrong captured private control lane", http.StatusForbidden)
			return
		}
		var request multihoprelay.Request
		if json.NewDecoder(r.Body).Decode(&request) != nil || entered[request.SessionID] == nil {
			http.Error(w, "unknown captured request", http.StatusBadRequest)
			return
		}
		requests.Add(1)
		close(entered[request.SessionID])
		select {
		case <-r.Context().Done():
			return
		case <-time.After(9 * time.Second):
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"node_id": "captured-entry"})
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	var workers sync.WaitGroup
	for _, test := range cases {
		workers.Add(1)
		go func() {
			defer workers.Done()
			command := &exec.Cmd{}
			app := &app{cmd: command}
			owner := &desktopRelayOwner{app: app, command: command, entry: common.RouterProfile{RouterAPI: "http://10.77.0.1:8787", APIToken: "captured-control-token"}, request: multihoprelay.Request{SessionID: test.name, ExitMode: test.mode}, renewed: test.renewed}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.canceled || test.replaced {
				go func() {
					select {
					case <-ctx.Done():
						return
					case <-entered[test.name]:
					}
					if test.canceled {
						cancel()
					} else {
						app.mu.Lock()
						app.cmd = &exec.Cmd{}
						app.mu.Unlock()
					}
				}()
			}
			var response struct {
				NodeID string `json:"node_id"`
			}
			started := time.Now()
			err := owner.requestControl(ctx, http.MethodPut, &response)
			if (err == nil) != test.wantOK || test.wantOK && response.NodeID != "captured-entry" {
				t.Errorf("private relay HTTP lost its captured startup/owner contract: %s: %v", test.name, err)
			}
			if test.canceled && time.Since(started) > 3*time.Second {
				t.Errorf("extended private lease startup ignored parent cancellation: %s", time.Since(started))
			}
		}()
	}
	workers.Wait()
	if requests.Load() != 6 {
		t.Fatal("a control request bypassed its captured private lane", requests.Load())
	}
}
