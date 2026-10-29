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
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/common"
)

// Only the native child and the network boundary are controlled. The shipping
// startup gate, private-file parser, HTTP client, node proof and owner checks run
// unchanged, with their actual deadlines. Synctest advances monotonic time;
// it does not replace production timers with shorter test constants.
func desktopNodeStartupFixture(t *testing.T, mode string, parent context.Context) (*app, *desktopNodeMTUFixture, common.RouterProfile) {
	t.Helper()
	fixture := newDesktopNodeMTUFixture(t)
	if err := fixture.launch.directoryRoot.Remove("node-mtu-status.json"); err != nil {
		t.Fatal(err)
	}
	fixture.launch.mode, fixture.launch.profileID = mode, "startup-node"
	a := &app{cmd: fixture.launch.command, connectionContext: parent,
		cfg: common.ClientConfig{AutoTestSeconds: 8}, state: state{Mode: mode, RuntimeMode: mode, RouterID: "startup-node", Phase: "checking"}}
	desktopNodeOwners.Store(a, fixture.launch)
	t.Cleanup(func() { desktopNodeOwners.Delete(a) })
	profile := common.RouterProfile{ID: "startup-node", PathProbeURL: "http://10.77.0.1:8787/health"}
	profile.NodeProofID = writeTestWGIdentity(t, os.Getenv("HOMEVPN_ROOT"), profile.ID)
	return a, fixture, profile
}

func desktopNodeStartupHTTP(t *testing.T, profile common.RouterProfile, delay time.Duration, fault func(), responseNode string) (*atomic.Int32, func()) {
	t.Helper()
	var calls atomic.Int32
	var workers sync.WaitGroup
	prior := http.DefaultTransport
	transport := prior.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if network != "tcp" || address != "10.77.0.1:8787" {
			return nil, fmt.Errorf("startup proof left its selected node: %s/%s", network, address)
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
			if request.URL.Path != "/health" {
				t.Error("startup proof changed its captured target", request.URL)
				return
			}
			calls.Add(1)
			time.Sleep(delay)
			if fault != nil {
				fault()
			}
			body, _ := json.Marshal(map[string]any{"ok": true, "node_id": responseNode, "proof": desktopNodeProofKind})
			response := http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Close: true}
			_ = response.Write(server)
		}()
		return client, nil
	}
	http.DefaultTransport = transport
	return &calls, func() {
		transport.CloseIdleConnections()
		workers.Wait()
		http.DefaultTransport = prior
	}
}

func TestDesktopNodeStartupCapturedNativePhasePrecedesOrdinaryProof(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	for _, mode := range []string{"wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				a, fixture, profile := desktopNodeStartupFixture(t, mode, parent)
				calls, drain := desktopNodeStartupHTTP(t, profile, 7*time.Second, nil, profile.NodeProofID)
				defer drain()
				started := time.Now()
				go func() {
					time.Sleep(29 * time.Second)
					if calls.Load() != 0 {
						t.Error("private proof ran before the exact native initial-key readback")
					}
					if err := fixture.publish(fixture.base, false); err != nil {
						t.Error(err)
					}
				}()
				latency, err := a.testStartedModeHealth(parent, profile, fixture.launch)
				if err != nil || calls.Load() != 1 || latency != 7*time.Second || time.Since(started) < 36*time.Second || time.Since(started) > 37*time.Second {
					t.Fatal("captured native readiness was clipped or counted as network latency", latency, err, calls.Load(), time.Since(started))
				}
				if a.state.Connected || a.state.Phase != "checking" || a.cmd != fixture.launch.command {
					t.Fatal("startup proof itself mutated connection ownership or adoption")
				}
			})
		})
	}
}

func TestDesktopNodeStartupDeadlineDoesNotExtendOrdinaryOrSteadyHealth(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2", "reality-pq", "max", "unknown", "wg-pq-steady"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, fixture, profile := desktopNodeStartupFixture(t, mode, context.Background())
				calls, drain := desktopNodeStartupHTTP(t, profile, 9*time.Second, nil, profile.NodeProofID)
				defer drain()
				started := time.Now()
				var err error
				if mode == "wg-pq-steady" {
					fixture.launch.mode = "wg-pq"
					_, err = a.testHealth(profile)
				} else {
					_, err = a.testStartedModeHealth(context.Background(), profile, fixture.launch)
				}
				if err == nil || calls.Load() != 1 || time.Since(started) != 8*time.Second {
					t.Fatal("initial-key allowance widened an ordinary or steady-state probe", err, calls.Load(), time.Since(started))
				}
			})
		})
	}
}

func TestDesktopNodeStartupReadinessKeepsExactReceiptCancellationAndOwner(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	for _, fault := range []string{"absent", "session", "config", "stale", "reader", "active", "generation", "request", "lease", "restored", "expired", "failed", "close", "foreign-close", "cancel", "deadline", "command", "owner", "foreign-profile"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				if fault == "deadline" {
					var cancelDeadline context.CancelFunc
					parent, cancelDeadline = context.WithTimeout(parent, 2*time.Second)
					defer cancelDeadline()
				}
				a, fixture, profile := desktopNodeStartupFixture(t, "wg-pq", parent)
				calls, drain := desktopNodeStartupHTTP(t, profile, 0, nil, profile.NodeProofID)
				defer drain()
				record := fixture.base
				switch fault {
				case "session":
					record.Session = strings.Repeat("b", 32)
				case "config":
					record.Config = strings.Repeat("c", 64)
				case "reader":
					record.Reader = 2
				case "active":
					record.Active = true
				case "generation":
					record.Generation = 1
				case "request":
					record.Request = strings.Repeat("d", 32)
				case "lease":
					record.Lease = strings.Repeat("e", 32)
				case "restored":
					record.Restored = true
				case "expired":
					record.Expired = true
				case "failed":
					record.Failure = "native startup failed"
				case "foreign-profile":
					profile.ID = "replacement"
				}
				switch fault {
				case "absent", "cancel", "deadline", "command", "owner":
				case "close", "foreign-close":
					stopped := desktopExternalStop{Schema: 1, SessionID: fixture.launch.mtuSession, SourceSHA256: fixture.launch.configSHA256, Closed: true}
					if fault == "foreign-close" {
						stopped.SessionID = strings.Repeat("f", 32)
					}
					raw, _ := json.Marshal(stopped)
					if err := writeDesktopRuntimeFile(fixture.launch, "stopped.json", raw, false); err != nil {
						t.Fatal(err)
					}
				default:
					if err := fixture.publish(record, false); err != nil {
						t.Fatal(err)
					}
					if fault == "stale" {
						time.Sleep(3 * time.Second)
					}
				}
				if fault == "cancel" {
					time.AfterFunc(2*time.Second, cancel)
				}
				if fault == "command" {
					time.AfterFunc(2*time.Second, func() { a.mu.Lock(); a.cmd = &exec.Cmd{}; a.mu.Unlock() })
				}
				if fault == "owner" {
					time.AfterFunc(2*time.Second, func() { desktopNodeOwners.Store(a, &desktopNodeLaunch{}) })
				}
				started := time.Now()
				_, err := a.testStartedModeHealth(parent, profile, fixture.launch)
				if err == nil || calls.Load() != 0 || time.Since(started) > 38*time.Second {
					t.Fatal("invalid native readiness became proof or escaped its captured deadline", err, calls.Load(), time.Since(started))
				}
				if (fault == "cancel" || fault == "deadline" || fault == "command" || fault == "owner") && time.Since(started) > 2100*time.Millisecond {
					t.Fatal("retirement waited for the unused initial-key allowance", time.Since(started))
				}
				if fault == "absent" && (!errors.Is(err, context.DeadlineExceeded) || time.Since(started) != 38*time.Second) {
					t.Fatal("unready native owner did not expire at its bounded ordinary-plus-key deadline", err, time.Since(started))
				}
				if a.state.Connected || a.state.Phase != "checking" {
					t.Fatal("failed readiness changed connection state")
				}
			})
		})
	}
}

func TestDesktopNodeStartupFinalProofRetainsShortBudgetAndRejectsLateOwners(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	for _, fault := range []string{"probe-timeout", "total-timeout", "wrong-node", "cancel", "command", "owner", "context-replacement", "context-replacement-uncanceled", "late-valid"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				a, fixture, profile := desktopNodeStartupFixture(t, "max-quic-awg", parent)
				ready, response := time.Second, time.Second
				responseNode := profile.NodeProofID
				if fault == "probe-timeout" {
					response = 9 * time.Second
				}
				if fault == "total-timeout" {
					ready, response = 33*time.Second, 6*time.Second
				}
				if fault == "late-valid" {
					ready, response = 31*time.Second, 6*time.Second
				}
				if fault == "wrong-node" {
					responseNode = strings.Repeat("d", 64)
				}
				onResponse := func() {
					switch fault {
					case "cancel":
						cancel()
					case "command":
						a.mu.Lock()
						a.cmd = &exec.Cmd{}
						a.mu.Unlock()
					case "owner":
						desktopNodeOwners.Store(a, &desktopNodeLaunch{})
					case "context-replacement":
						cancel()
						a.mu.Lock()
						a.connectionContext = context.Background()
						a.mu.Unlock()
					case "context-replacement-uncanceled":
						a.mu.Lock()
						a.connectionContext = context.Background()
						a.mu.Unlock()
					}
				}
				calls, drain := desktopNodeStartupHTTP(t, profile, response, onResponse, responseNode)
				defer drain()
				go func() {
					time.Sleep(ready)
					if err := fixture.publish(fixture.base, false); err != nil {
						t.Error(err)
					}
				}()
				started := time.Now()
				_, err := a.testStartedModeHealth(parent, profile, fixture.launch)
				elapsed := time.Since(started)
				if fault == "late-valid" {
					if err != nil || elapsed < 37*time.Second || elapsed >= 38*time.Second {
						t.Fatal("ordinary base window was lost while awaiting the initial key", err, elapsed)
					}
				} else if err == nil {
					t.Fatal("invalid, expired or retired final proof succeeded")
				}
				if calls.Load() != 1 {
					t.Fatal("readiness bypassed or duplicated the private proof", calls.Load())
				}
				if fault == "probe-timeout" && (elapsed < 9*time.Second || elapsed >= 10*time.Second) {
					t.Fatal("initial-key allowance widened the individual probe", elapsed)
				}
				if fault == "total-timeout" && elapsed != 38*time.Second {
					t.Fatal("readback restarted the total startup deadline", elapsed)
				}
			})
		})
	}
}

func TestDesktopNodeStartupNativeChildFixture(t *testing.T) {
	if os.Getenv("ROUTERVPN_NODE_STARTUP_FIXTURE") != "1" {
		return
	}
	var record desktopNodeMTURecord
	if json.Unmarshal([]byte(os.Getenv("ROUTERVPN_NODE_STARTUP_RECORD")), &record) != nil {
		os.Exit(71)
	}
	publisher, err := newDesktopNativeFixturePublisher(os.Getenv("ROUTERVPN_NODE_STARTUP_DIRECTORY"))
	if err != nil {
		os.Exit(72)
	}
	defer publisher.root.Close()
	started := time.Now()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for time.Since(started) < 50*time.Second {
		if raw, err := readDesktopRuntimeSnapshot(publisher.root, "stop.json", 1024); err == nil {
			var request desktopExternalStop
			if decodeRelayControlJSON(raw, &request) != nil || request.Schema != 1 || request.SessionID != record.Session || request.SourceSHA256 != record.Config || request.Closed {
				os.Exit(73)
			}
			request.Closed = true
			closed, _ := json.Marshal(request)
			if publisher.publish("stopped.json", closed) != nil {
				os.Exit(74)
			}
			return
		}
		if time.Since(started) >= 11*time.Second {
			record.Heartbeat = time.Now().UnixMilli()
			raw, _ := json.Marshal(record)
			if publisher.publish("node-mtu-status.json", raw) != nil {
				os.Exit(75)
			}
		}
		<-ticker.C
	}
	os.Exit(76)
}

// Exercise a real separately running child and its retained Wait/Stop owner.
// The child controls only key readiness and the TUN receipt; the parent keeps
// the real private-file protocol and ordinary private-node HTTP proof.
func TestDesktopNodeStartupActualChildReadinessAndCancellation(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel-%t", canceled), func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, fixture, profile := desktopNodeStartupFixture(t, "wg-pq", parent)
			raw, _ := json.Marshal(fixture.base)
			child := exec.Command(os.Args[0], "-test.run=^TestDesktopNodeStartupNativeChildFixture$")
			child.Env = append(os.Environ(), "ROUTERVPN_NODE_STARTUP_FIXTURE=1", "ROUTERVPN_NODE_STARTUP_RECORD="+string(raw), "ROUTERVPN_NODE_STARTUP_DIRECTORY="+fixture.launch.directory)
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			fixture.launch.command, a.cmd = child, child
			defer func() {
				if !desktopNodeProcessExited(fixture.launch) {
					_ = child.Process.Kill()
					<-desktopNodeProcessDone(fixture.launch)
				}
			}()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if _, err := readDesktopNodeMTU(fixture.launch); err != nil {
					t.Error("HTTP proof preceded native first-key readiness", err)
				}
				_, _ = fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, profile.NodeProofID, desktopNodeProofKind)
			}))
			defer server.Close()
			profile.PathProbeURL = server.URL
			started := time.Now()
			if canceled {
				time.AfterFunc(2*time.Second, cancel)
			}
			_, err := a.testStartedModeHealth(parent, profile, fixture.launch)
			elapsed := time.Since(started)
			if canceled {
				if err == nil || calls.Load() != 0 || elapsed > 4*time.Second {
					t.Fatal("canceled first-key child reached proof or ignored cancellation", err, calls.Load(), elapsed)
				}
			} else if err != nil || calls.Load() != 1 || elapsed < 11*time.Second {
				t.Fatal("valid native child was clipped by the ordinary eight-second probe", err, calls.Load(), elapsed)
			}
			if err := prepareDesktopNodeStop(a, child); err != nil {
				t.Fatal("pending or ready native child lost exact Stop ownership", err)
			}
			select {
			case <-desktopNodeProcessDone(fixture.launch):
			case <-time.After(4 * time.Second):
				t.Fatal("acknowledged native startup child did not drain")
			}
			if child.ProcessState == nil || !child.ProcessState.Success() || !fixture.launch.nodeStopAcknowledged {
				t.Fatal("startup cleanup accepted an unacknowledged or failed child")
			}
		})
	}
}
