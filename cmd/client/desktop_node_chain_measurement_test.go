package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func TestDesktopNodeChainMeasurementRowsRequireEveryIndependentPrefix(t *testing.T) {
	for _, count := range []int{3, 8} {
		_, launch := desktopNodeChainLaunchFixture(t, count, "linux")
		status := hopmeasure.Status{Complete: true, Drained: true, Stage: "complete"}
		for i, m := range launch.chain.selection.Nodes {
			role := "intermediate"
			if i == 0 {
				role = "entry"
			}
			if i == count-1 {
				role = "exit"
			}
			status.Results = append(status.Results, hopmeasure.Result{ID: m.Profile.ID, Role: role, Kind: "private-node", Ready: true, Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3}, Download: &hopmeasure.Transfer{Bytes: 65536, Seconds: 0.5, Mbps: 1.048576}, Upload: &hopmeasure.Transfer{Bytes: 65536, Seconds: 1, Mbps: 0.524288}})
		}
		rows, err := desktopNodeChainMeasurementRows(status, launch.chain.selection.Nodes, 65536)
		if err != nil || len(rows) != count || rows[1].Role != "intermediate" || rows[1].Speed.DownloadMs != 500 || !strings.Contains(rows[1].SpeedLabel, "node 2 of") {
			t.Fatal(rows, err)
		}
		for _, fault := range []string{"missing", "reorder", "role", "undrained", "failed", "bytes", "derived-speed", "nan", "public-benchmark", "response", "stage", "samples", "distribution", "jitter"} {
			t.Run(fault, func(t *testing.T) {
				raw, _ := json.Marshal(status)
				var bad hopmeasure.Status
				_ = json.Unmarshal(raw, &bad)
				switch fault {
				case "missing":
					bad.Results = bad.Results[:count-1]
				case "reorder":
					bad.Results[0], bad.Results[1] = bad.Results[1], bad.Results[0]
				case "role":
					bad.Results[1].Role = "exit"
				case "undrained":
					bad.Drained = false
				case "failed":
					bad.Results[1].Failure = "lost private proof"
				case "bytes":
					bad.Results[1].Download.Bytes--
				case "derived-speed":
					bad.Results[1].Download.Mbps = 3
				case "public-benchmark":
					bad.Results[1].Benchmark = &hopmeasure.LatencyBenchmark{}
				case "response":
					bad.Results[1].Response = &hopmeasure.PathResponse{}
				case "stage":
					bad.Stage = "running"
				case "samples":
					bad.Results[1].Idle.Samples = 100
				case "distribution":
					bad.Results[1].Idle.Min = 4
				case "jitter":
					bad.Results[1].Idle.Jitter = -1
				case "nan":
					bad.Results[1].Idle.Median = math.NaN()
				}
				if rows, err := desktopNodeChainMeasurementRows(bad, launch.chain.selection.Nodes, 65536); err == nil || rows != nil {
					t.Fatal("partial or substituted prefix accepted")
				}
			})
		}
	}
}

func TestDesktopNodeChainMeasurementExchangeJoinsExactMailbox(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "cancel-drain"}[cancelled], func(t *testing.T) {
			f := startupProvedNodeChainOwner(t, 3)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				deadline := time.NewTimer(30 * time.Second)
				defer deadline.Stop()
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					raw, err := readDesktopRuntimeFile(f.launch, "node-chain-measure-request.json", 16384)
					if err == nil {
						var request desktopNodeChainMeasurementRequest
						if json.Unmarshal(raw, &request) != nil {
							done <- errors.New("invalid request")
							return
						}
						if cancelled {
							cancel()
							for {
								body, err := readDesktopRuntimeFile(f.launch, "node-chain-measure-cancel.json", 16384)
								if err == nil {
									if string(body) != string(raw) {
										done <- errors.New("foreign cancel")
										return
									}
									break
								}
								select {
								case <-deadline.C:
									done <- errors.New("cancel missing")
									return
								case <-ticker.C:
								}
							}
						}
						result := desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: request, CompletedAt: time.Now().UnixMilli(), Status: hopmeasure.Status{Request: request.Request, Complete: true, Drained: true, Stage: "complete"}}
						body, _ := json.Marshal(result)
						if err := writeDesktopRuntimeFile(f.launch, "node-chain-measure-result.json", body, false); err != nil {
							done <- err
							return
						}
						if cancelled {
							if err := f.launch.directoryRoot.Remove("node-chain-measure-cancel.json"); err != nil {
								done <- err
								return
							}
						}
						done <- f.launch.directoryRoot.Remove("node-chain-measure-request.json")
						return
					}
					if !errors.Is(err, os.ErrNotExist) {
						done <- err
						return
					}
					select {
					case <-deadline.C:
						cancel()
						done <- errors.New("request missing")
						return
					case <-ticker.C:
					}
				}
			}()
			status, err := exchangeDesktopNodeChainMeasurement(ctx, f.launch, func(call context.Context) error { return call.Err() })
			if cancelled {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("lost caller cancellation", err)
				}
			} else if err != nil || !status.Drained {
				t.Fatal(status, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if f.launch.chain.measurementGeneration != 1 || f.launch.chain.measurementLast == "" {
				t.Fatal("request did not retain its generation")
			}
		})
	}
}

func TestDesktopNodeChainMeasurementHoldSurvivesPendingDrainUntilRetirement(t *testing.T) {
	f := startupProvedNodeChainOwner(t, 3)
	outer, err := f.a.holdCapturedMTU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	finish, err := beginDesktopNodeChainMeasurementHold(context.Background(), f.a, f.launch)
	if err != nil {
		t.Fatal(err)
	}
	finish(false)
	outer()
	if !mtuSuspended(f.a) || f.launch.chain.measurementRelease == nil {
		t.Fatal("pending native probe released MTU suspension")
	}
	if next, err := beginDesktopNodeChainMeasurementHold(context.Background(), f.a, f.launch); err == nil || next != nil {
		t.Fatal("pending probe admitted another parent hold")
	}
	if err := cleanupDesktopNodeLaunch(f.launch); err == nil {
		t.Fatal("live original child was cleaned")
	}
	if !mtuSuspended(f.a) {
		t.Fatal("failed retirement released pending measurement")
	}
	if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); err != nil {
		t.Fatal(err)
	}
	<-f.pulseDone
	if err := cleanupDesktopNodeLaunch(f.launch); err != nil {
		t.Fatal(err)
	}
	if f.launch.chain.measurementRelease != nil || mtuSuspended(f.a) {
		t.Fatal("joined original child retained stale measurement hold")
	}
}

func TestDesktopNodeChainMeasurementCancelCleanupHonorsCaller(t *testing.T) {
	launch := &desktopNodeLaunch{}
	launch.workspaceMu.Lock()
	defer launch.workspaceMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := retireDesktopNodeChainMeasurementCancel(ctx, launch, []byte("original")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cleanup renewed original deadline")
	}
}
