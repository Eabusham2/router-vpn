package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProxyThroughputCheckedClockRetainsBothProofs(t *testing.T) {
	originalClock := errors.New("original proxy throughput clock failure")
	originalOwner := errors.New("original proxy throughput owner retired")
	for _, direction := range []string{"download", "upload"} {
		for _, fault := range []string{"tiny", "ordinary", "start", "read", "zero", "negative", "nan", "infinity", "overflow", "cancel", "cancel-read", "first-identity", "last-identity", "wrong-ack"} {
			t.Run(direction+"/"+fault, func(t *testing.T) {
				_, p, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
				var proofs, downloads, uploads atomic.Int32
				var uploaded atomic.Int64
				asyncExitLaneServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer "+p.APIToken || r.Host != "10.77.0.1:8787" {
						t.Error("changed captured node/API/token")
					}
					switch r.URL.Path {
					case "/health":
						proof := proofs.Add(1)
						id := p.NodeProofID
						if fault == "first-identity" || (fault == "last-identity" && proof == 2) {
							id = strings.Repeat("f", 64)
						}
						fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, id, desktopNodeProofKind)
					case "/api/benchmark/download":
						downloads.Add(1)
						if r.URL.Query().Get("bytes") != "1048576" || r.Header.Get("Accept-Encoding") != "identity" {
							t.Error("changed exact download request")
						}
						_, _ = io.WriteString(w, strings.Repeat("x", 1<<20))
					case "/api/benchmark/upload":
						uploads.Add(1)
						n, err := io.Copy(io.Discard, r.Body)
						uploaded.Store(n)
						if err != nil || n != 1<<20 || r.ContentLength != 1<<20 {
							t.Errorf("changed upload bytes: %d %v", n, err)
						}
						if fault == "wrong-ack" {
							fmt.Fprint(w, `{"bytes":1}`)
						} else {
							fmt.Fprint(w, `{"bytes":1048576,"server_receive_ms":3.4567}`)
						}
					default:
						t.Errorf("unexpected request %s", r.URL.Path)
					}
				}))
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				starts, reads := 0, 0
				target := 1
				if direction == "upload" {
					target = 2
				}
				milliseconds := 12.3456
				switch fault {
				case "tiny":
					milliseconds = .000001
				case "zero":
					milliseconds = 0
				case "negative":
					milliseconds = -1
				case "nan":
					milliseconds = math.NaN()
				case "infinity":
					milliseconds = math.Inf(1)
				case "overflow":
					milliseconds = math.SmallestNonzeroFloat64
				}
				clock := func() (clientMeasurementInterval, error) {
					starts++
					stage := starts
					if proofs.Load() != 1 {
						t.Error("clock started without exact initial node proof")
					}
					if stage == target && fault == "start" {
						return nil, originalClock
					}
					return clientClockRead(func() (float64, error) {
						reads++
						if stage == 1 && downloads.Load() != 1 {
							t.Error("download interval did not own actual request")
						}
						if stage == 2 && uploaded.Load() != 1<<20 {
							t.Error("upload interval ended without delivered bytes")
						}
						if stage != target {
							return 20, nil
						}
						if fault == "cancel" || fault == "cancel-read" {
							cancel(originalOwner)
						}
						if fault == "read" || fault == "cancel-read" {
							return 0, originalClock
						}
						return milliseconds, nil
					}), nil
				}
				got, err := measureRoutedProfileSpeedViaProxyWithClock(ctx, p, 1<<20, multihopProofProxy, clock)
				if fault == "tiny" || fault == "ordinary" {
					down, up := 20.0, 20.0
					if target == 1 {
						down = milliseconds
					} else {
						up = milliseconds
					}
					if err != nil || got.Bytes != 1<<20 || got.RouterID != p.ID || got.DownloadMs != roundMeasuredMilliseconds(down) || got.UploadMs != roundMeasuredMilliseconds(up) || got.DownloadMbps != round3(8.388608/(down/1000)) || got.UploadMbps != round3(8.388608/(up/1000)) || got.ServerReceiveMs != 3.457 || !strings.Contains(got.Proof, multihopProofProxy) || proofs.Load() != 2 || downloads.Load() != 1 || uploads.Load() != 1 || starts != 2 || reads != 2 {
						t.Fatalf("lost interval or both original proofs: %+v err=%v proofs=%d starts/reads=%d/%d", got, err, proofs.Load(), starts, reads)
					}
					return
				}
				if err == nil || got != (routedSpeedResult{}) {
					t.Fatalf("unproved/invalid timing published result: %+v %v", got, err)
				}
				if (fault == "start" || fault == "read" || fault == "cancel-read") && !errors.Is(err, originalClock) {
					t.Fatalf("lost clock cause: %v", err)
				}
				if (fault == "cancel" || fault == "cancel-read") && !errors.Is(err, originalOwner) {
					t.Fatalf("lost owner cause: %v", err)
				}
				wantProof, wantDown, wantUp := int32(1), int32(1), int32(0)
				if direction == "upload" {
					wantUp = 1
				}
				if fault == "start" {
					if direction == "download" {
						wantDown = 0
					} else {
						wantUp = 0
					}
				}
				if fault == "first-identity" {
					wantDown = 0
					wantUp = 0
					if starts != 0 {
						t.Error("clock started before failed initial identity")
					}
				}
				if fault == "last-identity" {
					wantProof = 2
					wantDown = 1
					wantUp = 1
				}
				if fault == "wrong-ack" {
					wantDown = 1
					wantUp = 1
				}
				if proofs.Load() != wantProof || downloads.Load() != wantDown || uploads.Load() != wantUp {
					t.Fatalf("retried/substituted request after failure: proofs=%d download=%d upload=%d want=%d/%d/%d", proofs.Load(), downloads.Load(), uploads.Load(), wantProof, wantDown, wantUp)
				}
			})
		}
	}
}
