package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type speedLabClockRead func() (time.Duration, error)

func (f speedLabClockRead) Duration() (time.Duration, error) { return f() }

func TestSpeedLabTransferCheckedClock(t *testing.T) {
	original := errors.New("original transfer clock failure")
	for _, direction := range []string{"download", "upload"} {
		for _, parallel := range []bool{false, true} {
			for _, fault := range []string{"tiny", "ordinary", "start", "read", "zero", "negative"} {
				name := direction + "/single/" + fault
				if parallel {
					name = direction + "/parallel/" + fault
				}
				t.Run(name, func(t *testing.T) {
					var requests atomic.Int32
					var uploaded atomic.Int64
					installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.Host != "speed.cloudflare.com" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Cache-Control") != "no-store" {
							t.Error("changed fixed provider or request headers")
						}
						if direction == "download" {
							n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
							_, _ = io.WriteString(w, strings.Repeat("x", n))
						} else {
							n, err := io.Copy(io.Discard, r.Body)
							if err != nil && (fault == "tiny" || fault == "ordinary") {
								t.Errorf("upload read: %v", err)
							}
							uploaded.Add(n)
							_, _ = io.WriteString(w, "ack")
						}
					})
					client := newSpeedLabHTTPClientContext(context.Background(), time.Second)
					defer client.CloseIdleConnections()
					var starts, reads atomic.Int32
					want := 17 * time.Millisecond
					if fault == "tiny" {
						want = time.Nanosecond
					}
					clock := func() (speedLabTransferInterval, error) {
						starts.Add(1)
						if fault == "start" {
							return nil, original
						}
						return speedLabClockRead(func() (time.Duration, error) {
							reads.Add(1)
							switch fault {
							case "read":
								return 0, original
							case "zero":
								return 0, nil
							case "negative":
								return -time.Nanosecond, nil
							}
							return want, nil
						}), nil
					}
					var bytes int64
					var elapsed time.Duration
					var err error
					if parallel {
						bytes, elapsed, err = speedLabParallelRoundWithClock(context.Background(), direction, client, 1024, 2, []byte("pattern"), clock)
					} else if direction == "download" {
						bytes, elapsed, err = speedLabDownloadRoundWithClock(context.Background(), client, 1024, clock)
					} else {
						bytes, elapsed, err = speedLabUploadRoundWithClock(context.Background(), client, 1024, []byte("pattern"), clock)
					}
					if fault == "tiny" || fault == "ordinary" {
						wantRequests, wantIntervals := int32(1), int32(1)
						if parallel {
							wantRequests = 2
							wantIntervals = 3
						}
						if err != nil || bytes != 1024 || elapsed != want || requests.Load() != wantRequests || starts.Load() != wantIntervals || reads.Load() != wantIntervals || (direction == "upload" && uploaded.Load() != 1024) {
							t.Fatalf("lost actual transfer/checked interval: bytes=%d elapsed=%s err=%v requests=%d starts/reads=%d/%d", bytes, elapsed, err, requests.Load(), starts.Load(), reads.Load())
						}
					} else {
						if !errors.Is(err, errSpeedLabMeasurementClock) || speedLabContextError(err) {
							t.Fatalf("clock failure could become partial success: bytes=%d elapsed=%s err=%v", bytes, elapsed, err)
						}
						if (fault == "start" || fault == "read") && !errors.Is(err, original) {
							t.Fatalf("lost original clock cause: %v", err)
						}
						if fault == "start" && (requests.Load() != 0 || bytes != 0 || elapsed != 0) {
							t.Fatal("clock initialization failure sent HTTP work")
						}
						if parallel && direction == "upload" && bytes != 0 {
							t.Fatal("parallel failed upload credited unacknowledged bytes")
						}
					}
				})
			}
		}
	}
}

func TestSpeedLabDirectionCheckedClockOwnsDeadlineTail(t *testing.T) {
	original := errors.New("original timed load clock failure")
	owner := errors.New("original timed load caller cancelled")
	for _, level := range []string{"load", "parallel", "transfer"} {
		for _, fault := range []string{"measured", "tiny", "start", "read", "zero", "cancel"} {
			if fault == "tiny" && level != "load" {
				continue
			}
			t.Run(level+"/"+fault, func(t *testing.T) {
				var requests atomic.Int32
				installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.Header().Set("Content-Length", r.URL.Query().Get("bytes"))
					_, _ = w.Write(make([]byte, 256))
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				})
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				var starts, reads atomic.Int32
				target := int32(1)
				if level == "parallel" {
					target = 2
				}
				if level == "transfer" {
					target = 3
				}
				clock := func() (speedLabTransferInterval, error) {
					stage := starts.Add(1)
					if stage == target && fault == "start" {
						return nil, original
					}
					return speedLabClockRead(func() (time.Duration, error) {
						reads.Add(1)
						if stage == target {
							switch fault {
							case "tiny":
								return time.Nanosecond, nil
							case "read":
								return 0, original
							case "zero":
								return 0, nil
							case "cancel":
								cancel(owner)
							}
						}
						// Whole-load timing deliberately differs from scheduling time. The
						// completed result must use this interval, including its stalled tail.
						if stage == 1 {
							return 2 * time.Second, nil
						}
						return 200 * time.Millisecond, nil
					}), nil
				}
				got, err := measureSpeedLabDirectionWithClock(ctx, "download", 350*time.Millisecond, 350*time.Millisecond, 0, clock)
				if fault == "measured" || fault == "tiny" {
					seconds, mbps := 2.0, .001
					if fault == "tiny" {
						seconds, mbps = 1e-9, 2048000
					}
					if err != nil || got.Bytes != 256 || got.Seconds != seconds || got.Mbps != mbps || got.Rounds != 1 || got.StoppedStable || got.LoadedLatency.Samples < 2 || starts.Load() != 3 || reads.Load() != 3 || requests.Load() != 1 {
						t.Fatalf("lost verified partial bytes or checked whole-load tail: %+v err=%v starts/reads=%d/%d requests=%d", got, err, starts.Load(), reads.Load(), requests.Load())
					}
					if ctx.Err() != nil {
						t.Fatal("administrative deadline cancelled original caller")
					}
					return
				}
				if err == nil || got.Bytes != 0 || got.Mbps != 0 || got.Seconds != 0 {
					t.Fatalf("clock/caller failure salvaged partial throughput: %+v %v", got, err)
				}
				if fault == "cancel" {
					if !errors.Is(err, owner) {
						t.Fatalf("lost caller cause: %v", err)
					}
				} else {
					if !errors.Is(err, errSpeedLabMeasurementClock) || speedLabContextError(err) {
						t.Fatalf("clock failure treated as ordinary deadline: %v", err)
					}
					if fault != "zero" && !errors.Is(err, original) {
						t.Fatalf("lost clock cause: %v", err)
					}
					if fault == "read" && level != "load" && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("lost joined original direction deadline: %v", err)
					}
				}
				if fault == "start" && requests.Load() != 0 {
					t.Fatal("failed clock initialization sent load request")
				}
			})
		}
	}
}

func TestSpeedLabUploadDeadlineCannotHideClockFailure(t *testing.T) {
	original := errors.New("original upload deadline clock failure")
	for _, level := range []string{"load", "parallel", "transfer"} {
		t.Run(level, func(t *testing.T) {
			var requests atomic.Int32
			var acknowledged atomic.Int64
			installSpeedLabDurationEdge(t, func(w http.ResponseWriter, r *http.Request) {
				first := requests.Add(1) == 1
				n, err := io.Copy(io.Discard, r.Body)
				if err != nil {
					return
				}
				if first {
					acknowledged.Store(n)
					_, _ = io.WriteString(w, "ack")
					return
				}
				<-r.Context().Done()
			})
			var starts atomic.Int32
			target := int32(1)
			if level == "parallel" {
				target = 4
			}
			if level == "transfer" {
				target = 5
			}
			clock := func() (speedLabTransferInterval, error) {
				stage := starts.Add(1)
				return speedLabClockRead(func() (time.Duration, error) {
					if stage == target {
						return 0, original
					}
					if stage == 1 {
						return 2 * time.Second, nil
					}
					return 200 * time.Millisecond, nil
				}), nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			got, err := measureSpeedLabDirectionWithClock(ctx, "upload", 350*time.Millisecond, 350*time.Millisecond, 0, clock)
			if !errors.Is(err, original) || !errors.Is(err, errSpeedLabMeasurementClock) || speedLabContextError(err) || got.Bytes != 0 || got.Mbps != 0 || got.Rounds != 0 {
				t.Fatalf("clock failure salvaged earlier acknowledged upload: %+v err=%v", got, err)
			}
			if requests.Load() != 2 || acknowledged.Load() != 64<<10 || starts.Load() != 5 {
				t.Fatalf("did not exercise acknowledged first upload and stalled final tail: requests=%d ack=%d clocks=%d", requests.Load(), acknowledged.Load(), starts.Load())
			}
			if ctx.Err() != nil {
				t.Fatal("administrative deadline ended original caller")
			}
		})
	}
}
