package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func privateThroughputClockFixture(t *testing.T, fault string) (common.RouterProfile, *atomic.Int32, *atomic.Int64) {
	t.Helper()
	var requests atomic.Int32
	var uploaded atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer captured-token" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("private transfer changed captured authorization or encoding")
		}
		switch r.URL.Path {
		case "/api/benchmark/download":
			if r.URL.Query().Get("bytes") != "1048576" {
				t.Error("download changed requested byte count")
			}
			if fault == "status" {
				http.Error(w, "rejected", 403)
				return
			}
			if fault == "redirect" {
				http.Redirect(w, r, "/unexpected", 302)
				return
			}
			size := 1 << 20
			if fault == "short" {
				size--
			}
			if fault == "excess" {
				size++
			}
			_, _ = io.WriteString(w, strings.Repeat("x", size))
		case "/api/benchmark/upload":
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				t.Errorf("upload body: %v", err)
			}
			uploaded.Store(n)
			if n != 1<<20 || r.ContentLength != 1<<20 {
				t.Errorf("upload byte ownership changed: %d/%d", n, r.ContentLength)
			}
			ack := `{"bytes":1048576,"server_receive_ms":2.3456}`
			switch fault {
			case "wrong-ack":
				ack = `{"bytes":1048575}`
			case "bad-ack":
				ack = `{`
			case "oversized":
				ack += strings.Repeat(" ", (64<<10)+1-len(ack))
			}
			_, _ = io.WriteString(w, ack)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return common.RouterProfile{ID: "captured-node", Name: "Captured node", RouterAPI: server.URL, APIToken: "captured-token"}, &requests, &uploaded
}

func TestPrivateThroughputCheckedClock(t *testing.T) {
	clockFailure := errors.New("original throughput clock failure")
	cancelCause := errors.New("original throughput owner retired")
	for _, direction := range []string{"download", "upload"} {
		for _, fault := range []string{"tiny", "fraction", "ordinary", "start", "read", "zero", "negative", "nan", "infinity", "overflow", "cancel", "cancel-read"} {
			t.Run(direction+"/"+fault, func(t *testing.T) {
				p, requests, uploaded := privateThroughputClockFixture(t, "")
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				starts, reads := 0, 0
				target := 1
				if direction == "upload" {
					target = 2
				}
				wantMs := 12.3456
				switch fault {
				case "tiny":
					wantMs = .000001
				case "fraction":
					wantMs = .017
				case "zero":
					wantMs = 0
				case "negative":
					wantMs = -1
				case "nan":
					wantMs = math.NaN()
				case "infinity":
					wantMs = math.Inf(1)
				case "overflow":
					wantMs = math.SmallestNonzeroFloat64
				}
				clock := func() (clientMeasurementInterval, error) {
					starts++
					stage := starts
					if stage == target && fault == "start" {
						return nil, clockFailure
					}
					return clientClockRead(func() (float64, error) {
						reads++
						if requests.Load() != int32(stage) {
							t.Errorf("clock read outside its complete HTTP transfer: stage=%d requests=%d", stage, requests.Load())
						}
						if stage == 2 && uploaded.Load() != 1<<20 {
							t.Error("upload clock read before complete body delivery")
						}
						if stage != target {
							return 20, nil
						}
						if fault == "cancel" || fault == "cancel-read" {
							cancel(cancelCause)
						}
						if fault == "read" || fault == "cancel-read" {
							return 0, clockFailure
						}
						return wantMs, nil
					}), nil
				}
				got, err := measureRoutedProfileSpeedWithClock(ctx, p, 1<<20, clock)
				success := fault == "tiny" || fault == "fraction" || fault == "ordinary"
				if success {
					down, up := 20.0, 20.0
					if target == 1 {
						down = wantMs
					} else {
						up = wantMs
					}
					if err != nil || got.Bytes != 1<<20 || got.RouterID != p.ID || got.Name != p.Name || got.DownloadMs != roundMeasuredMilliseconds(down) || got.UploadMs != roundMeasuredMilliseconds(up) || got.DownloadMbps != round3(8.388608/(down/1000)) || got.UploadMbps != round3(8.388608/(up/1000)) || got.ServerReceiveMs != 2.346 || got.MeasuredAt.IsZero() || !strings.Contains(got.Proof, "unchanged current client routing graph") {
						t.Fatalf("measured throughput changed: %+v err=%v", got, err)
					}
					if starts != 2 || reads != 2 || requests.Load() != 2 || uploaded.Load() != 1<<20 {
						t.Fatal("transfer/interval lifecycle mismatch")
					}
					return
				}
				if err == nil || got != (routedSpeedResult{}) {
					t.Fatalf("invalid timing published throughput: %+v err=%v", got, err)
				}
				if (fault == "start" || fault == "read" || fault == "cancel-read") && !errors.Is(err, clockFailure) {
					t.Fatalf("lost original clock cause: %v", err)
				}
				if (fault == "cancel" || fault == "cancel-read") && !errors.Is(err, cancelCause) {
					t.Fatalf("lost original owner cancellation: %v", err)
				}
				wantRequests := target
				if fault == "start" {
					wantRequests--
				}
				if requests.Load() != int32(wantRequests) {
					t.Fatalf("clock failure retried or started unowned transfer: got %d want %d", requests.Load(), wantRequests)
				}
			})
		}
	}
}

func TestPrivateThroughputClockPreservesTransferProof(t *testing.T) {
	for _, fault := range []string{"short", "excess", "status", "redirect", "wrong-ack", "bad-ack", "oversized"} {
		t.Run(fault, func(t *testing.T) {
			p, requests, _ := privateThroughputClockFixture(t, fault)
			got, err := measureRoutedProfileSpeedWithClock(context.Background(), p, 1<<20, func() (clientMeasurementInterval, error) {
				return clientClockRead(func() (float64, error) { return 10, nil }), nil
			})
			if err == nil || got != (routedSpeedResult{}) {
				t.Fatalf("failed transfer accepted: %+v %v", got, err)
			}
			want := int32(1)
			if strings.Contains(fault, "ack") || fault == "oversized" {
				want = 2
			}
			if requests.Load() != want {
				t.Fatalf("unexpected transfer retry: %d want %d", requests.Load(), want)
			}
		})
	}
}

func TestPrivateThroughputProductionClockAndCancelledCaller(t *testing.T) {
	p, requests, _ := privateThroughputClockFixture(t, "")
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := fmt.Errorf("captured request ended")
	cancel(cause)
	got, err := measureRoutedProfileSpeedContext(ctx, p, 1<<20)
	if !errors.Is(err, cause) || got != (routedSpeedResult{}) || requests.Load() != 0 {
		t.Fatalf("cancelled caller sent transfer: %+v %v requests=%d", got, err, requests.Load())
	}
	got, err = measureRoutedProfileSpeedContext(context.Background(), p, 1<<20)
	if err != nil || got.Bytes != 1<<20 || got.DownloadMs <= 0 || got.UploadMs <= 0 || got.DownloadMbps <= 0 || got.UploadMbps <= 0 {
		t.Fatalf("production interval failed: %+v %v", got, err)
	}
}

// The upload interval ends after the complete bounded acknowledgement body,
// not after request-body transmission or the first successful response headers.
func TestPrivateThroughputClockIncludesCompleteAcknowledgement(t *testing.T) {
	ackStarted := make(chan struct{})
	releaseAck := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseAck) }) }
	defer release()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/benchmark/download" {
			_, _ = io.WriteString(w, strings.Repeat("x", 1<<20))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"bytes":`)
		w.(http.Flusher).Flush()
		close(ackStarted)
		<-releaseAck
		_, _ = io.WriteString(w, `1048576}`)
	}))
	defer server.Close()
	defer release()
	p := common.RouterProfile{ID: "captured-node", RouterAPI: server.URL, APIToken: "captured-token"}
	readUpload := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		starts := 0
		_, err := measureRoutedProfileSpeedWithClock(context.Background(), p, 1<<20, func() (clientMeasurementInterval, error) {
			starts++
			stage := starts
			return clientClockRead(func() (float64, error) {
				if stage == 2 {
					readUpload <- struct{}{}
				}
				return 10, nil
			}), nil
		})
		done <- err
	}()
	select {
	case <-ackStarted:
	case err := <-done:
		t.Fatalf("transfer ended before ack: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not reach ack boundary")
	}
	select {
	case <-readUpload:
		t.Error("upload interval ended before complete acknowledgement")
	case err := <-done:
		t.Errorf("transfer ended before complete acknowledgement: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("transfer did not join after acknowledgement")
	}
	if len(readUpload) != 1 {
		t.Fatal("complete acknowledged upload interval was not read once")
	}
}
