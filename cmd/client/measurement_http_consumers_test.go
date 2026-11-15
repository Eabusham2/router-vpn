package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The existing application fixture models the native host explicitly. The
// actual Darwin transport/clock/body methods run separately in its mandatory
// portable transport gate; this test exercises the three shipping consumers.
func TestDesktopPairedHTTPConsumersRetainCapturedTiming(t *testing.T) {
	for _, operation := range []string{"latency", "download", "upload"} {
		for _, fault := range []string{"none", "final-current", "post-body-clock", "cancel", "owner-replaced", "oversize-no-eof"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				a, profile, _, host := pairedMeasurementFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				binding, err := captureDesktopPairedMeasurement(ctx, a, profile, a.state)
				if err != nil || binding == nil {
					t.Fatal("original fixture capture failed", err)
				}
				ctx = withDesktopPairedMeasurement(ctx, binding)
				handler := host.handler
				var captured *httpTimingClock
				requests := 0
				host.handler = func(request *http.Request) (*http.Response, error) {
					requests++
					timing := clientHTTPRequestTiming(request.Context())
					if timing == nil {
						return nil, errors.New("shipping private consumer omitted original timing capture")
					}
					selected := operation == "latency" || strings.HasSuffix(request.URL.Path, "/"+operation)
					owner := &httpTimingOwner{}
					owner.current = func(context.Context) error {
						if selected && owner.checks == 2 {
							switch fault {
							case "final-current":
								return errors.New("original native owner refused")
							case "post-body-clock":
								captured.err = errors.New("original post-body clock failed")
							case "cancel":
								cancel()
							case "owner-replaced":
								owner.retired.Store(true)
							}
						}
						return nil
					}
					if err := timing.claim(owner); err != nil {
						return nil, err
					}
					if err := timing.currentBeforeIO(request.Context(), owner); err != nil {
						return nil, err
					}
					if err := timing.beginHTTP(owner); err != nil {
						return nil, err
					}
					response, err := handler(request)
					if err != nil {
						return nil, err
					}
					if selected && fault == "oversize-no-eof" {
						_ = response.Body.Close()
						response.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+2)))
					}
					body, err := timing.responseBody(request.Context(), owner, response.Body)
					if err != nil {
						response.Body.Close()
						return nil, err
					}
					response.Body = body
					return response, nil
				}
				clock := func() (clientMeasurementInterval, error) {
					captured = &httpTimingClock{values: []float64{1, 11, 41, 61, 71}}
					return captured, nil
				}
				if operation == "latency" {
					result, err := privatePathLatencyWithClock(ctx, profile, a.state, 1, clock)
					if fault == "none" {
						if err != nil || result.Samples != 1 || result.MedianMs != 31 || requests != 1 {
							t.Fatalf("actual private latency lost measured phase: %+v requests%d %v", result, requests, err)
						}
					} else if err == nil || result.Samples != 0 || result.MedianMs != 0 {
						t.Fatalf("invalid private latency published %+v %v", result, err)
					}
				} else {
					result, err := measureRoutedProfileSpeedWithClock(ctx, profile, 1<<20, clock)
					if fault == "none" {
						want, _ := privateBenchmarkMbps(1<<20, 31)
						if err != nil || result.DownloadMbps != want || result.UploadMbps != want || requests != 2 {
							t.Fatalf("actual private throughput lost measured phases: %+v requests%d want%v %v", result, requests, want, err)
						}
					} else if err == nil {
						t.Fatalf("invalid private throughput published %+v", result)
					}
				}
			})
		}
	}
}
