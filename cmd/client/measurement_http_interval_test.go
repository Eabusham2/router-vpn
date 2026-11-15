package main

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type httpTimingClock struct {
	values []float64
	err    error
}

func (c *httpTimingClock) Milliseconds() (float64, error) {
	if c.err != nil {
		return 0, c.err
	}
	if len(c.values) == 0 {
		return 0, errors.New("checked test clock exhausted")
	}
	v := c.values[0]
	c.values = c.values[1:]
	return v, nil
}

type httpTimingOwner struct {
	retired atomic.Bool
	checks  int
	current func(context.Context) error
}

func (o *httpTimingOwner) MatchesOriginal() bool { return !o.retired.Load() }
func (o *httpTimingOwner) Current(ctx context.Context) error {
	o.checks++
	if o.current != nil {
		return o.current(ctx)
	}
	return context.Cause(ctx)
}

func httpTimingFixture(t *testing.T) (*clientHTTPRequestInterval, *httpTimingOwner, *httpTimingClock, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://192.0.2.1/health", nil)
	clock := &httpTimingClock{values: []float64{1, 5, 20, 27, 40, 46, 83, 100, 110, 120, 130}}
	request, interval := captureClientHTTPRequestInterval(request, clock)
	timing := clientHTTPRequestTiming(request.Context())
	if timing != interval {
		t.Fatal("request lost original interval")
	}
	owner := &httpTimingOwner{}
	if err := timing.claim(owner); err != nil {
		t.Fatal(err)
	}
	return timing, owner, clock, cancel
}

func TestClientHTTPIntervalKeepsNetworkPhasesAndFinalProof(t *testing.T) {
	timing, owner, _, _ := httpTimingFixture(t)
	for i := 0; i < 3; i++ {
		if err := timing.currentBeforeIO(timing.caller, owner); err != nil {
			t.Fatal(err)
		}
	}
	if err := timing.beginDNS(owner); err != nil {
		t.Fatal(err)
	}
	if err := timing.endDNS(owner); err != nil {
		t.Fatal(err)
	}
	if err := timing.beginHTTP(owner); err != nil {
		t.Fatal(err)
	}
	body, err := timing.responseBody(timing.caller, owner, io.NopCloser(strings.NewReader("complete")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(body); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := clientMeasurementMilliseconds(timing.caller, timing)
	if err != nil || value != 66 || owner.checks != 4 {
		t.Fatalf("network interval or full original checks changed: value=%v checks=%v err=%v", value, owner.checks, err)
	}
}

func TestClientHTTPIntervalRefusesIncompleteAuthority(t *testing.T) {
	for _, fault := range []string{"clock-unavailable", "clock-regressed", "clock-nonfinite", "post-body-clock", "publication-clock", "final-current", "early-close", "oversize", "owner-before-body", "owner-at-eof", "owner-after-close", "cancel-at-eof", "cancel-after-close", "response-replay"} {
		t.Run(fault, func(t *testing.T) {
			timing, owner, clock, cancel := httpTimingFixture(t)
			if err := timing.currentBeforeIO(timing.caller, owner); err != nil {
				t.Fatal(err)
			}
			if err := timing.beginHTTP(owner); err != nil {
				t.Fatal(err)
			}
			body, err := timing.responseBody(timing.caller, owner, io.NopCloser(strings.NewReader("1234")))
			if err != nil {
				t.Fatal(err)
			}
			owner.current = func(context.Context) error {
				switch fault {
				case "post-body-clock":
					clock.err = errors.New("original clock unavailable after Current")
				case "final-current":
					return errors.New("original native Current refused")
				case "owner-at-eof":
					owner.retired.Store(true)
				case "cancel-at-eof":
					cancel()
				}
				return nil
			}
			switch fault {
			case "clock-unavailable":
				clock.err = errors.New("original clock unavailable")
			case "clock-regressed":
				clock.values = []float64{1}
			case "clock-nonfinite":
				clock.values = []float64{math.NaN()}
			case "owner-before-body":
				owner.retired.Store(true)
			case "response-replay":
				_, _ = timing.responseBody(timing.caller, owner, io.NopCloser(strings.NewReader("foreign")))
			}
			if fault == "oversize" {
				_, _ = io.ReadAll(io.LimitReader(body, 2))
			} else if fault != "early-close" {
				_, readErr := io.ReadAll(body)
				if fault == "post-body-clock" && readErr == nil {
					t.Fatal("post-body-clock failure was not checked before returning EOF")
				}
			}
			if fault == "post-body-clock" {
				clock.err = nil
			}
			_ = body.Close()
			switch fault {
			case "publication-clock":
				clock.err = errors.New("original clock unavailable at publication")
			case "owner-after-close":
				owner.retired.Store(true)
			case "cancel-after-close":
				cancel()
			}
			value, err := clientMeasurementMilliseconds(timing.caller, timing)
			if err == nil || value != 0 {
				t.Fatalf("invalid original authority produced measurement: fault=%s value=%v err=%v", fault, value, err)
			}
		})
	}
}

func TestClientHTTPIntervalRefusesOverlappingWork(t *testing.T) {
	for _, fault := range []string{"dns-in-flight", "http-in-flight", "foreign-owner", "request-replay", "concurrent-check"} {
		t.Run(fault, func(t *testing.T) {
			timing, owner, _, _ := httpTimingFixture(t)
			var err error
			switch fault {
			case "dns-in-flight":
				if e := timing.beginDNS(owner); e != nil {
					t.Fatal(e)
				}
				err = timing.currentBeforeIO(timing.caller, owner)
			case "http-in-flight":
				if e := timing.beginHTTP(owner); e != nil {
					t.Fatal(e)
				}
				err = timing.currentBeforeIO(timing.caller, owner)
			case "foreign-owner":
				err = timing.currentBeforeIO(timing.caller, &httpTimingOwner{})
			case "request-replay":
				err = timing.claim(owner)
			case "concurrent-check":
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
				owner.current = func(context.Context) error { close(entered); <-release; return nil }
				go func() { done <- timing.currentBeforeIO(timing.caller, owner) }()
				<-entered
				err = timing.currentBeforeIO(timing.caller, owner)
				close(release)
				if first := <-done; first == nil {
					t.Fatal("overlapped original guard survived")
				}
			}
			if err == nil {
				t.Fatal("overlapping or substituted request was allowed to exclude time")
			}
		})
	}
}

func TestClientHTTPIntervalOtherTransportsKeepOriginalClock(t *testing.T) {
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://192.0.2.1/", nil)
	clock := &httpTimingClock{values: []float64{0.000001}}
	_, interval := captureClientHTTPRequestInterval(request, clock)
	value, err := clientMeasurementMilliseconds(request.Context(), interval)
	if err != nil || value != 0.000001 || len(clock.values) != 0 {
		t.Fatalf("ordinary transport clock changed: %v %v", value, err)
	}
}
