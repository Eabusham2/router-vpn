package dnsmeasure

import (
	"context"
	"errors"
	"math"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

type probeClockRead func() (float64, error)

func (read probeClockRead) Milliseconds() (float64, error) { return read() }

// Exercise the real sample path with a complete DNS answer. No score may be
// substituted when the retained clock fails, even if the resolver succeeded.
func clockProbeFixture(t *testing.T, kind string) (*Service, *fakeEngine, Endpoint, *atomic.Int32) {
	t.Helper()
	s, engine := fixture(t)
	closed := new(atomic.Int32)
	endpoint := s.description.Selected
	if kind == "public" {
		endpoint = candidates("tcp", s.description.RouteLabel)[0]
		engine.dial = func(context.Context, string) (net.Conn, error) {
			return &countClose{Conn: served(tcpAnswer), closed: closed}, nil
		}
	}
	return s, engine, endpoint, closed
}

func TestProbeElapsedTimeRejectsZeroAndBackwardClock(t *testing.T) {
	for _, kind := range []string{"selected", "public"} {
		for _, elapsed := range []float64{0, -0.000001, -1000, math.NaN(), math.Inf(1), math.Inf(-1)} {
			t.Run(kind+"/"+strconv.FormatFloat(elapsed, 'g', -1, 64), func(t *testing.T) {
				s, _, endpoint, closed := clockProbeFixture(t, kind)
				measured, err := s.sampleWithClock(context.Background(), endpoint, func() (probeInterval, error) {
					return probeClockRead(func() (float64, error) { return elapsed, nil }), nil
				})
				if err == nil || measured != 0 {
					t.Fatalf("invalid elapsed interval %v acquired a score: %v, %v", elapsed, measured, err)
				}
				if kind == "public" && closed.Load() != 1 {
					t.Fatal("invalid timing did not close the original DNS socket")
				}
			})
		}
	}
}

func TestProbeElapsedTimePreservesActualSubmillisecondMeasurement(t *testing.T) {
	for _, kind := range []string{"selected", "public"} {
		for _, elapsed := range []float64{0.000001, 0.017, 3} {
			t.Run(kind+"/"+time.Duration(elapsed*1e6).String(), func(t *testing.T) {
				s, _, endpoint, closed := clockProbeFixture(t, kind)
				starts, reads := 0, 0
				measured, err := s.sampleWithClock(context.Background(), endpoint, func() (probeInterval, error) {
					starts++
					return probeClockRead(func() (float64, error) { reads++; return elapsed, nil }), nil
				})
				if err != nil || measured != elapsed || starts != 1 || reads != 1 {
					t.Fatalf("original interval changed: got %v want %v starts=%d reads=%d err=%v", measured, elapsed, starts, reads, err)
				}
				if kind == "public" && closed.Load() != 1 {
					t.Fatal("successful timing did not close the original DNS socket")
				}
			})
		}
	}
}

func TestProbeClockFailurePreservesCauseWithoutFallback(t *testing.T) {
	actual := errors.New("original native clock failure")
	for _, kind := range []string{"selected", "public"} {
		for _, phase := range []string{"start", "read"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				s, engine, endpoint, closed := clockProbeFixture(t, kind)
				reads := 0
				measured, err := s.sampleWithClock(context.Background(), endpoint, func() (probeInterval, error) {
					if phase == "start" {
						return nil, actual
					}
					return probeClockRead(func() (float64, error) { reads++; return 7, actual }), nil
				})
				if measured != 0 || !errors.Is(err, actual) {
					t.Fatalf("clock failure gained a sample or lost its cause: %v %v", measured, err)
				}
				engine.mu.Lock()
				dials := len(engine.dials)
				engine.mu.Unlock()
				work := dials + int(engine.selected.Load())
				if phase == "start" && (work != 0 || reads != 0) || phase == "read" && (work != 1 || reads != 1) {
					t.Fatalf("clock failure retried or started unmeasurable DNS work: work=%d reads=%d", work, reads)
				}
				if kind == "public" && phase == "read" && closed.Load() != 1 {
					t.Fatal("clock failure leaked original DNS socket")
				}
			})
		}
	}
}

func TestProbeClockReadCannotAdoptCancelledOrReplacedOwner(t *testing.T) {
	for _, kind := range []string{"selected", "public"} {
		for _, change := range []string{"cancel", "owner"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				s, engine, endpoint, closed := clockProbeFixture(t, kind)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				want := context.Canceled
				if change == "owner" {
					want = ErrStale
				}
				measured, err := s.sampleWithClock(ctx, endpoint, func() (probeInterval, error) {
					return probeClockRead(func() (float64, error) {
						if change == "cancel" {
							cancel()
						} else {
							engine.mu.Lock()
							engine.identity = "replacement-native-generation"
							engine.mu.Unlock()
						}
						return 0.017, nil
					}), nil
				})
				if measured != 0 || !errors.Is(err, want) {
					t.Fatalf("sample outlived original caller/owner: %v %v", measured, err)
				}
				if kind == "public" && closed.Load() != 1 {
					t.Fatal("retired measurement leaked original DNS socket")
				}
			})
		}
	}
}

func TestProbeProductionClockIsCheckedPlatformInterval(t *testing.T) {
	interval, err := startProbeInterval()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := interval.(hopmeasure.Interval); !ok {
		t.Fatalf("production DNS clock substituted %T for the checked native interval", interval)
	}
}
