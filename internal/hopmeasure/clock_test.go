package hopmeasure

import (
	"math"
	"runtime"
	"testing"
	"time"
)

func TestMeasurementCounterRetainsSingleTickIntervalAtLargeUptime(t *testing.T) {
	start := measurementInstant{ticks: math.MaxInt64 - 2, frequency: 10_000_000}
	finish := measurementInstant{ticks: math.MaxInt64 - 1, frequency: 10_000_000}
	elapsed, err := measurementSeconds(start, finish)
	if err != nil || elapsed != 0.0000001 {
		t.Fatal("real tick difference was rounded away or replaced", elapsed, err)
	}
	if float64(finish.ticks)-float64(start.ticks) != 0 {
		t.Fatal("negative control no longer covers premature float conversion")
	}
}

func TestMeasurementClockRejectsMissingRegressingAndBorrowedDomains(t *testing.T) {
	start := measurementInstant{ticks: 100, frequency: 10_000_000}
	for name, finish := range map[string]measurementInstant{
		"same-tick":           start,
		"regressed":           {ticks: 99, frequency: start.frequency},
		"missing-frequency":   {ticks: 101},
		"negative-frequency":  {ticks: 101, frequency: -1},
		"changed-frequency":   {ticks: 101, frequency: start.frequency + 1},
		"wall-clock-fallback": {monotonic: time.Now()},
		"ambiguous-domain":    {ticks: 101, frequency: start.frequency, monotonic: time.Now()},
	} {
		t.Run(name, func(t *testing.T) {
			if elapsed, err := measurementSeconds(start, finish); err == nil || elapsed != 0 {
				t.Fatal("invalid interval acquired a score", elapsed, err)
			}
		})
	}
	for _, invalid := range []measurementInstant{{}, {ticks: -1, frequency: start.frequency}, {ticks: 100}} {
		if elapsed, err := measurementSeconds(invalid, measurementInstant{ticks: 101, frequency: start.frequency}); err == nil || elapsed != 0 {
			t.Fatal("missing original clock acquired a score", elapsed, err)
		}
	}
}

func TestMeasurementMonotonicIntervalRejectsZeroAndBackwardTime(t *testing.T) {
	start := measurementInstant{monotonic: time.Now()}
	for _, duration := range []time.Duration{0, -time.Nanosecond, 100 * time.Nanosecond} {
		elapsed, err := measurementSeconds(start, measurementInstant{monotonic: start.monotonic.Add(duration)})
		if duration <= 0 {
			if err == nil || elapsed != 0 {
				t.Fatal("nonpositive interval acquired a fabricated minimum", elapsed, err)
			}
		} else if err != nil || elapsed != duration.Seconds() {
			t.Fatal("monotonic interval changed its scale", elapsed, err)
		}
	}
}

func TestMeasurementClockReadsActualTargetCounter(t *testing.T) {
	start, err := readMeasurementClock()
	if err != nil {
		t.Fatal("actual target measurement clock unavailable", err)
	}
	if runtime.GOOS == "windows" && (start.frequency <= 0 || !start.monotonic.IsZero()) {
		t.Fatal("Windows measurement substituted the clock-interrupt timer")
	}
	deadline := time.Now().Add(time.Second)
	for {
		finish, err := readMeasurementClock()
		if err != nil {
			t.Fatal("captured target clock failed readback", err)
		}
		if elapsed, err := measurementSeconds(start, finish); err == nil {
			if elapsed <= 0 || math.IsNaN(elapsed) || math.IsInf(elapsed, 0) {
				t.Fatal("actual target clock did not retain a finite positive interval", elapsed)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("actual target clock never advanced")
		}
	}
}
