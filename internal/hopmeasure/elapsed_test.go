package hopmeasure

import (
	"errors"
	"math"
	"testing"
	"time"
)

func capturedInterval(t *testing.T, start, finish measurementInstant) Interval {
	t.Helper()
	reads := 0
	interval, err := startInterval(func() (measurementInstant, error) {
		reads++
		if reads == 1 {
			return start, nil
		}
		if reads != 2 {
			t.Fatal("elapsed sample read a replacement clock")
		}
		return finish, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return interval
}

func TestElapsedIntervalPreservesOriginalCounterAndFraction(t *testing.T) {
	for _, sample := range []struct {
		name      string
		start     int64
		ticks     int64
		frequency int64
		want      time.Duration
	}{
		{"single-tick-large-uptime", math.MaxInt64 - 2, 1, 10_000_000, 100 * time.Nanosecond},
		{"fractional-second", 100, 5, 3, time.Second + 666666666*time.Nanosecond},
		{"large-frequency-product", 0, math.MaxInt64 - 1, math.MaxInt64, time.Second - time.Nanosecond},
		{"largest-duration", 0, math.MaxInt64, 1_000_000_000, time.Duration(math.MaxInt64)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			start := measurementInstant{ticks: sample.start, frequency: sample.frequency}
			finish := measurementInstant{ticks: sample.start + sample.ticks, frequency: sample.frequency}
			duration, err := capturedInterval(t, start, finish).Duration()
			if err != nil || duration != sample.want {
				t.Fatal("captured ticks lost exact bounded nanoseconds", duration, sample.want, err)
			}
			milliseconds, err := capturedInterval(t, start, finish).Milliseconds()
			if err != nil || milliseconds != float64(sample.ticks)/float64(sample.frequency)*1000 || milliseconds <= 0 {
				t.Fatal("captured ticks lost their unrounded milliseconds", milliseconds, err)
			}
		})
	}
	// The control loses one genuine tick if absolute counters are converted
	// before subtraction; this must remain distinguishable from the result.
	if float64(int64(math.MaxInt64-1))-float64(int64(math.MaxInt64-2)) != 0 {
		t.Fatal("single-tick precision control no longer reaches its defect")
	}
}

func TestElapsedIntervalRejectsClockFailureAndChangedDomain(t *testing.T) {
	actual := errors.New("captured clock failed")
	if interval, err := startInterval(nil); err == nil || interval.read != nil {
		t.Fatal("missing clock created a measurement")
	}
	if interval, err := startInterval(func() (measurementInstant, error) { return measurementInstant{}, actual }); !errors.Is(err, actual) || interval.read != nil {
		t.Fatal("initial clock failure was replaced", err)
	}
	for _, start := range []measurementInstant{{}, {ticks: -1, frequency: 10}, {frequency: -1}, {ticks: 1}, {ticks: 1, frequency: 10, monotonic: time.Now()}} {
		if interval, err := startInterval(func() (measurementInstant, error) { return start, nil }); err == nil || interval.read != nil {
			t.Fatal("invalid initial clock created a measurement", start)
		}
	}
	start := measurementInstant{ticks: 100, frequency: 10_000_000}
	for name, finish := range map[string]measurementInstant{
		"same-tick": start, "regression": {ticks: 99, frequency: start.frequency},
		"negative": {ticks: -1, frequency: start.frequency}, "lost-frequency": {ticks: 101},
		"foreign-frequency": {ticks: 101, frequency: start.frequency + 1},
		"wall-fallback":     {monotonic: time.Now()},
		"mixed-domain":      {ticks: 101, frequency: start.frequency, monotonic: time.Now()},
	} {
		t.Run(name, func(t *testing.T) {
			if elapsed, err := capturedInterval(t, start, finish).Milliseconds(); err == nil || elapsed != 0 {
				t.Fatal("invalid counter acquired a DNS sample", elapsed, err)
			}
			if elapsed, err := capturedInterval(t, start, finish).Duration(); err == nil || elapsed != 0 {
				t.Fatal("invalid counter acquired a duration", elapsed, err)
			}
		})
	}
	interval := Interval{start: start, read: func() (measurementInstant, error) { return measurementInstant{}, actual }}
	if elapsed, err := interval.Milliseconds(); elapsed != 0 || !errors.Is(err, actual) {
		t.Fatal("final clock error acquired a measurement or lost cause", elapsed, err)
	}
	if elapsed, err := interval.Duration(); elapsed != 0 || !errors.Is(err, actual) {
		t.Fatal("final clock error acquired a duration or lost cause", elapsed, err)
	}
	if elapsed, err := (Interval{}).Milliseconds(); elapsed != 0 || err == nil {
		t.Fatal("zero interval acquired a sample")
	}
}

func TestElapsedDurationRejectsOverflowAndUnrepresentableFraction(t *testing.T) {
	for _, sample := range []struct{ ticks, frequency int64 }{{math.MaxInt64, 1}, {math.MaxInt64, 999999999}, {1, math.MaxInt64}} {
		start, finish := measurementInstant{frequency: sample.frequency}, measurementInstant{ticks: sample.ticks, frequency: sample.frequency}
		if elapsed, err := capturedInterval(t, start, finish).Duration(); elapsed != 0 || err == nil {
			t.Fatal("unrepresentable duration was clamped or overflowed", sample, elapsed, err)
		}
		if elapsed, err := capturedInterval(t, start, finish).Milliseconds(); elapsed <= 0 || err != nil || math.IsInf(elapsed, 0) || math.IsNaN(elapsed) {
			t.Fatal("finite millisecond precision was incorrectly limited to Duration", sample, elapsed, err)
		}
	}
}

func TestElapsedIntervalRetainsPortableMonotonicPrecision(t *testing.T) {
	start := time.Now()
	for _, delta := range []time.Duration{1, 100, 123456789} {
		first, last := measurementInstant{monotonic: start}, measurementInstant{monotonic: start.Add(delta)}
		if elapsed, err := capturedInterval(t, first, last).Duration(); elapsed != delta || err != nil {
			t.Fatal("portable clock lost its original nanoseconds", elapsed, delta, err)
		}
	}
	start = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	finish := start.AddDate(1000, 0, 0)
	if elapsed, err := measurementDuration(measurementInstant{monotonic: start}, measurementInstant{monotonic: finish}); elapsed != 0 || err == nil {
		t.Fatal("portable saturated duration became a measurement", elapsed, err)
	}
}

func TestElapsedIntervalReadsActualPlatformClock(t *testing.T) {
	interval, err := StartInterval()
	if err != nil {
		t.Fatal(err)
	}
	// The original clock test independently verifies actual Windows QPC
	// binding. Retain this same original capture while allowing a genuine
	// same-tick refusal; the clock must advance without a synthetic delay.
	deadline := time.Now().Add(time.Second)
	for {
		elapsed, err := interval.Milliseconds()
		if err == nil {
			if elapsed <= 0 || math.IsNaN(elapsed) || math.IsInf(elapsed, 0) {
				t.Fatal("actual platform interval did not produce a measured sample", elapsed)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("actual captured platform clock never produced an interval", err)
		}
	}
}
