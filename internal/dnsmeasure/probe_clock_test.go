package dnsmeasure

import (
	"testing"
	"time"
)

func TestProbeElapsedTimeRejectsZeroAndBackwardClock(t *testing.T) {
	start := time.Unix(1700000000, 0)
	for _, elapsed := range []time.Duration{0, -time.Nanosecond, -time.Second} {
		measured, err := elapsedProbeMilliseconds(start, start.Add(elapsed))
		if err == nil || measured != 0 {
			t.Fatalf("invalid elapsed interval %s acquired a score: %v, %v", elapsed, measured, err)
		}
	}
}

func TestProbeElapsedTimePreservesActualSubmillisecondMeasurement(t *testing.T) {
	start := time.Unix(1700000000, 0)
	for _, test := range []struct {
		elapsed time.Duration
		want    float64
	}{{time.Nanosecond, 0.000001}, {17 * time.Microsecond, 0.017}, {3 * time.Millisecond, 3}} {
		measured, err := elapsedProbeMilliseconds(start, start.Add(test.elapsed))
		if err != nil || measured != test.want {
			t.Fatalf("actual elapsed interval %s changed: got %v, want %v, err %v", test.elapsed, measured, test.want, err)
		}
	}
}
