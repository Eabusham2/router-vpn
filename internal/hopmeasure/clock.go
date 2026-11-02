package hopmeasure

import (
	"errors"
	"time"
)

var errMeasurementClock = errors.New("measurement clock is unavailable or non-monotonic")

// An interval keeps one clock domain from start to finish. Windows supplies
// genuine performance-counter ticks; other targets retain time's monotonic
// component. Neither path may manufacture a positive minimum or use wall time
// as a fallback for an unavailable counter.
type measurementInstant struct {
	ticks, frequency int64
	monotonic        time.Time
}

func measurementSeconds(start, finish measurementInstant) (float64, error) {
	if start.frequency != 0 || finish.frequency != 0 {
		if start.frequency <= 0 || finish.frequency != start.frequency || start.ticks < 0 ||
			finish.ticks <= start.ticks || !start.monotonic.IsZero() || !finish.monotonic.IsZero() {
			return 0, errMeasurementClock
		}
		// Subtract integer ticks before converting, preserving short intervals
		// even when the machine's absolute counter is too large for float64.
		return float64(finish.ticks-start.ticks) / float64(start.frequency), nil
	}
	if start.ticks != 0 || finish.ticks != 0 || start.monotonic.IsZero() || finish.monotonic.IsZero() {
		return 0, errMeasurementClock
	}
	elapsed := finish.monotonic.Sub(start.monotonic).Seconds()
	if elapsed <= 0 {
		return 0, errMeasurementClock
	}
	return elapsed, nil
}
