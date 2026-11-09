package hopmeasure

import (
	"errors"
	"math"
	"math/bits"
	"time"
)

// Interval retains the original measurement clock from capture to readback.
// It measures elapsed work only; request deadlines and wall-clock timestamps
// remain the caller's responsibility. A zero value cannot produce a sample.
type Interval struct {
	start measurementInstant
	read  func() (measurementInstant, error)
}

// StartInterval captures the platform measurement clock. Windows uses the
// checked performance counter already used by native hop measurements.
func StartInterval() (Interval, error) {
	return startInterval(readMeasurementClock)
}

func startInterval(read func() (measurementInstant, error)) (Interval, error) {
	if read == nil {
		return Interval{}, errMeasurementClock
	}
	start, err := read()
	if err != nil {
		return Interval{}, errors.Join(errMeasurementClock, err)
	}
	if start.frequency < 0 || start.ticks < 0 ||
		start.frequency > 0 && !start.monotonic.IsZero() ||
		start.frequency == 0 && (start.ticks != 0 || start.monotonic.IsZero()) {
		return Interval{}, errMeasurementClock
	}
	return Interval{start: start, read: read}, nil
}

func (i Interval) finish() (measurementInstant, float64, error) {
	if i.read == nil {
		return measurementInstant{}, 0, errMeasurementClock
	}
	finish, err := i.read()
	if err != nil {
		return measurementInstant{}, 0, errors.Join(errMeasurementClock, err)
	}
	seconds, err := measurementSeconds(i.start, finish)
	if err != nil || seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return measurementInstant{}, 0, errors.Join(errMeasurementClock, err)
	}
	return finish, seconds, nil
}

// Milliseconds measures a positive interval without rounding to a microsecond
// or manufacturing a minimum. An unavailable or unchanged clock is an error.
func (i Interval) Milliseconds() (float64, error) {
	_, seconds, err := i.finish()
	if err != nil {
		return 0, err
	}
	milliseconds := seconds * 1000
	if milliseconds <= 0 || math.IsNaN(milliseconds) || math.IsInf(milliseconds, 0) {
		return 0, errMeasurementClock
	}
	return milliseconds, nil
}

// Duration retains every complete measured nanosecond. Intervals smaller than
// one nanosecond or outside time.Duration's range are errors, never clamped.
func (i Interval) Duration() (time.Duration, error) {
	finish, _, err := i.finish()
	if err != nil {
		return 0, err
	}
	return measurementDuration(i.start, finish)
}

func measurementDuration(start, finish measurementInstant) (time.Duration, error) {
	if _, err := measurementSeconds(start, finish); err != nil {
		return 0, err
	}
	if start.frequency == 0 {
		elapsed := finish.monotonic.Sub(start.monotonic)
		if elapsed <= 0 || !start.monotonic.Add(elapsed).Equal(finish.monotonic) {
			return 0, errMeasurementClock
		}
		return elapsed, nil
	}
	// Subtraction is safe after the shared nonnegative, increasing-counter
	// validation. Split whole seconds before scaling and use a 128-bit product
	// for the fractional remainder; long uptimes cannot overflow a multiply.
	ticks, frequency := uint64(finish.ticks-start.ticks), uint64(start.frequency)
	seconds, remainder := ticks/frequency, ticks%frequency
	unit := uint64(time.Second)
	if seconds > uint64(math.MaxInt64)/unit {
		return 0, errMeasurementClock
	}
	high, low := bits.Mul64(remainder, unit)
	if high >= frequency {
		return 0, errMeasurementClock
	}
	fraction, _ := bits.Div64(high, low, frequency)
	whole := seconds * unit
	if fraction > uint64(math.MaxInt64)-whole || whole+fraction == 0 {
		return 0, errMeasurementClock
	}
	return time.Duration(whole + fraction), nil
}
