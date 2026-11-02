//go:build !windows

package hopmeasure

import "time"

func readMeasurementClock() (measurementInstant, error) {
	return measurementInstant{monotonic: time.Now()}, nil
}
