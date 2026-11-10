package main

import (
	"context"
	"errors"
	"math"

	"router-vpn/internal/hopmeasure"
)

type clientMeasurementInterval interface {
	Milliseconds() (float64, error)
}

type clientMeasurementClock func() (clientMeasurementInterval, error)

// Each sample owns its checked platform interval. Factories are passed only
// through private call seams; there is no mutable global or context override.
func startClientMeasurementInterval() (clientMeasurementInterval, error) {
	return hopmeasure.StartInterval()
}

func clientMeasurementMilliseconds(ctx context.Context, interval clientMeasurementInterval) (float64, error) {
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	milliseconds, err := interval.Milliseconds()
	if err != nil || context.Cause(ctx) != nil {
		return 0, errors.Join(err, context.Cause(ctx))
	}
	if milliseconds <= 0 || math.IsNaN(milliseconds) || math.IsInf(milliseconds, 0) {
		return 0, errors.New("measurement clock did not produce a positive finite interval")
	}
	return milliseconds, nil
}

// Keep ordinary display precision without turning a real positive interval
// into zero. Returning the original tiny value adds no invented minimum RTT.
func roundMeasuredMilliseconds(milliseconds float64) float64 {
	rounded := round3(milliseconds)
	if rounded == 0 && milliseconds > 0 {
		return milliseconds
	}
	return rounded
}

// Accumulate measured means without a large sum or losing a constant tiny
// interval below the observed minimum through repeated-addition rounding.
func averageMeasuredMilliseconds(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := values[0]
	for index, value := range values[1:] {
		mean += (value - mean) / float64(index+2)
	}
	return mean
}
