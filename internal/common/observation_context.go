package common

import (
	"context"
	"errors"
)

// ObservationContextOnly distinguishes an expired read from confirmed owner
// loss. A joined error is pure cancellation only if every constituent is;
// cancellation cannot hide a separately witnessed identity or lease failure.
func ObservationContextOnly(err error) bool {
	if err == nil {
		return false
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !ObservationContextOnly(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return ObservationContextOnly(wrapped.Unwrap())
	}
	return false
}

// ObservationContextExpired accepts only the original expired caller and an
// error chain containing no independently witnessed non-context failure.
func ObservationContextExpired(ctx context.Context, err error) bool {
	return ctx != nil && ctx.Err() != nil && ObservationContextOnly(err) && errors.Is(err, ctx.Err())
}
