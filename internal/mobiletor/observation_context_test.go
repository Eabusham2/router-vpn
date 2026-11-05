package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestObservationCancellationCannotHideConfirmedOwnerLoss(t *testing.T) {
	genuine := errors.New("original native owner changed")
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, fmt.Errorf("read: %w", context.DeadlineExceeded), errors.Join(context.Canceled, context.DeadlineExceeded)} {
		if !ObservationContextOnly(err) {
			t.Fatal("pure cancellation misclassified", err)
		}
	}
	for _, err := range []error{nil, genuine, errors.Join(genuine, context.DeadlineExceeded), errors.Join(context.Canceled, fmt.Errorf("identity: %w", genuine)), fmt.Errorf("read: %w", errors.Join(genuine, context.Canceled))} {
		if ObservationContextOnly(err) {
			t.Fatal("genuine loss hidden by cancellation", err)
		}
	}
}

func TestObservationExpiryRequiresOriginalCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !ObservationContextExpired(ctx, fmt.Errorf("original read: %w", context.Canceled)) {
		t.Fatal("original cancellation not classified")
	}
	for _, err := range []error{context.DeadlineExceeded, errors.Join(context.Canceled, errors.New("captured owner replaced"))} {
		if ObservationContextExpired(ctx, err) {
			t.Fatal("foreign expiry or real failure was hidden", err)
		}
	}
	if ObservationContextExpired(context.Background(), context.Canceled) {
		t.Fatal("live original caller treated as expired")
	}
}
