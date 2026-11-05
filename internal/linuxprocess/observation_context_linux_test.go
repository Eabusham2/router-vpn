//go:build linux

package linuxprocess

import (
	"context"
	"errors"
	"testing"
)

func TestProcessObservationExpiryAfterAdmissionPreservesWitness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	witness := &Witness{complete: true}
	if _, err := witness.current(ctx); !errors.Is(err, context.Canceled) || witness.revoked {
		t.Fatal("observer expiry became native identity loss", err)
	}
	witness.revoked = true
	if _, err := witness.current(ctx); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("real prior revocation became observer expiry", err)
	}
}
