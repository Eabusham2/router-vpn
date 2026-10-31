//go:build linux

package linuxprocess

import (
	"context"
	"strings"
	"testing"
)

func TestBootstrapObservationsRejectIncompleteOrCancelledOwner(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled, context.Background()} {
		for _, owner := range []*Bootstrap{nil, {}, {gate: readyGate(), parentRecord: Observation{ProcessID: 41}, childRecord: Observation{ProcessID: 42}}} {
			parent, child, err := owner.Observations(ctx)
			if err == nil || parent != (Observation{}) || child != (Observation{}) {
				t.Fatal("incomplete or cancelled bootstrap exposed cached process authority", err)
			}
			if err := owner.CheckCapture(ctx, strings.Repeat("a", 64)); err == nil {
				t.Fatal("incomplete or cancelled bootstrap admitted a captured request")
			}
		}
	}
}
