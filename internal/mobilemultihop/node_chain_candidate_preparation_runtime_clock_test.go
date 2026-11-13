package mobilemultihop

import (
	"context"
	"errors"
	"math"
	"testing"

	"router-vpn/internal/hopmeasure"
)

func TestNodeChainCandidatePreparationProofClockFailureRetiresOriginal(t *testing.T) {
	for _, phase := range []string{"capture", "completion"} {
		t.Run(phase, func(t *testing.T) {
			r, owner := newCandidatePreparationRuntimeFixture(t, "wg")
			captureFailure := errors.New("original measurement clock unavailable")
			captures := 0
			r.testInterval = func() (hopmeasure.Interval, error) {
				captures++
				if phase == "capture" {
					return hopmeasure.Interval{}, captureFailure
				}
				// A zero value has no valid retained clock. It must never become
				// a fabricated positive sample after a successful real HTTP proof.
				return hopmeasure.Interval{}, nil
			}
			err := r.StartContext(context.Background())
			if err == nil || phase == "capture" && !errors.Is(err, captureFailure) {
				t.Fatal("unchecked prefix proof clock admitted preparation", phase, err)
			}
			progress := r.Progress()
			if captures != 1 || progress.Prepared || progress.Stage != "retired" || len(progress.Prefixes) != 0 || owner.count.Load() != 0 {
				t.Fatal("invalid interval published a prefix or retained candidate authority", captures, progress, owner.count.Load())
			}
			owner.nodeChainTestEngine.mu.Lock()
			calls := len(owner.nodeChainTestEngine.calls)
			owner.nodeChainTestEngine.mu.Unlock()
			want := 0
			if phase == "completion" {
				want = 1
			}
			if calls != want {
				t.Fatal("clock refusal did not retain its original exchange boundary", calls, want)
			}
			if _, err := r.NewMeasurementContext(context.Background()); err == nil {
				t.Fatal("invalid measured prefix acquired candidate lease")
			}
		})
	}
}

func TestNodeChainCandidatePreparationProofClockPublishesMeasuredPositiveIntervals(t *testing.T) {
	r, _ := newCandidatePreparationRuntimeFixture(t, "awg2-fast")
	if err := r.StartContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	progress := r.Progress()
	if !progress.Prepared || len(progress.Prefixes) != 2 {
		t.Fatal("real private prefix proof did not prepare", progress)
	}
	for _, prefix := range progress.Prefixes {
		if !prefix.Proven || prefix.ResponseMS <= 0 || math.IsNaN(prefix.ResponseMS) || math.IsInf(prefix.ResponseMS, 0) {
			t.Fatal("private prefix proof published an invalid interval", prefix)
		}
	}
}
