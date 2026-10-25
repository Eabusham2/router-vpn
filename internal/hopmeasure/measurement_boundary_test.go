package hopmeasure

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

type boundaryEngine struct {
	*testEngine
	checks atomic.Int32
	failAt int32
}

func (e *boundaryEngine) VerifyMeasurement(ctx context.Context) error {
	if ctx.Err() != nil || e.checks.Add(1) == e.failAt {
		return errors.New("private provider transport generation changed")
	}
	return nil
}

func TestFreshTransportBoundaryDiscardsCompletedHopResults(t *testing.T) {
	// The native owner remains identical throughout. Only its separately
	// observed provider transport changes, including after both real private
	// HTTP transfers have completed but before their result set is published.
	for _, failure := range []int32{0, 1, 2, 4, 5} {
		t.Run(string(rune('0'+failure)), func(t *testing.T) {
			s, native := fixture(t)
			e := &boundaryEngine{testEngine: native, failAt: failure}
			s.engine = e
			if err := s.Start(strings.Repeat("9", 32), 65536); err != nil {
				t.Fatal(err)
			}
			result := wait(t, s)
			if native.Identity() != s.identity {
				t.Fatal("fixture changed the ordinary native owner")
			}
			if failure == 0 {
				if result.Failure != "" || len(result.Results) != 2 || e.checks.Load() != 5 || !result.Results[0].Ready || !result.Results[1].Ready {
					t.Fatal("unchanged native path lost its measured results", result)
				}
			} else if result.Stage != "invalidated" || len(result.Results) != 0 || result.Failure == "" || e.checks.Load() != failure {
				t.Fatal("old provider generation published hop results", result)
			}
			if strings.Contains(s.StatusJSON(), "private provider") {
				t.Fatal("private verification error escaped into measurement status")
			}
			if failure == 1 {
				native.mu.Lock()
				requests := native.requests["entry-wg"] + native.requests["proxy"]
				native.mu.Unlock()
				if requests != 0 {
					t.Fatal("unproved transport started measurements")
				}
			}
		})
	}
}
