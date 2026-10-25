package dnsmeasure

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

type boundaryEngine struct {
	*fakeEngine
	checks atomic.Int32
	failAt int32
}

func (e *boundaryEngine) VerifyMeasurement(ctx context.Context) error {
	if ctx.Err() != nil || e.checks.Add(1) == e.failAt {
		return errors.New("private provider transport generation changed")
	}
	return nil
}

func TestFreshTransportBoundaryDiscardsCompleteDNSRetest(t *testing.T) {
	for _, failure := range []int32{0, 1, 2} {
		t.Run(string(rune('0'+failure)), func(t *testing.T) {
			s, native := fixture(t)
			native.dial = func(context.Context, string) (net.Conn, error) { return served(tcpAnswer), nil }
			e := &boundaryEngine{fakeEngine: native, failAt: failure}
			s.engine = e
			if err := s.Start(firstRequest, "tcp"); err != nil {
				t.Fatal(err)
			}
			result := finish(t, s, firstRequest)
			if native.Identity() != s.identity {
				t.Fatal("fixture changed the enclosing VPN owner")
			}
			if failure == 0 {
				if result.Failure != "" || len(result.Results) < 2 || e.checks.Load() != 2 {
					t.Fatal("unchanged transport lost its real DNS answers", result)
				}
				for _, row := range result.Results {
					if !row.Ready || row.Median == nil || row.Failed != 0 {
						t.Fatal("fixture did not exchange successful DNS answers", row)
					}
				}
			} else if result.Stage != "invalidated" || result.Failure == "" || len(result.Results) != 0 || e.checks.Load() != failure {
				t.Fatal("stale provider transport published DNS timings", result)
			}
			if strings.Contains(s.StatusJSON(), "private provider") {
				t.Fatal("private native error became public status")
			}
			if failure == 1 && native.selected.Load() != 0 {
				t.Fatal("unproved provider transport started the DNS retest")
			}
		})
	}
}
