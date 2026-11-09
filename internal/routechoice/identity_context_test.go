package routechoice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type identityCallerKey struct{}

type contextualIdentityTrial struct {
	*trial
	legacy, observations int
	observe              func(context.Context, int) (string, error)
	phase                context.Context
	contexts             []context.Context
}

func (s *contextualIdentityTrial) Identity() string {
	s.legacy++
	return s.trial.Identity()
}
func (s *contextualIdentityTrial) IdentityContext(ctx context.Context) (string, error) {
	s.observations++
	s.contexts = append(s.contexts, ctx)
	if s.observe != nil {
		return s.observe(ctx, s.observations)
	}
	return s.trial.Identity(), nil
}
func (s *contextualIdentityTrial) Verify(ctx context.Context) error {
	s.phase = ctx
	return s.trial.Verify(ctx)
}
func (s *contextualIdentityTrial) ProbeLast(ctx context.Context) (time.Duration, error) {
	s.phase = ctx
	return s.trial.ProbeLast(ctx)
}
func (s *contextualIdentityTrial) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	s.phase = ctx
	return s.trial.ProbeExternal(ctx, target)
}

func TestContextIdentityUsesOriginalProbeCallerAndDeadline(t *testing.T) {
	parent, stop := context.WithTimeout(context.WithValue(context.Background(), identityCallerKey{}, "original-round"), time.Second)
	defer stop()
	parentDeadline, _ := parent.Deadline()
	s := &contextualIdentityTrial{trial: sample(10, 20)}
	s.observe = func(ctx context.Context, call int) (string, error) {
		deadline, hasDeadline := ctx.Deadline()
		if ctx.Value(identityCallerKey{}) != "original-round" || !hasDeadline || deadline.After(parentDeadline) || ctx.Err() != nil {
			return "", errors.New("identity lost the original bounded caller")
		}
		if call > 1 && ctx != s.phase {
			return "", errors.New("post-probe identity replaced that probe's exact budget")
		}
		return s.trial.Identity(), nil
	}
	o := opts()
	o.ProbeTimeout = 100 * time.Millisecond
	m := measure(parent, cand()[0], s, o.Targets[0], o)
	if !m.Eligible || m.ScoreMS == nil || *m.ScoreMS != 15 || s.legacy != 0 || s.observations != 4 || len(s.calls) != 3 {
		t.Fatal("original contextual path did not earn its two-probe mean", m, s.legacy, s.observations, s.calls)
	}
	if s.contexts[0] != s.contexts[1] || s.contexts[1] == s.contexts[2] || s.contexts[2] == s.contexts[3] {
		t.Fatal("identity capture/proof lost their shared original budget or probes reused another phase")
	}
	for _, ctx := range s.contexts {
		if ctx.Err() == nil {
			t.Fatal("completed phase retained its observation context")
		}
	}
}

func TestContextIdentityFailureAndLateCancellationNeverEarnScore(t *testing.T) {
	for _, fault := range []string{"empty", "error", "cancelled", "changed"} {
		for at := 1; at <= 4; at++ {
			if fault == "changed" && at == 1 {
				continue // A new original identity is allowed before any proof.
			}
			t.Run(fmt.Sprintf("%s/%d", fault, at), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				s := &contextualIdentityTrial{trial: sample(10, 20)}
				s.observe = func(ctx context.Context, call int) (string, error) {
					if call == at {
						switch fault {
						case "empty":
							return "", nil
						case "error":
							return "owned-session", errors.New("private identity diagnostic")
						case "cancelled":
							cancel()
							return "owned-session", nil // A late value is not authority.
						case "changed":
							return "replacement-session", nil
						}
					}
					return "owned-session", nil
				}
				o := opts()
				o.ProbeTimeout = time.Second
				m := measure(ctx, cand()[0], s, o.Targets[0], o)
				if m.Eligible || m.ScoreMS != nil || m.Failure == "" || strings.Contains(m.Failure, "private") || s.legacy != 0 || s.observations != at {
					t.Fatal("unproved, changed or cancelled identity earned a score or fell back", m, s.legacy, s.observations)
				}
				if len(s.calls) != at-1 {
					t.Fatal("failed identity admitted an additional path operation", s.calls)
				}
			})
		}
	}
}

type contextualIdentityDriver struct {
	sessions []*contextualIdentityTrial
	count    int
}

func (d *contextualIdentityDriver) Open(_ context.Context, _ Candidate) (Session, error) {
	if d.count >= len(d.sessions) {
		return nil, errors.New("unexpected additional candidate")
	}
	s := d.sessions[d.count]
	d.count++
	return s, nil
}

func TestCompareRechecksContextIdentityOnRetainedWinner(t *testing.T) {
	sessions := []*contextualIdentityTrial{
		{trial: sample(10, 20)}, {trial: sample(40, 60)}, {trial: sample(10, 20)}, {trial: sample(40, 60)},
	}
	// The initially faster candidate changes its retained identity after the
	// final external probe. Its old score is revoked and the slower path reproves.
	sessions[2].observe = func(_ context.Context, call int) (string, error) {
		if call == 4 {
			return "replacement-session", nil
		}
		return "owned-session", nil
	}
	d := &contextualIdentityDriver{sessions: sessions}
	result, retained, err := Compare(context.Background(), cand(), d, opts())
	if err != nil || retained != sessions[3] || result.Winner == nil || result.Winner.Execution != Server || result.Final == nil || !result.Final.Eligible || result.Final.ScoreMS == nil || *result.Final.ScoreMS != 50 || result.Measurements[0].Eligible || result.Measurements[0].ScoreMS != nil {
		t.Fatal("final contextual identity did not revoke the old winner and reprove its survivor", result, err)
	}
	for index, s := range sessions {
		if s.legacy != 0 || s.observations != 4 || s.closed != (index != 3) || s.target != result.Target {
			t.Fatal("comparison lost contextual identity, same target or exact cleanup ownership", index, s)
		}
	}
}
