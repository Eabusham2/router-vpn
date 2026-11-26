package routechoice

import (
	"context"
	"errors"
	"testing"
	"time"
)

type trial struct {
	last, external               time.Duration
	stale, changed, dead, closed bool
	target                       string
}

func (s *trial) Identity() string {
	if s.changed {
		return "new-session"
	}
	return "owned-session"
}
func (s *trial) Verify(ctx context.Context) error { return ctx.Err() }
func (s *trial) ProbeLast(ctx context.Context) (time.Duration, error) {
	s.changed = s.stale
	return s.last, ctx.Err()
}
func (s *trial) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	s.target = target
	return s.external, ctx.Err()
}
func (s *trial) Close(context.Context) error {
	s.closed = true
	if s.dead {
		return errors.New("cleanup failed")
	}
	return nil
}

type driver struct {
	runs   map[Execution][]*trial
	opened []Execution
}

func (d *driver) Open(_ context.Context, c Candidate) (Session, error) {
	d.opened = append(d.opened, c.Execution)
	runs := d.runs[c.Execution]
	if len(runs) == 0 {
		return nil, errors.New("no remaining trial")
	}
	d.runs[c.Execution] = runs[1:]
	return runs[0], nil
}
func cand() []Candidate {
	return []Candidate{{Local, "wg", "entry", "exit"}, {Server, "wg", "entry", "exit"}}
}
func sample(last, external int) *trial {
	return &trial{last: time.Duration(last) * time.Millisecond, external: time.Duration(external) * time.Millisecond}
}
func opts() Options {
	return Options{Targets: []string{"https://approved.example/check"}, Preferred: Local}
}

func TestCompareRetainsTheLowerScoringProvedRoute(t *testing.T) {
	local, server, keep := sample(10, 90), sample(30, 40), sample(31, 40)
	d := &driver{runs: map[Execution][]*trial{Local: {local}, Server: {server, keep}}}
	result, owned, err := Compare(context.Background(), cand(), d, opts())
	if err != nil || result.Winner == nil || result.Winner.Execution != Server || owned != keep ||
		len(result.Measurements) != 2 || result.Measurements[0].ScoreMS == nil || result.Measurements[1].ScoreMS == nil ||
		*result.Measurements[0].ScoreMS != 50 || *result.Measurements[1].ScoreMS != 35 ||
		!local.closed || !server.closed || keep.closed {
		t.Fatal("selection lost measured score or original owner", result, err)
	}
	if local.target != server.target || server.target != keep.target {
		t.Fatal("comparison used different public targets")
	}
}

func TestChangedRouteCannotScoreAndIncompleteCleanupRetainsOwnership(t *testing.T) {
	stale, good, keep := sample(1, 1), sample(30, 40), sample(31, 40)
	stale.stale = true
	d := &driver{runs: map[Execution][]*trial{Local: {stale}, Server: {good, keep}}}
	result, owned, err := Compare(context.Background(), cand(), d, opts())
	if err != nil || owned != keep || result.Winner == nil || result.Winner.Execution != Server || len(result.Measurements) != 2 ||
		result.Measurements[0].Eligible || result.Measurements[0].ScoreMS != nil || !stale.closed {
		t.Fatal("changed original owner received a score", result, err)
	}
	blocked := sample(1, 1)
	blocked.dead = true
	d = &driver{runs: map[Execution][]*trial{Local: {blocked}}}
	_, owned, err = Compare(context.Background(), cand(), d, opts())
	if !errors.Is(err, ErrTeardown) || owned != blocked || len(d.opened) != 1 {
		t.Fatal("incomplete cleanup lost ownership or admitted another route", err)
	}
}
