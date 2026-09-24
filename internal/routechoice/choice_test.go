package routechoice

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

type trial struct {
	last, external time.Duration
	fail           string
	dead           bool
	changed        bool
	closed         bool
	target         string
	calls          []string
}

func (s *trial) Identity() string {
	if s.changed {
		return "new-session"
	}
	return "owned-session"
}
func (s *trial) Verify(c context.Context) error {
	s.calls = append(s.calls, "verify")
	if s.fail == "verify" {
		return errors.New("private secret")
	}
	return nil
}
func (s *trial) ProbeLast(c context.Context) (time.Duration, error) {
	s.calls = append(s.calls, "last")
	if s.fail == "last" {
		return 0, context.DeadlineExceeded
	}
	if s.fail == "stale" {
		s.changed = true
	}
	return s.last, nil
}
func (s *trial) ProbeExternal(c context.Context, target string) (time.Duration, error) {
	s.target = target
	s.calls = append(s.calls, "external")
	if s.fail == "external" {
		return 0, context.DeadlineExceeded
	}
	return s.external, nil
}
func (s *trial) Close(c context.Context) error {
	s.closed = true
	if s.dead {
		return errors.New("cleanup failed")
	}
	return nil
}

type driver struct {
	runs   map[Execution][]*trial
	opened []Execution
	fail   map[Execution]bool
}

func (d *driver) Open(ctx context.Context, c Candidate) (Session, error) {
	d.opened = append(d.opened, c.Execution)
	if d.fail[c.Execution] {
		return nil, errors.New("private credentials")
	}
	a := d.runs[c.Execution]
	if len(a) == 0 {
		return nil, errors.New("no remaining trial")
	}
	d.runs[c.Execution] = a[1:]
	return a[0], nil
}
func cand() []Candidate {
	return []Candidate{{Local, "wg", "entry", "exit"}, {Server, "wg", "entry", "exit"}}
}
func sample(last, out int) *trial {
	return &trial{last: time.Duration(last) * time.Millisecond, external: time.Duration(out) * time.Millisecond}
}
func opts() Options {
	return Options{Targets: []string{"https://approved.example/check"}, Preferred: Local}
}
func TestExactMean(t *testing.T) {
	for _, v := range []struct {
		a, b time.Duration
		mean float64
	}{{20 * time.Millisecond, 60 * time.Millisecond, 40}, {1, 3, .000002}, {time.Duration(math.MaxInt64), time.Duration(math.MaxInt64), float64(math.MaxInt64) / 1e6}} {
		m, e := Score(cand()[0], v.a, v.b)
		if e != nil || !m.Eligible || *m.ScoreMS != v.mean {
			t.Fatal(m, e)
		}
	}
	for _, v := range []time.Duration{0, -1} {
		if _, e := Score(cand()[0], v, time.Second); e == nil {
			t.Fatal("invalid latency accepted")
		}
	}
}
func TestLowerScoreStays(t *testing.T) {
	a, b, keep := sample(10, 90), sample(30, 40), sample(31, 40)
	d := &driver{runs: map[Execution][]*trial{Local: {a}, Server: {b, keep}}}
	r, s, e := Compare(context.Background(), cand(), d, opts())
	if e != nil || r.Winner.Execution != Server || s != keep || *r.Measurements[0].ScoreMS != 50 || *r.Measurements[1].ScoreMS != 35 || !a.closed || !b.closed || keep.closed {
		t.Fatal(r, e)
	}
	if a.target != b.target || a.target != keep.target {
		t.Fatal("different comparison targets")
	}
}
func TestFailuresNeverGetAScore(t *testing.T) {
	for _, failure := range []string{"verify", "last", "external", "stale"} {
		t.Run(failure, func(t *testing.T) {
			bad := sample(1, 1)
			bad.fail = failure
			good, keep := sample(40, 50), sample(40, 50)
			d := &driver{runs: map[Execution][]*trial{Local: {bad}, Server: {good, keep}}}
			r, _, e := Compare(context.Background(), cand(), d, opts())
			if e != nil || r.Winner.Execution != Server || r.Measurements[0].Eligible || r.Measurements[0].ScoreMS != nil || strings.Contains(r.Measurements[0].Failure, "private") {
				t.Fatal(r, e)
			}
			if failure == "last" && bad.target != "" {
				t.Fatal("external probe followed failed last-node probe")
			}
		})
	}
}
func TestTimeoutEvenWithoutDriverError(t *testing.T) {
	bad := sample(2600, 1)
	d := &driver{runs: map[Execution][]*trial{Local: {bad}, Server: {sample(10, 10), sample(10, 10)}}}
	r, _, e := Compare(context.Background(), cand(), d, opts())
	if e != nil || r.Winner.Execution != Server || r.Measurements[0].ScoreMS != nil {
		t.Fatal(r, e)
	}
}
func TestTieRetainsPreferred(t *testing.T) {
	for _, mode := range []Execution{Local, Server} {
		o := opts()
		o.Preferred = mode
		d := &driver{runs: map[Execution][]*trial{Local: {sample(20, 40), sample(21, 41)}, Server: {sample(30, 30), sample(31, 31)}}}
		r, s, e := Compare(context.Background(), cand(), d, o)
		if e != nil || s == nil || r.Winner.Execution != mode {
			t.Fatal(r, e)
		}
	}
}
func TestBothTimeoutNoWinner(t *testing.T) {
	a, b := sample(10, 10), sample(10, 10)
	a.fail = "last"
	b.fail = "external"
	d := &driver{runs: map[Execution][]*trial{Local: {a}, Server: {b}}}
	r, s, e := Compare(context.Background(), cand(), d, opts())
	if !errors.Is(e, ErrNoWinner) || s != nil || r.Winner != nil || !a.closed || !b.closed {
		t.Fatal(r, e)
	}
}
func TestFailedWinnerActivationUsesNextProved(t *testing.T) {
	bad := sample(1, 1)
	bad.fail = "external"
	d := &driver{runs: map[Execution][]*trial{Local: {sample(1, 1), bad}, Server: {sample(30, 30), sample(31, 31)}}}
	r, _, e := Compare(context.Background(), cand(), d, opts())
	if e != nil || r.Winner.Execution != Server || !bad.closed {
		t.Fatal(r, e)
	}
}
func TestCleanupStopsFurtherCandidates(t *testing.T) {
	bad := sample(1, 1)
	bad.dead = true
	d := &driver{runs: map[Execution][]*trial{Local: {bad}}}
	_, owned, e := Compare(context.Background(), cand(), d, opts())
	if !errors.Is(e, ErrTeardown) || owned != bad || len(d.opened) != 1 {
		t.Fatal(e, d.opened)
	}
}
func TestCancelledBeforeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &driver{}
	_, _, e := Compare(ctx, cand(), d, opts())
	if !errors.Is(e, context.Canceled) || len(d.opened) > 0 {
		t.Fatal(e)
	}
}
func TestNeverPretendSecondImplementation(t *testing.T) {
	for _, c := range [][]Candidate{{cand()[0], cand()[0]}, {cand()[0], {Local, "shadowsocks", "entry", "exit"}}, {cand()[0], {Server, "wg", "other", "exit"}}} {
		d := &driver{}
		_, _, e := Compare(context.Background(), c, d, opts())
		if e == nil || len(d.opened) > 0 {
			t.Fatal("accepted invalid comparison")
		}
	}
}
func TestTargetsAndBudgets(t *testing.T) {
	for _, o := range []Options{{}, {Targets: []string{"x", "x"}}, {Targets: []string{"x"}, ProbeTimeout: -1}, {Targets: []string{"x"}, Preferred: "invented"}} {
		d := &driver{}
		if _, _, e := Compare(context.Background(), cand(), d, o); e == nil {
			t.Fatal("invalid policy")
		}
	}
}
func TestProgressEventsAndNoSecretFailures(t *testing.T) {
	o := opts()
	var events []string
	o.Notify = func(e Event) { events = append(events, e.Stage) }
	d := &driver{runs: map[Execution][]*trial{Server: {sample(2, 2), sample(2, 2)}}, fail: map[Execution]bool{Local: true}}
	r, _, e := Compare(context.Background(), cand(), d, o)
	if e != nil || events[len(events)-1] != "selected" || strings.Contains(r.Measurements[0].Failure, "credentials") {
		t.Fatal(r, e, events)
	}
}
