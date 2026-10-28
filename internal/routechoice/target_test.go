package routechoice

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// This driver models an owned external anchor which must exist before the
// last-node probe. Returning a nonnil failed startup still transfers cleanup.
type anchoredTrial struct {
	*trial
	anchorTarget string
}

func (s *anchoredTrial) Verify(ctx context.Context) error {
	if s.anchorTarget == "" {
		return errors.New("external stream was not captured before path proof")
	}
	return s.trial.Verify(ctx)
}

func (s *anchoredTrial) ProbeLast(ctx context.Context) (time.Duration, error) {
	if s.anchorTarget == "" {
		return 0, errors.New("last-node probe has no captured external path")
	}
	return s.trial.ProbeLast(ctx)
}

func (s *anchoredTrial) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	if target != s.anchorTarget {
		return 0, errors.New("external probe changed its captured endpoint")
	}
	return s.trial.ProbeExternal(ctx, target)
}

type anchoredDriver struct {
	runs        map[Execution][]*anchoredTrial
	fail        map[Execution]bool
	opened      []Candidate
	targets     []string
	legacyCalls int
}

func (d *anchoredDriver) Open(context.Context, Candidate) (Session, error) {
	d.legacyCalls++
	return nil, errors.New("target-aware path must never use legacy startup")
}

func (d *anchoredDriver) OpenTarget(ctx context.Context, candidate Candidate, target string) (Session, error) {
	d.opened = append(d.opened, candidate)
	d.targets = append(d.targets, target)
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || target == "" {
		return nil, errors.New("capture requires a live bounded startup and exact target")
	}
	runs := d.runs[candidate.Execution]
	if len(runs) == 0 {
		return nil, errors.New("unexpected candidate startup")
	}
	session := runs[0]
	d.runs[candidate.Execution] = runs[1:]
	session.anchorTarget = target
	if d.fail[candidate.Execution] {
		return session, errors.New("captured stream failed startup")
	}
	return session, nil
}

func anchoredSample(last, external int) *anchoredTrial {
	return &anchoredTrial{trial: sample(last, external)}
}

func TestTargetCapturePrecedesBothProbesAndSurvivesWinnerRecheck(t *testing.T) {
	local, server, selected := anchoredSample(10, 90), anchoredSample(30, 40), anchoredSample(31, 41)
	driver := &anchoredDriver{runs: map[Execution][]*anchoredTrial{Local: {local}, Server: {server, selected}}}
	options := opts()
	options.Targets = []string{"https://one.example/check", "https://two.example/check"}
	result, active, err := Compare(context.Background(), cand(), driver, options)
	if err != nil || result.Winner == nil || result.Winner.Execution != Server || active != selected || driver.legacyCalls != 0 {
		t.Fatal("comparison lost target-aware candidate ownership", result, active, err, driver.legacyCalls)
	}
	if result.Target != options.Targets[0] && result.Target != options.Targets[1] {
		t.Fatal("comparison selected an unapproved target", result.Target)
	}
	if !reflect.DeepEqual(driver.targets, []string{result.Target, result.Target, result.Target}) {
		t.Fatal("startup or final recheck used another target", driver.targets, result.Target)
	}
	for _, session := range []*anchoredTrial{local, server, selected} {
		if session.anchorTarget != result.Target || session.target != result.Target ||
			!reflect.DeepEqual(session.calls, []string{"verify", "last", "external"}) {
			t.Fatal("probe did not use the captured stream in the required order", session)
		}
	}
	if !local.closed || !server.closed || selected.closed || result.Final == nil || *result.Final.ScoreMS != 36 {
		t.Fatal("winner retained without repeated mean and exact trial teardown", result)
	}
}

func TestTargetCaptureFailureClosesOwnerWithoutFallbackOrScore(t *testing.T) {
	failed, server, selected := anchoredSample(1, 1), anchoredSample(30, 40), anchoredSample(31, 41)
	driver := &anchoredDriver{
		runs: map[Execution][]*anchoredTrial{Local: {failed}, Server: {server, selected}},
		fail: map[Execution]bool{Local: true},
	}
	result, active, err := Compare(context.Background(), cand(), driver, opts())
	if err != nil || active != selected || !failed.closed || len(failed.calls) != 0 ||
		driver.legacyCalls != 0 || len(result.Measurements) != 2 || result.Measurements[0].Eligible || result.Measurements[0].ScoreMS != nil {
		t.Fatal("failed anchor acquired a fallback or a score, or escaped cleanup", result, active, err)
	}
}

func TestTargetCaptureFailedCloseRetainsExactOwnerAndStopsComparison(t *testing.T) {
	failed := anchoredSample(1, 1)
	failed.dead = true
	driver := &anchoredDriver{
		runs: map[Execution][]*anchoredTrial{Local: {failed}},
		fail: map[Execution]bool{Local: true},
	}
	result, active, err := Compare(context.Background(), cand(), driver, opts())
	if !errors.Is(err, ErrTeardown) || active != failed || result.Winner != nil || len(driver.opened) != 1 ||
		driver.opened[0] != cand()[0] || driver.legacyCalls != 0 || !failed.closed || len(failed.calls) != 0 {
		t.Fatal("failed anchor cleanup escaped its exact owner", result, active, err, driver.opened)
	}
}
