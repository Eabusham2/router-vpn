package routechoice

import (
	"context"
	"errors"
	"testing"
)

func TestFailedFinalActivationClearsOldScoreAndPublishesDisqualification(t *testing.T) {
	for _, fault := range []string{"startup", "verify", "last", "external", "stale", "cleanup", "both"} {
		t.Run(fault, func(t *testing.T) {
			bad := sample(1, 1)
			bad.fail = fault
			if fault == "cleanup" || fault == "both" {
				bad.fail = "external"
			}
			bad.dead = fault == "cleanup"
			keep := sample(31, 31)
			if fault == "both" {
				keep.fail = "last"
			}
			local := []*trial{sample(1, 1), bad}
			if fault == "startup" {
				local = local[:1]
			}
			d := &driver{runs: map[Execution][]*trial{Local: local, Server: {sample(30, 30), keep}}}
			options := opts()
			var invalid []Measurement
			options.Notify = func(event Event) {
				if event.Stage == "activation-failed" && event.Result != nil {
					invalid = append(invalid, *event.Result)
				}
			}
			result, active, err := Compare(context.Background(), cand(), d, options)
			if len(result.Measurements) != 2 || result.Measurements[0].Eligible || result.Measurements[0].ScoreMS != nil || result.Measurements[0].Failure == "" {
				t.Fatal("failed final activation retained its obsolete candidate score", result, err)
			}
			if len(invalid) == 0 || invalid[0].Candidate != cand()[0] || invalid[0].Eligible || invalid[0].ScoreMS != nil || invalid[0].Failure == "" {
				t.Fatal("failed final activation did not publish its no-score state", invalid)
			}
			switch fault {
			case "cleanup":
				if !errors.Is(err, ErrTeardown) || active != bad || result.Winner != nil || len(d.opened) != 3 {
					t.Fatal("failed cleanup admitted another candidate", result, err)
				}
			case "both":
				if !errors.Is(err, ErrNoWinner) || active != nil || result.Winner != nil || result.Measurements[1].Eligible || result.Measurements[1].ScoreMS != nil || len(invalid) != 2 {
					t.Fatal("two failed final activations retained a scored winner", result, err)
				}
			default:
				if err != nil || active != keep || result.Winner == nil || result.Winner.Execution != Server || result.Final == nil || !result.Final.Eligible || !result.Measurements[1].Eligible || *result.Measurements[1].ScoreMS != 30 {
					t.Fatal("valid fallback lost its own repeated measurements", result, err)
				}
			}
		})
	}
}
