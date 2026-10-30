package mobiletor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDesktopPFBaselinePlansBeforeMutationAndProvesTarget(t *testing.T) {
	request := desktopPFBaselineFixture()
	target := DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("c", 64)}
	var current DesktopDarwinPFBaselineProof
	reads, ready, writes := 0, 0, 0
	backend := desktopPFBaselineBackend{
		read:    func(context.Context) (DesktopDarwinPFBaselineProof, error) { reads++; return current, nil },
		ready:   func(context.Context) error { ready++; return nil },
		replace: func(context.Context) error { writes++; current = target; return nil },
	}
	plan, err := desktopPFTransitionBaseline(context.Background(), request, target, false, backend)
	if err != nil || plan.Previous != current || plan.Target != target || plan.Applied || reads != 2 || ready != 1 || writes != 0 {
		t.Fatal("baseline plan did not preserve its exact preimage without mutation", plan, reads, ready, writes, err)
	}
	result, err := desktopPFTransitionBaseline(context.Background(), request, target, true, backend)
	if err != nil || !result.Applied || result.Previous != plan.Previous || result.Target != plan.Target ||
		result.RequestSHA256 != plan.RequestSHA256 || reads != 5 || ready != 2 || writes != 1 {
		t.Fatal("baseline apply did not prove the planned kernel target", result, reads, ready, writes, err)
	}
	request.Expected = []DesktopDarwinPFBaselineProof{plan.Previous, plan.Target}
	result, err = desktopPFTransitionBaseline(context.Background(), request, target, true, backend)
	if err != nil || !result.Applied || writes != 1 || ready != 2 {
		t.Fatal("baseline ambiguous-commit retry rewrote an already proved exact target", result, writes, ready, err)
	}
}

func TestDesktopPFBaselineNeverOverwritesChangedOwner(t *testing.T) {
	request := desktopPFBaselineFixture()
	target := DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("c", 64)}
	foreign := DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("d", 64)}
	for _, replacedBeforeRead := range []bool{true, false} {
		current, writes := DesktopDarwinPFBaselineProof{}, 0
		if replacedBeforeRead {
			current = foreign
		}
		backend := desktopPFBaselineBackend{
			read:    func(context.Context) (DesktopDarwinPFBaselineProof, error) { return current, nil },
			ready:   func(context.Context) error { current = foreign; return nil },
			replace: func(context.Context) error { writes++; return nil },
		}
		result, err := desktopPFTransitionBaseline(context.Background(), request, target, true, backend)
		if err == nil || result.Applied || writes != 0 || current != foreign {
			t.Fatal("baseline wrote over a replacement during independent ownership inspection", replacedBeforeRead, writes, err)
		}
	}
}

func TestDesktopPFBaselineRequiresNamespaceAbsenceAfterClear(t *testing.T) {
	prior := DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("c", 64)}
	request := DesktopDarwinPFBaselineRequest{Schema: 1, Action: "clear", Expected: []DesktopDarwinPFBaselineProof{prior}}
	for _, failure := range []string{"retained-empty-anchor", "replacement-after-commit", "failed-readback", "cancel-after-commit", "commit-error-after-install"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			current, written := prior, false
			backend := desktopPFBaselineBackend{
				read: func(context.Context) (DesktopDarwinPFBaselineProof, error) {
					if written && failure == "failed-readback" {
						return DesktopDarwinPFBaselineProof{}, errors.New("native read failed")
					}
					return current, nil
				},
				ready: func(context.Context) error { return nil },
				replace: func(context.Context) error {
					written = true
					current = DesktopDarwinPFBaselineProof{}
					switch failure {
					case "retained-empty-anchor":
						current = DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: desktopPFDigest(nil)}
					case "replacement-after-commit":
						current = DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("d", 64)}
					case "cancel-after-commit":
						cancel()
					case "commit-error-after-install":
						return errors.New("native completion unknown")
					}
					return nil
				},
			}
			result, err := desktopPFTransitionBaseline(ctx, request, DesktopDarwinPFBaselineProof{}, true, backend)
			if err == nil || result.Applied || !written {
				t.Fatal("baseline falsely retired unknown state or an empty but retained namespace", failure, result, err)
			}
		})
	}
}

func TestDesktopPFBaselineRetainsUnjoinedChildAndCancelledPlan(t *testing.T) {
	request := desktopPFBaselineFixture()
	target := DesktopDarwinPFBaselineProof{Present: true, RulesSHA256: strings.Repeat("c", 64)}
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		writes := 0
		backend := desktopPFBaselineBackend{
			read: func(context.Context) (DesktopDarwinPFBaselineProof, error) {
				return DesktopDarwinPFBaselineProof{}, nil
			},
			ready: func(context.Context) error {
				if cancelled {
					cancel()
					return nil
				}
				return errors.New("owned child has not retired")
			},
			replace: func(context.Context) error { writes++; return nil },
		}
		result, err := desktopPFTransitionBaseline(ctx, request, target, true, backend)
		cancel()
		if err == nil || result.Applied || writes != 0 {
			t.Fatal("baseline changed before complete captured-child retirement or after cancellation", cancelled, writes, err)
		}
	}
}
