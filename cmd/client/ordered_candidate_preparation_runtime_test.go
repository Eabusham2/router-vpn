package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestOrderedCandidateNativeConstructorBindsBeforeStaging(t *testing.T) {
	for _, target := range []string{"windows", "linux", "darwin"} {
		t.Run(target, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			p := beginOrderedPreparationFixture(t, a, q)
			launch, err := newDesktopNodeChainLaunchForPurpose(context.Background(), p.selection, strings.Repeat("b", 32), target, p)
			if err != nil {
				t.Fatal(err)
			}
			if p.launch != launch || launch.chain.preparation != p || launch.command != nil || launch.directory != "" || launch.chain.capture != nil || launch.ownedNode != nil || launch.chain.platform != nil {
				t.Fatal("purpose binding followed native partial registration")
			}
			if err := validateDesktopNodeChainLaunch(context.Background(), launch); err != nil {
				t.Fatal("purpose changed original sealed native projection", err)
			}
			config := string(launch.config)
			if other, err := newDesktopNodeChainLaunchForPurpose(context.Background(), p.selection, strings.Repeat("c", 32), target, p); err == nil || other != nil {
				t.Fatal("constructor rebound original purpose")
			}
			if p.launch != launch || string(launch.config) != config {
				t.Fatal("rejected duplicate constructor erased original launch")
			}
		})
	}
}

func TestOrderedCandidateNativeStageRejectsMissingOrForeignPurpose(t *testing.T) {
	for _, fault := range []string{"missing", "foreign", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			a, q := orderedPreparationFixture(t, "wg")
			p := beginOrderedPreparationFixture(t, a, q)
			launch, err := newDesktopNodeChainLaunch(p.selection, strings.Repeat("b", 32), "windows")
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "foreign":
				launch.chain.preparation = &orderedCandidatePreparation{}
			case "cancelled":
				if err := p.bindLaunch(context.Background(), launch); err != nil {
					t.Fatal(err)
				}
				p.cancel()
			}
			if err := stageOwnedNativeMultihopInputsContext(context.Background(), a, p.selection, launch); err == nil {
				t.Fatal("native staging accepted another or absent temporary purpose")
			}
			if launch.command != nil || launch.directory != "" || launch.directoryRoot != nil || a.cmd != nil || a.state.Connected {
				t.Fatal("refused purpose reached native staging/publication")
			}
		})
	}
}

func TestOrderedCandidateNativeOrdinaryProjectionIsUnchanged(t *testing.T) {
	_, selection := desktopNodeChainHostSelectionFixture(t, 3)
	for _, target := range []string{"windows", "linux", "darwin"} {
		t.Run(target, func(t *testing.T) {
			original, err := newDesktopNodeChainLaunch(selection, strings.Repeat("b", 32), target)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := newDesktopNodeChainLaunchForPurpose(context.Background(), selection, strings.Repeat("b", 32), target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if wrapped.chain.preparation != nil || string(wrapped.config) != string(original.config) || string(wrapped.metadata) != string(original.metadata) || wrapped.chain.input != original.chain.input || !reflect.DeepEqual(wrapped.chain.policy.Metadata(), original.chain.policy.Metadata()) {
				t.Fatal("ordinary wrapper changed original source, config, session or metadata")
			}
		})
	}
}

func TestOrderedCandidateNativeConstructorCannotDropCapturedHostPurpose(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	p := beginOrderedPreparationFixture(t, a, q)
	// Only the captured-controller association is needed to test this early
	// refusal. No modeled controller capability supplies native authority.
	p.selection.Native.chain.host = &desktopNodeChainHostCapture{app: a}
	if launch, err := newDesktopNodeChainLaunchForPurpose(context.Background(), p.selection, strings.Repeat("b", 32), "linux", nil); err == nil || launch != nil {
		t.Fatal("captured candidate controller created an ordinary native purpose")
	}
	if p.launch != nil || a.cmd != nil || a.state.Connected {
		t.Fatal("missing purpose reached native registration")
	}
}
