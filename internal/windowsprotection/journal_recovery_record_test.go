package windowsprotection

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func journalRecoveryController() Controller {
	controller := journalTestController()
	controller.PID, controller.StartTimeUTCTicks = 303, controller.StartTimeUTCTicks+1000
	return controller
}

func journalRecoverySelection(t *testing.T, record JournalRecord) JournalSelection {
	t.Helper()
	raw := journalTestBody(t, record)
	digest, err := JournalRecordSHA256(raw)
	if err != nil {
		t.Fatal(err)
	}
	return JournalSelection{Record: cloneJournalRecord(record), SHA256: digest, Slot: int((record.Sequence - 1) % 2)}
}

func TestWindowsProtectionJournalRecoveryExactOutcomes(t *testing.T) {
	initial := journalTestInitial()
	successor := journalTestSuccessor(t, initial, "b")
	live := journalTestSettled(t, successor, successor.Intent.Candidate)
	retained := journalTestRetained(t)
	off := journalTestOff(t)
	release := cloneJournalRecord(off)
	release.Committed.Target.Policy = "on-connect"
	release.Intent.Action, release.Intent.ResultProfileRevision = "release", release.Intent.ProfileRevision
	for name, previous := range map[string]JournalRecord{"initial": initial, "successor": successor, "live": live,
		"retained-always": retained, "release": release, "pending-off": off} {
		candidates, err := JournalRecoveryCandidates(previous)
		if err != nil {
			t.Fatal(err)
		}
		for index := range candidates {
			t.Run(name+string(rune('0'+index)), func(t *testing.T) {
				next, err := deriveJournalRecoveryTransition(previous, journalRecoveryController(), strings.Repeat("e", 32), index)
				if err != nil || CheckJournalRecoveryTransition(previous, next) != nil {
					t.Fatal("exact checked-recovery comparison was rejected", err)
				}
				if CheckJournalTransition(previous, next) == nil {
					t.Fatal("recovery marker granted ordinary controller-replacement authority")
				}
				expected := cloneJournalState(candidates[index])
				expected.Engine = nil
				if !sameJournalState(expected, next.Adoption.Observed) || next.Adoption.PreviousController != previous.Controller ||
					next.Adoption.Controller != next.Controller {
					t.Fatal("recovery handover lost its captured process and outcome provenance")
				}
				if name == "pending-off" {
					if next.Phase != "intent" || !sameJournalState(next.Committed, previous.Committed) || *next.Intent != *previous.Intent {
						t.Fatal("recovery erased the accepted Off before its actual profile-save acknowledgment")
					}
				} else if next.Phase != "settled" || next.Intent != nil || !sameJournalState(next.Committed, expected) {
					t.Fatal("recovery did not settle exactly its observed retired outcome")
				}
				var slots [2][]byte
				slots[(previous.Sequence-1)%2] = journalTestBody(t, previous)
				slots[(next.Sequence-1)%2] = journalTestBody(t, next)
				selected, err := SelectJournalRecord(previous.JournalID, slots)
				if err != nil || selected.Record.Sequence != next.Sequence || selected.Incomplete {
					t.Fatal("canonical recovery slot pair did not retain the exact handover", err)
				}
				checkpoint := journalTestNext(t, next)
				if checkpoint.Phase == "intent" {
					checkpoint.Phase, checkpoint.Intent, checkpoint.Committed = "settled", nil, expected
				}
				if err := CheckJournalTransition(next, checkpoint); err != nil {
					t.Fatal("ordinary acknowledged settlement lost immutable adoption provenance", err)
				}
				if next.Adoption.Observed.Target != nil {
					next.Adoption.Observed.Target.Policy = "on-connect"
					if previous.Committed.Target != nil && previous.Committed.Target.Policy != "always" && name != "release" {
						t.Fatal("returned adoption mutated its prior protection target")
					}
				}
			})
		}
	}
}

func TestWindowsProtectionJournalRecoveryKeepsPendingOff(t *testing.T) {
	previous := journalTestOff(t)
	previous.Intent.ProfileRevision = strings.Repeat("8", 64) // accepted UI revision may differ from the source
	for _, index := range []int{0, 1} {
		next, err := deriveJournalRecoveryTransition(previous, journalRecoveryController(), strings.Repeat("e", 32), index)
		if err != nil {
			t.Fatal(err)
		}
		if next.Intent.ProfileRevision != previous.Intent.ProfileRevision || next.Intent.ResultProfileRevision != previous.Intent.ResultProfileRevision ||
			next.Committed.ProfileRevision != previous.Committed.ProfileRevision {
			t.Fatal("recovery substituted a selected profile for source or accepted Off revisions")
		}
		candidates, err := JournalRecoveryCandidates(next)
		if err != nil {
			t.Fatal(err)
		}
		if index == 1 && (len(candidates) != 1 || candidates[0].Target != nil) {
			t.Fatal("an absence-proved pending Off could resurrect its old baseline")
		}
		if index == 1 && CheckJournalTransition(next, journalTestSettled(t, next, next.Committed)) == nil {
			t.Fatal("ordinary settlement resurrected an absence-proved pending Off baseline")
		}
		if index == 0 && len(candidates) != 2 {
			t.Fatal("retained pending Off lost its already accepted removal outcome")
		}
		third := journalRecoveryController()
		third.PID++
		third.StartTimeUTCTicks++
		again, err := deriveJournalRecoveryTransition(next, third, strings.Repeat("d", 32), len(candidates)-1)
		if err != nil || CheckJournalRecoveryTransition(next, again) != nil || again.Intent == nil {
			t.Fatal("a second controller restart lost accepted pending Off", err)
		}
		if again.Intent.ProfileRevision != previous.Intent.ProfileRevision || again.Intent.ResultProfileRevision != previous.Intent.ResultProfileRevision ||
			again.Adoption.Observed.Target != nil {
			t.Fatal("repeated recovery changed pending Off's exact absence and profile result")
		}
	}
}

func TestWindowsProtectionJournalRecoveryRejectsChangedProvenance(t *testing.T) {
	previous := journalTestRetained(t)
	valid, err := deriveJournalRecoveryTransition(previous, journalRecoveryController(), strings.Repeat("e", 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*JournalRecord){
		"dropped-marker":        func(r *JournalRecord) { r.Adoption = nil },
		"marker-sequence":       func(r *JournalRecord) { r.Adoption.Sequence-- },
		"previous-controller":   func(r *JournalRecord) { r.Adoption.PreviousController.PID++ },
		"previous-token":        func(r *JournalRecord) { r.Adoption.PreviousController.AuthenticationID++ },
		"new-marker-controller": func(r *JournalRecord) { r.Adoption.Controller.PID++ },
		"previous-digest":       func(r *JournalRecord) { r.Adoption.PreviousSHA256 = strings.Repeat("1", 64) },
		"foreign-journal":       func(r *JournalRecord) { r.JournalID = strings.Repeat("1", 32) },
		"skipped-generation":    func(r *JournalRecord) { r.Sequence++ },
		"unrecorded-target":     func(r *JournalRecord) { r.Adoption.Observed.Target.BaselineSHA256 = strings.Repeat("1", 64) },
		"source-revision":       func(r *JournalRecord) { r.Adoption.Observed.ProfileRevision = strings.Repeat("1", 64) },
		"retained-engine":       func(r *JournalRecord) { c := journalTestController(); r.Adoption.Observed.Engine = &c },
		"other-outcome":         func(r *JournalRecord) { r.Committed = JournalState{} },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := cloneJournalRecord(valid)
			mutate(&wrong)
			if CheckJournalRecoveryTransition(previous, wrong) == nil {
				t.Fatal("changed handover provenance acquired recovery comparison acceptance")
			}
		})
	}
	for name, mutate := range map[string]func(*JournalRecord){
		"drop":          func(r *JournalRecord) { r.Adoption = nil },
		"request":       func(r *JournalRecord) { r.Adoption.RequestID = strings.Repeat("d", 32) },
		"outcome-index": func(r *JournalRecord) { r.Adoption.CandidateIndex = 1 },
		"profile":       func(r *JournalRecord) { r.Adoption.Observed.ProfileID += "different" },
		"revision":      func(r *JournalRecord) { r.Adoption.Observed.ProfileRevision = strings.Repeat("d", 64) },
	} {
		t.Run("ordinary-"+name, func(t *testing.T) {
			wrong := journalTestNext(t, valid)
			mutate(&wrong)
			if CheckJournalTransition(valid, wrong) == nil {
				t.Fatal("ordinary checkpoint rewrote immutable adoption provenance")
			}
		})
	}
	off := journalTestOff(t)
	adopted, err := deriveJournalRecoveryTransition(off, journalRecoveryController(), strings.Repeat("e", 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	adopted.Phase, adopted.Intent, adopted.Committed = "settled", nil, JournalState{}
	if CheckJournalRecoveryTransition(off, adopted) == nil {
		t.Fatal("absence alone erased an accepted Off's unsaved result")
	}
}

func TestWindowsProtectionJournalRecoveryRequiresBoundIntactHead(t *testing.T) {
	for name, mutate := range map[string]func(*JournalRecord){
		"legacy-unbound":     func(r *JournalRecord) { r.Committed.ProfileRevision = "" },
		"exhausted-sequence": func(r *JournalRecord) { r.Sequence = math.MaxUint64 },
		"invalid-controller": func(r *JournalRecord) { r.Controller.PID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			previous := journalTestRetained(t)
			mutate(&previous)
			if _, err := deriveJournalRecoveryTransition(previous, journalRecoveryController(), strings.Repeat("e", 32), 0); err == nil {
				t.Fatal("unbound or malformed predecessor acquired adoption authority")
			}
		})
	}
	previous := journalTestRetained(t)
	for _, index := range []int{-1, 1, 2} {
		if _, err := deriveJournalRecoveryTransition(previous, journalRecoveryController(), strings.Repeat("e", 32), index); err == nil {
			t.Fatal("recovery invented a native outcome")
		}
	}
	if _, err := deriveJournalRecoveryTransition(previous, previous.Controller, strings.Repeat("e", 32), 0); err == nil {
		t.Fatal("a live same-controller checkpoint masqueraded as restart adoption")
	}
}

func TestWindowsProtectionJournalRecoveryProcessProvenance(t *testing.T) {
	successor := journalTestSuccessor(t, journalTestInitial(), "b")
	processes, err := journalRecoveryProcesses(successor)
	if err != nil || len(processes) != 2 || processes[0] != successor.Controller || processes[1] != *successor.Intent.Candidate.Engine {
		t.Fatal("recovery omitted its previous controller or possible native source", err)
	}
	live := journalTestSettled(t, successor, successor.Intent.Candidate)
	processes, err = journalRecoveryProcesses(live)
	if err != nil || len(processes) != 2 || processes[1] != *live.Committed.Engine {
		t.Fatal("settled recovery forgot its still-recorded source identity", err)
	}
	before := journalTestBody(t, live)
	processes[1].PID++
	if !bytes.Equal(before, journalTestBody(t, live)) {
		t.Fatal("returned process comparison values changed the captured record")
	}
	conflict := cloneJournalRecord(live)
	engine := conflict.Controller
	engine.AuthenticationID++
	conflict.Committed.Engine = &engine
	if _, err := journalRecoveryProcesses(conflict); err == nil {
		t.Fatal("conflicting tokens for one recorded process creation were accepted")
	}
}
