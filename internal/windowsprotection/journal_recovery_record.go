package windowsprotection

import (
	"bytes"
	"errors"
	"math"
)

// JournalAdoption records one independently checked controller handover. It is
// comparison data, never a capability derived from JSON. Only the native
// recovery owner may write this transition after retaining the original
// desktop/Data authority, retiring all recorded processes and observing one
// complete recorded BFE outcome inside the durable-write callback.
type JournalAdoption struct {
	Sequence           uint64       `json:"sequence"`
	PreviousSHA256     string       `json:"previous_sha256"`
	PreviousController Controller   `json:"previous_controller"`
	Controller         Controller   `json:"controller"`
	RequestID          string       `json:"request_id"`
	CandidateIndex     int          `json:"candidate_index"`
	Observed           JournalState `json:"observed"`
}

func validateJournalAdoption(record JournalRecord) error {
	a := record.Adoption
	if a == nil {
		return nil
	}
	if a.Sequence < 2 || a.Sequence > record.Sequence || !lowerHex(a.PreviousSHA256, 64) ||
		a.PreviousController.Validate() != nil || a.Controller != record.Controller || a.PreviousController == a.Controller ||
		!lowerHex(a.RequestID, 32) || a.CandidateIndex < 0 || a.CandidateIndex > 1 || a.Observed.Validate() != nil ||
		a.Observed.Engine != nil || a.Observed.Target != nil && !lowerHex(a.Observed.ProfileRevision, 64) {
		return errors.New("Windows journal adoption lost its exact handover provenance")
	}
	if a.Sequence == record.Sequence {
		if a.PreviousSHA256 != record.PreviousSHA256 {
			return errors.New("Windows journal handover changed its preceding digest")
		}
		if record.Phase == "settled" {
			if !sameJournalState(record.Committed, a.Observed) {
				return errors.New("Windows journal handover changed its observed settled outcome")
			}
		} else if record.Phase != "intent" || record.Intent == nil || record.Intent.Action != "off" ||
			!sameJournalState(a.Observed, record.Committed) && !sameJournalState(a.Observed, record.Intent.Candidate) {
			return errors.New("Windows journal handover lost its accepted pending Off outcome")
		}
	}
	return nil
}

func sameJournalAdoption(a, b *JournalAdoption) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Sequence == b.Sequence && a.PreviousSHA256 == b.PreviousSHA256 && a.PreviousController == b.PreviousController &&
		a.Controller == b.Controller && a.RequestID == b.RequestID && a.CandidateIndex == b.CandidateIndex && sameJournalState(a.Observed, b.Observed)
}

// The constructor is private. Exported parsers/checkers expose comparison
// evidence only; supplying a newly encoded controller never opens native
// recovery authority or bypasses the store's ordinary Append gate.
func deriveJournalRecoveryTransition(previous JournalRecord, controller Controller, requestID string, matched int) (JournalRecord, error) {
	if previous.Validate() != nil || requireJournalProfileBindings(previous) != nil || previous.Sequence == math.MaxUint64 ||
		controller.Validate() != nil || controller == previous.Controller || !lowerHex(requestID, 32) {
		return JournalRecord{}, errors.New("Windows journal recovery lost its bound predecessor and new controller")
	}
	candidates, err := JournalRecoveryCandidates(previous)
	if err != nil || matched < 0 || matched >= len(candidates) {
		return JournalRecord{}, errors.New("Windows journal recovery selected an unrecorded outcome")
	}
	raw, err := CanonicalJournalRecord(previous)
	if err != nil {
		return JournalRecord{}, err
	}
	digest, err := JournalRecordSHA256(raw)
	if err != nil {
		return JournalRecord{}, err
	}
	observed := cloneJournalState(candidates[matched])
	observed.Engine = nil // native retirement precedes this comparison derivation
	next := cloneJournalRecord(previous)
	next.Sequence++
	next.PreviousSHA256, next.Controller = digest, controller
	next.Adoption = &JournalAdoption{Sequence: next.Sequence, PreviousSHA256: digest, PreviousController: previous.Controller,
		Controller: controller, RequestID: requestID, CandidateIndex: matched, Observed: observed}
	if previous.Phase != "intent" || previous.Intent.Action != "off" {
		next.Phase, next.Intent, next.Committed = "settled", nil, cloneJournalState(observed)
	}
	if err := next.Validate(); err != nil {
		return JournalRecord{}, err
	}
	return next, nil
}

// CheckJournalRecoveryTransition recognizes only the exact comparison record
// produced by a handover. It does not prove process death or BFE and is never
// used by ordinary Append to relax its controller identity. The old engine is
// cleared only in the observed outcome; pending Off preserves its accepted
// original/result revisions until the actual saved-profile acknowledgment.
func CheckJournalRecoveryTransition(previous, next JournalRecord) error {
	if next.Validate() != nil || next.Adoption == nil || next.Adoption.Sequence != next.Sequence {
		return errors.New("Windows journal has no exact controller-handover marker")
	}
	expected, err := deriveJournalRecoveryTransition(previous, next.Controller, next.Adoption.RequestID, next.Adoption.CandidateIndex)
	if err != nil {
		return err
	}
	want, err := CanonicalJournalRecord(expected)
	if err != nil {
		return err
	}
	actual, err := CanonicalJournalRecord(next)
	if err != nil || !bytes.Equal(actual, want) {
		return errors.New("Windows journal handover changed its captured predecessor, outcome or pending request")
	}
	return nil
}

func journalRecoveryProcesses(record JournalRecord) ([]Controller, error) {
	if record.Validate() != nil || requireJournalProfileBindings(record) != nil {
		return nil, errors.New("Windows journal recovery has no bound process provenance")
	}
	processes := []Controller{record.Controller}
	states := []JournalState{record.Committed}
	if record.Intent != nil {
		states = append(states, record.Intent.Candidate)
	}
	for _, state := range states {
		if state.Engine == nil {
			continue
		}
		duplicate := false
		for _, prior := range processes {
			if prior == *state.Engine {
				duplicate = true
			} else if prior.PID == state.Engine.PID && prior.StartTimeUTCTicks == state.Engine.StartTimeUTCTicks {
				return nil, errors.New("Windows journal process creation has conflicting recorded token identities")
			}
		}
		if !duplicate {
			processes = append(processes, *state.Engine)
		}
	}
	return processes, nil
}
