package windowsprotection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"router-vpn/internal/mobiletor"
)

const (
	JournalRecordSchema = 1
	JournalRecordKind   = "routervpn-owned-wfp-journal"
	JournalRecordLimit  = 16384
)

// JournalState names one independently observed protection state. Nil Target
// means proved absence, not a request to discover the current BFE baseline.
// Engine is the retained creation identity of the native source when that
// state was observed; it may be cleared only after the actual source joined.
// These fields are comparison data. Parsed values confer no native authority.
type JournalState struct {
	Target    *mobiletor.DesktopWindowsProtectionTarget `json:"target"`
	ProfileID string                                    `json:"profile_id"`
	// Omitted only by legacy records. Their canonical bytes stay readable, but
	// missing source binding cannot grant new writes or restart adoption.
	ProfileRevision string      `json:"profile_revision,omitempty"`
	Engine          *Controller `json:"engine"`
}

// JournalIntent is flushed before the native write transaction may commit.
// A restart cannot infer from this record whether that commit occurred. It
// must prove either Committed or Candidate, with all old processes retired.
// ProfileRevision binds the accepted application request, including explicit
// Off; the record does not authorize a new request with another revision.
type JournalIntent struct {
	Action                string       `json:"action"`
	RequestID             string       `json:"request_id"`
	ProfileID             string       `json:"profile_id"`
	ProfileRevision       string       `json:"profile_revision"`
	ResultProfileRevision string       `json:"result_profile_revision"`
	Candidate             JournalState `json:"candidate"`
}

type JournalRecord struct {
	Schema         int            `json:"schema"`
	Kind           string         `json:"kind"`
	JournalID      string         `json:"journal_id"`
	Sequence       uint64         `json:"sequence"`
	PreviousSHA256 string         `json:"previous_sha256"`
	Controller     Controller     `json:"controller"`
	Phase          string         `json:"phase"`
	Committed      JournalState   `json:"committed"`
	Intent         *JournalIntent `json:"intent"`
	// The latest checked controller handover remains immutable through all
	// ordinary checkpoints. Omission preserves legacy canonical bytes.
	Adoption *JournalAdoption `json:"adoption,omitempty"`
}

func journalProfileID(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func (s JournalState) Validate() error {
	if s.Target == nil {
		if s.ProfileID != "" || s.ProfileRevision != "" || s.Engine != nil {
			return errors.New("absent journal protection cannot retain a profile or native engine")
		}
		return nil
	}
	if s.Target.Validate() != nil || !journalProfileID(s.ProfileID) || s.ProfileRevision != "" && !lowerHex(s.ProfileRevision, 64) {
		return errors.New("journal protection lost its exact target and profile binding")
	}
	if s.Engine != nil {
		return s.Engine.Validate()
	}
	return nil
}

func (r JournalRecord) Validate() error {
	if r.Schema != JournalRecordSchema || r.Kind != JournalRecordKind || !lowerHex(r.JournalID, 32) ||
		r.Sequence == 0 || (r.Sequence == 1 && r.PreviousSHA256 != "") || (r.Sequence > 1 && !lowerHex(r.PreviousSHA256, 64)) ||
		r.Controller.Validate() != nil || r.Committed.Validate() != nil {
		return errors.New("Windows journal lost its bounded record, controller or committed identity")
	}
	if r.Sequence == 1 && (r.Phase != "settled" || r.Committed.Target != nil || r.Intent != nil) {
		return errors.New("a new Windows journal must begin at independently proved absence")
	}
	if err := validateJournalAdoption(r); err != nil {
		return err
	}
	if r.Phase == "settled" {
		if r.Intent != nil {
			return errors.New("settled Windows journal cannot retain an unresolved intent")
		}
		return nil
	}
	intent := r.Intent
	if r.Phase != "intent" || intent == nil || !lowerHex(intent.RequestID, 32) || !journalProfileID(intent.ProfileID) ||
		!lowerHex(intent.ProfileRevision, 64) || !lowerHex(intent.ResultProfileRevision, 64) || intent.Candidate.Validate() != nil {
		return errors.New("Windows journal intent lost its exact accepted request")
	}
	// A successor or explicit retirement can start only after the old engine
	// joined. Its persistent deny is kept until this intended mutation commits.
	if r.Committed.Engine != nil {
		return errors.New("Windows journal intent cannot replace a still-owned native engine")
	}
	switch intent.Action {
	case "successor":
		candidate := intent.Candidate
		if intent.ResultProfileRevision != intent.ProfileRevision || candidate.Target == nil || candidate.ProfileID != intent.ProfileID || candidate.Engine == nil ||
			candidate.ProfileRevision != "" && candidate.ProfileRevision != intent.ProfileRevision ||
			candidate.Engine.PID == r.Controller.PID || candidate.Engine.StartTimeUTCTicks < r.Controller.StartTimeUTCTicks ||
			candidate.Engine.SID != r.Controller.SID || candidate.Engine.AuthenticationID != r.Controller.AuthenticationID || candidate.Engine.SessionID != r.Controller.SessionID ||
			r.Committed.Target != nil && candidate.Target.Capture == r.Committed.Target.Capture {
			return errors.New("Windows journal successor lost its new retained engine and captured profile")
		}
	case "release", "off":
		if r.Committed.Target == nil || intent.ProfileID != r.Committed.ProfileID || intent.Action == "release" && intent.ResultProfileRevision != intent.ProfileRevision {
			return errors.New("Windows journal retirement requires the exact retained profile")
		}
		if intent.Action == "release" && r.Committed.ProfileRevision != "" && r.Committed.ProfileRevision != intent.ProfileRevision {
			return errors.New("Windows normal release changed its retained source profile revision")
		}
		expected := JournalState{}
		if intent.Action == "release" && r.Committed.Target.Policy == "always" {
			expected = r.Committed
		}
		if !sameJournalState(intent.Candidate, expected) {
			return errors.New("Windows journal retirement changed normal Always or explicit Off semantics")
		}
	default:
		return errors.New("Windows journal has an unsupported native mutation")
	}
	return nil
}

func cloneJournalState(s JournalState) JournalState {
	if s.Target != nil {
		target := *s.Target
		s.Target = &target
	}
	if s.Engine != nil {
		engine := *s.Engine
		s.Engine = &engine
	}
	return s
}

func cloneJournalRecord(r JournalRecord) JournalRecord {
	r.Committed = cloneJournalState(r.Committed)
	if r.Intent != nil {
		intent := *r.Intent
		intent.Candidate = cloneJournalState(intent.Candidate)
		r.Intent = &intent
	}
	if r.Adoption != nil {
		adoption := *r.Adoption
		adoption.Observed = cloneJournalState(adoption.Observed)
		r.Adoption = &adoption
	}
	return r
}

func sameJournalProtection(a, b JournalState) bool {
	if a.ProfileID != b.ProfileID || a.ProfileRevision != b.ProfileRevision || (a.Target == nil) != (b.Target == nil) {
		return false
	}
	return a.Target == nil || *a.Target == *b.Target
}

// Legacy canonical records are preserved as comparison evidence. A modern
// caller cannot turn their missing source revision into newly acknowledged
// authority by copying a current selected profile or clearing the old target.
func requireJournalProfileBindings(record JournalRecord) error {
	states := []JournalState{record.Committed}
	if record.Intent != nil {
		states = append(states, record.Intent.Candidate)
	}
	for _, state := range states {
		if state.Target != nil && !lowerHex(state.ProfileRevision, 64) {
			return errors.New("Windows journal target has no durably captured source profile revision")
		}
	}
	return nil
}

func sameJournalState(a, b JournalState) bool {
	if !sameJournalProtection(a, b) || (a.Engine == nil) != (b.Engine == nil) {
		return false
	}
	return a.Engine == nil || *a.Engine == *b.Engine
}

// A successful checked join can clear an engine identity. It cannot install
// another engine under the old baseline or otherwise rewrite its source.
func settledJournalState(actual, expected JournalState) bool {
	return sameJournalProtection(actual, expected) && (actual.Engine == nil || sameJournalState(actual, expected))
}

func CanonicalJournalRecord(record JournalRecord) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) == 0 || len(raw) > JournalRecordLimit {
		return nil, errors.New("Windows journal encoding is empty or exceeds its bound")
	}
	return raw, nil
}

func ParseJournalRecord(raw []byte) (JournalRecord, error) {
	if len(raw) == 0 || len(raw) > JournalRecordLimit {
		return JournalRecord{}, errors.New("Windows journal input is empty or exceeds its bound")
	}
	var record JournalRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return JournalRecord{}, errors.New("Windows journal input has unsupported fields or types")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return JournalRecord{}, errors.New("Windows journal input has trailing content")
	}
	canonical, err := CanonicalJournalRecord(record)
	if err != nil || !bytes.Equal(raw, canonical) {
		return JournalRecord{}, errors.New("Windows journal input is not its exact canonical encoding")
	}
	return record, nil
}

func JournalRecordSHA256(raw []byte) (string, error) {
	if _, err := ParseJournalRecord(raw); err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// CheckJournalTransition validates the durable sequence, not the native
// operation. Its caller must independently prove the actual process, BFE and
// private-file owners before writing any next record. An explicit Off remains
// an intent after native absence until its exact ResultProfileRevision is
// durably saved; a settled-absence checkpoint must not erase off-unsaved intent.
// Ordinary writes keep the exact controller creation identity. Restart adoption
// requires a distinct native-checked transition; no checkpoint may silently
// forget the process that owned a live engine or unresolved intent.
func CheckJournalTransition(previous, next JournalRecord) error {
	if previous.Validate() != nil || next.Validate() != nil || previous.Sequence == math.MaxUint64 ||
		next.Sequence != previous.Sequence+1 || next.JournalID != previous.JournalID || next.Controller != previous.Controller ||
		!sameJournalAdoption(previous.Adoption, next.Adoption) {
		return errors.New("Windows journal transition lost its exact previous generation")
	}
	raw, err := CanonicalJournalRecord(previous)
	if err != nil {
		return err
	}
	digest, err := JournalRecordSHA256(raw)
	if err != nil || next.PreviousSHA256 != digest {
		return errors.New("Windows journal transition lost its previous canonical digest")
	}
	if previous.Phase == "intent" {
		candidates, err := JournalRecoveryCandidates(previous)
		proved := false
		for _, candidate := range candidates {
			proved = proved || settledJournalState(next.Committed, candidate)
		}
		if err != nil || next.Phase != "settled" || !proved {
			return errors.New("Windows journal must prove one exact intent outcome before another mutation")
		}
		return nil
	}
	if next.Phase == "intent" {
		if !sameJournalState(next.Committed, previous.Committed) {
			return errors.New("Windows journal intent changed its last proved committed state")
		}
		return nil
	}
	if !settledJournalState(next.Committed, previous.Committed) {
		return errors.New("Windows journal checkpoint changed protection without a recorded intent")
	}
	return nil
}

// JournalRecoveryCandidates returns comparison values only. No invalid slot
// or timeout is interpreted as native absence, an aborted intent, or permission
// to remove an unknown baseline. Every old controller and engine must be
// independently proved retired before a caller can use these alternatives.
func JournalRecoveryCandidates(record JournalRecord) ([]JournalState, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	// Once a checked handover has proved the pending Off's absence, it cannot
	// later resurrect that old baseline. A retained-target handover still
	// permits the already accepted Off to finish its recorded removal.
	if record.Phase == "intent" && record.Intent.Action == "off" && record.Adoption != nil &&
		record.Adoption.Sequence == record.Sequence && record.Adoption.Observed.Target == nil {
		return []JournalState{{}}, nil
	}
	states := []JournalState{cloneJournalState(record.Committed)}
	if record.Intent != nil && !sameJournalState(record.Committed, record.Intent.Candidate) {
		states = append(states, cloneJournalState(record.Intent.Candidate))
	}
	return states, nil
}

type JournalSelection struct {
	Record     JournalRecord
	SHA256     string
	Slot       int
	Incomplete bool
}

// SelectJournalRecord validates two fixed, independently retained files. The
// native store proves their identities, protected ACL, immutable journal ID
// and exclusive lock; supplying these bytes alone is never recovery authority.
// An incomplete peer slot leaves only the surviving record's possible outcomes.
// If BFE names a different outcome, recovery must stay blocked, even if that
// different state might have belonged to a now-torn acknowledged intent.
func SelectJournalRecord(journalID string, slots [2][]byte) (JournalSelection, error) {
	if !lowerHex(journalID, 32) {
		return JournalSelection{}, errors.New("Windows journal selection has no retained directory identity")
	}
	var records [2]*JournalRecord
	var digests [2]string
	for index, raw := range slots {
		if len(raw) > JournalRecordLimit {
			return JournalSelection{}, errors.New("Windows journal slot exceeds its fixed bound")
		}
		record, err := ParseJournalRecord(raw)
		if err != nil {
			continue
		}
		if record.JournalID != journalID || (record.Sequence-1)%2 != uint64(index) {
			return JournalSelection{}, errors.New("Windows journal slot contains another owner or generation")
		}
		records[index] = &record
		digests[index], _ = JournalRecordSHA256(raw)
	}
	if records[0] == nil && records[1] == nil {
		return JournalSelection{}, errors.New("Windows journal has no complete recorded state")
	}
	if records[0] == nil || records[1] == nil {
		index := 0
		if records[0] == nil {
			index = 1
		}
		record := *records[index]
		incomplete := len(slots[1-index]) != 0 || record.Sequence != 1
		return JournalSelection{cloneJournalRecord(record), digests[index], index, incomplete}, nil
	}
	older, newer := 0, 1
	if records[0].Sequence > records[1].Sequence {
		older, newer = 1, 0
	}
	if err := CheckJournalTransition(*records[older], *records[newer]); err != nil {
		if recoveryErr := CheckJournalRecoveryTransition(*records[older], *records[newer]); recoveryErr != nil {
			return JournalSelection{}, errors.Join(err, recoveryErr)
		}
	}
	return JournalSelection{cloneJournalRecord(*records[newer]), digests[newer], newer, false}, nil
}
