package linuxprotection

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

const JournalRecordSchema = 1
const JournalRecordKind = "routervpn-owned-nft-journal"
const JournalRecordLimit = 32768

// ProtectionTarget retains the selected policy and exact observed Linux
// baseline. Guardian identifies the original native process which provisioned
// the isolated socket UID; it remains comparison data after that source joins.
type ProtectionTarget struct {
	Native       mobiletor.DesktopLinuxProtectionRecord `json:"native"`
	ConfigSHA256 string                                 `json:"config_sha256"`
	Policy       string                                 `json:"policy"`
	Guardian     ProcessRecord                          `json:"guardian"`
}

func (t ProtectionTarget) Validate() error {
	if t.Native.Validate() != nil || !lowerHex(t.ConfigSHA256, 64) || (t.Policy != "on-connect" && t.Policy != "always") ||
		t.Guardian.Validate() != nil || uint32(t.Guardian.ProcessID) != t.Native.Owner.ProcessID {
		return errors.New("Linux journal target lost its exact baseline, selected policy or original guardian")
	}
	return nil
}

type JournalState struct {
	Target          *ProtectionTarget `json:"target"`
	ProfileID       string            `json:"profile_id"`
	ProfileRevision string            `json:"profile_revision"`
	Engine          *ProcessRecord    `json:"engine"`
}

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
	Controller     ParentRecord   `json:"controller"`
	Phase          string         `json:"phase"`
	Committed      JournalState   `json:"committed"`
	Intent         *JournalIntent `json:"intent"`
}

func profileID(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func (s JournalState) Validate() error {
	if s.Target == nil {
		if s.ProfileID != "" || s.ProfileRevision != "" || s.Engine != nil {
			return errors.New("absent Linux protection cannot retain a profile or engine")
		}
		return nil
	}
	if s.Target.Validate() != nil || !profileID(s.ProfileID) || !lowerHex(s.ProfileRevision, 64) {
		return errors.New("Linux journal protection lost its exact captured profile")
	}
	if s.Engine != nil {
		g, e := s.Target.Guardian, s.Engine
		if e.Validate() != nil || g.BootID != e.BootID || g.ParentProcessID != e.ProcessID || g.ProcProcessID == e.ProcProcessID || g.Image != e.Image ||
			g.StartTicks < e.StartTicks || g.NetworkNamespace != e.NetworkNamespace || g.PIDNamespace != e.PIDNamespace {
			return errors.New("Linux journal guardian belongs to another native engine lifetime")
		}
	}
	return nil
}

func (r JournalRecord) Validate() error {
	if r.Schema != JournalRecordSchema || r.Kind != JournalRecordKind || !lowerHex(r.JournalID, 32) || r.Sequence == 0 ||
		(r.Sequence == 1 && r.PreviousSHA256 != "") || (r.Sequence > 1 && !lowerHex(r.PreviousSHA256, 64)) ||
		r.Controller.Validate() != nil || r.Committed.Validate() != nil {
		return errors.New("Linux journal lost its bounded record, retained creator or committed state")
	}
	if r.Committed.Engine != nil && !processBelongsToParent(*r.Committed.Engine, r.Controller) {
		return errors.New("Linux journal committed engine belongs to another retained creator")
	}
	if r.Sequence == 1 && (r.Phase != "settled" || r.Committed.Target != nil || r.Intent != nil) {
		return errors.New("Linux journal must begin at independently proved absence")
	}
	if r.Phase == "settled" {
		if r.Intent != nil {
			return errors.New("settled Linux journal cannot hide an unresolved intent")
		}
		return nil
	}
	i := r.Intent
	if r.Phase != "intent" || i == nil || !lowerHex(i.RequestID, 32) || !profileID(i.ProfileID) ||
		!lowerHex(i.ProfileRevision, 64) || !lowerHex(i.ResultProfileRevision, 64) || i.Candidate.Validate() != nil || r.Committed.Engine != nil {
		return errors.New("Linux journal intent lost its accepted request or joined predecessor")
	}
	switch i.Action {
	case "successor":
		c, owner := i.Candidate, r.Controller
		if i.ResultProfileRevision != i.ProfileRevision || c.Target == nil || c.Engine == nil || c.ProfileID != i.ProfileID || c.ProfileRevision != i.ProfileRevision ||
			!processBelongsToParent(*c.Engine, owner) ||
			r.Committed.Target != nil && (c.Target.Native.Capture.SessionID == r.Committed.Target.Native.Capture.SessionID || c.Target.Guardian == r.Committed.Target.Guardian) {
			return errors.New("Linux successor lost its new native engine, source or exact profile")
		}
	case "release", "off":
		if r.Committed.Target == nil || i.ProfileID != r.Committed.ProfileID ||
			i.Action == "release" && (i.ProfileRevision != r.Committed.ProfileRevision || i.ResultProfileRevision != i.ProfileRevision) {
			return errors.New("Linux retirement lost its exact retained profile")
		}
		want := JournalState{}
		if i.Action == "release" && r.Committed.Target.Policy == "always" {
			want = r.Committed
		}
		if !sameState(i.Candidate, want) {
			return errors.New("Linux retirement changed normal Always or explicit Off semantics")
		}
	default:
		return errors.New("Linux journal has an unsupported native mutation")
	}
	return nil
}

func processBelongsToParent(engine ProcessRecord, owner ParentRecord) bool {
	return engine.BootID == owner.BootID && engine.ParentProcessID == owner.ProcessID && engine.ProcProcessID != owner.ProcProcessID &&
		engine.StartTicks >= owner.StartTicks && engine.NetworkNamespace == owner.NetworkNamespace && engine.PIDNamespace == owner.PIDNamespace
}

func CloneState(s JournalState) JournalState {
	if s.Target != nil {
		copy := *s.Target
		s.Target = &copy
	}
	if s.Engine != nil {
		copy := *s.Engine
		s.Engine = &copy
	}
	return s
}
func CloneRecord(r JournalRecord) JournalRecord {
	r.Committed = CloneState(r.Committed)
	if r.Intent != nil {
		copy := *r.Intent
		copy.Candidate = CloneState(copy.Candidate)
		r.Intent = &copy
	}
	return r
}
func sameProtection(a, b JournalState) bool {
	return a.ProfileID == b.ProfileID && a.ProfileRevision == b.ProfileRevision &&
		((a.Target == nil && b.Target == nil) || (a.Target != nil && b.Target != nil && *a.Target == *b.Target))
}
func sameState(a, b JournalState) bool {
	return sameProtection(a, b) && ((a.Engine == nil && b.Engine == nil) || (a.Engine != nil && b.Engine != nil && *a.Engine == *b.Engine))
}
func settledState(a, b JournalState) bool {
	return sameProtection(a, b) && (a.Engine == nil || sameState(a, b))
}

func CanonicalJournalRecord(r JournalRecord) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(r)
	if err != nil || len(body) == 0 || len(body) > JournalRecordLimit {
		return nil, errors.New("Linux journal encoding exceeds its fixed bound")
	}
	return body, nil
}

func ParseJournalRecord(body []byte) (JournalRecord, error) {
	if len(body) == 0 || len(body) > JournalRecordLimit {
		return JournalRecord{}, errors.New("Linux journal input is empty or unbounded")
	}
	var record JournalRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return JournalRecord{}, errors.New("Linux journal input has unsupported fields or types")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return JournalRecord{}, errors.New("Linux journal input has trailing content")
	}
	canonical, err := CanonicalJournalRecord(record)
	if err != nil || !bytes.Equal(canonical, body) {
		return JournalRecord{}, errors.New("Linux journal input is not its exact canonical encoding")
	}
	return record, nil
}

func JournalRecordSHA256(body []byte) (string, error) {
	if _, err := ParseJournalRecord(body); err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// CheckJournalTransition checks durable comparison data, not native authority.
// Its caller must prove the exact native mutation and both process owners.
// Off settlement additionally belongs to the actual saved-profile transaction;
// a successful kernel removal alone does not authorize clearing that intent.
func CheckJournalTransition(previous, next JournalRecord) error {
	if previous.Validate() != nil || next.Validate() != nil || previous.Sequence == math.MaxUint64 || next.Sequence != previous.Sequence+1 ||
		next.JournalID != previous.JournalID || next.Controller != previous.Controller {
		return errors.New("Linux journal transition changed its retained creator or sequence")
	}
	body, err := CanonicalJournalRecord(previous)
	digest, digestErr := JournalRecordSHA256(body)
	if err != nil || digestErr != nil || next.PreviousSHA256 != digest {
		return errors.New("Linux journal transition lost its preceding canonical digest")
	}
	if previous.Phase == "intent" {
		allowed := settledState(next.Committed, previous.Committed) || settledState(next.Committed, previous.Intent.Candidate)
		if next.Phase != "settled" || !allowed {
			return errors.New("Linux journal must settle one exact recorded intent outcome")
		}
		return nil
	}
	if next.Phase == "intent" {
		if !sameState(next.Committed, previous.Committed) {
			return errors.New("Linux intent changed its last independently proved state")
		}
		return nil
	}
	if !settledState(next.Committed, previous.Committed) {
		return errors.New("Linux checkpoint changed protection without its recorded intent")
	}
	return nil
}

type JournalSelection struct {
	Record     JournalRecord
	SHA256     string
	Slot       int
	Incomplete bool
}

// Fixed slots retain the preceding complete generation across a torn write.
// An invalid peer is reported as incomplete, never as native absence or an
// invitation to overwrite either file. Recovery must prove the original owner.
func SelectJournalRecord(journalID string, slots [2][]byte) (JournalSelection, error) {
	if !lowerHex(journalID, 32) {
		return JournalSelection{}, errors.New("Linux journal selection lost its immutable directory identity")
	}
	var records [2]*JournalRecord
	var digests [2]string
	for index, body := range slots {
		if len(body) > JournalRecordLimit {
			return JournalSelection{}, errors.New("Linux journal slot exceeds its fixed bound")
		}
		record, err := ParseJournalRecord(body)
		if err != nil {
			continue
		}
		if record.JournalID != journalID || (record.Sequence-1)%2 != uint64(index) {
			return JournalSelection{}, errors.New("Linux journal slot belongs to another owner or generation")
		}
		records[index] = &record
		digests[index], _ = JournalRecordSHA256(body)
	}
	if records[0] == nil && records[1] == nil {
		return JournalSelection{}, errors.New("Linux journal has no complete recorded state")
	}
	if records[0] == nil || records[1] == nil {
		index := 0
		if records[0] == nil {
			index = 1
		}
		r := *records[index]
		return JournalSelection{CloneRecord(r), digests[index], index, len(slots[1-index]) != 0 || r.Sequence != 1}, nil
	}
	older, newer := 0, 1
	if records[0].Sequence > records[1].Sequence {
		older, newer = 1, 0
	}
	if err := CheckJournalTransition(*records[older], *records[newer]); err != nil {
		return JournalSelection{}, err
	}
	return JournalSelection{CloneRecord(*records[newer]), digests[newer], newer, false}, nil
}
