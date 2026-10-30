package windowsprotection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"

	"router-vpn/internal/mobiletor"
)

const (
	JournalCommitSchema       = 1
	JournalCommitCaptureKind  = "routervpn-wfp-commit-capture-v1"
	JournalCommitRequestKind  = "routervpn-wfp-commit-request-v1"
	JournalCommitReplyKind    = "routervpn-wfp-commit-reply-v1"
	JournalCommitCaptureLimit = 32768
	JournalCommitWireLimit    = 2048
)

// JournalCommitCapture is private comparison data captured before creating a
// successor. Its head must have no unresolved intent or unjoined engine. The
// native store and authenticated process channel independently establish who
// owns this head; a file, digest or parsed record cannot establish authority.
type JournalCommitCapture struct {
	Schema          int                                       `json:"schema"`
	Kind            string                                    `json:"kind"`
	Head            JournalRecord                             `json:"head"`
	ProfileID       string                                    `json:"profile_id"`
	ProfileRevision string                                    `json:"profile_revision"`
	Transfer        mobiletor.DesktopProtectionTransferRecord `json:"transfer"`
}

// JournalCommitRequest binds the native candidate to one complete capture.
// Nonce is a caller-generated challenge; parsing its spelling proves neither
// randomness nor freshness. The real retained child and private pipe supply
// those ownership boundaries before the parent may persist an intent.
type JournalCommitRequest struct {
	Schema        int                                      `json:"schema"`
	Kind          string                                   `json:"kind"`
	CaptureSHA256 string                                   `json:"capture_sha256"`
	Nonce         string                                   `json:"nonce"`
	Candidate     mobiletor.DesktopWindowsProtectionTarget `json:"candidate"`
}

// JournalCommitReply compares the exact request with the complete derived
// intent. It contains no permissive accepted flag or native mutation right.
// Only the authenticated parent may send it after the actual store flush.
type JournalCommitReply struct {
	Schema        int    `json:"schema"`
	Kind          string `json:"kind"`
	RequestSHA256 string `json:"request_sha256"`
	IntentSHA256  string `json:"intent_sha256"`
	Sequence      uint64 `json:"sequence"`
}

func journalCommitSameTarget(a, b *mobiletor.DesktopWindowsProtectionTarget) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (capture JournalCommitCapture) Validate() error {
	if capture.Schema != JournalCommitSchema || capture.Kind != JournalCommitCaptureKind ||
		capture.Head.Validate() != nil || capture.Head.Phase != "settled" || capture.Head.Committed.Engine != nil ||
		capture.Head.Sequence == math.MaxUint64 || !journalProfileID(capture.ProfileID) ||
		!lowerHex(capture.ProfileRevision, 64) || capture.Transfer.Validate() != nil {
		return errors.New("Windows commit capture lost its settled head or requested profile")
	}
	if !journalCommitSameTarget(capture.Head.Committed.Target, capture.Transfer.Predecessor) {
		return errors.New("Windows commit capture changed its exact retained predecessor")
	}
	return nil
}

func (request JournalCommitRequest) Validate(capture JournalCommitCapture) error {
	canonical, err := CanonicalJournalCommitCapture(capture)
	if err != nil {
		return err
	}
	if request.Schema != JournalCommitSchema || request.Kind != JournalCommitRequestKind ||
		request.CaptureSHA256 != journalCommitDigest(canonical) || !lowerHex(request.Nonce, 64) ||
		request.Candidate.Validate() != nil {
		return errors.New("Windows commit request lost its complete captured launch")
	}
	if request.Candidate.Capture.SessionID != capture.Transfer.SessionID ||
		request.Candidate.Capture.SourceSHA256 != capture.Transfer.SourceSHA256 || request.Candidate.Policy != capture.Transfer.Policy {
		return errors.New("Windows commit request substituted its native candidate")
	}
	return nil
}

func (reply JournalCommitReply) Validate(capture JournalCommitCapture, request JournalCommitRequest, actualEngine Controller) error {
	if reply.Schema != JournalCommitSchema || reply.Kind != JournalCommitReplyKind {
		return errors.New("Windows commit reply has another protocol identity")
	}
	intent, err := DeriveJournalCommitIntent(capture, request, actualEngine)
	if err != nil {
		return err
	}
	requestRaw, err := CanonicalJournalCommitRequest(request, capture)
	if err != nil {
		return err
	}
	intentRaw, err := CanonicalJournalRecord(intent)
	if err != nil {
		return err
	}
	if reply.RequestSHA256 != journalCommitDigest(requestRaw) || reply.IntentSHA256 != journalCommitDigest(intentRaw) || reply.Sequence != intent.Sequence {
		return errors.New("Windows commit reply changed its exact request or durable intent")
	}
	return nil
}

// DeriveJournalCommitIntent preserves the exact old head/controller and binds
// the successor to the independently captured native child identity. It does
// not open that process, read BFE, write the journal or acknowledge a flush.
func DeriveJournalCommitIntent(capture JournalCommitCapture, request JournalCommitRequest, actualEngine Controller) (JournalRecord, error) {
	if err := request.Validate(capture); err != nil {
		return JournalRecord{}, err
	}
	if err := actualEngine.Validate(); err != nil {
		return JournalRecord{}, err
	}
	previousRaw, err := CanonicalJournalRecord(capture.Head)
	if err != nil {
		return JournalRecord{}, err
	}
	next := cloneJournalRecord(capture.Head)
	next.Sequence++
	next.PreviousSHA256 = journalCommitDigest(previousRaw)
	next.Phase = "intent"
	candidate := request.Candidate
	next.Intent = &JournalIntent{Action: "successor", RequestID: capture.Transfer.SessionID,
		ProfileID: capture.ProfileID, ProfileRevision: capture.ProfileRevision, ResultProfileRevision: capture.ProfileRevision,
		Candidate: JournalState{Target: &candidate, ProfileID: capture.ProfileID, Engine: &actualEngine}}
	if err := CheckJournalTransition(capture.Head, next); err != nil {
		return JournalRecord{}, err
	}
	if _, err := CanonicalJournalRecord(next); err != nil {
		return JournalRecord{}, err
	}
	return next, nil
}

func NewJournalCommitReply(capture JournalCommitCapture, request JournalCommitRequest, actualEngine Controller) (JournalCommitReply, error) {
	intent, err := DeriveJournalCommitIntent(capture, request, actualEngine)
	if err != nil {
		return JournalCommitReply{}, err
	}
	requestRaw, err := CanonicalJournalCommitRequest(request, capture)
	if err != nil {
		return JournalCommitReply{}, err
	}
	intentRaw, err := CanonicalJournalRecord(intent)
	if err != nil {
		return JournalCommitReply{}, err
	}
	return JournalCommitReply{Schema: JournalCommitSchema, Kind: JournalCommitReplyKind,
		RequestSHA256: journalCommitDigest(requestRaw), IntentSHA256: journalCommitDigest(intentRaw), Sequence: intent.Sequence}, nil
}

func canonicalJournalCommit(value any, limit int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("Windows commit record encoding exceeds its fixed bound")
	}
	return raw, nil
}

func parseJournalCommit(raw []byte, value any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("Windows commit record input is empty or exceeds its fixed bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("Windows commit record has unsupported fields or types")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("Windows commit record has trailing content")
	}
	return nil
}

func journalCommitDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func CanonicalJournalCommitCapture(capture JournalCommitCapture) ([]byte, error) {
	if err := capture.Validate(); err != nil {
		return nil, err
	}
	return canonicalJournalCommit(capture, JournalCommitCaptureLimit)
}

func ParseJournalCommitCapture(raw []byte) (JournalCommitCapture, error) {
	var capture JournalCommitCapture
	if err := parseJournalCommit(raw, &capture, JournalCommitCaptureLimit); err != nil {
		return JournalCommitCapture{}, err
	}
	canonical, err := CanonicalJournalCommitCapture(capture)
	if err != nil || !bytes.Equal(raw, canonical) {
		return JournalCommitCapture{}, errors.New("Windows commit capture is not its exact canonical encoding")
	}
	return capture, nil
}

func JournalCommitCaptureSHA256(raw []byte) (string, error) {
	if _, err := ParseJournalCommitCapture(raw); err != nil {
		return "", err
	}
	return journalCommitDigest(raw), nil
}

func CanonicalJournalCommitRequest(request JournalCommitRequest, capture JournalCommitCapture) ([]byte, error) {
	if err := request.Validate(capture); err != nil {
		return nil, err
	}
	return canonicalJournalCommit(request, JournalCommitWireLimit)
}

func ParseJournalCommitRequest(raw []byte, capture JournalCommitCapture) (JournalCommitRequest, error) {
	var request JournalCommitRequest
	if err := parseJournalCommit(raw, &request, JournalCommitWireLimit); err != nil {
		return JournalCommitRequest{}, err
	}
	canonical, err := CanonicalJournalCommitRequest(request, capture)
	if err != nil || !bytes.Equal(raw, canonical) {
		return JournalCommitRequest{}, errors.New("Windows commit request is not its exact canonical encoding")
	}
	return request, nil
}

func JournalCommitRequestSHA256(raw []byte, capture JournalCommitCapture) (string, error) {
	if _, err := ParseJournalCommitRequest(raw, capture); err != nil {
		return "", err
	}
	return journalCommitDigest(raw), nil
}

func CanonicalJournalCommitReply(reply JournalCommitReply, capture JournalCommitCapture, request JournalCommitRequest, actualEngine Controller) ([]byte, error) {
	if err := reply.Validate(capture, request, actualEngine); err != nil {
		return nil, err
	}
	return canonicalJournalCommit(reply, JournalCommitWireLimit)
}

func ParseJournalCommitReply(raw []byte, capture JournalCommitCapture, request JournalCommitRequest, actualEngine Controller) (JournalCommitReply, error) {
	var reply JournalCommitReply
	if err := parseJournalCommit(raw, &reply, JournalCommitWireLimit); err != nil {
		return JournalCommitReply{}, err
	}
	canonical, err := CanonicalJournalCommitReply(reply, capture, request, actualEngine)
	if err != nil || !bytes.Equal(raw, canonical) {
		return JournalCommitReply{}, errors.New("Windows commit reply is not its exact canonical encoding")
	}
	return reply, nil
}

func JournalCommitReplySHA256(raw []byte, capture JournalCommitCapture, request JournalCommitRequest, actualEngine Controller) (string, error) {
	if _, err := ParseJournalCommitReply(raw, capture, request, actualEngine); err != nil {
		return "", err
	}
	return journalCommitDigest(raw), nil
}
