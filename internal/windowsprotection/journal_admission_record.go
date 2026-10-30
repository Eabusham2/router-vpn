package windowsprotection

import (
	"bytes"
	"errors"
	"math"
)

const (
	JournalAdmissionSchema      = 1
	JournalAdmissionRequestKind = "routervpn-wfp-admission-request-v1"
	JournalAdmissionReplyKind   = "routervpn-wfp-admission-reply-v1"
	JournalAdmissionWireLimit   = 2048
)

// JournalAdmissionRequest compares one prepared child with its exact flushed
// successor intent. The native channel must independently prove the retained
// peer and committed BFE candidate; this record cannot establish either fact.
// Nonce validation checks only spelling, not freshness or randomness.
type JournalAdmissionRequest struct {
	Schema       int    `json:"schema"`
	Kind         string `json:"kind"`
	IntentSHA256 string `json:"intent_sha256"`
	Nonce        string `json:"nonce"`
}

// JournalAdmissionReply binds the complete request to the exact settled-active
// checkpoint. An authenticated parent may send it only after that checkpoint
// is durably stored. Its digest is comparison data, not permission to start.
type JournalAdmissionReply struct {
	Schema        int    `json:"schema"`
	Kind          string `json:"kind"`
	RequestSHA256 string `json:"request_sha256"`
	SettledSHA256 string `json:"settled_sha256"`
	Sequence      uint64 `json:"sequence"`
}

func journalAdmissionIntentRaw(intent JournalRecord) ([]byte, error) {
	if intent.Validate() != nil || intent.Phase != "intent" || intent.Intent == nil ||
		intent.Intent.Action != "successor" || intent.Intent.Candidate.Target == nil || intent.Intent.Candidate.Engine == nil ||
		intent.Sequence == math.MaxUint64 {
		return nil, errors.New("Windows admission requires a bounded successor intent with its live retained engine")
	}
	if err := requireJournalProfileBindings(intent); err != nil {
		return nil, err
	}
	return CanonicalJournalRecord(intent)
}

func (request JournalAdmissionRequest) Validate(intent JournalRecord) error {
	intentRaw, err := journalAdmissionIntentRaw(intent)
	if err != nil {
		return err
	}
	if request.Schema != JournalAdmissionSchema || request.Kind != JournalAdmissionRequestKind ||
		request.IntentSHA256 != journalCommitDigest(intentRaw) || !lowerHex(request.Nonce, 64) {
		return errors.New("Windows admission request changed its complete successor intent or challenge")
	}
	return nil
}

func (reply JournalAdmissionReply) Validate(intent JournalRecord, request JournalAdmissionRequest) error {
	if reply.Schema != JournalAdmissionSchema || reply.Kind != JournalAdmissionReplyKind {
		return errors.New("Windows admission reply has another protocol identity")
	}
	requestRaw, err := CanonicalJournalAdmissionRequest(request, intent)
	if err != nil {
		return err
	}
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		return err
	}
	settledRaw, err := CanonicalJournalRecord(settled)
	if err != nil {
		return err
	}
	if reply.RequestSHA256 != journalCommitDigest(requestRaw) || reply.SettledSHA256 != journalCommitDigest(settledRaw) || reply.Sequence != settled.Sequence {
		return errors.New("Windows admission reply changed its exact request or active checkpoint")
	}
	return nil
}

// DeriveJournalAdmissionSettlement selects only the successor candidate and
// keeps its live engine identity. It does not prove BFE commit, join an engine,
// write the journal or acknowledge durable storage. A later independently
// checked retirement is required before that engine identity can be cleared.
func DeriveJournalAdmissionSettlement(intent JournalRecord) (JournalRecord, error) {
	intentRaw, err := journalAdmissionIntentRaw(intent)
	if err != nil {
		return JournalRecord{}, err
	}
	next := cloneJournalRecord(intent)
	next.Sequence++
	next.PreviousSHA256 = journalCommitDigest(intentRaw)
	next.Phase = "settled"
	next.Committed = next.Intent.Candidate
	next.Intent = nil
	if err := CheckJournalTransition(intent, next); err != nil {
		return JournalRecord{}, err
	}
	if _, err := CanonicalJournalRecord(next); err != nil {
		return JournalRecord{}, err
	}
	return next, nil
}

func NewJournalAdmissionReply(intent JournalRecord, request JournalAdmissionRequest) (JournalAdmissionReply, error) {
	requestRaw, err := CanonicalJournalAdmissionRequest(request, intent)
	if err != nil {
		return JournalAdmissionReply{}, err
	}
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		return JournalAdmissionReply{}, err
	}
	settledRaw, err := CanonicalJournalRecord(settled)
	if err != nil {
		return JournalAdmissionReply{}, err
	}
	return JournalAdmissionReply{Schema: JournalAdmissionSchema, Kind: JournalAdmissionReplyKind,
		RequestSHA256: journalCommitDigest(requestRaw), SettledSHA256: journalCommitDigest(settledRaw), Sequence: settled.Sequence}, nil
}

func CanonicalJournalAdmissionRequest(request JournalAdmissionRequest, intent JournalRecord) ([]byte, error) {
	if err := request.Validate(intent); err != nil {
		return nil, err
	}
	return canonicalJournalCommit(request, JournalAdmissionWireLimit)
}

func ParseJournalAdmissionRequest(raw []byte, intent JournalRecord) (JournalAdmissionRequest, error) {
	var request JournalAdmissionRequest
	if err := parseJournalCommit(raw, &request, JournalAdmissionWireLimit); err != nil {
		return JournalAdmissionRequest{}, err
	}
	canonical, err := CanonicalJournalAdmissionRequest(request, intent)
	if err != nil || !bytes.Equal(raw, canonical) {
		return JournalAdmissionRequest{}, errors.New("Windows admission request is not its exact canonical encoding")
	}
	return request, nil
}

func JournalAdmissionRequestSHA256(raw []byte, intent JournalRecord) (string, error) {
	if _, err := ParseJournalAdmissionRequest(raw, intent); err != nil {
		return "", err
	}
	return journalCommitDigest(raw), nil
}

func CanonicalJournalAdmissionReply(reply JournalAdmissionReply, intent JournalRecord, request JournalAdmissionRequest) ([]byte, error) {
	if err := reply.Validate(intent, request); err != nil {
		return nil, err
	}
	return canonicalJournalCommit(reply, JournalAdmissionWireLimit)
}

func ParseJournalAdmissionReply(raw []byte, intent JournalRecord, request JournalAdmissionRequest) (JournalAdmissionReply, error) {
	var reply JournalAdmissionReply
	if err := parseJournalCommit(raw, &reply, JournalAdmissionWireLimit); err != nil {
		return JournalAdmissionReply{}, err
	}
	canonical, err := CanonicalJournalAdmissionReply(reply, intent, request)
	if err != nil || !bytes.Equal(raw, canonical) {
		return JournalAdmissionReply{}, errors.New("Windows admission reply is not its exact canonical encoding")
	}
	return reply, nil
}

func JournalAdmissionReplySHA256(raw []byte, intent JournalRecord, request JournalAdmissionRequest) (string, error) {
	if _, err := ParseJournalAdmissionReply(raw, intent, request); err != nil {
		return "", err
	}
	return journalCommitDigest(raw), nil
}
