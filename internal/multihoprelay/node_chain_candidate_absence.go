package multihoprelay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Returned by the installed private source registry only when the ID is
// absent for this entry owner. A stale or mismatched source is a hard failure.
var ErrCandidateNotRegistered = errors.New("paired candidate is not registered on this server")

// Only the manager issues this error, after joining the original native
// operation and freshly checking the same live lease.
type CandidateRegistryAbsence struct{ capture NodeChainCandidateCapture }

func (a *CandidateRegistryAbsence) Error() string { return ErrCandidateNotRegistered.Error() }

type NodeChainCandidateAbsenceReceipt struct {
	Schema      int    `json:"schema"`
	Disposition string `json:"candidate_disposition"`
	Owner       string `json:"operation_owner_id"`
	Capture     string `json:"capture_sha256"`
	Drained     bool   `json:"drained"`
	MAC         string `json:"mac"`
}

// The paired entry API token authenticates the terminal refusal. Its digest
// includes the entire original request, endpoint, lease, trial and worker.
func candidateRegistryMAC(token, digest string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("routervpn-joined-candidate-not-registered-v1\n" + digest))
	return hex.EncodeToString(mac.Sum(nil))
}

func candidateRegistryReceiptMAC(schema int, token, digest string) string {
	if schema == 2 {
		return candidateRegistryMAC(token, digest)
	}
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("routervpn-joined-public-candidate-not-registered-v3\n" + digest))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *CandidateRegistryAbsence) Receipt(q NodeChainCandidateRequest, token string, now time.Time) (NodeChainCandidateAbsenceReceipt, error) {
	var empty NodeChainCandidateAbsenceReceipt
	if a == nil || (q.Schema != 2 && q.Schema != 3) || !sameNodeChainCandidate(q, a.capture.Request) || token == "" || q.DeadlineAt <= now.UnixMilli() {
		return empty, ErrOwnership
	}
	d, err := a.capture.Digest()
	if err != nil {
		return empty, err
	}
	return NodeChainCandidateAbsenceReceipt{q.Schema, "not-registered", a.capture.OperationOwnerID, d, true, candidateRegistryReceiptMAC(q.Schema, token, d)}, nil
}
func (r NodeChainCandidateAbsenceReceipt) Validate(c NodeChainCandidateCapture, token string, now time.Time) error {
	d, err := c.Digest()
	if err != nil || (c.Request.Schema != 2 && c.Request.Schema != 3) || token == "" || r.Schema != c.Request.Schema || r.Disposition != "not-registered" || r.Owner != c.OperationOwnerID || !r.Drained || r.Capture != d || c.Request.DeadlineAt <= now.UnixMilli() || !hmac.Equal([]byte(r.MAC), []byte(candidateRegistryReceiptMAC(r.Schema, token, d))) {
		return ErrOwnership
	}
	return nil
}

// Refusals are exchanged as canonical positive-HTTP responses from the
// originally authenticated agent. The ordinary error/status channel stays fatal.
func DecodeNodeChainCandidateAbsenceReceipt(raw []byte, lease NodeChainCapture, q NodeChainCandidateRequest, token string, now time.Time) error {
	var v NodeChainCandidateAbsenceReceipt
	if q.Position < 1 || q.Position >= len(lease.Source.Members) || decodeNodeChainJSON(raw, &v, NodeChainCandidateResponseMaximumBytes) != nil {
		return ErrOwnership
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return ErrOwnership
	}
	c := NodeChainCandidateCapture{Schema: 1, Lease: lease.Clone(), Request: q.Clone(), Member: lease.Source.Members[q.Position-1], OperationOwnerID: v.Owner}
	return v.Validate(c, token, now)
}
