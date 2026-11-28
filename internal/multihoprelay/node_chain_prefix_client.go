package multihoprelay

import "time"

func RestoreNodeChainPrefixCandidateCapture(lease NodeChainPrefixCapture, q NodeChainPrefixCandidateRequest, owner string) (NodeChainPrefixCandidateCapture, error) {
	if lease.Validate() != nil || q.Validate() != nil || !proofID.MatchString(owner) {
		return NodeChainPrefixCandidateCapture{}, errNodeChainPrefix
	}
	var candidate NodeChainPrefixCandidate
	for _, value := range lease.Source.Candidates {
		if value.ProfileID == q.CandidateID && value.SourceSHA256 == q.CandidateSourceSHA256 {
			candidate = value
			break
		}
	}
	digest, err := q.Digest()
	if err != nil {
		return NodeChainPrefixCandidateCapture{}, err
	}
	capture := NodeChainPrefixCandidateCapture{Schema: 1, Lease: lease.Clone(), Request: q.Clone(), OwnerID: owner, RequestSHA256: digest, Candidate: candidate, Deadline: time.UnixMilli(q.ExpiresAt).UTC()}
	return capture, capture.Validate()
}
func DecodeNodeChainPrefixStopAcknowledgement(raw []byte, q NodeChainPrefixRequest) error {
	var value struct {
		Schema        int    `json:"schema"`
		Purpose       string `json:"purpose"`
		SessionID     string `json:"session_id"`
		RequestSHA256 string `json:"request_sha256"`
		Stopped       bool   `json:"stopped"`
	}
	digest, err := q.Digest()
	if err != nil || decodeNodeChainPrefixJSON(raw, &value, 4096) != nil || value.Schema != 1 || value.Purpose != NodeChainPrefixPurpose || value.SessionID != q.SessionID || value.RequestSHA256 != digest || !value.Stopped {
		return errNodeChainPrefix
	}
	return nil
}
func DecodeNodeChainPrefixCandidateStopAcknowledgement(raw []byte, q NodeChainPrefixCandidateRequest) error {
	var value struct {
		Schema        int    `json:"schema"`
		Purpose       string `json:"purpose"`
		OperationID   string `json:"operation_id"`
		RequestSHA256 string `json:"request_sha256"`
		Stopped       bool   `json:"stopped"`
	}
	digest, err := q.Digest()
	if err != nil || decodeNodeChainPrefixJSON(raw, &value, 4096) != nil || value.Schema != 1 || value.Purpose != NodeChainPrefixPurpose || value.OperationID != q.OperationID || value.RequestSHA256 != digest || !value.Stopped {
		return errNodeChainPrefix
	}
	return nil
}
