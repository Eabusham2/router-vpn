package multihoprelay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// An absent seed preserves every older control family. An explicitly supplied
// value must be canonical at every depth, including inside candidate IPC.
type nodeChainFrontSeed string

func (s *nodeChainFrontSeed) UnmarshalJSON(raw []byte) error {
	var value string
	if json.Unmarshal(raw, &value) != nil || !proofID.MatchString(value) {
		return nodeChainCaptureError
	}
	*s = nodeChainFrontSeed(value)
	return nil
}

// NewExternalFinalFrontCredentials fixes each prefix's independent listener
// credentials before construction of the client graph. Only the original
// authenticated lease and its private worker retain the derivation key.
func NewExternalFinalFrontCredentials(q NodeChainRequest, positions int) (NodeChainRequest, error) {
	if q.Schema != 8 {
		return NodeChainRequest{}, nodeChainCaptureError
	}
	return newRegisteredFrontCredentials(q, positions)
}

// NewExtendedPrivateFrontCredentials is restricted to a deep original
// private-final lease with one retained packet entry. It cannot authorize
// an external-final source or change the private proof for the exit.
func NewExtendedPrivateFrontCredentials(q NodeChainRequest, positions int) (NodeChainRequest, error) {
	if q.Schema != 6 || positions <= NodeChainMaximumMembers {
		return NodeChainRequest{}, nodeChainCaptureError
	}
	return newRegisteredFrontCredentials(q, positions)
}

func (q NodeChainRequest) HasRegisteredFronts() bool {
	return q.FrontSeed != "" || q.PrivateFrontSeed != ""
}

func (q NodeChainRequest) registeredBinding() (string, nodeChainFrontSeed) {
	switch {
	case q.Schema == 8 && q.PrivateFrontSeed == "" && q.FrontSeed != "":
		return "public-final", q.FrontSeed
	case q.Schema == 6 && q.FrontSeed == "" && q.PrivateFrontSeed != "":
		return "extended-private-final", q.PrivateFrontSeed
	}
	return "", ""
}

func (q NodeChainRequest) registeredProtocol(purpose string) string {
	family, _ := q.registeredBinding()
	if family == "" {
		return ""
	}
	return family + "-" + purpose + "-v1"
}

func newRegisteredFrontCredentials(q NodeChainRequest, positions int) (NodeChainRequest, error) {
	if len(q.Users) != 0 || q.HasRegisteredFronts() {
		return NodeChainRequest{}, nodeChainCaptureError
	}
	key, err := nodeChainSecret()
	q = q.Clone()
	if q.Schema == 6 {
		q.PrivateFrontSeed = nodeChainFrontSeed(key)
	} else {
		q.FrontSeed = nodeChainFrontSeed(key)
	}
	if err == nil {
		q.Users, err = q.registeredFronts(positions)
	}
	if err != nil || q.validateShape() != nil {
		return NodeChainRequest{}, nodeChainCaptureError
	}
	return q, nil
}

func (q NodeChainRequest) registeredFronts(count int) ([]NodeChainUser, error) {
	family, seed := q.registeredBinding()
	if family == "" || count < 2 || q.Schema == 6 && count <= NodeChainMaximumMembers || !validMemberCount(q.Schema, count) || !proofID.MatchString(string(seed)) ||
		!proofID.MatchString(q.DescriptorSHA256) || !nonce.MatchString(q.SessionID) {
		return nil, nodeChainCaptureError
	}
	key, err := hex.DecodeString(string(seed))
	if err != nil {
		return nil, nodeChainCaptureError
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	// A new acquisition challenge for the same projected native graph retains
	// the front. Its fresh session and epoch are bound by the complete request,
	// worker capture, stop capability and every authenticated receipt.
	context := []byte("routervpn-" + family + "-front-v1\x00" + q.DescriptorSHA256 + "\x00")
	derive := func(role, position byte) string {
		mac.Reset()
		mac.Write(context)
		mac.Write([]byte{role, position})
		return hex.EncodeToString(mac.Sum(nil)[:24])
	}
	users := make([]NodeChainUser, count)
	for i := range users {
		position := i + 1
		users[i] = NodeChainUser{position, derive('u', byte(position)), derive('p', byte(position))}
	}
	return users, nil
}

// Each registered family encodes its own count and seed. The logical request
// retains every credential in order, including in its original digest.
type nodeChainRequestWire struct {
	NodeChainRequest
	PublicFrontCount  *int    `json:"public_front_count,omitempty"`
	PrivateFrontCount *int    `json:"private_front_count,omitempty"`
	StatusNonce       *string `json:"status_nonce,omitempty"`
}

func compactNodeChainRequest(q NodeChainRequest) (nodeChainRequestWire, error) {
	if q.validateShape() != nil {
		return nodeChainRequestWire{}, nodeChainCaptureError
	}
	row := nodeChainRequestWire{NodeChainRequest: q}
	if q.HasRegisteredFronts() {
		count := len(q.Users)
		if q.Schema == 6 {
			row.PrivateFrontCount = &count
		} else {
			row.PublicFrontCount = &count
		}
		row.Users = []NodeChainUser{}
	}
	return row, nil
}

func (row nodeChainRequestWire) restore() (NodeChainRequest, error) {
	q := row.NodeChainRequest
	if row.PublicFrontCount != nil || row.PrivateFrontCount != nil {
		if len(q.Users) != 0 || (row.PublicFrontCount != nil) != (q.FrontSeed != "") ||
			(row.PrivateFrontCount != nil) != (q.PrivateFrontSeed != "") {
			return NodeChainRequest{}, nodeChainCaptureError
		}
		var err error
		count := row.PublicFrontCount
		if count == nil {
			count = row.PrivateFrontCount
		}
		q.Users, err = q.registeredFronts(*count)
		if err != nil {
			return NodeChainRequest{}, err
		}
	} else if q.HasRegisteredFronts() {
		return NodeChainRequest{}, nodeChainCaptureError
	}
	if q.validateShape() != nil {
		return NodeChainRequest{}, nodeChainCaptureError
	}
	return q.Clone(), nil
}

func MarshalNodeChainLeaseRequest(q NodeChainRequest, statusNonce string) ([]byte, error) {
	w, err := compactNodeChainRequest(q)
	if err != nil {
		return nil, err
	}
	if statusNonce != "" {
		if !proofID.MatchString(statusNonce) {
			return nil, nodeChainCaptureError
		}
		w.StatusNonce = &statusNonce
	}
	return boundedNodeChainFrame(w, NodeChainLeaseRequestMaximumBytes)
}

func boundedNodeChainFrame(value any, maximum int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maximum {
		clear(raw)
		return nil, nodeChainCaptureError
	}
	return raw, nil
}

// The grant refers to the independently retained request. The digest commits
// the complete original grant, including both copies of the position table.
type nodeChainPublicGrant struct {
	Protocol          string         `json:"protocol"`
	OwnerID           string         `json:"owner_id"`
	Host              string         `json:"host"`
	Phase             NodeChainPhase `json:"phase"`
	ExpiresAt         time.Time      `json:"expires_at"`
	BootstrapDeadline time.Time      `json:"bootstrap_deadline"`
	LeaseSHA256       string         `json:"lease_sha256"`
}

func (w nodeChainPublicGrant) lease(q NodeChainRequest) NodeChainLease {
	return NodeChainLease{Request: q.Clone(), NodeID: q.EntryNodeID, OwnerID: w.OwnerID, Host: w.Host, Port: q.Port,
		Users: slices.Clone(q.Users), RegistrySHA256: q.DescriptorSHA256, DNSPolicySHA256: q.DNSPolicySHA256,
		Phase: w.Phase, ExpiresAt: w.ExpiresAt, BootstrapDeadline: w.BootstrapDeadline}
}

func MarshalNodeChainLeaseGrant(lease NodeChainLease) ([]byte, error) {
	if !lease.Request.HasRegisteredFronts() {
		return boundedNodeChainFrame(lease, MaxControlResponseBytes)
	}
	if lease.Request.validateShape() != nil {
		return nil, nodeChainCaptureError
	}
	w := nodeChainPublicGrant{Protocol: lease.Request.registeredProtocol("grant"), OwnerID: lease.OwnerID, Host: lease.Host, Phase: lease.Phase, ExpiresAt: lease.ExpiresAt, BootstrapDeadline: lease.BootstrapDeadline}
	var err error
	w.LeaseSHA256, err = nodeChainDigest(w.Protocol, lease)
	if err != nil {
		return nil, err
	}
	restored, err := nodeChainDigest(w.Protocol, w.lease(lease.Request))
	if err != nil || restored != w.LeaseSHA256 {
		return nil, nodeChainCaptureError
	}
	return boundedNodeChainFrame(w, MaxControlResponseBytes)
}

func DecodeNodeChainLeaseGrant(raw []byte, original NodeChainRequest) (NodeChainLease, error) {
	if !original.HasRegisteredFronts() {
		var lease NodeChainLease
		if decodeNodeChainJSON(raw, &lease, MaxControlResponseBytes) != nil || !sameNodeChainRequest(lease.Request, original) {
			return NodeChainLease{}, nodeChainCaptureError
		}
		return lease, nil
	}
	var w nodeChainPublicGrant
	if original.validateShape() != nil || decodeNodeChainJSON(raw, &w, MaxControlResponseBytes) != nil || w.Protocol != original.registeredProtocol("grant") ||
		!proofID.MatchString(w.OwnerID) || !nodeChainPrivateAddress(w.Host) || (w.Phase != NodeChainPending && w.Phase != NodeChainReady) {
		return NodeChainLease{}, nodeChainCaptureError
	}
	lease := w.lease(original)
	actual, err := nodeChainDigest(w.Protocol, lease)
	if err != nil || actual != w.LeaseSHA256 {
		return NodeChainLease{}, nodeChainCaptureError
	}
	return lease, nil
}

// A registered worker capture is restored only against the independently reopened
// private registration. Neither a client nor a staged control file supplies a
// replacement descriptor.
type nodeChainPublicCapture struct {
	Protocol          string               `json:"protocol"`
	Request           nodeChainRequestWire `json:"request"`
	OwnerID           string               `json:"owner_id"`
	Host              string               `json:"host"`
	BootstrapDeadline time.Time            `json:"bootstrap_deadline"`
	CaptureSHA256     string               `json:"capture_sha256"`
}

func MarshalNodeChainWorkerCapture(c NodeChainCapture) ([]byte, error) {
	if !c.Request.HasRegisteredFronts() {
		return boundedNodeChainFrame(c, NodeChainCaptureMaximumBytes)
	}
	digest, err := c.Digest()
	if err != nil {
		return nil, err
	}
	request, err := compactNodeChainRequest(c.Request)
	if err != nil {
		return nil, err
	}
	return boundedNodeChainFrame(nodeChainPublicCapture{c.Request.registeredProtocol("capture"), request, c.OwnerID, c.Host, c.BootstrapDeadline, digest}, NodeChainCaptureMaximumBytes)
}

// NodeChainUsesRegisteredCapture selects the private source reader. Only the
// strict typed decoder and the reopened source can authorize the capture.
func NodeChainUsesRegisteredCapture(raw []byte) bool {
	return NodeChainRegisteredCaptureSchema(raw) != 0
}

func NodeChainRegisteredCaptureSchema(raw []byte) int {
	var kind struct {
		Protocol string `json:"protocol"`
	}
	if len(raw) <= NodeChainCaptureMaximumBytes && json.Unmarshal(raw, &kind) == nil {
		switch kind.Protocol {
		case "public-final-capture-v1":
			return 8
		case "extended-private-final-capture-v1":
			return 6
		}
	}
	return 0
}

func DecodeNodeChainRegisteredCapture(raw []byte, source NodeChainDescriptor) (NodeChainCapture, error) {
	if (source.Schema != 6 && source.Schema != 8) || NodeChainRegisteredCaptureSchema(raw) != source.Schema {
		return NodeChainCapture{}, nodeChainCaptureError
	}
	var w nodeChainPublicCapture
	if decodeNodeChainJSON(raw, &w, NodeChainCaptureMaximumBytes) != nil || w.Request.StatusNonce != nil || w.Protocol != w.Request.NodeChainRequest.registeredProtocol("capture") {
		return NodeChainCapture{}, nodeChainCaptureError
	}
	q, err := w.Request.restore()
	if err != nil {
		return NodeChainCapture{}, err
	}
	c := NodeChainCapture{Schema: 1, Request: q, Source: source.Clone(), RegistrySHA256: q.DescriptorSHA256, OwnerID: w.OwnerID, Peer: q.Peer, Host: w.Host, BootstrapDeadline: w.BootstrapDeadline}
	actual, err := c.Digest()
	if err != nil || actual != w.CaptureSHA256 {
		return NodeChainCapture{}, nodeChainCaptureError
	}
	return c, nil
}
