package multihoprelay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const NodeChainPrefixPrivateResponse = "private-agent-response"
const NodeChainPrefixComparePair = "compare-pair"

type NodeChainPrefixCandidateRequest struct {
	Schema                   int                    `json:"schema"`
	Purpose                  string                 `json:"purpose"`
	Lease                    NodeChainPrefixRequest `json:"lease"`
	LeaseOwnerID             string                 `json:"lease_owner_id"`
	TrialID                  string                 `json:"trial_id"`
	OperationID              string                 `json:"operation_id"`
	CandidateID              string                 `json:"candidate_id"`
	CandidateSourceSHA256    string                 `json:"candidate_source_sha256"`
	AppendPosition           int                    `json:"append_position"`
	InventorySHA256          string                 `json:"inventory_sha256"`
	ChildPurpose             string                 `json:"child_purpose"`
	ExternalTarget           string                 `json:"external_target"`
	ExpiresAt                int64                  `json:"expires_at"`
	CandidateMode            string                 `json:"candidate_mode,omitempty"`
	CandidateClientPublicKey string                 `json:"candidate_client_public_key,omitempty"`
	CandidateHysteriaSHA256  string                 `json:"candidate_hysteria_sha256,omitempty"`
}

func prefixCompareTarget(target string) bool {
	return target == "https://1.1.1.1/cdn-cgi/trace" || target == "https://1.0.0.1/cdn-cgi/trace"
}
func (q NodeChainPrefixCandidateRequest) Validate() error {
	if q.Schema != 1 && q.Schema != 2 && q.Schema != 3 || q.Purpose != NodeChainPrefixPurpose || q.Lease.validateShape() != nil || !proofID.MatchString(q.LeaseOwnerID) ||
		!nonce.MatchString(q.TrialID) || !nonce.MatchString(q.OperationID) || q.TrialID == q.OperationID || !prefixProfileID(q.CandidateID) ||
		!proofID.MatchString(q.CandidateSourceSHA256) || q.AppendPosition != q.Lease.ActualPrefixCount() ||
		q.InventorySHA256 != q.Lease.InventorySHA256 || q.ExpiresAt <= 0 {
		return errNodeChainPrefix
	}
	if q.Schema == 3 {
		if !q.IsHysteria() || q.Lease.Schema != 5 && q.Lease.Schema != 6 || q.CandidateClientPublicKey != "" || !proofID.MatchString(q.CandidateHysteriaSHA256) {
			return errNodeChainPrefix
		}
	} else if q.CandidateHysteriaSHA256 != "" {
		return errNodeChainPrefix
	} else if q.IsPacket() {
		if q.Lease.Schema != 3 && q.Lease.Schema != 4 && q.Lease.Schema != 6 || !nodeChainPacketMode(q.CandidateMode) || !nodeChainPacketPublic(q.CandidateClientPublicKey) {
			return errNodeChainPrefix
		}
		for _, key := range q.Lease.LocalPacketPublicKeys {
			if key == q.CandidateClientPublicKey {
				return errNodeChainPrefix
			}
		}
	} else if q.Lease.Schema == 3 || q.CandidateMode != "" || q.CandidateClientPublicKey != "" {
		return errNodeChainPrefix
	}
	if q.ChildPurpose == NodeChainPrefixPrivateResponse {
		if q.ExternalTarget != "" {
			return errNodeChainPrefix
		}
	} else if q.ChildPurpose != NodeChainPrefixComparePair || !prefixCompareTarget(q.ExternalTarget) {
		return errNodeChainPrefix
	}
	return nil
}
func (q NodeChainPrefixCandidateRequest) Clone() NodeChainPrefixCandidateRequest {
	q.Lease = q.Lease.Clone()
	return q
}
func (q NodeChainPrefixCandidateRequest) Digest() (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	if q.IsHysteria() {
		return nodeChainDigest("routervpn-node-chain-prefix-candidate-request-v3", q)
	}
	if q.IsPacket() {
		return nodeChainDigest("routervpn-node-chain-prefix-candidate-request-v2", q)
	}
	return nodeChainDigest("routervpn-node-chain-prefix-candidate-request-v1", q)
}
func samePrefixCandidateRequest(a, b NodeChainPrefixCandidateRequest) bool {
	x, e := a.Digest()
	y, f := b.Digest()
	return e == nil && f == nil && x == y
}

type NodeChainPrefixCandidateCapture struct {
	Schema        int                             `json:"schema"`
	Lease         NodeChainPrefixCapture          `json:"lease"`
	Request       NodeChainPrefixCandidateRequest `json:"request"`
	OwnerID       string                          `json:"owner_id"`
	RequestSHA256 string                          `json:"request_sha256"`
	Candidate     NodeChainPrefixCandidate        `json:"candidate"`
	Deadline      time.Time                       `json:"deadline"`
}

func (c NodeChainPrefixCandidateCapture) Validate() error {
	digest, err := c.Request.Digest()
	_, offset := c.Deadline.Zone()
	if err != nil || c.Schema != 1 || c.Lease.Validate() != nil || !sameNodeChainPrefixRequest(c.Request.Lease, c.Lease.Request) ||
		c.Request.LeaseOwnerID != c.Lease.OwnerID || !proofID.MatchString(c.OwnerID) || c.OwnerID == c.Lease.OwnerID || c.RequestSHA256 != digest ||
		!c.validCandidate() || c.Candidate.ProfileID != c.Request.CandidateID || c.Candidate.SourceSHA256 != c.Request.CandidateSourceSHA256 ||
		c.Request.AppendPosition != len(c.Lease.Source.LocalPrefix) || c.Deadline.IsZero() || offset != 0 || c.Deadline.UnixMilli() != c.Request.ExpiresAt {
		return errNodeChainPrefix
	}
	matches := 0
	for _, candidate := range c.Lease.Source.Candidates {
		if candidate == c.Candidate {
			matches++
		}
	}
	if matches != 1 {
		return errNodeChainPrefix
	}
	return nil
}
func (c NodeChainPrefixCandidateCapture) Clone() NodeChainPrefixCandidateCapture {
	c.Lease = c.Lease.Clone()
	c.Request = c.Request.Clone()
	return c
}
func (c NodeChainPrefixCandidateCapture) Digest() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return nodeChainDigest("routervpn-node-chain-prefix-candidate-capture-v1", c)
}
func NewNodeChainPrefixCandidateCapture(lease NodeChainPrefixCapture, q NodeChainPrefixCandidateRequest, leaseExpiry, now time.Time) (NodeChainPrefixCandidateCapture, error) {
	if lease.Validate() != nil || q.Validate() != nil || !sameNodeChainPrefixRequest(q.Lease, lease.Request) || q.LeaseOwnerID != lease.OwnerID ||
		q.ExpiresAt <= now.UnixMilli() || time.UnixMilli(q.ExpiresAt).After(leaseExpiry) || time.UnixMilli(q.ExpiresAt).After(now.Add(NodeChainCandidateLifetime)) {
		return NodeChainPrefixCandidateCapture{}, errNodeChainPrefix
	}
	var candidate NodeChainPrefixCandidate
	for _, v := range lease.Source.Candidates {
		if v.ProfileID == q.CandidateID && v.SourceSHA256 == q.CandidateSourceSHA256 {
			candidate = v
			break
		}
	}
	owner, err := nodeChainSecret()
	if err != nil {
		return NodeChainPrefixCandidateCapture{}, err
	}
	digest, _ := q.Digest()
	c := NodeChainPrefixCandidateCapture{Schema: 1, Lease: lease.Clone(), Request: q.Clone(), OwnerID: owner, RequestSHA256: digest, Candidate: candidate, Deadline: time.UnixMilli(q.ExpiresAt).UTC()}
	if c.Validate() != nil {
		return NodeChainPrefixCandidateCapture{}, errNodeChainPrefix
	}
	return c, nil
}

type NodeChainPrefixCandidateReceipt struct {
	Schema                int       `json:"schema"`
	Purpose               string    `json:"purpose"`
	CaptureSHA256         string    `json:"capture_sha256"`
	OwnerID               string    `json:"owner_id"`
	LeaseOwnerID          string    `json:"lease_owner_id"`
	TrialID               string    `json:"trial_id"`
	OperationID           string    `json:"operation_id"`
	CandidateID           string    `json:"candidate_id"`
	CandidateSourceSHA256 string    `json:"candidate_source_sha256"`
	AppendPosition        int       `json:"append_position"`
	ChildPurpose          string    `json:"child_purpose"`
	ExternalTarget        string    `json:"external_target"`
	Prepared              bool      `json:"prepared"`
	Drained               bool      `json:"drained"`
	Connections           int       `json:"connections"`
	Nonce                 string    `json:"nonce"`
	ObservedAt            time.Time `json:"observed_at"`
	PairingSHA256         string    `json:"pairing_sha256,omitempty"`
	HysteriaSHA256        string    `json:"hysteria_sha256,omitempty"`
}

func (r NodeChainPrefixCandidateReceipt) Validate(c NodeChainPrefixCandidateCapture, challenge string, started, now time.Time) error {
	digest, err := c.Digest()
	q := c.Request
	pairing := ""
	if q.IsPacket() {
		pair, pairErr := c.packetPair()
		if pairErr != nil {
			return errNodeChainPrefix
		}
		pairing, pairErr = pair.Digest()
		if pairErr != nil {
			return errNodeChainPrefix
		}
	}
	hysteria := ""
	if q.IsHysteria() {
		pair, pairErr := c.hysteriaPair()
		if pairErr != nil {
			return errNodeChainPrefix
		}
		hysteria, pairErr = pair.Digest()
		if pairErr != nil {
			return errNodeChainPrefix
		}
	}
	limit := NodeChainCandidateMaximumConnects
	if q.ChildPurpose == NodeChainPrefixComparePair {
		limit = 2
	}
	_, offset := r.ObservedAt.Zone()
	if err != nil || r.PairingSHA256 != pairing || r.HysteriaSHA256 != hysteria || r.Schema != 1 || r.Purpose != NodeChainPrefixPurpose || r.CaptureSHA256 != digest || r.OwnerID != c.OwnerID || r.LeaseOwnerID != c.Lease.OwnerID ||
		r.TrialID != q.TrialID || r.OperationID != q.OperationID || r.CandidateID != q.CandidateID || r.CandidateSourceSHA256 != q.CandidateSourceSHA256 ||
		r.AppendPosition != q.AppendPosition || r.ChildPurpose != q.ChildPurpose || r.ExternalTarget != q.ExternalTarget || r.Connections < 0 || r.Connections > limit ||
		challenge != "" && !proofID.MatchString(challenge) || r.Nonce != challenge || offset != 0 || r.ObservedAt.Before(started) || r.ObservedAt.After(now) || r.Drained && r.Prepared {
		return errNodeChainPrefix
	}
	return nil
}

// A front grant is consumed once. Public Compare targets and private challenge
// slots are separate purposes and cannot spend each other's connection quota.
type NodeChainPrefixFrontGrant struct {
	CaptureSHA256 string `json:"capture_sha256"`
	ChildPurpose  string `json:"child_purpose"`
	Ordinal       int    `json:"ordinal"`
	Network       string `json:"network"`
	Address       string `json:"address"`
}

func prefixPrivateAPIAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip, e := netip.ParseAddr(host)
	number, f := strconv.Atoi(port)
	return err == nil && e == nil && f == nil && nodeChainPrivateAddress(ip.String()) && number > 0 && number <= 65535 && net.JoinHostPort(ip.String(), strconv.Itoa(number)) == address
}
func (c NodeChainPrefixCandidateCapture) FrontGrant(privateAddress string, ordinal int) (NodeChainPrefixFrontGrant, error) {
	digest, err := c.Digest()
	if err != nil || !prefixPrivateAPIAddress(privateAddress) {
		return NodeChainPrefixFrontGrant{}, errNodeChainPrefix
	}
	q := c.Request
	limit := NodeChainCandidateMaximumConnects
	address := privateAddress
	if q.ChildPurpose == NodeChainPrefixComparePair {
		limit = 2
		if ordinal == 1 {
			u, e := url.Parse(q.ExternalTarget)
			if e != nil {
				return NodeChainPrefixFrontGrant{}, errNodeChainPrefix
			}
			address = net.JoinHostPort(u.Hostname(), "443")
		}
	}
	if ordinal < 0 || ordinal >= limit {
		return NodeChainPrefixFrontGrant{}, errNodeChainPrefix
	}
	return NodeChainPrefixFrontGrant{digest, q.ChildPurpose, ordinal, "tcp", address}, nil
}
func (c NodeChainPrefixCandidateCapture) FrontCredentials(grant NodeChainPrefixFrontGrant, privateAddress string) (string, string, error) {
	original, err := c.FrontGrant(privateAddress, grant.Ordinal)
	if err != nil || original != grant {
		return "", "", errNodeChainPrefix
	}
	key, err := hex.DecodeString(c.Lease.Request.FrontSeed)
	if err != nil || len(key) != 32 {
		return "", "", errNodeChainPrefix
	}
	defer clear(key)
	raw, err := json.Marshal(grant)
	if err != nil {
		return "", "", errNodeChainPrefix
	}
	defer clear(raw)
	digest := func(domain string) string {
		m := hmac.New(sha256.New, key)
		_, _ = m.Write([]byte(domain + "\x00"))
		_, _ = m.Write(raw)
		return hex.EncodeToString(m.Sum(nil)[:24])
	}
	return digest("routervpn-node-chain-prefix-front-username-v1"), digest("routervpn-node-chain-prefix-front-password-v1"), nil
}

type NodeChainPrefixCandidateOperation interface {
	Prepare(context.Context) (NodeChainPrefixCandidateReceipt, error)
	Snapshot(context.Context, string) (NodeChainPrefixCandidateReceipt, error)
	Close(context.Context) error
}
type NodeChainPrefixCandidateProcess interface {
	NewPrefixCandidateOperation(context.Context, NodeChainPrefixCandidateCapture) (NodeChainPrefixCandidateOperation, error)
}

// Only the original private source owner may supply privateAddress. This gate
// does not construct a transport or certify Prepared; the native owner must
// additionally prove its exact registered candidate source and original reader.
type NodeChainPrefixCandidateAdmission struct {
	self           *NodeChainPrefixCandidateAdmission
	capture        NodeChainPrefixCandidateCapture
	privateAddress string
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	retired        bool
	accepted       int
	used           [NodeChainCandidateMaximumConnects]bool
	active         chan struct{}
}

func NewNodeChainPrefixCandidateAdmission(parent context.Context, c NodeChainPrefixCandidateCapture, privateAddress string) (*NodeChainPrefixCandidateAdmission, error) {
	if parent == nil || parent.Err() != nil || c.Validate() != nil || !prefixPrivateAPIAddress(privateAddress) || !time.Now().Before(c.Deadline) || c.Deadline.After(time.Now().Add(NodeChainCandidateLifetime)) {
		return nil, errNodeChainPrefix
	}
	ctx, cancel := context.WithDeadline(parent, c.Deadline)
	a := &NodeChainPrefixCandidateAdmission{capture: c.Clone(), privateAddress: privateAddress, ctx: ctx, cancel: cancel}
	a.self = a
	return a, nil
}
func (a *NodeChainPrefixCandidateAdmission) Begin(ctx context.Context, username, password, network, address string) (func(), error) {
	if a == nil || a.self != a || ctx == nil || ctx.Err() != nil || a.capture.Validate() != nil || network != "tcp" {
		return nil, errNodeChainPrefix
	}
	selected := -1
	limit := NodeChainCandidateMaximumConnects
	if a.capture.Request.ChildPurpose == NodeChainPrefixComparePair {
		limit = 2
	}
	for i := 0; i < limit; i++ {
		grant, e := a.capture.FrontGrant(a.privateAddress, i)
		if e != nil {
			return nil, e
		}
		u, p, e := a.capture.FrontCredentials(grant, a.privateAddress)
		if e == nil && subtle.ConstantTimeCompare([]byte(username), []byte(u)) == 1 && subtle.ConstantTimeCompare([]byte(password), []byte(p)) == 1 && address == grant.Address {
			selected = i
		}
	}
	if selected < 0 {
		return nil, errNodeChainPrefix
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.retired || a.ctx.Err() != nil || !time.Now().Before(a.capture.Deadline) || a.active != nil || a.used[selected] {
		return nil, errNodeChainPrefix
	}
	joined := make(chan struct{})
	a.active = joined
	a.used[selected] = true
	a.accepted++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			if a.active == joined {
				a.active = nil
			}
			close(joined)
			a.mu.Unlock()
		})
	}, nil
}
func (a *NodeChainPrefixCandidateAdmission) CloseContext(ctx context.Context) error {
	if a == nil || a.self != a || ctx == nil {
		return errNodeChainPrefix
	}
	a.mu.Lock()
	a.retired = true
	a.cancel()
	active := a.active
	a.mu.Unlock()
	if active != nil {
		select {
		case <-active:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}
func (a *NodeChainPrefixCandidateAdmission) Snapshot() NodeChainCandidateUsage {
	if a == nil || a.self != a {
		return NodeChainCandidateUsage{Retired: true}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	retired := a.retired || a.ctx.Err() != nil || !time.Now().Before(a.capture.Deadline)
	return NodeChainCandidateUsage{Retired: retired, Drained: retired && a.active == nil, Accepted: a.accepted, InFlight: a.active != nil}
}
func DecodeNodeChainPrefixCandidateRequest(raw []byte, status bool) (NodeChainPrefixCandidateRequest, string, error) {
	if status {
		var v struct {
			Request NodeChainPrefixCandidateRequest `json:"request"`
			Nonce   string                          `json:"nonce"`
		}
		if decodeNodeChainPrefixJSON(raw, &v, NodeChainPrefixMaximumRequestBytes) == nil && v.Request.Validate() == nil && proofID.MatchString(v.Nonce) {
			return v.Request.Clone(), v.Nonce, nil
		}
		return NodeChainPrefixCandidateRequest{}, "", errNodeChainPrefix
	}
	var q NodeChainPrefixCandidateRequest
	if decodeNodeChainPrefixJSON(raw, &q, NodeChainPrefixMaximumRequestBytes) != nil || q.Validate() != nil {
		return NodeChainPrefixCandidateRequest{}, "", errNodeChainPrefix
	}
	return q.Clone(), "", nil
}
func DecodeNodeChainPrefixCandidateCapture(raw []byte) (NodeChainPrefixCandidateCapture, error) {
	var c NodeChainPrefixCandidateCapture
	if decodeNodeChainPrefixJSON(raw, &c, MaxNodeChainPrefixCapabilitiesBytes) != nil || c.Validate() != nil {
		return NodeChainPrefixCandidateCapture{}, errNodeChainPrefix
	}
	return c.Clone(), nil
}
