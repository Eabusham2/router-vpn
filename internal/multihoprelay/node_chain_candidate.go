package multihoprelay

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const NodeChainCandidateLifetime = 90 * time.Second
const NodeChainCandidateMaximumConnects = 50

// The original lease body remains capped at 4 KiB. This separate envelope adds
// at most seven 64-byte digests/secrets, one 128-byte ID, one 32-byte trial, one literal IP tuple,
// scalar selection fields and JSON framing. 8 KiB bounds that exact union; it
// does not admit source files, lists of targets or arbitrary extension members.
const NodeChainCandidateMaximumBytes = 8 << 10

var errNodeChainCandidate = errors.New("original ordered candidate authority is unavailable")

type NodeChainCandidateRequest struct {
	Schema                int              `json:"schema"`
	Lease                 NodeChainRequest `json:"lease"`
	OwnerID               string           `json:"owner_id"`
	CaptureSHA256         string           `json:"capture_sha256"`
	Operation             string           `json:"operation_id"`
	ExecutionSHA256       string           `json:"execution_sha256"`
	Trial                 string           `json:"trial_id"`
	SelectionEpoch        uint64           `json:"selection_epoch"`
	InventorySHA256       string           `json:"inventory_sha256"`
	Position              int              `json:"position"`
	CandidateID           string           `json:"candidate_id"`
	CandidateSourceSHA256 string           `json:"candidate_source_sha256"`
	Address               string           `json:"address"`
	DeadlineAt            int64            `json:"deadline_at"`
	Password              string           `json:"password"`
}

func nodeChainCandidateAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	// Private/loopback/link-local addresses are not generically banned: the
	// original operator policy decides LAN reachability in the native compiler.
	return err == nil && ipErr == nil && portErr == nil && ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast() && number > 0 && number <= 65535 && net.JoinHostPort(ip.String(), strconv.Itoa(number)) == address
}
func (q NodeChainCandidateRequest) Clone() NodeChainCandidateRequest {
	q.Lease = q.Lease.Clone()
	return q
}
func (q NodeChainCandidateRequest) Validate() error {
	if (q.Schema != 1 && q.Schema != 2) || q.Lease.validateShape() != nil || !proofID.MatchString(q.OwnerID) || !proofID.MatchString(q.CaptureSHA256) || !proofID.MatchString(q.Operation) || !proofID.MatchString(q.ExecutionSHA256) || !nonce.MatchString(q.Trial) || q.SelectionEpoch == 0 || !proofID.MatchString(q.InventorySHA256) || q.Position < 1 || (q.Schema == 1 && q.Position >= NodeChainMaximumMembers || q.Position >= NodeChainExtendedMaximumMembers) || !ident.MatchString(q.CandidateID) || !proofID.MatchString(q.CandidateSourceSHA256) || !nodeChainCandidateAddress(q.Address) || q.DeadlineAt <= 0 || !proofID.MatchString(q.Password) {
		return errNodeChainCandidate
	}
	if q.Schema == 2 && (q.Lease.Schema != 2 && q.Lease.Schema != 6 || q.Position >= len(q.Lease.Users)) {
		return errNodeChainCandidate
	}
	for _, user := range q.Lease.Users {
		if q.Password == user.Password {
			return errNodeChainCandidate
		}
	}
	return nil
}
func (q NodeChainCandidateRequest) Digest() (string, error) {
	if q.Validate() != nil {
		return "", errNodeChainCandidate
	}
	return nodeChainDigest("routervpn-node-chain-candidate-request-v1", q)
}
func DecodeNodeChainCandidateRequest(raw []byte) (NodeChainCandidateRequest, error) {
	var q NodeChainCandidateRequest
	if decodeNodeChainJSON(raw, &q, NodeChainCandidateMaximumBytes) != nil || q.Validate() != nil {
		return NodeChainCandidateRequest{}, errNodeChainCandidate
	}
	return q.Clone(), nil
}

// This private worker capture is derived by the original lease manager. Member
// identity comes from the complete operator descriptor; no request carries a tag.
type NodeChainCandidateCapture struct {
	Schema           int                       `json:"schema"`
	Lease            NodeChainCapture          `json:"lease"`
	Request          NodeChainCandidateRequest `json:"request"`
	Member           NodeChainMember           `json:"member"`
	OperationOwnerID string                    `json:"operation_owner_id"`
}

func (c NodeChainCandidateCapture) Clone() NodeChainCandidateCapture {
	c.Lease = c.Lease.Clone()
	c.Request = c.Request.Clone()
	return c
}
func (c NodeChainCandidateCapture) Validate() error {
	q := c.Request
	digest, err := c.Lease.Digest()
	if c.Schema != 1 || c.Lease.Validate() != nil || q.Validate() != nil || err != nil || q.OwnerID != c.Lease.OwnerID || q.CaptureSHA256 != digest || !sameNodeChainRequest(q.Lease, c.Lease.Request) || !proofID.MatchString(c.OperationOwnerID) || q.Position >= len(c.Lease.Source.Members) || c.Member != c.Lease.Source.Members[q.Position-1] {
		return errNodeChainCandidate
	}
	if q.Schema == 1 {
		if !nodeChainPacketMode(c.Member.Mode) || c.Member.NodeKind != "" {
			return errNodeChainCandidate
		}
	} else if !c.Lease.Source.CandidateResponsePrefix(q.Position) {
		return errNodeChainCandidate
	}
	return nil
}

// CandidateResponsePrefix is only descriptive. The server worker must additionally
// hold the original suffix outbound and independently provisioned candidate.
func (s NodeChainDescriptor) CandidateResponsePrefix(position int) bool {
	if (s.Schema != 2 && s.Schema != 6) || position < 1 || position >= len(s.Members) || s.Validate() != nil {
		return false
	}
	m := s.Members[position-1]
	return m.Mode == "shadowsocks" && m.StartLayer == "off" &&
		(m.NodeKind == "external" && m.ProofKind == "public-path" || s.PrivateStreamAt(position))
}

// Username is unique to this server-generated operation owner. A client may
// reuse its proposed password, but never the prior operation's wire identity.
func (c NodeChainCandidateCapture) Username() string {
	if c.Validate() != nil {
		return ""
	}
	return "candidate-" + c.OperationOwnerID
}
func (c NodeChainCandidateCapture) Digest() (string, error) {
	if c.Validate() != nil {
		return "", errNodeChainCandidate
	}
	return nodeChainDigest("routervpn-node-chain-candidate-capture-v1", c)
}
func NewNodeChainCandidateCapture(lease NodeChainCapture, q NodeChainCandidateRequest, now time.Time) (NodeChainCandidateCapture, error) {
	if q.Validate() != nil || lease.Validate() != nil || q.Position >= len(lease.Source.Members) || q.DeadlineAt <= now.UnixMilli() || q.DeadlineAt > now.Add(NodeChainCandidateLifetime).UnixMilli() {
		return NodeChainCandidateCapture{}, errNodeChainCandidate
	}
	owner, err := nodeChainSecret()
	if err != nil {
		return NodeChainCandidateCapture{}, err
	}
	c := NodeChainCandidateCapture{1, lease.Clone(), q.Clone(), lease.Source.Members[q.Position-1], owner}
	return c, c.Validate()
}

type NodeChainCandidateReceipt struct {
	Schema           int    `json:"schema"`
	Operation        string `json:"operation_id"`
	OperationOwnerID string `json:"operation_owner_id"`
	CaptureSHA256    string `json:"capture_sha256"`
	DeadlineAt       int64  `json:"deadline_at"`
	Prepared         bool   `json:"prepared"`
	Retired          bool   `json:"retired"`
	Drained          bool   `json:"drained"`
	Accepted         int    `json:"accepted"`
	InFlight         bool   `json:"in_flight"`
}

func (r NodeChainCandidateReceipt) Validate(c NodeChainCandidateCapture) error {
	digest, err := c.Digest()
	if err != nil || r.Schema != 1 || r.Operation != c.Request.Operation || r.OperationOwnerID != c.OperationOwnerID || r.CaptureSHA256 != digest || r.DeadlineAt != c.Request.DeadlineAt || r.Accepted < 0 || r.Accepted > NodeChainCandidateMaximumConnects || r.InFlight && r.Accepted == 0 || r.Drained && (!r.Retired || r.InFlight) || !r.Prepared && (r.Accepted != 0 || r.InFlight) {
		return errNodeChainCandidate
	}
	return nil
}

// The native operation must return every allocated handle before Prepare does
// foreign work. Close joins that exact handle and never looks up an owner/key.
// Current native workers do not implement this capability yet and are refused.
type NodeChainCandidateProcess interface {
	NewCandidateOperation(context.Context, NodeChainCandidateCapture) (NodeChainCandidateOperation, error)
}
type NodeChainCandidateOperation interface {
	Prepare(context.Context) (NodeChainCandidateReceipt, error)
	Snapshot(context.Context) (NodeChainCandidateReceipt, error)
	Close(context.Context) error
}

// Admission is the native worker's connect-only quota, not a socket or a ready
// receipt. Its release callback must follow the actual original socket close.
// Parent cancellation/expiry refuses further admission; Close waits its join.
type NodeChainCandidateAdmission struct {
	self     *NodeChainCandidateAdmission
	capture  NodeChainCandidateCapture
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	retired  bool
	accepted int
	active   chan struct{}
}

func NewNodeChainCandidateAdmission(parent context.Context, c NodeChainCandidateCapture) (*NodeChainCandidateAdmission, error) {
	if parent == nil || parent.Err() != nil || c.Validate() != nil || !time.Now().Before(time.UnixMilli(c.Request.DeadlineAt)) || time.UnixMilli(c.Request.DeadlineAt).After(time.Now().Add(NodeChainCandidateLifetime)) {
		return nil, errNodeChainCandidate
	}
	ctx, cancel := context.WithDeadline(parent, time.UnixMilli(c.Request.DeadlineAt))
	a := &NodeChainCandidateAdmission{capture: c.Clone(), ctx: ctx, cancel: cancel}
	a.self = a
	return a, nil
}
func (a *NodeChainCandidateAdmission) Begin(ctx context.Context, username, password, network, address string) (func(), error) {
	if a == nil || a.self != a || ctx == nil || ctx.Err() != nil || subtle.ConstantTimeCompare([]byte(username), []byte(a.capture.Username())) != 1 || subtle.ConstantTimeCompare([]byte(password), []byte(a.capture.Request.Password)) != 1 || network != "tcp" || address != a.capture.Request.Address || a.capture.Validate() != nil {
		return nil, errNodeChainCandidate
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.retired || a.ctx.Err() != nil || !time.Now().Before(time.UnixMilli(a.capture.Request.DeadlineAt)) || a.active != nil || a.accepted >= NodeChainCandidateMaximumConnects {
		return nil, errNodeChainCandidate
	}
	joined := make(chan struct{})
	a.active = joined
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
func (a *NodeChainCandidateAdmission) CloseContext(ctx context.Context) error {
	if a == nil || a.self != a || ctx == nil {
		return errNodeChainCandidate
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

// Usage deliberately carries no Prepared flag or native owner receipt. Only the
// concrete worker can publish preparation after its original owner checks.
type NodeChainCandidateUsage struct {
	Retired  bool
	Drained  bool
	Accepted int
	InFlight bool
}

func (a *NodeChainCandidateAdmission) Snapshot() NodeChainCandidateUsage {
	if a == nil || a.self != a {
		return NodeChainCandidateUsage{Retired: true}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	retired := a.retired || a.ctx.Err() != nil || !time.Now().Before(time.UnixMilli(a.capture.Request.DeadlineAt))
	return NodeChainCandidateUsage{retired, retired && a.active == nil, a.accepted, a.active != nil}
}

// A successful HTTP cancellation also covers a retained cancel-before-create
// tombstone. It identifies the exact request, never merely the enclosing VPN.
type NodeChainCandidateCloseAcknowledgement struct {
	Schema             int    `json:"schema"`
	Operation          string `json:"operation_id"`
	RequestSHA256      string `json:"request_sha256"`
	LeaseCaptureSHA256 string `json:"lease_capture_sha256"`
	OwnerID            string `json:"owner_id"`
	Stopped            bool   `json:"stopped"`
}

func NewNodeChainCandidateCloseAcknowledgement(q NodeChainCandidateRequest) (NodeChainCandidateCloseAcknowledgement, error) {
	digest, err := q.Digest()
	if err != nil {
		return NodeChainCandidateCloseAcknowledgement{}, err
	}
	return NodeChainCandidateCloseAcknowledgement{1, q.Operation, digest, q.CaptureSHA256, q.OwnerID, true}, nil
}
func (a NodeChainCandidateCloseAcknowledgement) Validate(q NodeChainCandidateRequest) error {
	expected, err := NewNodeChainCandidateCloseAcknowledgement(q)
	if err != nil || a != expected {
		return errNodeChainCandidate
	}
	return nil
}
func DecodeNodeChainCandidateCloseAcknowledgement(raw []byte, q NodeChainCandidateRequest) (NodeChainCandidateCloseAcknowledgement, error) {
	var a NodeChainCandidateCloseAcknowledgement
	if decodeNodeChainJSON(raw, &a, NodeChainCandidateResponseMaximumBytes) != nil || a.Validate(q) != nil {
		return NodeChainCandidateCloseAcknowledgement{}, errNodeChainCandidate
	}
	return a, nil
}

func (c NodeChainCandidateCapture) ResponseSourceFile() string {
	if c.Request.Schema != 2 || c.Validate() != nil {
		return ""
	}
	return "candidate-response-" + c.OperationOwnerID + ".json"
}
