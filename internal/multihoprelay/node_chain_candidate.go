package multihoprelay

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/netip"
	"reflect"
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
	Schema                   int              `json:"schema"`
	Lease                    NodeChainRequest `json:"lease"`
	OwnerID                  string           `json:"owner_id"`
	CaptureSHA256            string           `json:"capture_sha256"`
	Operation                string           `json:"operation_id"`
	ExecutionSHA256          string           `json:"execution_sha256"`
	Trial                    string           `json:"trial_id"`
	SelectionEpoch           uint64           `json:"selection_epoch"`
	InventorySHA256          string           `json:"inventory_sha256"`
	Position                 int              `json:"position"`
	CandidateID              string           `json:"candidate_id"`
	CandidateSourceSHA256    string           `json:"candidate_source_sha256"`
	Address                  string           `json:"address"`
	DeadlineAt               int64            `json:"deadline_at"`
	Password                 string           `json:"password"`
	CandidateMode            string           `json:"candidate_mode,omitempty"`
	CandidateClientPublicKey string           `json:"candidate_client_public_key,omitempty"`
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
	if q.Lease.validateShape() != nil {
		return errNodeChainCandidate
	}
	return q.validateCandidateFields()
}

func (q NodeChainCandidateRequest) validateCandidateFields() error {
	if (q.Schema != 1 && q.Schema != 2 && q.Schema != 3 && q.Schema != 4 && q.Schema != 5) || !proofID.MatchString(q.OwnerID) || !proofID.MatchString(q.CaptureSHA256) || !proofID.MatchString(q.Operation) || !proofID.MatchString(q.ExecutionSHA256) || !nonce.MatchString(q.Trial) || q.SelectionEpoch == 0 || !proofID.MatchString(q.InventorySHA256) || (q.Schema == 5 && q.Position != 0 || q.Schema != 5 && q.Position < 1) || (q.Schema == 1 && q.Position >= NodeChainMaximumMembers || q.Position >= NodeChainExtendedMaximumMembers) || !ident.MatchString(q.CandidateID) || !proofID.MatchString(q.CandidateSourceSHA256) || !nodeChainCandidateAddress(q.Address) || q.DeadlineAt <= 0 || !proofID.MatchString(q.Password) {
		return errNodeChainCandidate
	}
	if (q.Schema == 3) != (q.Lease.Schema == 8) || q.Schema == 3 && q.Position >= len(q.Lease.Users) {
		return errNodeChainCandidate
	}
	if q.Schema == 2 {
		if q.Position >= len(q.Lease.Users) {
			return errNodeChainCandidate
		}
		switch q.Lease.Schema {
		case 2, 6:
		case 3, 4, 5:
			if q.Position != len(q.Lease.Users)-1 {
				return errNodeChainCandidate
			}
		default:
			return errNodeChainCandidate
		}
	}
	if q.IsPacketResponse() {
		if !nodeChainPacketMode(q.CandidateMode) || !nodeChainPacketPublic(q.CandidateClientPublicKey) ||
			q.Position >= len(q.Lease.Users)-1 || (q.Lease.Schema != 1 && q.Lease.Schema != 6) {
			return errNodeChainCandidate
		}
		for _, key := range q.Lease.LocalPacketPublicKeys {
			if key == q.CandidateClientPublicKey {
				return errNodeChainCandidate
			}
		}
	} else if q.CandidateMode != "" || q.CandidateClientPublicKey != "" {
		return errNodeChainCandidate
	}
	for _, user := range q.Lease.Users {
		if q.Password == user.Password {
			return errNodeChainCandidate
		}
	}
	return nil
}

// IsPacketResponse is descriptive only. Validate and the original operation
// determine whether a packet request may acquire its own native transport.
func (q NodeChainCandidateRequest) IsPacketResponse() bool {
	return q.Schema == 4 || q.Schema == 5
}

func (q NodeChainCandidateRequest) Digest() (string, error) {
	if q.Validate() != nil {
		return "", errNodeChainCandidate
	}
	if q.Schema == 5 {
		return nodeChainDigest("routervpn-selected-first-packet-candidate-request-v5", q)
	}
	if q.Schema == 4 {
		return nodeChainDigest("routervpn-selected-packet-candidate-request-v4", q)
	}
	if q.Schema == 3 {
		return nodeChainDigest("routervpn-public-final-candidate-request-v3", q)
	}
	return nodeChainDigest("routervpn-node-chain-candidate-request-v1", q)
}
func DecodeNodeChainCandidateRequest(raw []byte) (NodeChainCandidateRequest, error) {
	var q NodeChainCandidateRequest
	if decodeNodeChainJSON(raw, &q, NodeChainCandidateMaximumBytes) == nil && !q.Lease.HasRegisteredFronts() && q.Validate() == nil {
		return q.Clone(), nil
	}
	var compact nodeChainPublicCandidateRequest
	if decodeNodeChainJSON(raw, &compact, NodeChainCandidateMaximumBytes) != nil {
		return NodeChainCandidateRequest{}, errNodeChainCandidate
	}
	return compact.restore()
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
	// Digest validated the original lease, including every derived front. Compare
	// all live request fields before reusing that result for its candidate copy.
	if err != nil || c.Schema != 1 || q.validateCandidateFields() != nil || q.OwnerID != c.Lease.OwnerID || q.CaptureSHA256 != digest ||
		(!reflect.DeepEqual(q.Lease, c.Lease.Request) && !sameNodeChainRequest(q.Lease, c.Lease.Request)) || !proofID.MatchString(c.OperationOwnerID) || q.Position >= len(c.Lease.Source.Members) {
		return errNodeChainCandidate
	}
	if q.Schema == 5 {
		if c.Member != (NodeChainMember{}) || !c.Lease.Source.FirstPacketCandidateResponse(q.CandidateMode) {
			return errNodeChainCandidate
		}
	} else if c.Member != c.Lease.Source.Members[q.Position-1] {
		return errNodeChainCandidate
	}
	if q.Schema == 1 {
		if !nodeChainPacketMode(c.Member.Mode) || c.Member.NodeKind != "" {
			return errNodeChainCandidate
		}
	} else if q.Schema == 3 {
		// The validated lease descriptor, candidate fields and bounds above
		// establish that position is an intermediate public prefix of schema 8.
		if c.Lease.Source.Schema != 8 || q.CandidateID == c.Lease.Source.EntryID {
			return errNodeChainCandidate
		}
		for _, m := range c.Lease.Source.Members {
			if q.CandidateID == m.ProfileID || q.CandidateSourceSHA256 == m.SourceSHA256 {
				return errNodeChainCandidate
			}
		}
	} else if q.IsPacketResponse() {
		if q.CandidateID == c.Lease.Source.EntryID || q.Schema == 4 && !c.Lease.Source.PacketCandidateResponsePrefix(q.Position, q.CandidateMode) {
			return errNodeChainCandidate
		}
		for _, member := range c.Lease.Source.Members {
			if member.ProfileID == q.CandidateID || member.ClientPublicKey == q.CandidateClientPublicKey || member.ServerPublicKey == q.CandidateClientPublicKey {
				return errNodeChainCandidate
			}
		}
	} else if !c.Lease.Source.CandidateResponsePrefix(q.Position) {
		return errNodeChainCandidate
	}
	return nil
}

// CandidateResponsePrefix is only descriptive. The server worker must additionally
// hold the original suffix outbound and independently provisioned candidate.
func (s NodeChainDescriptor) CandidateResponsePrefix(position int) bool {
	if position < 1 || position >= len(s.Members) || s.Validate() != nil {
		return false
	}
	m := s.Members[position-1]
	switch s.Schema {
	case 2, 6:
		return m.Mode == "shadowsocks" && m.StartLayer == "off" &&
			(m.NodeKind == "external" && m.ProofKind == "public-path" || s.PrivateStreamAt(position))
	case 3, 4, 5:
		last := s.Members[len(s.Members)-1]
		if position != len(s.Members)-1 || m.NodeKind != "external" || m.ProofKind != "public-path" ||
			m.StartLayer != "off" || last.Mode != "shadowsocks" || last.StartLayer != "off" {
			return false
		}
		return s.Schema == 3 && m.Mode == "socks5" ||
			s.Schema == 4 && (m.Mode == "http-connect" || m.Mode == "https-connect") ||
			s.Schema == 5 && m.Mode == "openvpn"
	default:
		return false
	}
}

// Only a public intermediate prefix of the original public-final lease can
// host this measurement. A registered candidate still owns its SS credentials,
// exact target and independent expected public address.
func (s NodeChainDescriptor) PublicCandidateResponsePrefix(position int) bool {
	return s.Schema == 8 && position >= 1 && position < len(s.Members) && s.Validate() == nil
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
	if c.Request.Schema == 5 {
		return nodeChainDigest("routervpn-selected-first-packet-candidate-capture-v5", c)
	}
	if c.Request.Schema == 4 {
		return nodeChainDigest("routervpn-selected-packet-candidate-capture-v4", c)
	}
	if c.Request.Schema == 3 {
		return nodeChainDigest("routervpn-public-final-candidate-capture-v3", c)
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
	return RestoreNodeChainCandidateCapture(lease, q, owner)
}

// RestoreNodeChainCandidateCapture reconstructs validated metadata only. The
// authenticated original lease/receipt remains the caller's runtime authority.
// First-suffix requests retain their real entry in Lease and no suffix Member.
func RestoreNodeChainCandidateCapture(lease NodeChainCapture, q NodeChainCandidateRequest, owner string) (NodeChainCandidateCapture, error) {
	if q.Validate() != nil || lease.Validate() != nil || q.Position >= len(lease.Source.Members) {
		return NodeChainCandidateCapture{}, errNodeChainCandidate
	}
	c := NodeChainCandidateCapture{Schema: 1, Lease: lease.Clone(), Request: q.Clone(), OperationOwnerID: owner}
	if q.Schema != 5 {
		c.Member = lease.Source.Members[q.Position-1]
	}
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
	PairingSHA256    string `json:"pairing_sha256,omitempty"`
}

func (r NodeChainCandidateReceipt) Validate(c NodeChainCandidateCapture) error {
	if c.Request.IsPacketResponse() && !proofID.MatchString(r.PairingSHA256) || !c.Request.IsPacketResponse() && r.PairingSHA256 != "" {
		return errNodeChainCandidate
	}
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
	if c.Validate() == nil {
		switch c.Request.Schema {
		case 2:
			return "candidate-response-" + c.OperationOwnerID + ".json"
		case 4:
			return "packet-candidate-response-" + c.OperationOwnerID + ".json"
		case 3:
			return "public-candidate-response-" + c.OperationOwnerID + ".json"
		}
	}
	return ""
}

// PacketCandidateResponsePrefix describes only a same-mode paired replacement
// inside an original packet/literal-import suffix. It does not register a
// candidate, grant a UDP socket, or substitute the authenticated entry owner.
func (s NodeChainDescriptor) PacketCandidateResponsePrefix(position int, mode string) bool {
	if (s.Schema != 1 && s.Schema != 6) || s.Validate() != nil || position < 1 || position >= len(s.Members)-1 || !nodeChainPacketMode(mode) {
		return false
	}
	next := s.Members[position]
	if next.Mode != mode || next.StartLayer != "off" || next.NodeKind != "" {
		return false
	}
	for _, member := range s.Members[:position] {
		if nodeChainPacketMode(member.Mode) && member.NodeKind == "" {
			continue
		}
		if s.Schema != 6 || member.Mode != "shadowsocks" || member.StartLayer != "off" || member.NodeKind != "external" || member.ProofKind != "public-path" {
			return false
		}
	}
	return true
}

// FirstPacketCandidateResponse identifies a replacement of the first Server
// suffix under the original authenticated entry. It grants no physical route.
func (s NodeChainDescriptor) FirstPacketCandidateResponse(mode string) bool {
	if (s.Schema != 1 && s.Schema != 6) || s.Validate() != nil || len(s.Members) < 2 || !nodeChainPacketMode(mode) {
		return false
	}
	first := s.Members[0]
	return first.Mode == mode && first.StartLayer == "off" && first.NodeKind == ""
}
