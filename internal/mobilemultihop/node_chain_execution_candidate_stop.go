package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

// This optional native capability is separate from lease acquisition cleanup:
// candidate work starts on an already selected, live application permit. The
// returned stop must retain that exact entry and permit before any candidate
// PUT, including when that PUT's reply is lost.
type NodeChainExecutionCandidateStopEngine interface {
	CaptureExecutionCandidateStop(context.Context, NodeChainExecutionCandidateStopCapture) (LeaseStop, error)
}

type NodeChainExecutionCandidateStopCapture struct {
	entryTag, api, address, token, selectedTag string
	identity                                   NodeChainIdentity
	lease                                      multihoprelay.NodeChainCapture
	request                                    multihoprelay.NodeChainCandidateRequest
	body, seal                                 string
}

func (c NodeChainExecutionCandidateStopCapture) Route() (string, string) {
	return c.entryTag, c.address
}
func (c NodeChainExecutionCandidateStopCapture) Identity() NodeChainIdentity { return c.identity }
func (c NodeChainExecutionCandidateStopCapture) Selection() (string, uint64) {
	return c.selectedTag, c.request.SelectionEpoch
}

func (c NodeChainExecutionCandidateStopCapture) digest() string {
	raw, _ := json.Marshal([]any{"routervpn-node-chain-candidate-stop-v1", c.entryTag, c.api,
		c.address, c.token, c.selectedTag, c.identity, c.lease, c.request, c.body})
	defer clear(raw)
	return externalDigest(raw)
}

// Validation here is immutable, so exact cleanup can outlive cancellation or
// expiry of the public measurement. Native ownership is checked independently
// on every dial and after every response by the original sealed callback.
func (c NodeChainExecutionCandidateStopCapture) validate() error {
	q, err := multihoprelay.DecodeNodeChainCandidateRequest([]byte(c.body))
	digest, leaseErr := c.lease.Digest()
	u, apiErr := privateAPI(c.api)
	if err != nil || leaseErr != nil || apiErr != nil || c.lease.Validate() != nil ||
		!reflect.DeepEqual(q, c.request) || !reflect.DeepEqual(q.Lease, c.lease.Request) ||
		q.OwnerID != c.lease.OwnerID || q.CaptureSHA256 != digest || q.ExecutionSHA256 != c.identity.SourceSHA256 ||
		q.Position >= len(c.lease.Source.Members) || q.Schema == 1 && (!NodeChainPrefixMode(c.lease.Source.Members[q.Position-1].Mode) || c.lease.Source.Members[q.Position-1].NodeKind != "") ||
		q.Schema == 2 && !c.lease.Source.CandidateResponsePrefix(q.Position) ||
		q.Schema == 3 && !c.lease.Source.PublicCandidateResponsePrefix(q.Position) ||
		q.Schema == 4 && !c.lease.Source.PacketCandidateResponsePrefix(q.Position, q.CandidateMode) ||
		q.Schema == 5 && !c.lease.Source.FirstPacketCandidateResponse(q.CandidateMode) ||
		!exactID.MatchString(c.entryTag) || !exactID.MatchString(c.selectedTag) || c.address != u.Host || c.token == "" ||
		!nodeChainIdentityText(c.identity.EngineID) || !nodeChainIdentityText(c.identity.SessionID) || !nodeChainIdentityText(c.identity.NetworkID) ||
		!proofID.MatchString(c.identity.ConfigSHA256) || c.seal == "" || c.seal != c.digest() {
		return nodeChainExecutionError
	}
	return nil
}

func (s *nodeChainExecutionTrial) candidateStopCapture(ctx context.Context, q multihoprelay.NodeChainCandidateRequest) (NodeChainExecutionCandidateStopCapture, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.runtime == nil || s.execution != "server" || q.Validate() != nil {
		return NodeChainExecutionCandidateStopCapture{}, nodeChainExecutionError
	}
	if err := s.runtime.current(ctx, s, true); err != nil {
		return NodeChainExecutionCandidateStopCapture{}, err
	}
	s.mu.Lock()
	attempt, closed := s.attempt, s.closed
	s.mu.Unlock()
	if attempt == nil || closed {
		return NodeChainExecutionCandidateStopCapture{}, nodeChainExecutionError
	}
	now := time.Now()
	attempt.mu.Lock()
	valid := attempt.issued && !attempt.stopped && attempt.lease.Phase == multihoprelay.NodeChainReady &&
		attempt.receipt.Phase == multihoprelay.NodeChainReady && now.Before(attempt.deadline) && now.Before(attempt.proofDeadline)
	lease := multihoprelay.NodeChainCapture{Schema: 1, Request: attempt.request.Clone(), Source: attempt.source.Clone(),
		RegistrySHA256: attempt.lease.RegistrySHA256, OwnerID: attempt.lease.OwnerID, Peer: attempt.request.Peer,
		Host: attempt.lease.Host, BootstrapDeadline: attempt.lease.BootstrapDeadline}
	attempt.mu.Unlock()
	if !valid || q.Trial != s.id || q.SelectionEpoch != s.selectionEpoch ||
		q.DeadlineAt <= now.UnixMilli() || q.DeadlineAt > now.Add(multihoprelay.NodeChainCandidateLifetime).UnixMilli() {
		return NodeChainExecutionCandidateStopCapture{}, nodeChainExecutionError
	}
	s.runtime.mu.Lock()
	identity := s.runtime.identity
	s.runtime.mu.Unlock()
	entry := s.runtime.projection.policy.local.nodes[0]
	api := predecessorText(entry.profile, "router_api")
	u, err := privateAPI(api)
	if err != nil {
		return NodeChainExecutionCandidateStopCapture{}, err
	}
	body, err := multihoprelay.MarshalNodeChainCandidateRequest(q)
	if err != nil {
		return NodeChainExecutionCandidateStopCapture{}, err
	}
	defer clear(body)
	c := NodeChainExecutionCandidateStopCapture{entryTag: s.runtime.projection.policy.local.proofs[0].Tag,
		api: api, address: u.Host, token: predecessorText(entry.profile, "api_token"), selectedTag: s.tag,
		identity: identity, lease: lease, request: q.Clone(), body: string(body)}
	c.seal = c.digest()
	if err := c.validate(); err != nil {
		return NodeChainExecutionCandidateStopCapture{}, err
	}
	if err := s.runtime.current(ctx, s, true); err != nil {
		return NodeChainExecutionCandidateStopCapture{}, err
	}
	s.mu.Lock()
	valid = s.attempt == attempt && !s.closed
	s.mu.Unlock()
	if !valid || !attempt.fresh() {
		return NodeChainExecutionCandidateStopCapture{}, nodeChainExecutionError
	}
	return c, nil
}

type ownedNodeChainExecutionCandidateStop struct {
	self                                       *ownedNodeChainExecutionCandidateStop
	mu                                         sync.Mutex
	gate                                       chan struct{}
	capture                                    NodeChainExecutionCandidateStopCapture
	io                                         *nodeChainExecutionIO
	discard                                    func()
	attempted, acknowledged, joined, discarded bool
}

func NewOwnedNodeChainExecutionCandidateStop(capture NodeChainExecutionCandidateStopCapture, dial func(context.Context) (net.Conn, error), current func(context.Context) error, discard func()) (LeaseStop, error) {
	if capture.validate() != nil || dial == nil || current == nil || discard == nil {
		return nil, nodeChainExecutionError
	}
	// The native caller cannot change a request through shared slice storage.
	capture.lease = capture.lease.Clone()
	capture.request = capture.request.Clone()
	owner := &ownedNodeChainExecutionCandidateStop{capture: capture, discard: discard, gate: make(chan struct{}, 1)}
	owner.self = owner
	var err error
	owner.io, err = newNodeChainExecutionIO(capture.entryTag, capture.api, capture.token, func(ctx context.Context, tag, address string) (net.Conn, error) {
		if tag != capture.entryTag || address != capture.address {
			return nil, nodeChainExecutionError
		}
		return dial(ctx)
	}, current)
	if err != nil {
		return nil, err
	}
	owner.gate <- struct{}{}
	return owner, nil
}

func (s *ownedNodeChainExecutionCandidateStop) Stop(ctx context.Context) error {
	if s == nil || s.self != s || ctx == nil || s.capture.validate() != nil {
		return nodeChainExecutionError
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	s.mu.Lock()
	if s.discarded {
		s.mu.Unlock()
		return nodeChainExecutionError
	}
	if s.joined {
		s.mu.Unlock()
		return ctx.Err()
	}
	s.attempted = true
	acknowledged := s.acknowledged
	s.mu.Unlock()
	if !acknowledged {
		data, err := s.io.exchangeCandidate(ctx, "DELETE", []byte(s.capture.body))
		if err != nil {
			return err
		}
		if _, err = multihoprelay.DecodeNodeChainCandidateCloseAcknowledgement(data, s.capture.request); err != nil {
			return errors.Join(err, errors.New("ordered candidate cleanup has no exact joined receipt"))
		}
		s.mu.Lock()
		s.acknowledged = true
		s.mu.Unlock()
	}
	// A valid remote ACK cannot waive late original local callbacks. Retain the
	// ACK across a failed join so retry never needs a replacement lease/permit.
	if err := s.io.close(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.discarded || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	s.joined = true
	return nil
}

func (s *ownedNodeChainExecutionCandidateStop) Discard() {
	if s == nil || s.self != s {
		return
	}
	s.mu.Lock()
	if s.discarded || s.attempted && !s.joined {
		s.mu.Unlock()
		return
	}
	s.discarded = true
	s.mu.Unlock()
	if s.io.close(context.Background()) == nil {
		s.discard()
	}
}
