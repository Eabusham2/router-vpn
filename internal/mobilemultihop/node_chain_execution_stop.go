package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"

	"router-vpn/internal/multihoprelay"
)

// The engine retains one original preparation Box through the explicit native
// graph transition. Observations use the actual final projected ConfigSHA256.
// All application controls include the original TUN ingress/DNS guard, not
// merely the final outbound. The platform owner alone closes the Box/TUN.
type NodeChainExecutionEngine interface {
	NodeChainExecutionDiscoveryEngine
	SelectContext(context.Context, string) error
	SelectedContext(context.Context) (string, error)
	DNSExecutionProofContext(context.Context, NodeChainExecutionDNSCapture) error
	RevokeApplicationContext(context.Context) error
	OpenApplicationContext(context.Context, NodeChainIdentity, string) error
	ApplicationOpenContext(context.Context) (bool, error)
	CaptureExecutionStop(context.Context, NodeChainExecutionStopCapture) (LeaseStop, error)
}

// NodeChainExecutionStopCapture grants only one immutable DELETE. It must be
// sealed by the original native entry before PUT, including when PUT's reply
// is lost or a later source check fails. No public field can replace its
// destination, credentials, acquisition challenge or positional identities.
type NodeChainExecutionStopCapture struct {
	entryTag, api, address, token, node, session, body string
	identity                                           NodeChainIdentity
}

func (s NodeChainExecutionStopCapture) Route() (string, string)     { return s.entryTag, s.address }
func (s NodeChainExecutionStopCapture) Identity() NodeChainIdentity { return s.identity }

func (p *NodeChainExecutionProjection) stopCapture(request multihoprelay.NodeChainRequest, identity NodeChainIdentity) (NodeChainExecutionStopCapture, error) {
	if p.validateCapture() != nil || request.Validate(p.policy.source.Server) != nil ||
		!nodeChainIdentityText(identity.EngineID) || !nodeChainIdentityText(identity.SessionID) || !nodeChainIdentityText(identity.NetworkID) ||
		identity.SourceSHA256 != p.SourceSHA256() || identity.ConfigSHA256 != p.ConfigSHA256() {
		return NodeChainExecutionStopCapture{}, nodeChainExecutionError
	}
	normalized := request.Clone()
	normalized.SessionID = p.policy.source.Request.SessionID
	normalized.Epoch = p.policy.source.Request.Epoch
	normalized.AcquireExpiresAt = p.policy.source.Request.AcquireExpiresAt
	if !reflect.DeepEqual(normalized, p.policy.Request()) {
		return NodeChainExecutionStopCapture{}, nodeChainExecutionError
	}
	entry := p.policy.local.nodes[0]
	api := predecessorText(entry.profile, "router_api")
	u, err := privateAPI(api)
	if err != nil {
		return NodeChainExecutionStopCapture{}, err
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > 4096 {
		return NodeChainExecutionStopCapture{}, nodeChainExecutionError
	}
	return NodeChainExecutionStopCapture{entryTag: p.policy.local.proofs[0].Tag, api: api, address: u.Host,
		token: predecessorText(entry.profile, "api_token"), node: p.policy.source.Server.EntryNodeID, session: request.SessionID, body: string(body), identity: identity}, nil
}

type ownedNodeChainExecutionStop struct {
	mu                           sync.Mutex
	gate                         chan struct{}
	capture                      NodeChainExecutionStopCapture
	io                           *nodeChainExecutionIO
	discard                      func()
	attempted, joined, discarded bool
}

// Native callbacks retain the exact original entry and either its live owner
// or its acknowledged terminal data barrier. They never consult a newly
// selected profile or grant any other request after public source retirement.
func NewOwnedNodeChainExecutionStop(capture NodeChainExecutionStopCapture, dial func(context.Context) (net.Conn, error), current func(context.Context) error, discard func()) (LeaseStop, error) {
	if capture.entryTag == "" || capture.address == "" || capture.api == "" || capture.token == "" || !proofID.MatchString(capture.node) || capture.session == "" || capture.body == "" ||
		!nodeChainIdentityText(capture.identity.EngineID) || !nodeChainIdentityText(capture.identity.SessionID) || !nodeChainIdentityText(capture.identity.NetworkID) ||
		!proofID.MatchString(capture.identity.SourceSHA256) || !proofID.MatchString(capture.identity.ConfigSHA256) || dial == nil || current == nil || discard == nil {
		return nil, nodeChainExecutionError
	}
	owner := &ownedNodeChainExecutionStop{capture: capture, discard: discard, gate: make(chan struct{}, 1)}
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

func (s *ownedNodeChainExecutionStop) Stop(ctx context.Context) error {
	if s == nil || ctx == nil {
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
	s.mu.Unlock()
	data, err := s.io.exchange(ctx, "DELETE", nodeChainExecutionLeasePath, []byte(s.capture.body), 4096)
	if err != nil {
		return err
	}
	var receipt struct {
		NodeID    string `json:"node_id"`
		SessionID string `json:"session_id"`
		Stopped   bool   `json:"stopped"`
	}
	if exactJSON(data, &receipt, 4096) != nil || !receipt.Stopped || receipt.NodeID != s.capture.node || receipt.SessionID != s.capture.session {
		return errors.New("ordered server cleanup has no exact joined receipt")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.discarded || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	s.joined = true
	return nil
}

// An attempted but unproved cleanup cannot discard its original native
// authority. The runtime retains this object and retries Stop. An unused
// factory result or a positively joined stop can release its native reference.
func (s *ownedNodeChainExecutionStop) Discard() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.discarded || s.attempted && !s.joined {
		s.mu.Unlock()
		return
	}
	s.discarded = true
	s.mu.Unlock()
	// No entered operation exists in either permitted state: Stop only marks
	// joined after its original worker, response and socket have all joined.
	if s.io.close(context.Background()) == nil {
		s.discard()
	}
}
