package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"net"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// CandidateResponseInput returns a complete original paired candidate available
// on this independently provisioned server. A client supplies only references.
func (p *NodeChainServerPolicy) CandidateResponseInput(c multihoprelay.NodeChainCandidateCapture) (string, error) {
	if c.Request.Schema != 2 || c.Validate() != nil || p.validateCapture() != nil || p.descriptor.EntryNodeID != c.Lease.Source.EntryNodeID {
		return "", nodeChainServerError
	}
	for _, n := range p.nodes {
		if n == nil || n.mode != "shadowsocks" || n.source != c.Request.CandidateSourceSHA256 || n.profile["id"] != c.Request.CandidateID {
			continue
		}
		input, err := n.LaunchInput()
		if err != nil {
			return "", err
		}
		if _, err = NewNodeChainServerCandidateResponder(c, input); err != nil {
			return "", err
		}
		return input, nil
	}
	return "", nodeChainServerError
}

type NodeChainServerCandidateResponder struct {
	self    *NodeChainServerCandidateResponder
	capture string
	source  candidateResponseSource
}

func NewNodeChainServerCandidateResponder(c multihoprelay.NodeChainCandidateCapture, input string) (*NodeChainServerCandidateResponder, error) {
	seal, err := c.Digest()
	if err != nil || c.Request.Schema != 2 || len(input) == 0 || len(input) > NodeChainInputLimit {
		return nil, nodeChainServerError
	}
	s, err := parseCandidateResponseSource(input)
	if err != nil || s.NodeID == c.Lease.Source.EntryNodeID || s.Target.ID == c.Lease.Source.EntryID || s.Target.ID != c.Request.CandidateID || s.Target.SourceSHA256 != c.Request.CandidateSourceSHA256 || s.Target.Address != c.Request.Address {
		return nil, nodeChainServerError
	}
	for _, member := range c.Lease.Source.Members {
		if member.NodeID == s.NodeID || member.ProfileID == s.Target.ID {
			return nil, nodeChainServerError
		}
	}
	r := &NodeChainServerCandidateResponder{capture: seal, source: s}
	r.self = r
	return r, nil
}

// Reply sends only a worker-constructed GET on the original candidate transport.
// The returned MAC must have arrived from the independently selected private API.
func (r *NodeChainServerCandidateResponder) Reply(ctx context.Context, c multihoprelay.NodeChainCandidateCapture, original net.Conn, nonce, request string, wrap func(context.Context, net.Conn, string, string, string) (net.Conn, error)) (string, error) {
	seal, err := c.Digest()
	if err != nil || r == nil || r.self != r || r.capture != seal || ctx == nil || ctx.Err() != nil || original == nil || wrap == nil || !hopmeasure.ValidCandidateNonce(nonce) || !hmac.Equal([]byte(request), []byte(hopmeasure.CandidateChallengeMAC(r.source.Token, r.source.NodeID, nonce, false))) {
		return "", nodeChainServerError
	}
	used := false
	const tag = "original-server-candidate"
	dial := func(call context.Context, owner, address string) (net.Conn, error) {
		if used || call.Err() != nil || owner != tag || address != r.source.Target.Address {
			return nil, nodeChainServerError
		}
		used = true
		return original, nil
	}
	var response string
	if err := r.source.exchangeNonce(ctx, dial, wrap, tag, nonce, func(authenticated string) error { response = authenticated; return ctx.Err() }); err != nil || !used || response == "" {
		return "", nodeChainServerError
	}
	return response, nil
}
