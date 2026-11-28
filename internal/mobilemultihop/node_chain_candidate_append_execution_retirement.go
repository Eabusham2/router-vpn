package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"router-vpn/internal/multihoprelay"
)

// Captured before acquisition is issued. This owner has no GET, PUT, POST,
// renewal or candidate-start API: it can only delete its original request and
// require that same authenticated remote retirement acknowledgement.
type nodeChainAppendExecutionRetirement struct {
	self      *nodeChainAppendExecutionRetirement
	runtime   *NodeChainCandidateAppendExecutionRuntime
	lease     *nodeChainAppendExecutionLease
	candidate *nodeChainAppendExecutionRemoteCandidate
	digest    string
	io        *nodeChainExecutionIO
}

func (r *NodeChainCandidateAppendExecutionRuntime) newRetirement(lease *nodeChainAppendExecutionLease, candidate *nodeChainAppendExecutionRemoteCandidate) (*nodeChainAppendExecutionRetirement, error) {
	if lease == nil || lease.runtime != r || lease.self != lease {
		return nil, errNodeChainAppendExecution
	}
	owned := &nodeChainAppendExecutionRetirement{runtime: r, lease: lease, candidate: candidate}
	owned.self = owned
	var err error
	if candidate != nil {
		if candidate.lease != lease || candidate.self != candidate {
			return nil, errNodeChainAppendExecution
		}
		owned.digest, err = nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-candidate-request-v1", candidate.request)
	} else {
		owned.digest, err = nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-request-v1", lease.request)
	}
	if err != nil {
		return owned, err
	}
	p := r.preparation.original
	node := p.prefixNode(0)
	tag := p.proofs[0].Tag
	owned.io, err = newNodeChainExecutionIO(tag, predecessorText(node.profile, "router_api"), predecessorText(node.profile, "api_token"), func(ctx context.Context, actual, address string) (net.Conn, error) {
		return r.dialControl(ctx, actual, address, nil, owned)
	}, func(ctx context.Context) error {
		if err := owned.valid(); err != nil {
			return err
		}
		return r.nativeCurrent(ctx, true)
	})
	return owned, err
}
func (s *nodeChainAppendExecutionRetirement) valid() error {
	if s == nil || s.self != s || s.runtime == nil || s.lease == nil || s.lease.runtime != s.runtime || s.lease.self != s.lease || s.digest == "" {
		return errNodeChainAppendExecution
	}
	s.runtime.mu.Lock()
	retained := s.runtime.pending[s.lease] && !s.runtime.closed
	s.runtime.mu.Unlock()
	if !retained {
		return errNodeChainAppendExecution
	}
	s.lease.mu.Lock()
	leaseClosed, leaseIssued, candidate := s.lease.closed, s.lease.issued, s.lease.candidate
	s.lease.mu.Unlock()
	if leaseClosed || !leaseIssued {
		return errNodeChainAppendExecution
	}
	var digest string
	var err error
	if s.candidate != nil {
		if candidate != s.candidate || s.candidate.lease != s.lease || s.candidate.self != s.candidate {
			return errNodeChainAppendExecution
		}
		s.candidate.mu.Lock()
		issued, closed := s.candidate.issued, s.candidate.closed
		s.candidate.mu.Unlock()
		if !issued || closed {
			return errNodeChainAppendExecution
		}
		digest, err = nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-candidate-request-v1", s.candidate.request)
	} else {
		digest, err = nodeChainAppendExecutionDigest("routervpn-node-chain-prefix-request-v1", s.lease.request)
	}
	if err != nil || digest != s.digest {
		return errNodeChainAppendExecution
	}
	return nil
}
func (s *nodeChainAppendExecutionRetirement) stop(ctx context.Context) error {
	if ctx == nil || s.valid() != nil || s.io == nil {
		return errNodeChainAppendExecution
	}
	if s.candidate != nil {
		body, err := json.Marshal(s.candidate.request)
		if err != nil {
			return err
		}
		raw, err := s.io.exchangePrefixCandidate(ctx, "DELETE", body)
		if err != nil {
			return err
		}
		return multihoprelay.DecodeNodeChainPrefixCandidateStopAcknowledgement(raw, s.candidate.request)
	}
	body, err := json.Marshal(s.lease.request)
	if err != nil {
		return err
	}
	raw, err := s.io.exchangePrefix(ctx, "DELETE", body)
	if err != nil {
		return err
	}
	return multihoprelay.DecodeNodeChainPrefixStopAcknowledgement(raw, s.lease.request)
}
func (s *nodeChainAppendExecutionRetirement) close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.io == nil {
		return nil
	}
	return errors.Join(s.io.close(ctx), ctx.Err())
}
