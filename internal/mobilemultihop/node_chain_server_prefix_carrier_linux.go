//go:build linux

package mobilemultihop

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/multihoprelay"
)

func captureNodeChainPrefixCarrier(ctx, lifetime context.Context, source, sourceSHA string, target PhysicalEgress) (*NodeChainServerCarrier, error) {
	if ctx == nil || ctx.Err() != nil || lifetime == nil || lifetime.Err() != nil || !proofID.MatchString(sourceSHA) || target.Network != "tcp" && target.Network != "udp" {
		return nil, nodeChainServerCarrierError
	}
	owner, err := newNodeChainServerLinuxCarrier(lifetime, target)
	if err != nil {
		return nil, err
	}
	c := &NodeChainServerCarrier{source: source, sourceSHA: sourceSHA, family: 7, target: target, read: owner.observe, close: owner.closeContext, check: owner.admit, retired: owner.done}
	owner.authority.Store(c)
	c.snapshot, err = owner.observe(ctx)
	if err != nil || c.snapshot.validate(target) != nil || owner.invalid.Load() {
		owner.cancel()
		return c, errors.Join(err, nodeChainServerCarrierError)
	}
	c.seal = c.digest()
	if err = c.CurrentContext(ctx); err != nil {
		owner.cancel()
		return c, err
	}
	return c, nil
}
func NewNodeChainServerPrefixSessionContext(ctx, lifetime context.Context, policy *NodeChainServerPrefixPolicy, capture multihoprelay.NodeChainPrefixCapture) (*NodeChainServerPrefixSession, error) {
	if ctx == nil || ctx.Err() != nil || lifetime == nil || lifetime.Err() != nil || policy == nil || policy.BindCapture(capture) != nil {
		return nil, errNodeChainAppendExecution
	}
	s := &NodeChainServerPrefixSession{policy: policy, capturedPolicy: policy, capture: capture.Clone()}
	s.self = s
	if s.mixedStreamRoot() {
		s.mixedCloseGate = make(chan struct{}, 1)
	}
	var err error
	s.captureSHA, err = capture.Digest()
	if err != nil {
		return nil, err
	}
	if len(policy.nodes) > 0 {
		var target PhysicalEgress
		if (policy.record.Schema == 2 || policy.record.Schema == 4 || policy.record.Schema == 5) && policy.nodes[0].mode == "shadowsocks" {
			target, err = nodeChainPrefixStreamPhysical(policy.nodes[0], policy.record.Schema)
			if err != nil {
				return nil, err
			}
		} else {
			physical, err := policy.nodes[0].PhysicalEgress()
			if err != nil || len(physical) != 1 || physical[0].Network != "udp" {
				return nil, errNodeChainAppendExecution
			}
			target = physical[0]
		}
		s.carrier, err = captureNodeChainPrefixCarrier(ctx, lifetime, policy.source, policy.sourceSHA, target)
		if err != nil {
			return s, err
		}
		if s.mixedStreamRoot() {
			udp, targetErr := nodeChainPrefixStreamUDPPhysical(policy.nodes[0])
			if targetErr != nil {
				return s, targetErr
			}
			s.udpCarrier, err = captureNodeChainPrefixCarrier(ctx, lifetime, policy.source, policy.sourceSHA, udp)
			if err != nil {
				return s, err
			}
		}
		if err = s.bindConfig(); err != nil {
			return s, err
		}
	}
	s.seal = s.digest()
	return s, s.CurrentContext(ctx)
}
func NewNodeChainServerPrefixCandidateTargetContext(ctx, lifetime context.Context, session *NodeChainServerPrefixSession, c multihoprelay.NodeChainPrefixCandidateCapture) (*NodeChainServerPrefixCandidateTarget, error) {
	if ctx == nil || ctx.Err() != nil || lifetime == nil || lifetime.Err() != nil || session == nil || session.CurrentContext(ctx) != nil || c.Validate() != nil {
		return nil, errNodeChainAppendExecution
	}
	lease, err := c.Lease.Digest()
	if err != nil || lease != session.captureSHA {
		return nil, errNodeChainAppendExecution
	}
	source, err := session.policy.candidate(c)
	if err != nil {
		return nil, err
	}
	digest, err := c.Digest()
	if err != nil || time.Now().UnixMilli() >= c.Deadline.UnixMilli() {
		return nil, errNodeChainAppendExecution
	}
	t := &NodeChainServerPrefixCandidateTarget{session: session, capture: c.Clone(), captureSHA: digest, response: source}
	t.self = t
	if len(session.policy.nodes) == 0 {
		physical, err := session.policy.candidatePhysical(c)
		if err != nil {
			return nil, err
		}
		t.carrier, err = captureNodeChainPrefixCarrier(ctx, lifetime, session.policy.source, session.policy.sourceSHA, physical)
		if err != nil {
			return t, err
		}
		t.dialOptions, err = prefixCarrierDialOptions(t.carrier)
		if err != nil {
			return t, err
		}
	}
	t.seal = t.digest()
	return t, t.CurrentContext(ctx)
}
