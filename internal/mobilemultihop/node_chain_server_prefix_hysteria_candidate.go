package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"reflect"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// The original unfinished-prefix operation is the only reader of this request.
// Its companion identity is not a packet-key reservation or a complete route.
type NodeChainServerPrefixHysteriaEngine interface {
	ServerPrefixHysteriaCurrentContext(context.Context, *NodeChainServerPrefixCandidateHysteriaRequest) error
	DialServerPrefixHysteriaPacketContext(context.Context, *NodeChainServerPrefixCandidateHysteriaRequest) (net.Conn, error)
}

type NodeChainServerPrefixCandidateHysteriaRequest struct {
	self                                         *NodeChainServerPrefixCandidateHysteriaRequest
	reader                                       NodeChainServerPrefixHysteriaEngine
	target                                       *NodeChainServerPrefixCandidateTarget
	session                                      *NodeChainServerPrefixSession
	capture                                      multihoprelay.NodeChainPrefixCandidateCapture
	source                                       candidateResponseSource
	tag, privateAddress, optionsSHA, hysteriaSHA string
	grant                                        *nodeChainAppendExecutionPacketGrant
}

func (t *NodeChainServerPrefixCandidateTarget) NewHysteriaRequest(ctx context.Context, session *NodeChainServerPrefixSession, capture multihoprelay.NodeChainPrefixCandidateCapture, reader NodeChainServerPrefixHysteriaEngine) (*NodeChainServerPrefixCandidateHysteriaRequest, error) {
	if ctx == nil || ctx.Err() != nil || t == nil || t.session != session || session == nil ||
		!capture.Request.IsHysteria() || reader == nil || !reflect.TypeOf(reader).Comparable() {
		return nil, errNodeChainAppendExecution
	}
	tag, address, method, password, privateAddress, _, err := t.ReadContext(ctx, session, capture)
	identity, identityErr := session.policy.HysteriaCandidateRuntimeIdentity(capture)
	if err != nil || identityErr != nil || identity != capture.Request.CandidateHysteriaSHA256 ||
		address != t.response.Target.Address || method != "" || password != "" ||
		t.response.Hysteria2Options == "" || t.response.PacketOptions != "" || t.response.ClientKey != "" || t.response.ServerKey != "" {
		return nil, errNodeChainAppendExecution
	}
	if tag == "" {
		if t.carrier == nil || len(session.policy.nodes) != 0 || t.carrier.target.Network != "udp" {
			return nil, errNodeChainAppendExecution
		}
	} else if t.carrier != nil || session.policy.plan == nil || session.policy.prefix == nil ||
		session.policy.plan.appendSource != session.policy.prefix {
		return nil, errNodeChainAppendExecution
	}
	q := &NodeChainServerPrefixCandidateHysteriaRequest{reader: reader, target: t, session: session,
		capture: capture.Clone(), source: t.response, tag: tag, privateAddress: privateAddress,
		optionsSHA: externalDigest([]byte(t.response.Hysteria2Options)), hysteriaSHA: identity}
	q.self = q
	if capture.Request.ChildPurpose == multihoprelay.NodeChainPrefixComparePair {
		q.grant, err = newNodeChainAppendExecutionPacketGrant(q, capture.Request.ExternalTarget, q.nativePacketCurrent)
		if err != nil {
			return nil, err
		}
	}
	return q, nil
}

func (r *NodeChainServerPrefixCandidateHysteriaRequest) ReadServerPrefixHysteria(ctx context.Context, reader NodeChainServerPrefixHysteriaEngine, session *NodeChainServerPrefixSession, capture multihoprelay.NodeChainPrefixCandidateCapture) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.self != r || reader == nil || !reflect.TypeOf(reader).Comparable() || reader != r.reader ||
		session == nil || session != r.session || r.target == nil || r.target.session != session || !reflect.DeepEqual(capture, r.capture) ||
		!capture.Request.IsHysteria() || r.source.Hysteria2Options == "" || r.optionsSHA != externalDigest([]byte(r.source.Hysteria2Options)) ||
		r.source != r.target.response {
		return "", "", errNodeChainAppendExecution
	}
	tag, address, method, password, privateAddress, _, err := r.target.ReadContext(ctx, session, capture)
	identity, identityErr := session.policy.HysteriaCandidateRuntimeIdentity(capture)
	if err != nil || identityErr != nil || identity != r.hysteriaSHA || identity != capture.Request.CandidateHysteriaSHA256 ||
		tag != r.tag || address != r.source.Target.Address || privateAddress != r.privateAddress || method != "" || password != "" {
		return "", "", errNodeChainAppendExecution
	}
	if err = reader.ServerPrefixHysteriaCurrentContext(ctx, r); err != nil {
		return "", "", err
	}
	return tag, address, nil
}

func (r *NodeChainServerPrefixCandidateHysteriaRequest) HysteriaSHA256() string {
	if r == nil || r.self != r {
		return ""
	}
	pair, err := r.capture.HysteriaPair()
	if err != nil {
		return ""
	}
	digest, err := pair.Digest()
	if err != nil || digest != r.hysteriaSHA {
		return ""
	}
	return digest
}
func (r *NodeChainServerPrefixCandidateHysteriaRequest) nativePacketCurrent(ctx context.Context) error {
	if r == nil {
		return errNodeChainAppendExecution
	}
	_, _, err := r.ReadServerPrefixHysteria(ctx, r.reader, r.session, r.capture)
	return err
}
func (r *NodeChainServerPrefixCandidateHysteriaRequest) nativePacketSource() candidateResponseSource {
	return r.source
}
func (r *NodeChainServerPrefixCandidateHysteriaRequest) nativePacketMode() string {
	return r.capture.Request.CandidateMode
}
func (r *NodeChainServerPrefixCandidateHysteriaRequest) nativePacketAddress() string {
	return r.source.Target.Address
}
func (r *NodeChainServerPrefixCandidateHysteriaRequest) dial(ctx context.Context) (net.Conn, error) {
	if err := r.nativePacketCurrent(ctx); err != nil {
		return nil, err
	}
	conn, err := r.reader.DialServerPrefixHysteriaPacketContext(ctx, r)
	return conn, errors.Join(err, r.nativePacketCurrent(ctx), ctx.Err())
}

// The same original stream-only client serves the private and one exact public
// Compare grant. Neither grant can escape its original request or destination.
func (r *NodeChainServerPrefixCandidateHysteriaRequest) DialProbe(ctx context.Context, endpoint NodeChainCandidateEndpoint, address string) (net.Conn, error) {
	if err := r.nativePacketCurrent(ctx); err != nil {
		return nil, err
	}
	original, ok := endpoint.(nodeChainAppendExecutionPacketEndpoint)
	if !ok || original.appendExecutionPacketRequest() != r {
		return nil, errNodeChainAppendExecution
	}
	var conn net.Conn
	var err error
	if address == r.privateAddress {
		conn, err = original.dialAppendExecutionPrivate(ctx, r, address)
	} else {
		if r.grant == nil || r.grant.validate(ctx, r, address) != nil {
			return nil, errNodeChainAppendExecution
		}
		conn, err = original.dialAppendExecutionPublic(ctx, r.grant, address)
	}
	return conn, errors.Join(err, r.nativePacketCurrent(ctx), ctx.Err())
}

func (r *NodeChainServerPrefixCandidateHysteriaRequest) ReplyHysteria(ctx context.Context, original net.Conn, nonce, request string) (string, error) {
	if r.nativePacketCurrent(ctx) != nil || r.capture.Request.ChildPurpose != multihoprelay.NodeChainPrefixPrivateResponse ||
		original == nil || !hopmeasure.ValidCandidateNonce(nonce) || !constantCandidateChallenge(r.source, nonce, request) {
		return "", errNodeChainAppendExecution
	}
	used := false
	const tag = "original-server-prefix-hysteria-candidate"
	response := ""
	err := r.source.exchangeChallenge(ctx, func(call context.Context, actual, address string) (net.Conn, error) {
		if used || actual != tag || address != r.privateAddress || r.nativePacketCurrent(call) != nil {
			return nil, errNodeChainAppendExecution
		}
		used = true
		return original, nil
	}, tag, nonce, func(authenticated string) error {
		if r.nativePacketCurrent(ctx) != nil {
			return errNodeChainAppendExecution
		}
		response = authenticated
		return ctx.Err()
	})
	if err != nil || !used || response == "" {
		return "", errors.Join(err, errNodeChainAppendExecution)
	}
	return response, nil
}
