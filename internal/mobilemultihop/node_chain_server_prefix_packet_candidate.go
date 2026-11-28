package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"reflect"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// This interface belongs only to an actual unfinished-prefix operation. The
// complete selected Server policy and its packet request are not accepted.
type NodeChainServerPrefixPacketEngine interface {
	ServerPrefixCandidateCurrentContext(context.Context, *NodeChainServerPrefixCandidatePacketRequest) error
	DialServerPrefixCandidatePacketContext(context.Context, *NodeChainServerPrefixCandidatePacketRequest) (net.Conn, error)
}

type NodeChainServerPrefixCandidatePacketRequest struct {
	self                                        *NodeChainServerPrefixCandidatePacketRequest
	reader                                      NodeChainServerPrefixPacketEngine
	target                                      *NodeChainServerPrefixCandidateTarget
	session                                     *NodeChainServerPrefixSession
	capture                                     multihoprelay.NodeChainPrefixCandidateCapture
	source                                      candidateResponseSource
	tag, privateAddress, optionsSHA, pairingSHA string
	grant                                       *nodeChainAppendExecutionPacketGrant
}

func (t *NodeChainServerPrefixCandidateTarget) NewPacketRequest(ctx context.Context, session *NodeChainServerPrefixSession, capture multihoprelay.NodeChainPrefixCandidateCapture, reader NodeChainServerPrefixPacketEngine) (*NodeChainServerPrefixCandidatePacketRequest, error) {
	if ctx == nil || ctx.Err() != nil || t == nil || t.session != session || session == nil ||
		!capture.Request.IsPacket() || reader == nil || !reflect.TypeOf(reader).Comparable() {
		return nil, errNodeChainAppendExecution
	}
	tag, address, method, password, privateAddress, _, err := t.ReadContext(ctx, session, capture)
	pair, pairErr := capture.PacketPair()
	keys, pairing, keyErr := session.policy.PacketCandidateRuntimeKeys(capture)
	if err != nil || pairErr != nil || keyErr != nil || len(keys) != 3 ||
		keys[0] != pair.ServerClientPublicKey || keys[1] != pair.PeerPublicKey || keys[2] != pair.LocalClientPublicKey ||
		address != t.response.Target.Address || method != "" || password != "" ||
		t.response.PacketOptions == "" || t.response.Hysteria2Options != "" ||
		t.response.ClientKey != pair.ServerClientPublicKey || t.response.ServerKey != pair.PeerPublicKey {
		return nil, errNodeChainAppendExecution
	}
	source := t.response
	if tag == "" {
		if t.carrier == nil || len(session.policy.nodes) != 0 {
			return nil, errNodeChainAppendExecution
		}
		found := false
		for i, candidate := range session.policy.record.PacketCandidatePairs {
			if candidate == pair && i < len(session.policy.candidates) {
				source.PacketOptions, err = nodeChainPrefixPacketOptions(session.policy.candidates[i], t.carrier)
				if err != nil {
					return nil, err
				}
				found = true
				break
			}
		}
		if !found {
			return nil, errNodeChainAppendExecution
		}
	} else if t.carrier != nil || session.policy.plan == nil || session.policy.prefix == nil ||
		session.policy.plan.appendSource != session.policy.prefix {
		return nil, errNodeChainAppendExecution
	}
	q := &NodeChainServerPrefixCandidatePacketRequest{reader: reader, target: t, session: session,
		capture: capture.Clone(), source: source, tag: tag, privateAddress: privateAddress,
		optionsSHA: externalDigest([]byte(source.PacketOptions)), pairingSHA: pairing}
	q.self = q
	if capture.Request.ChildPurpose == multihoprelay.NodeChainPrefixComparePair {
		q.grant, err = newNodeChainAppendExecutionPacketGrant(q, capture.Request.ExternalTarget, q.nativePacketCurrent)
		if err != nil {
			return nil, err
		}
	}
	return q, nil
}

func (r *NodeChainServerPrefixCandidatePacketRequest) ReadServerPrefix(ctx context.Context, reader NodeChainServerPrefixPacketEngine, session *NodeChainServerPrefixSession, capture multihoprelay.NodeChainPrefixCandidateCapture) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.self != r || reader == nil ||
		!reflect.TypeOf(reader).Comparable() || reader != r.reader || session == nil || session != r.session ||
		r.target == nil || r.target.session != session || !reflect.DeepEqual(capture, r.capture) ||
		!capture.Request.IsPacket() || r.source.PacketOptions == "" || r.optionsSHA != externalDigest([]byte(r.source.PacketOptions)) ||
		!nodeChainPrefixPacketResponseEqual(r.source, r.target.response) {
		return "", "", errNodeChainAppendExecution
	}
	tag, address, method, password, privateAddress, _, err := r.target.ReadContext(ctx, session, capture)
	if err != nil || tag != r.tag || address != r.source.Target.Address || privateAddress != r.privateAddress ||
		method != "" || password != "" {
		return "", "", errNodeChainAppendExecution
	}
	keys, pairing, err := session.policy.PacketCandidateRuntimeKeys(capture)
	if err != nil || pairing != r.pairingSHA || len(keys) != 3 ||
		keys[0] != r.source.ClientKey || keys[1] != r.source.ServerKey {
		return "", "", errNodeChainAppendExecution
	}
	if err = reader.ServerPrefixCandidateCurrentContext(ctx, r); err != nil {
		return "", "", err
	}
	return tag, address, nil
}

func (r *NodeChainServerPrefixCandidatePacketRequest) PairingSHA256() string {
	if r == nil || r.self != r {
		return ""
	}
	pair, err := r.capture.PacketPair()
	if err != nil {
		return ""
	}
	digest, err := pair.Digest()
	if err != nil || digest != r.pairingSHA {
		return ""
	}
	return digest
}

func (r *NodeChainServerPrefixCandidatePacketRequest) nativePacketCurrent(ctx context.Context) error {
	if r == nil {
		return errNodeChainAppendExecution
	}
	_, _, err := r.ReadServerPrefix(ctx, r.reader, r.session, r.capture)
	return err
}
func (r *NodeChainServerPrefixCandidatePacketRequest) nativePacketSource() candidateResponseSource {
	return r.source
}
func (r *NodeChainServerPrefixCandidatePacketRequest) nativePacketMode() string {
	return r.capture.Request.CandidateMode
}
func (r *NodeChainServerPrefixCandidatePacketRequest) nativePacketAddress() string {
	return r.source.Target.Address
}
func (r *NodeChainServerPrefixCandidatePacketRequest) dial(ctx context.Context) (net.Conn, error) {
	if err := r.nativePacketCurrent(ctx); err != nil {
		return nil, err
	}
	conn, err := r.reader.DialServerPrefixCandidatePacketContext(ctx, r)
	return conn, errors.Join(err, r.nativePacketCurrent(ctx), ctx.Err())
}

// The exact original endpoint serves both one-use Compare destinations. The
// separate private-only endpoint method is unchanged for every ordinary caller.
func (r *NodeChainServerPrefixCandidatePacketRequest) DialProbe(ctx context.Context, endpoint NodeChainCandidateEndpoint, address string) (net.Conn, error) {
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

// The worker has already retained this original stream from DialProbe. Reply
// performs the same real fresh private HTTP/HMAC exchange, with no cipher layer.
func (r *NodeChainServerPrefixCandidatePacketRequest) ReplyPacket(ctx context.Context, original net.Conn, nonce, request string) (string, error) {
	if r.nativePacketCurrent(ctx) != nil || r.capture.Request.ChildPurpose != multihoprelay.NodeChainPrefixPrivateResponse ||
		original == nil || !hopmeasure.ValidCandidateNonce(nonce) || !constantCandidateChallenge(r.source, nonce, request) {
		return "", errNodeChainAppendExecution
	}
	used := false
	const tag = "original-server-prefix-packet-candidate"
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
