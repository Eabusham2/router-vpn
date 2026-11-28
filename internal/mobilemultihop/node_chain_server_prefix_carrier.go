package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// The lease owns the real server suffix. Zero suffix retains no fabricated
// graph: only a later original candidate operation can acquire physical I/O.
type NodeChainServerPrefixSession struct {
	self                     *NodeChainServerPrefixSession
	policy, capturedPolicy   *NodeChainServerPrefixPolicy
	capture                  multihoprelay.NodeChainPrefixCapture
	captureSHA, config, seal string
	carrier                  *NodeChainServerCarrier
	udpCarrier               *NodeChainServerCarrier
	mixedCloseGate           chan struct{}
	mixedCloseErr            error
	closed                   atomic.Bool
}

func (s *NodeChainServerPrefixSession) digest() string {
	if s == nil || s.policy == nil {
		return ""
	}
	carrier := ""
	if s.carrier != nil {
		carrier = s.carrier.seal
	}
	if s.udpCarrier != nil {
		return desktopExternalObjectDigest([]any{"routervpn-server-prefix-mixed-session-v1", s.policy.seal, s.capture, s.captureSHA, s.config, carrier, s.udpCarrier.seal})
	}
	return desktopExternalObjectDigest([]any{"routervpn-server-prefix-session-v1", s.policy.seal, s.capture, s.captureSHA, s.config, carrier})
}
func (s *NodeChainServerPrefixSession) validate() error {
	if s == nil || s.self != s || s.policy == nil || s.policy != s.capturedPolicy || s.policy.BindCapture(s.capture) != nil || s.closed.Load() || s.seal == "" || s.seal != s.digest() {
		return errNodeChainAppendExecution
	}
	digest, err := s.capture.Digest()
	if err != nil || digest != s.captureSHA || len(s.policy.nodes) == 0 && (s.carrier != nil || s.config != "") || len(s.policy.nodes) > 0 && (s.carrier == nil || s.config == "") {
		return errNodeChainAppendExecution
	}
	if s.mixedStreamRoot() {
		if !s.mixedStreamCarriersMatch() {
			return nodeChainServerCarrierError
		}
	} else if s.udpCarrier != nil {
		return nodeChainServerCarrierError
	}
	return nil
}
func (s *NodeChainServerPrefixSession) CurrentContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.validate() != nil {
		return errors.Join(errNodeChainAppendExecution, contextError(ctx))
	}
	if s.udpCarrier != nil {
		tcpErr := s.carrier.CurrentContext(ctx)
		udpErr := s.udpCarrier.CurrentContext(ctx)
		return errors.Join(tcpErr, udpErr)
	}
	if s.carrier != nil {
		return s.carrier.CurrentContext(ctx)
	}
	return ctx.Err()
}
func (s *NodeChainServerPrefixSession) ConfigContext(ctx context.Context) (string, error) {
	if err := s.CurrentContext(ctx); err != nil {
		return "", err
	}
	return s.config, nil
}
func (s *NodeChainServerPrefixSession) ProofsContext(ctx context.Context) ([]NodeChainServerProof, error) {
	if err := s.CurrentContext(ctx); err != nil {
		return nil, err
	}
	return s.policy.Proofs()
}
func (s *NodeChainServerPrefixSession) CloseContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.closed.Store(true)
	if s.udpCarrier != nil {
		if ctx == nil || s.mixedCloseGate == nil {
			return errNodeChainAppendExecution
		}
		select {
		case s.mixedCloseGate <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		defer func() { <-s.mixedCloseGate }()
		tcpErr := s.carrier.CloseContext(ctx)
		udpErr := s.udpCarrier.CloseContext(ctx)
		if s.mixedCloseErr == nil {
			s.mixedCloseErr = errors.Join(tcpErr, udpErr)
		}
		return s.mixedCloseErr
	}
	if s.carrier != nil {
		return s.carrier.CloseContext(ctx)
	}
	if ctx == nil {
		return errNodeChainAppendExecution
	}
	return ctx.Err()
}
func (s *NodeChainServerPrefixSession) bindConfig() error {
	if s.policy.validate() != nil || len(s.policy.nodes) == 0 || s.carrier == nil || !s.carrier.sealed() {
		return errNodeChainAppendExecution
	}
	if (s.policy.record.Schema == 2 || s.policy.record.Schema == 4 || s.policy.record.Schema == 5) && s.policy.nodes[0].mode == "shadowsocks" {
		// A real SS root is a TCP carrier, not a packet ancestor. The original
		// typed append graph remains unchanged; no endpoint MTU is fabricated.
		target, err := nodeChainPrefixStreamPhysical(s.policy.nodes[0], s.policy.record.Schema)
		if err != nil || target != s.carrier.target || s.policy.prefix.record.Schema != 3 {
			return nodeChainServerCarrierError
		}
	} else if s.policy.record.Schema == 5 && s.policy.nodes[0].mode == "hysteria2" {
		// HY2 retains its actual UDP carrier and exact QUIC options. It is not
		// a packet ancestor and supplies no synthetic endpoint MTU allowance.
		closure, err := nodeMultihopPredecessor(s.policy.nodes[0])
		physical, physicalErr := s.policy.nodes[0].PhysicalEgress()
		if err != nil || !nodeChainCapturedHysteriaClosure(s.policy.nodes[0], closure) || physicalErr != nil ||
			len(physical) != 1 || physical[0].Network != "udp" || physical[0] != s.carrier.target ||
			s.policy.prefix == nil || s.policy.prefix.record.Schema != 3 {
			return nodeChainServerCarrierError
		}
	} else {
		closure, err := nodeMultihopPredecessor(s.policy.nodes[0])
		if err != nil {
			return err
		}
		requested, err := mtuNumber(closure.final["mtu"])
		if err != nil {
			return err
		}
		if err = s.carrier.apply(s.policy.nodes[0], closure); err != nil {
			return err
		}
		actual, err := mtuNumber(closure.final["mtu"])
		if err != nil || actual != requested {
			return nodeChainServerCarrierError
		}
	}
	if s.mixedStreamRoot() {
		if err := s.validateMixedStreamPacketBounds(); err != nil {
			return err
		}
	}
	// No retained endpoint is silently resized to fit a physical route. The
	// original typed graph and every packet envelope must already fit this owner.
	var graph map[string]any
	if exactJSON([]byte(s.policy.config), &graph, 4<<20) != nil {
		return errNodeChainAppendExecution
	}
	if s.carrier.bind(graph, s.policy.prefix.proofs[0].Tag) != nil {
		return nodeChainServerCarrierError
	}
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return errNodeChainAppendExecution
	}
	s.config = string(raw)
	return nil
}

// Each candidate retains its exact registered source and operation capture.
// Direct (zero-suffix) candidates additionally own their original TCP route.
type NodeChainServerPrefixCandidateTarget struct {
	self              *NodeChainServerPrefixCandidateTarget
	session           *NodeChainServerPrefixSession
	capture           multihoprelay.NodeChainPrefixCandidateCapture
	captureSHA        string
	response          candidateResponseSource
	carrier           *NodeChainServerCarrier
	dialOptions, seal string
	closed            atomic.Bool
}

func (t *NodeChainServerPrefixCandidateTarget) digest() string {
	if t == nil || t.session == nil {
		return ""
	}
	carrier := ""
	if t.carrier != nil {
		carrier = t.carrier.seal
	}
	return desktopExternalObjectDigest([]any{"routervpn-server-prefix-candidate-target-v1", t.session.seal, t.capture, t.captureSHA, t.response, carrier, t.dialOptions})
}
func (t *NodeChainServerPrefixCandidateTarget) CurrentContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || t == nil || t.self != t || t.session == nil || t.closed.Load() || t.seal == "" || t.digest() != t.seal {
		return errNodeChainAppendExecution
	}
	if err := t.session.CurrentContext(ctx); err != nil {
		return err
	}
	source, err := t.session.policy.candidate(t.capture)
	if err != nil || !reflect.DeepEqual(source, t.response) {
		return errNodeChainAppendExecution
	}
	if t.carrier != nil {
		return t.carrier.CurrentContext(ctx)
	}
	return ctx.Err()
}

// These native options are derived from the original capture, never an HTTP
// supplied destination. A nonempty tag identifies the exact retained suffix.
func (t *NodeChainServerPrefixCandidateTarget) ReadContext(ctx context.Context, session *NodeChainServerPrefixSession, c multihoprelay.NodeChainPrefixCandidateCapture) (tag, address, method, password, privateAddress, dialOptions string, err error) {
	fail := func() (string, string, string, string, string, string, error) {
		return "", "", "", "", "", "", errNodeChainAppendExecution
	}
	if t == nil || t.session != session || t.CurrentContext(ctx) != nil {
		return fail()
	}
	digest, e := c.Digest()
	if e != nil || digest != t.captureSHA {
		return fail()
	}
	if len(session.policy.nodes) > 0 {
		tag = session.policy.prefix.proofs[len(session.policy.prefix.proofs)-1].Tag
		if t.carrier != nil || t.dialOptions != "" {
			return fail()
		}
	} else if t.carrier == nil || t.dialOptions == "" {
		return fail()
	}
	api, e := privateAPI(t.response.API)
	if e != nil {
		return fail()
	}
	return tag, t.response.Target.Address, t.response.Method, t.response.Password, api.Host, t.dialOptions, nil
}
func (t *NodeChainServerPrefixCandidateTarget) Reply(ctx context.Context, original net.Conn, nonce, request string, wrap func(context.Context, net.Conn, string, string, string) (net.Conn, error)) (string, error) {
	if t.CurrentContext(ctx) != nil || t.capture.Request.ChildPurpose != "private-agent-response" || original == nil || wrap == nil || !hopmeasure.ValidCandidateNonce(nonce) || !constantCandidateChallenge(t.response, nonce, request) {
		return "", errNodeChainAppendExecution
	}
	used := false
	const tag = "original-server-prefix-candidate"
	dial := func(call context.Context, owner, address string) (net.Conn, error) {
		if used || owner != tag || address != t.response.Target.Address || t.CurrentContext(call) != nil {
			return nil, errNodeChainAppendExecution
		}
		used = true
		return original, nil
	}
	response := ""
	if err := t.response.exchangeNonce(ctx, dial, wrap, tag, nonce, func(authenticated string) error {
		if t.CurrentContext(ctx) != nil {
			return errNodeChainAppendExecution
		}
		response = authenticated
		return ctx.Err()
	}); err != nil || !used || response == "" {
		return "", errors.Join(err, errNodeChainAppendExecution)
	}
	return response, nil
}
func (t *NodeChainServerPrefixCandidateTarget) CloseContext(ctx context.Context) error {
	if t == nil {
		return nil
	}
	t.closed.Store(true)
	if t.carrier != nil {
		return t.carrier.CloseContext(ctx)
	}
	if ctx == nil {
		return errNodeChainAppendExecution
	}
	return ctx.Err()
}
func constantCandidateChallenge(source candidateResponseSource, nonce, request string) bool {
	return hmac.Equal([]byte(request), []byte(hopmeasure.CandidateChallengeMAC(source.Token, source.NodeID, nonce, false)))
}
func prefixCarrierDialOptions(carrier *NodeChainServerCarrier) (string, error) {
	if carrier == nil || !carrier.sealed() {
		return "", nodeChainServerCarrierError
	}
	binding := map[string]string{"bind_interface": carrier.snapshot.InterfaceName}
	field := "inet4_bind_address"
	if netip.MustParseAddr(carrier.snapshot.SourceAddress).Is6() {
		field = "inet6_bind_address"
	}
	binding[field] = carrier.snapshot.SourceAddress
	raw, err := json.Marshal(binding)
	return string(raw), err
}
