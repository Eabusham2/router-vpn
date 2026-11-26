package mobilemultihop

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// Only the independent registered candidate source supplies its transport
// credential. The original active lease must belong to this exact entry peer.
func (p *NodeChainServerPolicy) PublicCandidateResponseInput(c multihoprelay.NodeChainCandidateCapture) (string, error) {
	if c.Request.Schema != 3 || c.Validate() != nil || p.validateCapture() != nil || !p.descriptor.SameExternalFinalEntry(c.Lease.Source) {
		return "", nodeChainServerError
	}
	for _, m := range p.externalFinal.members {
		if m.source != c.Request.CandidateSourceSHA256 || m.id() != c.Request.CandidateID {
			continue
		}
		if _, err := NewNodeChainServerPublicCandidateResponder(c, m.input); err != nil {
			return "", err
		}
		return m.input, nil
	}
	return "", nodeChainServerError
}

type NodeChainServerPublicCandidateResponder struct {
	original *NodeChainServerPublicCandidateResponder
	capture  string
	source   candidatePublicResponseSource
}

func NewNodeChainServerPublicCandidateResponder(c multihoprelay.NodeChainCandidateCapture, input string) (*NodeChainServerPublicCandidateResponder, error) {
	digest, err := c.Digest()
	if err != nil || c.Request.Schema != 3 || len(input) == 0 || len(input) > NodeChainInputLimit {
		return nil, nodeChainServerError
	}
	s, err := parseCandidatePublicResponseSource(input)
	if err != nil || s.Target.ID != c.Request.CandidateID || s.Target.SourceSHA256 != c.Request.CandidateSourceSHA256 || s.Target.Address != c.Request.Address {
		return nil, nodeChainServerError
	}
	r := &NodeChainServerPublicCandidateResponder{capture: digest, source: s}
	r.original = r
	return r, nil
}

// A candidate is admitted against every original registered member once.
// Socket and status reads then check the whole current policy and both live
// captures against the independently retained originals before using its tag.
type nodeChainServerPublicCandidateTarget struct {
	owner     *NodeChainServerCandidateTarget
	capture   multihoprelay.NodeChainCandidateCapture
	digest    string
	policy    *nodeChainRegisteredServerSnapshot
	responder *NodeChainServerPublicCandidateResponder
	source    candidatePublicResponseSource
}

func (o *nodeChainServerPublicCandidateTarget) matches(c multihoprelay.NodeChainCandidateCapture) bool {
	if reflect.DeepEqual(c, o.capture) {
		return true
	}
	// Preserve canonical equivalence for a capture reopened by another decoder.
	digest, err := c.Digest()
	return err == nil && digest == o.digest
}

func (t *NodeChainServerCandidateTarget) readPublicCandidate(p *NodeChainServerPolicy, c multihoprelay.NodeChainCandidateCapture) (string, string, error) {
	o := t.publicOriginal
	if o == nil || o.owner != t || o.responder == nil || o.responder.original != o.responder || o.responder.capture != o.digest || o.responder.source != o.source ||
		p.externalFinal == nil || o.policy == nil || p.externalFinal.original != o.policy || !o.matches(t.capture) || !o.matches(c) {
		return "", "", nodeChainServerError
	}
	// binding compares the fresh descriptor, DNS policy, graph, targets and
	// every member's actual transport and credentials against the original.
	if _, err := p.binding(c.Lease); err != nil {
		return "", "", err
	}
	index := o.capture.Request.Position - 1
	if t.node != nil || t.stream != p.externalFinal.members[index] || t.tag == "" || t.tag != p.proofs[index].Tag {
		return "", "", nodeChainServerError
	}
	return t.tag, o.capture.Request.Address, nil
}

func (p *NodeChainServerPolicy) PublicResponseCandidateTarget(c multihoprelay.NodeChainCandidateCapture, r *NodeChainServerPublicCandidateResponder) (*NodeChainServerCandidateTarget, error) {
	seal, err := c.Digest()
	if err != nil || r == nil || r.original != r || c.Request.Schema != 3 || r.capture != seal || p.validateCapture() != nil || p.externalFinal == nil || p.externalFinal.original == nil {
		return nil, nodeChainServerError
	}
	for _, m := range p.externalFinal.members {
		occupied, err := publicCandidateMember(m)
		if err != nil || occupied.Target.ID == r.source.Target.ID || occupied.Target.Address == r.source.Target.Address || occupied.keyIdentity == r.source.keyIdentity {
			return nil, nodeChainServerError
		}
	}
	target, err := p.originalCandidateTarget(c)
	if err != nil {
		return nil, err
	}
	target.publicOriginal = &nodeChainServerPublicCandidateTarget{owner: target, capture: c.Clone(), digest: seal, policy: p.externalFinal.original, responder: r, source: r.source}
	return target, nil
}

func publicCandidateSampleMAC(c multihoprelay.NodeChainCandidateCapture, digest, nonce, phase, elapsed string) string {
	key, err := hex.DecodeString(c.Request.Password)
	if err != nil || len(key) != 32 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	clear(key)
	fmt.Fprintf(mac, "routervpn-external-final-public-response-v1\x00%s\x00%s\x00%s\x00%s", digest, nonce, phase, elapsed)
	return hex.EncodeToString(mac.Sum(nil))
}

func externalFinalPublicChallenge(c multihoprelay.NodeChainCandidateCapture, nonce string) (string, error) {
	digest, err := c.Digest()
	if err != nil || c.Request.Schema != 3 || !hopmeasure.ValidCandidateNonce(nonce) {
		return "", nodeChainServerError
	}
	return publicCandidateSampleMAC(c, digest, nonce, "request", ""), nil
}

// The response carries a fixed-width worker-measured interval followed by its
// MAC. The authenticated operation/nonce and independent expected IP bind it
// to a single checked HTTPS response through the captured candidate.
func readExternalFinalPublicResponse(c multihoprelay.NodeChainCandidateCapture, nonce, frame string) (time.Duration, error) {
	digest, err := c.Digest()
	if err != nil || c.Request.Schema != 3 || !hopmeasure.ValidCandidateNonce(nonce) || len(frame) != 80 {
		return 0, nodeChainServerError
	}
	elapsed, err := strconv.ParseUint(frame[:16], 16, 63)
	if err != nil || elapsed == 0 || elapsed > uint64(5*time.Second) || fmt.Sprintf("%016x", elapsed) != frame[:16] || !hmac.Equal([]byte(frame[16:]), []byte(publicCandidateSampleMAC(c, digest, nonce, "verified", frame[:16]))) {
		return 0, nodeChainServerError
	}
	return time.Duration(elapsed), nil
}

func (r *NodeChainServerPublicCandidateResponder) Reply(ctx context.Context, c multihoprelay.NodeChainCandidateCapture, original net.Conn, nonce, request string, wrap func(context.Context, net.Conn, string, string, string) (net.Conn, error)) (string, error) {
	return r.reply(ctx, c, original, nonce, request, wrap, nil)
}
func (r *NodeChainServerPublicCandidateResponder) reply(ctx context.Context, c multihoprelay.NodeChainCandidateCapture, original net.Conn, nonce, request string, wrap func(context.Context, net.Conn, string, string, string) (net.Conn, error), trust *tls.Config) (string, error) {
	digest, err := c.Digest()
	if err != nil || c.Request.Schema != 3 || !hopmeasure.ValidCandidateNonce(nonce) || r == nil || r.original != r || r.capture != digest || ctx == nil || ctx.Err() != nil || original == nil || wrap == nil || !hmac.Equal([]byte(publicCandidateSampleMAC(c, digest, nonce, "request", "")), []byte(request)) {
		return "", nodeChainServerError
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	used := false
	dial := func(call context.Context, tag, endpoint string) (net.Conn, error) {
		if used || tag != "registered-public-candidate" || endpoint != r.source.Target.Address || call.Err() != nil {
			return nil, nodeChainServerError
		}
		used = true
		return original, nil
	}
	var interval hopmeasure.Interval
	var duration time.Duration
	_, err = externalProofHTTPMeasured(bounded, func(call context.Context, tag, destination string) (net.Conn, error) {
		if destination != "1.1.1.1:443" {
			return nil, nodeChainServerError
		}
		return dialCandidateStream(call, dial, wrap, tag, r.source.Target.Address, r.source.Method, r.source.Password, destination)
	}, "registered-public-candidate", hopmeasure.CandidatePublicResponseEndpoint+"?routervpn_candidate="+nonce, "", "", trust, func() error {
		var err error
		interval, err = hopmeasure.StartInterval()
		return err
	}, func(body []byte) error {
		if err := externalTraceAddress(body, r.source.ExpectedIP); err != nil {
			return err
		}
		var err error
		duration, err = interval.Duration()
		return err
	})
	if err != nil || !used || duration <= 0 || duration > 5*time.Second || bounded.Err() != nil {
		return "", errors.Join(nodeChainServerError, err, bounded.Err())
	}
	elapsed := fmt.Sprintf("%016x", duration.Nanoseconds())
	return elapsed + publicCandidateSampleMAC(c, digest, nonce, "verified", elapsed), nil
}
