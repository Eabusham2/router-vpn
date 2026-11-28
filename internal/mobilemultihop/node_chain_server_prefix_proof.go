package mobilemultihop

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"time"
)

// This is exclusively a real retained server suffix. Its empty proof set is
// meaningful for a zero suffix and never grants full-path, DNS or public Ready.
type NodeChainServerPrefixBinding struct {
	SourceSHA256  string `json:"source_sha256"`
	CaptureSHA256 string `json:"capture_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
}
type NodeChainServerPrefixProofEngine interface {
	ObservePrefixContext(context.Context, *NodeChainServerPrefixSession) (NodeChainServerPrefixBinding, error)
	DialPrefixProofContext(context.Context, *NodeChainServerPrefixSession, string, string) (net.Conn, error)
}
type NodeChainServerPrefixProofResult struct {
	Binding  NodeChainServerPrefixBinding
	Prefixes []NodeChainServerPrefixResult
	ProvenAt time.Time
}

func (s *NodeChainServerPrefixSession) BindingContext(ctx context.Context) (NodeChainServerPrefixBinding, error) {
	if err := s.CurrentContext(ctx); err != nil {
		return NodeChainServerPrefixBinding{}, err
	}
	configSHA := ""
	if s.config != "" {
		sum := sha256.Sum256([]byte(s.config))
		configSHA = hex.EncodeToString(sum[:])
	}
	return NodeChainServerPrefixBinding{s.policy.sourceSHA, s.captureSHA, configSHA}, nil
}
func (s *NodeChainServerPrefixSession) ProveContext(ctx context.Context, engine NodeChainServerPrefixProofEngine) (NodeChainServerPrefixProofResult, error) {
	return s.provePrefix(ctx, engine, nil)
}
func (s *NodeChainServerPrefixSession) provePrefix(ctx context.Context, engine NodeChainServerPrefixProofEngine, testTLS *tls.Config) (NodeChainServerPrefixProofResult, error) {
	bad := errNodeChainAppendExecution
	fail := func() (NodeChainServerPrefixProofResult, error) { return NodeChainServerPrefixProofResult{}, bad }
	if ctx == nil || ctx.Err() != nil || engine == nil {
		return fail()
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return fail()
	}
	binding, err := s.BindingContext(ctx)
	if err != nil {
		return fail()
	}
	current := func(call context.Context) error {
		expected, e := s.BindingContext(call)
		if e != nil || expected != binding {
			return bad
		}
		actual, e := engine.ObservePrefixContext(call, s)
		if e != nil || actual != binding || call.Err() != nil {
			return bad
		}
		return nil
	}
	if current(ctx) != nil {
		return fail()
	}
	targets, err := s.ProofsContext(ctx)
	if err != nil {
		return fail()
	}
	dial := func(call context.Context, tag, address string) (net.Conn, error) {
		allowed := false
		for _, target := range targets {
			if target.Proof.Tag == tag && target.Network == "tcp" && target.Address == address {
				allowed = true
			}
		}
		if !allowed || current(call) != nil {
			return nil, bad
		}
		original, e := engine.DialPrefixProofContext(call, s, tag, address)
		if e != nil || original == nil || current(call) != nil {
			if original != nil {
				return nil, errors.Join(bad, original.Close())
			}
			return nil, bad
		}
		return original, nil
	}
	result := NodeChainServerPrefixProofResult{Binding: binding, Prefixes: make([]NodeChainServerPrefixResult, 0, len(targets))}
	for _, target := range targets {
		proofCtx, done := context.WithTimeout(ctx, 5*time.Second)
		started := time.Now()
		data, e := externalProofHTTP(proofCtx, dial, target.Proof.Tag, healthURL(target.API), target.Token, testTLS)
		elapsed := time.Since(started)
		var proof struct {
			OK     bool   `json:"ok"`
			NodeID string `json:"node_id"`
			Proof  string `json:"proof"`
		}
		valid := e == nil && exactJSON(data, &proof, 8192) == nil && proof.OK && proof.NodeID == target.Proof.NodeID && proof.Proof == "router-vpn-private-agent-v1" && elapsed > 0 && current(proofCtx) == nil
		done()
		if !valid {
			return fail()
		}
		result.Prefixes = append(result.Prefixes, NodeChainServerPrefixResult{Proof: target.Proof, ResponseMS: float64(elapsed) / float64(time.Millisecond)})
	}
	if current(ctx) != nil {
		return fail()
	}
	result.ProvenAt = time.Now().UTC()
	return result, nil
}
