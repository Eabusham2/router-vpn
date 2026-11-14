package mobilemultihop

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"router-vpn/internal/multihoprelay"
)

// NodeChainServerProofEngine is one retained worker's original native owner.
// Observe must verify its actual Box, outbound and resolver pointers and source,
// not return an identity copied from a receipt. Every operation honors the
// original context and joins late I/O; the worker alone owns native retirement.
// No method is authority to open the separate authenticated application front.
type NodeChainServerProofEngine interface {
	ObserveServerContext(context.Context) (NodeChainServerBinding, error)
	DialServerContext(context.Context, string, string, string) (net.Conn, error)
	ProveServerDNSContext(context.Context, NodeChainServerDNSCapture) error
}

type NodeChainServerPrefixResult struct {
	Proof      NodeChainProof `json:"proof"`
	ResponseMS float64        `json:"response_ms"`
}

// ProvenAt is the original proof completion time, never a status-read time.
// This result is necessary evidence for the worker's admission, not a lease or
// a readiness assertion. Manager/native ownership still must be rechecked.
type NodeChainServerProofResult struct {
	Binding      NodeChainServerBinding        `json:"binding"`
	Prefixes     []NodeChainServerPrefixResult `json:"prefixes"`
	DNSProven    bool                          `json:"dns_proven"`
	PublicProven bool                          `json:"public_proven"`
	ExitIP       string                        `json:"exit_ip"`
	ProvenAt     time.Time                     `json:"proven_at"`
}

func (p *NodeChainServerPolicy) Prove(ctx context.Context, capture multihoprelay.NodeChainCapture, engine NodeChainServerProofEngine) (NodeChainServerProofResult, error) {
	return p.prove(ctx, capture, engine, nil)
}

// testTLS is only reachable by package tests, as in the existing ordered Local
// proof fixture. Shipping callers always use the operating system verifier.
func (p *NodeChainServerPolicy) prove(parent context.Context, original multihoprelay.NodeChainCapture, engine NodeChainServerProofEngine, testTLS *tls.Config) (NodeChainServerProofResult, error) {
	bad := errors.New("ordered server native proof lost its original owner or selected path")
	fail := func() (NodeChainServerProofResult, error) { return NodeChainServerProofResult{}, bad }
	if parent == nil || engine == nil || parent.Err() != nil {
		return fail()
	}
	// The original worker applies BootstrapDeadline to first admission and its
	// prior proof's expiry to refreshes. Neither changes the captured deadline
	// or identity. An unbounded detached proof caller is never accepted.
	if _, bounded := parent.Deadline(); !bounded {
		return fail()
	}
	capture := original.Clone()
	binding, err := p.binding(capture)
	if err != nil {
		return fail()
	}
	ctx := parent
	current := func(check context.Context) error {
		if check.Err() != nil {
			return bad
		}
		actual, err := engine.ObserveServerContext(check)
		if err != nil || check.Err() != nil || actual != binding {
			return bad
		}
		still, err := p.binding(capture)
		if err != nil || still != binding {
			return bad
		}
		return nil
	}
	if current(ctx) != nil {
		return fail()
	}
	targets, err := p.ProofTargets(capture)
	if err != nil || len(targets) == 0 {
		return fail()
	}
	final := targets[len(targets)-1].Proof.Tag
	dial := func(dialCtx context.Context, tag, address string) (net.Conn, error) {
		allowed := tag == final && address == "1.1.1.1:443"
		for _, target := range targets {
			allowed = allowed || target.Proof.Tag == tag && target.Network == "tcp" && target.Address == address
		}
		if !allowed || current(dialCtx) != nil {
			return nil, bad
		}
		connection, err := engine.DialServerContext(dialCtx, tag, "tcp", address)
		if err != nil || connection == nil || current(dialCtx) != nil {
			if connection != nil {
				return nil, errors.Join(bad, connection.Close())
			}
			return nil, bad
		}
		return connection, nil
	}
	result := NodeChainServerProofResult{Binding: binding}
	for _, target := range targets {
		proofCtx, done := context.WithTimeout(ctx, 5*time.Second)
		started := time.Now()
		if target.Proof.NodeKind == "external" {
			err := proveExternalPublicIP(proofCtx, dial, target.Proof.Tag, target.ExpectedPublicIP, testTLS)
			elapsed := time.Since(started)
			valid := err == nil && elapsed > 0 && current(proofCtx) == nil
			done()
			if !valid {
				return fail()
			}
			result.Prefixes = append(result.Prefixes, NodeChainServerPrefixResult{target.Proof, float64(elapsed) / float64(time.Millisecond)})
			continue
		}
		data, err := externalProofHTTP(proofCtx, dial, target.Proof.Tag, healthURL(target.API), target.Token, testTLS)
		elapsed := time.Since(started)
		var proof struct {
			OK     bool   `json:"ok"`
			NodeID string `json:"node_id"`
			Proof  string `json:"proof"`
		}
		valid := err == nil && exactJSON(data, &proof, 8192) == nil && proof.OK && proof.NodeID == target.Proof.NodeID &&
			proof.Proof == "router-vpn-private-agent-v1" && elapsed > 0 && current(proofCtx) == nil
		done()
		if !valid {
			return fail()
		}
		result.Prefixes = append(result.Prefixes, NodeChainServerPrefixResult{target.Proof, float64(elapsed) / float64(time.Millisecond)})
	}
	dns, err := p.DNSCapture(capture)
	if err != nil || current(ctx) != nil {
		return fail()
	}
	dnsCtx, dnsDone := context.WithTimeout(ctx, 5*time.Second)
	dnsErr := engine.ProveServerDNSContext(dnsCtx, dns)
	dnsValid := dnsErr == nil && current(dnsCtx) == nil
	dnsDone()
	if !dnsValid {
		return fail()
	}
	result.DNSProven = true
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fail()
	}
	publicCtx, publicDone := context.WithTimeout(ctx, 8*time.Second)
	data, err := externalProofHTTP(publicCtx, dial, final, "https://1.1.1.1/cdn-cgi/trace?routervpn_proof="+hex.EncodeToString(nonce[:]), "", testTLS)
	valid := err == nil && current(publicCtx) == nil
	publicDone()
	if !valid {
		return fail()
	}
	address, count := "", 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ip=") {
			address, count = strings.TrimSpace(strings.TrimPrefix(line, "ip=")), count+1
		}
	}
	if count != 1 || !externalPublicIP(address) || current(ctx) != nil {
		return fail()
	}
	result.PublicProven, result.ExitIP, result.ProvenAt = true, address, time.Now().UTC()
	return result, nil
}
