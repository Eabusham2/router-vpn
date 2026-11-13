package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"router-vpn/internal/hopmeasure"
)

func nodeChainExecutionTarget(target string) bool {
	for _, allowed := range Targets {
		if target == allowed {
			return true
		}
	}
	return false
}

// retainDial keeps even a nonnil connection returned with an error. The
// original scope joins late dials, stream I/O and failed/retried closes; a
// proof helper's error can never make that ownership disappear.
func (s *nodeChainExecutionTrial) retainDial(operation *leaseStopIO, ctx context.Context, tag, address string) (net.Conn, error) {
	proofs, err := s.runtime.projection.ProofInventory(s.execution)
	if err != nil {
		return nil, err
	}
	allowed := false
	for i, proof := range proofs {
		api, err := privateAPI(predecessorText(s.runtime.projection.policy.local.nodes[i].profile, "router_api"))
		allowed = allowed || err == nil && tag == proof.Tag && address == api.Host
	}
	if tag == s.tag && (address == "1.1.1.1:443" || address == "1.0.0.1:443") {
		allowed = true
	}
	if !allowed {
		return nil, nodeChainExecutionError
	}
	call, finish, err := operation.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if err := s.runtime.current(call, s, true); err != nil {
		return nil, err
	}
	connection, dialErr := s.runtime.engine.Dial(call, tag, address)
	var keepErr error
	if connection != nil {
		connection, keepErr = operation.keep(connection)
	}
	currentErr := s.runtime.current(call, s, true)
	if connection == nil || dialErr != nil || keepErr != nil || currentErr != nil || call.Err() != nil {
		if original, ok := connection.(*leaseStopConn); ok {
			original.startClose()
		}
		return connection, errors.Join(dialErr, keepErr, currentErr, call.Err(), nodeChainExecutionError)
	}
	return connection, nil
}

func (s *nodeChainExecutionTrial) provePrefix(parent context.Context, position int) (time.Duration, error) {
	proofs, err := s.runtime.projection.ProofInventory(s.execution)
	if err != nil || position < 0 || position >= len(proofs) {
		return 0, nodeChainExecutionError
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	captureInterval := hopmeasure.StartInterval
	if s.runtime.testInterval != nil {
		captureInterval = s.runtime.testInterval
	}
	started, err := captureInterval()
	if err != nil {
		return 0, err
	}
	_, err = s.proofIO.run(ctx, func(call context.Context, operation *leaseStopIO) ([]byte, error) {
		node, proof := s.runtime.projection.policy.local.nodes[position], proofs[position]
		data, err := externalProofHTTP(call, func(dialCtx context.Context, tag, address string) (net.Conn, error) {
			return s.retainDial(operation, dialCtx, tag, address)
		}, proof.Tag,
			healthURL(predecessorText(node.profile, "router_api")), predecessorText(node.profile, "api_token"), s.runtime.testTLS)
		if err != nil {
			return nil, err
		}
		var response struct {
			OK     bool   `json:"ok"`
			NodeID string `json:"node_id"`
			Proof  string `json:"proof"`
		}
		if exactJSON(data, &response, 8192) != nil || !response.OK || response.NodeID != proof.NodeID || response.Proof != "router-vpn-private-agent-v1" {
			return nil, nodeChainExecutionError
		}
		return nil, nil
	})
	if err != nil {
		return 0, err
	}
	return started.Duration()
}

func (s *nodeChainExecutionTrial) proveDNS(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	capture, err := s.runtime.projection.DNSCapture(s.execution)
	if err != nil {
		return err
	}
	_, err = s.proofIO.run(ctx, func(call context.Context, _ *leaseStopIO) ([]byte, error) {
		return nil, s.runtime.engine.DNSExecutionProofContext(call, capture)
	})
	return err
}

func (s *nodeChainExecutionTrial) proveExternal(parent context.Context, target string) (time.Duration, error) {
	if !nodeChainExecutionTarget(target) {
		return 0, nodeChainExecutionError
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	nonce, err := randomHex(16)
	if err != nil {
		return 0, err
	}
	captureInterval := hopmeasure.StartInterval
	if s.runtime.testInterval != nil {
		captureInterval = s.runtime.testInterval
	}
	started, err := captureInterval()
	if err != nil {
		return 0, err
	}
	_, err = s.proofIO.run(ctx, func(call context.Context, operation *leaseStopIO) ([]byte, error) {
		data, err := externalProofHTTP(call, func(dialCtx context.Context, tag, address string) (net.Conn, error) {
			return s.retainDial(operation, dialCtx, tag, address)
		}, s.tag, target+"?routervpn_proof="+nonce, "", s.runtime.testTLS)
		if err != nil {
			return nil, err
		}
		address, count := "", 0
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ip=") {
				address, count = strings.TrimSpace(strings.TrimPrefix(line, "ip=")), count+1
			}
		}
		if count != 1 || !externalPublicIP(address) {
			return nil, nodeChainExecutionError
		}
		return nil, nil
	})
	if err != nil {
		return 0, err
	}
	return started.Duration()
}

func (s *nodeChainExecutionTrial) proveComplete(ctx context.Context) error {
	proofs, err := s.runtime.projection.ProofInventory(s.execution)
	if err != nil {
		return err
	}
	rows := make([]NodeChainPrefixProgress, 0, len(proofs))
	for i, proof := range proofs {
		elapsed, err := s.provePrefix(ctx, i)
		if err != nil {
			return err
		}
		rows = append(rows, NodeChainPrefixProgress{Position: proof.Position, ProfileID: proof.ProfileID, ResponseMS: float64(elapsed) / float64(time.Millisecond), Proven: true})
	}
	if err := s.proveDNS(ctx); err != nil {
		return err
	}
	if _, err := s.proveExternal(ctx, Targets[0]); err != nil {
		return err
	}
	if s.execution == "server" {
		if err := s.status(ctx, true); err != nil {
			return err
		}
	}
	if err := s.runtime.current(ctx, s, true); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.lifetime.Err() != nil || ctx.Err() != nil {
		return nodeChainExecutionError
	}
	s.prefixes = rows
	s.checkedAt = time.Now()
	return nil
}

func (s *nodeChainExecutionTrial) ProbeLast(ctx context.Context) (time.Duration, error) {
	if err := s.cachedReady(ctx); err != nil {
		return 0, err
	}
	elapsed, err := s.provePrefix(ctx, len(s.runtime.projection.policy.local.nodes)-1)
	if err == nil {
		err = s.runtime.current(ctx, s, true)
	}
	return elapsed, err
}
func (s *nodeChainExecutionTrial) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	if target != s.target {
		return 0, nodeChainExecutionError
	}
	if err := s.cachedReady(ctx); err != nil {
		return 0, err
	}
	elapsed, err := s.proveExternal(ctx, target)
	if err == nil {
		err = s.runtime.current(ctx, s, true)
	}
	return elapsed, err
}
