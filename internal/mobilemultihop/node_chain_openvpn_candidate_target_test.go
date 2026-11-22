package mobilemultihop

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/nativeopenvpn"
)

// The retained engine checks the exact original prefix tag and captured
// literal destination, then routes to the test listener. Its accepted sockets
// are counted independently of the benchmark report.
func TestNodeChainOpenVPNCandidateTargetFifty(t *testing.T) {
	input := nodeChainOpenVPNFixture(t, "wg", "tcp").Nodes[1]
	member, err := parseNodeChainOpenVPNMember(input)
	if err != nil {
		t.Fatal(err)
	}
	chain := nodeChainFixture(t, 3, "")
	plan, err := chain.NewCandidatePlan(1, candidateInventoryFixture(t, "openvpn-tcp-original", input))
	if err != nil || len(plan.targets) != 1 {
		t.Fatal("single TCP OpenVPN target unavailable", err)
	}
	target := plan.targets[0]
	if target.ID != member.id() || target.SourceSHA256 != member.source || target.Address != "203.0.113.24:1194" || !NodeChainCandidateInputSupported(input) {
		t.Fatal("TCP OpenVPN candidate lost original identity, protocol or endpoint")
	}
	if strings.Contains(plan.Metadata(), "203.0.113.24") || strings.Contains(plan.Metadata(), "password") {
		t.Fatal("candidate metadata exposed original endpoint or private material")
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	done := make(chan struct{})
	fifty := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if accepted.Add(1) == 50 {
				close(fifty)
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	engine := &candidateRouteFixture{nodeChainTestEngine: newNodeChainTestEngine(t, chain), tag: chain.proofs[1].Tag, address: target.Address, peer: listener.Addr().String()}
	if err := chain.Run(ctx, engine); err != nil {
		t.Fatal(err)
	}
	owner := &candidateOwnerFixture{nodeChainMeasurementFixture: nodeChainMeasurementFixture{chain: chain}, capture: plan.capture}
	service, err := plan.NewMeasurementContext(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	request := strings.Repeat("a", 32)
	if err := service.StartContext(ctx, request, target.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Drain(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fifty:
	case <-ctx.Done():
		t.Fatal("original endpoint did not accept fifty connections", accepted.Load())
	}
	status := candidateStatus(t, service)
	if !status.Complete || !status.Drained || status.Failure != "" || status.Stage != "complete" || status.Measurement != "routed-tcp-connect" ||
		status.PrefixPosition != 1 || status.PrefixID != chain.proofs[1].ProfileID || status.CaptureSHA256 != plan.capture || status.CandidateID != target.ID || status.CandidateSourceSHA256 != member.source ||
		len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 || status.Results[0].Benchmark.Distribution.Samples != 50 ||
		accepted.Load() != 50 || engine.count.Load() != 50 || chain.runtime.engine != engine || owner.active.Load() || owner.released.Load() != 1 {
		t.Fatal("TCP OpenVPN candidate lost original route or fifty completed destination connections", status, accepted.Load(), engine.count.Load())
	}
}
func TestNodeChainOpenVPNCandidateRejectsForeignSources(t *testing.T) {
	input := nodeChainOpenVPNFixture(t, "wg", "tcp").Nodes[1]
	var original nodeChainImportedInput
	if err := json.Unmarshal([]byte(input), &original); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"udp-same-address", "plural-remotes", "hostname", "config-port", "protocol-capture", "injected-detour", "wrong-kind"} {
		t.Run(fault, func(t *testing.T) {
			changed := original
			graph := startObject(t, changed.Config)
			capture := startObject(t, changed.Capture)
			endpoint := graph["endpoints"].([]any)[0].(map[string]any)
			profile := capture["profile"].(map[string]any)
			transport := profile["external"].(map[string]any)["openvpn"].(map[string]any)
			switch fault {
			case "udp-same-address":
				changedInput := nodeChainOpenVPNFixture(t, "wg", "udp").Nodes[1]
				if NodeChainCandidateInputSupported(changedInput) {
					t.Fatal("UDP OpenVPN was timed as TCP")
				}
				return
			case "plural-remotes":
				transport["config"] = transport["config"].(string) + "\nremote 203.0.113.25 1194 tcp\n"
				compiled, err := nativeopenvpn.CompileEndpoint(transport["config"].(string), transport["username"].(string), transport["password"].(string), ExternalFinalTag, "")
				if err != nil {
					t.Fatal("standalone two-remote provider must be syntactically valid", err)
				}
				alternate := startObject(t, compiled)
				remotes, err := nativeopenvpn.Remotes(alternate)
				if err != nil || len(remotes) != 2 || remotes[0].Network != "tcp" || remotes[1].Network != "tcp" {
					t.Fatal("original standalone provider lost one of its two TCP remotes", err)
				}
				graph["endpoints"] = []any{alternate}
			case "hostname":
				endpoint["server"] = "provider.example"
			case "config-port":
				endpoint["server_port"] = 443
			case "protocol-capture":
				endpoint["network"] = "udp"
			case "injected-detour":
				endpoint["detour"] = "unowned"
			case "wrong-kind":
				changed.Kind = "routervpn-node-chain-connect-member"
			}
			changed.Config = startJSON(t, graph)
			changed.Capture = startJSON(t, capture)
			if NodeChainCandidateInputSupported(startJSON(t, changed)) {
				t.Fatal("changed original OpenVPN source granted candidate access", fault)
			}
		})
	}
}
