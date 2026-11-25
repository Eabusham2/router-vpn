package mobilemultihop

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

func TestServerStreamCandidateOriginalResponses(t *testing.T) {
	input, err := nodeChainFixtureNodes(t, 8, "")[7].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseCandidateResponseSource(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct {
		name, requested string
		fault           bool
	}{{"explicit", "server", false}, {"compare-winner", "auto", false}, {"wrong-response", "server", true}} {
		t.Run(example.name, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixtureFromPreparationTTL(t, nodeChainImportedPrefixExecutionSource(t, 1, "wg", example.requested), nil, 0)
			r := remoteCandidateFixtureAt(t, f, example.requested, 1, input)
			original := f.runtime.active
			if _, err := f.runtime.NewRemoteCandidatePlanContext(t.Context(), 1, r.plan.packet.inventory); err == nil {
				t.Fatal("ordinary connect-only admission opened a stream")
			}
			events := entryMaintainServerProof(t, f)
			var count atomic.Int32
			r.reply = fixtureServerCandidateReply(t, input, example.fault, &count)
			if err := r.measurement.Start(strings.Repeat("a", 32), s.Target.ID); err != nil {
				t.Fatal(err)
			}
			status := r.wait(t)
			if err := r.measurement.Drain(strings.Repeat("a", 32)); err != nil {
				t.Fatal(err)
			}
			if example.fault {
				if len(status.Results) != 1 || status.Results[0].Ready || count.Load() != 1 {
					t.Fatal("bad candidate earned a response", status, count.Load())
				}
			} else if len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].Benchmark.Attempts != 50 || status.Results[0].Benchmark.Measurement != hopmeasure.CandidatePrivateResponseMeasurement || count.Load() != 50 {
				t.Fatal("missing original replies", status, count.Load())
			}
			if r.deleted != 1 || r.capture.Request.Schema != 2 || f.runtime.active != original || r.owner.active.Load() || events.Load() == 0 {
				t.Fatal("retirement or server ownership")
			}
			for _, secret := range []string{s.Token, s.Password, s.API} {
				if strings.Contains(r.plan.Metadata(), secret) {
					t.Fatal("published private candidate source")
				}
			}
		})
	}
}

func TestServerStreamCandidatePrivateRegistration(t *testing.T) {
	_, active, lease := nodeChainImportedServerFixture(t, "wg", "")
	registered, _ := nodeChainServerFixture(t, 8, "")
	last := registered.nodes[len(registered.nodes)-1]
	input, err := last.LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseCandidateResponseSource(input)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := lease.Digest()
	if err != nil {
		t.Fatal(err)
	}
	q := multihoprelay.NodeChainCandidateRequest{Schema: 2, Lease: lease.Request.Clone(), OwnerID: lease.OwnerID, CaptureSHA256: digest, Operation: strings.Repeat("a", 64), ExecutionSHA256: strings.Repeat("b", 64), Trial: strings.Repeat("c", 32), SelectionEpoch: 1, InventorySHA256: strings.Repeat("d", 64), Position: 1, CandidateID: s.Target.ID, CandidateSourceSHA256: s.Target.SourceSHA256, Address: s.Target.Address, DeadlineAt: time.Now().Add(time.Minute).UnixMilli(), Password: strings.Repeat("9", 64)}
	c, err := multihoprelay.NewNodeChainCandidateCapture(lease, q, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := registered.CandidateResponseInput(c); err != nil || selected != input {
		t.Fatal("independent registration", err)
	}
	if _, err := active.CandidateTarget(c); err == nil {
		t.Fatal("stream acquired ordinary connect-only target")
	}
	target, err := active.ResponseCandidateTarget(c)
	if err != nil {
		t.Fatal("original stream", err)
	}
	tag, address, err := target.Read(active, c)
	if err != nil || tag != active.proofs[0].Tag || address != s.Target.Address {
		t.Fatal("wrong original prefix")
	}
	if _, err = active.CandidateResponseInput(c); err == nil {
		t.Fatal("locally paired-only candidate admitted")
	}
	for _, change := range []func(*multihoprelay.NodeChainCandidateCapture){
		func(x *multihoprelay.NodeChainCandidateCapture) {
			x.Request.CandidateSourceSHA256 = strings.Repeat("f", 64)
		},
		func(x *multihoprelay.NodeChainCandidateCapture) { x.Request.CandidateID = "changed" },
		func(x *multihoprelay.NodeChainCandidateCapture) { x.Request.Address = "198.51.100.2:443" },
		func(x *multihoprelay.NodeChainCandidateCapture) { x.Request.Schema = 1 },
		func(x *multihoprelay.NodeChainCandidateCapture) {
			x.Member = x.Lease.Source.Members[len(x.Lease.Source.Members)-1]
		},
	} {
		changed := c.Clone()
		change(&changed)
		if _, err := registered.CandidateResponseInput(changed); err == nil {
			t.Fatal("changed registered request acquired original candidate")
		}
		if _, err := NewNodeChainServerCandidateResponder(changed, input); err == nil {
			t.Fatal("changed request acquired private worker")
		}
	}
}

func TestServerStreamCandidatePreservesSelectedPrefix(t *testing.T) {
	input, err := nodeChainFixtureNodes(t, 8, "")[7].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	inventory := candidateInventoryFixture(t, "stream-original-inventory", input)
	for _, test := range []struct {
		name, outcome, requested string
		pos                      int
	}{
		{"private", "server", "server", 2}, {"literal", "compare-server", "auto", 1}, {"local-winner", "compare-local", "auto", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, selectedPrivateStreamLayout(5, 2), test.requested)
			prep := f.runtime.projection.preparation
			if !prep.SupportsServerResponseCandidate(test.pos) || prep.SupportsServerResponseCandidate(0) || prep.SupportsServerResponseCandidate(4) {
				t.Fatal("wrong original candidate positions")
			}
			entryRun(t, f, test.outcome)
			t.Cleanup(func() {
				if err := closeRemoteCandidateRuntime(f.runtime); err != nil {
					t.Error(err)
				}
			})
			trial := f.runtime.active
			plan, err := f.runtime.NewRemoteResponseCandidatePlanContext(t.Context(), test.pos, inventory)
			if test.outcome == "compare-local" {
				if err == nil || plan != nil {
					t.Fatal("Server adopted Local winner")
				}
				return
			}
			if err != nil || plan.trial != trial || plan.packet.prefix != prep.local.proofs[test.pos] || !strings.Contains(plan.MetadataForCandidate(plan.packet.targets[0].ID), hopmeasure.CandidatePrivateResponseMeasurement) {
				t.Fatal("lost sealed stream position", err)
			}
			if _, err := f.runtime.NewRemoteCandidatePlanContext(t.Context(), test.pos, inventory); err == nil {
				t.Fatal("ordinary packet owner acquired stream")
			}
		})
	}
}

func fixtureServerCandidateReply(t *testing.T, input string, badMAC bool, count *atomic.Int32) func(net.Conn, multihoprelay.NodeChainCandidateCapture) {
	t.Helper()
	s, err := parseCandidateResponseSource(input)
	if err != nil {
		t.Fatal(err)
	}
	var seen sync.Map
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		nonce := q.URL.Query().Get("nonce")
		api, _ := privateAPI(s.API)
		if _, repeated := seen.LoadOrStore(nonce, true); repeated || q.Host != api.Host || q.Method != "GET" || q.URL.Path != hopmeasure.CandidateChallengePath || !hopmeasure.ValidCandidateNonce(nonce) || q.Header.Get("Authorization") != "Bearer "+hopmeasure.CandidateChallengeMAC(s.Token, s.NodeID, nonce, false) {
			http.Error(w, "invalid original", 403)
			return
		}
		count.Add(1)
		token := s.Token
		if badMAC {
			token = "wrong-secret"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"node_id": s.NodeID, "nonce": nonce, "response": hopmeasure.CandidateChallengeMAC(token, s.NodeID, nonce, true)})
	}))
	t.Cleanup(peer.Close)
	return func(conn net.Conn, c multihoprelay.NodeChainCandidateCapture) {
		var req [96]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil {
			return
		}
		responder, err := NewNodeChainServerCandidateResponder(c, input)
		if err != nil {
			return
		}
		// Actual HTTP endpoint with a distinct native-cipher boundary double.
		remote, err := net.Dial("tcp", peer.Listener.Addr().String())
		if err != nil {
			return
		}
		defer remote.Close()
		reply, err := responder.Reply(t.Context(), c, remote, string(req[:32]), string(req[32:]), func(ctx context.Context, raw net.Conn, method, key, address string) (net.Conn, error) {
			api, _ := privateAPI(s.API)
			if method != s.Method || key != s.Password || address != api.Host {
				return nil, nodeChainError
			}
			return raw, nil
		})
		if err == nil {
			_, _ = io.WriteString(conn, reply)
		}
	}

}
