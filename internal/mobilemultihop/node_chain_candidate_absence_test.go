package mobilemultihop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// The test peer owns this entry token and signs its simulated registry
// response independently of the decoder. The agent/Manager tests exercise
// the real missing-source lookup, native close and signing path.
func fixtureEntryCandidateAbsence(c multihoprelay.NodeChainCandidateCapture, token string) multihoprelay.NodeChainCandidateAbsenceReceipt {
	d, err := c.Digest()
	if err != nil {
		panic(err)
	}
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("routervpn-joined-candidate-not-registered-v1\n" + d))
	return multihoprelay.NodeChainCandidateAbsenceReceipt{Schema: 2, Disposition: "not-registered", Owner: c.OperationOwnerID, Capture: d, Drained: true, MAC: hex.EncodeToString(m.Sum(nil))}
}
func TestServerStreamCandidateRegistryAbsence(t *testing.T) {
	missing, err := nodeChainFixtureNodes(t, 7, "")[6].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := nodeChainFixtureNodes(t, 8, "")[7].LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	miss, err := parseCandidateResponseSource(missing)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := parseCandidateResponseSource(registered)
	if err != nil {
		t.Fatal(err)
	}
	for _, example := range []string{"missing-then-registered", "forged", "other-candidate", "stale-epoch", "unjoined", "missing-cleanup-held"} {
		t.Run(example, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixtureFromPreparationTTL(t, nodeChainImportedPrefixExecutionSource(t, 1, "wg", "server"), nil, 0)
			r := remoteCandidateFixtureAt(t, f, "server", 1, missing, registered)
			trial := f.runtime.active
			entryMaintainServerProof(t, f)
			var count atomic.Int32
			r.reply = fixtureServerCandidateReply(t, registered, false, &count)
			r.absence = func(w http.ResponseWriter, h *http.Request, c multihoprelay.NodeChainCandidateCapture) bool {
				if c.Request.CandidateID != miss.Target.ID {
					return false
				}
				token := predecessorText(r.plan.projection.policy.local.nodes[0].profile, "api_token")
				if h.Header.Get("Authorization") != "Bearer "+token {
					http.Error(w, "unauthorized", 403)
					return true
				}
				if example == "other-candidate" {
					c.Request.CandidateID = valid.Target.ID
					c.Request.CandidateSourceSHA256 = valid.Target.SourceSHA256
				}
				if example == "stale-epoch" {
					c.Request.SelectionEpoch++
				}
				if example == "forged" {
					token = "foreign-entry-token"
				}
				receipt := fixtureEntryCandidateAbsence(c, token)
				if example == "unjoined" {
					receipt.Drained = false
				}
				_ = json.NewEncoder(w).Encode(receipt)
				return true
			}
			if example == "missing-cleanup-held" {
				r.mu.Lock()
				r.badACK = true
				r.mu.Unlock()
			}
			id := strings.Repeat("a", 32)
			if err := r.measurement.Start(id, miss.Target.ID); err != nil {
				t.Fatal("discarded registry response before authenticated request", err)
			}
			raw := r.wait(t)
			if example == "missing-cleanup-held" {
				if err := r.measurement.Drain(id); err == nil {
					t.Fatal("unacknowledged local stop released the absence")
				}
				var held hopmeasure.CandidateStatus
				if json.Unmarshal([]byte(r.measurement.StatusJSON()), &held) != nil || held.Drained || len(held.Results) != 0 {
					t.Fatal("unjoined absence released a result", held)
				}
				if r.measurement.Start(strings.Repeat("c", 32), valid.Target.ID) == nil {
					t.Fatal("unjoined absence released next candidate")
				}
				r.mu.Lock()
				r.badACK = false
				r.mu.Unlock()
				if err := r.measurement.Drain(id); err != nil {
					t.Fatal("original close retry failed", err)
				}
				return
			}
			if err := r.measurement.Drain(id); err != nil {
				t.Fatal(err)
			}
			var status hopmeasure.CandidateStatus
			if json.Unmarshal([]byte(r.measurement.StatusJSON()), &status) != nil || !status.Complete || !status.Drained || f.runtime.active != trial || count.Load() != 0 || r.deleted != 1 || r.put != 1 {
				t.Fatal("unjoined or changed first candidate", raw, status, count.Load(), r.deleted)
			}
			if example != "missing-then-registered" {
				if status.Stage != "invalidated" || status.Failure == "" || len(status.Results) != 0 {
					t.Fatal("forged absence was accepted as target-local", status)
				}
				return
			}
			if status.Stage != "complete" || status.Failure != "" || status.CandidateID != miss.Target.ID || status.CandidateSourceSHA256 != miss.Target.SourceSHA256 || status.MeasuredAt <= 0 || status.ExpiresAt != status.MeasuredAt+hopmeasure.CandidateReceiptLifetime.Milliseconds() || len(status.Results) != 1 {
				t.Fatal("unattributed registry absence", status)
			}
			row := status.Results[0]
			if row.ID != miss.Target.ID || row.Role != "candidate" || row.Kind != "private-agent-response" || row.Ready || row.Failure != hopmeasure.ErrCandidateNotRegistered.Error() || row.CandidateDisposition != hopmeasure.CandidateNotRegistered || row.Benchmark != nil {
				t.Fatal("absent candidate received a score or lost its exact reason", row)
			}
			next := strings.Repeat("b", 32)
			if err := r.measurement.Start(next, valid.Target.ID); err != nil {
				t.Fatal("joined absence blocked next registered candidate", err)
			}
			r.wait(t)
			if err := r.measurement.Drain(next); err != nil {
				t.Fatal(err)
			}
			status = hopmeasure.CandidateStatus{} // Omitted per-target fields belong to this response only.
			if json.Unmarshal([]byte(r.measurement.StatusJSON()), &status) != nil || status.Request != next || status.CandidateID != valid.Target.ID || len(status.Results) != 1 || !status.Results[0].Ready || status.Results[0].CandidateDisposition != "" || status.Results[0].Benchmark.Attempts != 50 || count.Load() != 50 || r.put != 2 || r.deleted != 2 || f.runtime.active != trial || status.ExpiresAt <= time.Now().UnixMilli() {
				t.Fatal("next candidate borrowed the first result or changed original trial", status, count.Load(), r.put, r.deleted)
			}
		})
	}
}
