package multihoprelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestServerCandidateMissingRequiresJoinedOriginal(t *testing.T) {
	for _, fault := range []string{"original", "wrong-registry", "failed-close", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			runner := &candidateFixtureRunner{}
			cfg := nodeChainFixtureConfig(t, 3)
			capture := multipleImportedCaptureFixture(t, 3, []int{1, 2})
			capture.Source.EntryNodeID = cfg.NodeChains[0].EntryNodeID
			cfg.NodeChains[0] = capture.Source
			m, err := New(cfg, req().EntryNodeID, runner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { nodeChainFixtureClose(t, m) })
			peer := netip.MustParseAddr("10.77.0.2")
			lease := nodeChainFixtureRequestFor(t, m, peer)
			lease.Schema = 6
			lease.LocalPacketPositions = capture.Request.LocalPacketPositions
			lease.LocalPacketPublicKeys = capture.Request.LocalPacketPublicKeys
			nodeChainFixtureAcquire(t, m, peer, lease)
			deadline := time.Now().Add(time.Second)
			for {
				nonce, _ := nodeChainSecret()
				s, e := m.ChainStatus(t.Context(), peer, lease, nonce)
				if e == nil && s.Receipt.Phase == NodeChainReady {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("original not ready", e)
				}
				time.Sleep(time.Millisecond)
			}
			q := candidateRequestFixture(t, runner.process.capture)
			q.Schema = 2
			runner.process.prepareError = ErrCandidateNotRegistered
			runner.process.failClose = fault == "failed-close"
			if fault == "wrong-registry" {
				runner.process.prepareError = ErrUnavailable
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if fault == "cancelled" {
				cancel()
			}
			_, err = m.CreateChainCandidate(ctx, peer, q)
			var absent *CandidateRegistryAbsence
			if fault != "original" {
				if err == nil || errors.As(err, &absent) {
					t.Fatal("failed authority or join produced a typed absence", err)
				}
				if runner.process.operation != nil {
					runner.process.operation.mu.Lock()
					runner.process.operation.failClose = false
					runner.process.operation.mu.Unlock()
				}
				return
			}
			if !errors.As(err, &absent) {
				t.Fatal("joined original has no registry disposition", err)
			}
			const token = "original-private-entry-token"
			receipt, err := absent.Receipt(q, token, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(receipt)
			original := runner.process.capture
			if DecodeNodeChainCandidateAbsenceReceipt(raw, original, q, token, time.Now()) != nil {
				t.Fatal("valid signed refusal")
			}
			for _, mutation := range []string{"target", "endpoint", "source", "inventory", "owner", "epoch", "trial", "expiry", "lease", "token", "tamper", "duplicate", "undrained"} {
				bad := q.Clone()
				body := bytes.Clone(raw)
				key := token
				now := time.Now()
				switch mutation {
				case "target":
					bad.CandidateID = "other"
				case "endpoint":
					bad.Address = "198.51.100.9:443"
				case "source":
					bad.CandidateSourceSHA256 = strings.Repeat("3", 64)
				case "inventory":
					bad.InventorySHA256 = strings.Repeat("1", 64)
				case "owner":
					bad.OwnerID = strings.Repeat("2", 64)
				case "epoch":
					bad.SelectionEpoch++
				case "trial":
					bad.Trial = strings.Repeat("0", 32)
				case "expiry":
					now = time.UnixMilli(q.DeadlineAt)
				case "lease":
					bad.Lease.DescriptorSHA256 = strings.Repeat("7", 64)
				case "token":
					key = "foreign"
				case "tamper":
					forged := receipt
					forged.MAC = strings.Repeat("9", 64)
					body, _ = json.Marshal(forged)
				case "duplicate":
					body = append([]byte(`{"schema":2,`), body[1:]...)
				case "undrained":
					forged := receipt
					forged.Drained = false
					body, _ = json.Marshal(forged)
				}
				if DecodeNodeChainCandidateAbsenceReceipt(body, original, bad, key, now) == nil {
					t.Fatal("borrowed terminal disposition", mutation)
				}
			}
			if err = m.DeleteChainCandidate(ctx, peer, q); err != nil {
				t.Fatal("original tombstone no longer portable", err)
			}
			if _, err = m.CreateChainCandidate(ctx, peer, q); err == nil || errors.As(err, &absent) {
				t.Fatal("replay acquired another disposition", err)
			}
		})
	}
}
