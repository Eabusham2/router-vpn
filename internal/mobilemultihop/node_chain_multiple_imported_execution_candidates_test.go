package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func selectedMultipleImportedLast(t *testing.T, r *NodeChainExecutionRuntime) string {
	t.Helper()
	last, err := r.CaptureLastContext(t.Context())
	if err != nil || last.JSON() == "" {
		t.Fatal("missing original selected Last", err)
	}
	return last.JSON()
}

func TestNodeChainMultipleImportedExecutionPacketCandidates(t *testing.T) {
	layout := multipleImportedServerLayouts[2] // original imports 1 and 3 flank paired packet 2
	for _, outcome := range []string{"server", "compare-server", "compare-local"} {
		t.Run(outcome, func(t *testing.T) {
			setting := "auto"
			if outcome == "server" {
				setting = "server"
			}
			// The grant is bounded by the original lease. Use the real manager's
			// provisioned default (90s) for a complete 50-connection request.
			_, prep, source := multipleImportedExecutionFixture(t, layout, "wg", "", setting, "")
			f := newNodeChainExecutionRuntimeFixtureFromPreparationTTL(t, source, prep, 0)
			const position = 2
			id := strings.Repeat("a", 32)
			if outcome == "compare-local" {
				entryRun(t, f, outcome)
				t.Cleanup(func() {
					if err := closeRemoteCandidateRuntime(f.runtime); err != nil {
						t.Error(err)
					}
				})
				inventory, address := entryInventory(t)
				p, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, inventory)
				if err != nil || p.plan.multiple == nil || p.plan.multiple.registry != f.runtime.projection.preparation.multiple.owners {
					t.Fatal("selected Local packet lost original registry", err)
				}
				last := selectedMultipleImportedLast(t, f.runtime)
				trial := f.runtime.active
				ok := entryTarget(t, f, p, address)
				owner := &executionEntryOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: p.capture}
				service := entryMeasurement(t, p, owner)
				if err := service.Start(id, p.plan.targets[0].ID); err != nil {
					t.Fatal(err)
				}
				entryWait(t, service)
				if err := service.Drain(id); err != nil {
					t.Fatal(err)
				}
				result := entryStatus(t, service)
				if !result.Complete || !result.Drained || result.Failure != "" || len(result.Results) != 1 || result.Results[0].Benchmark == nil || result.Results[0].Benchmark.Attempts != 50 || ok.Load() != 50 {
					t.Fatal("selected packet did not complete fifty destination TCP connections", result, ok.Load())
				}
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
				if selectedMultipleImportedLast(t, f.runtime) != last || f.runtime.active != trial || owner.active.Load() {
					t.Fatal("timing rewrote Local choice or leaked original work")
				}
				return
			}
			r := remoteCandidateFixtureAtPacket(t, f, setting, position)
			entryMaintainServerProof(t, f)
			last := selectedMultipleImportedLast(t, f.runtime)
			trial := f.runtime.active
			if r.plan.packet.multiple == nil || r.plan.packet.multiple.registry != f.runtime.projection.preparation.multiple.owners {
				t.Fatal("selected Server packet lost original registry")
			}
			if err := r.measurement.Start(id, r.plan.packet.targets[0].ID); err != nil {
				t.Fatal(err)
			}
			status := r.wait(t)
			if err := r.measurement.Drain(id); err != nil {
				t.Fatal(err)
			}
			if status.Failure != "" || len(status.Results) != 1 || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 {
				t.Fatal("selected Server packet timing incomplete", status)
			}
			r.mu.Lock()
			put, deleted, usage, actual := r.put, r.deleted, r.admission.Snapshot(), r.capture
			r.mu.Unlock()
			if !usage.Drained || usage.Accepted != 50 || put != 1 || deleted != 1 || actual.Request.Position != position || actual.Member != f.runtime.projection.policy.Descriptor().Members[position-1] || r.payload.Load() != 0 || r.owner.active.Load() {
				t.Fatal("remote timing lost captured packet, target or joined stop", usage, put, deleted)
			}
			if selectedMultipleImportedLast(t, f.runtime) != last || trial != f.runtime.active {
				t.Fatal("timing rewrote selected Server choice")
			}
		})
	}
}

func TestNodeChainMultipleImportedExecutionCandidateScope(t *testing.T) {
	for _, outcome := range []string{"compare-local", "server"} {
		t.Run(outcome, func(t *testing.T) {
			setting := "server"
			if outcome == "compare-local" {
				setting = "auto"
			}
			f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], setting)
			entryRun(t, f, outcome)
			t.Cleanup(func() {
				if err := closeRemoteCandidateRuntime(f.runtime); err != nil {
					t.Error(err)
				}
			})
			inventory, _ := entryInventory(t)
			if entry, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory); err != nil || entry.plan.multiple == nil {
				t.Fatal("selected entry packet not retained", err)
			}
			for _, position := range []int{-1, 0, 1, 3, 4, 5} {
				if p, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), position, inventory); p != nil || err == nil {
					t.Fatal("unowned Local packet stop", position)
				}
				if p, err := f.runtime.NewRemoteCandidatePlanContext(t.Context(), position, inventory); p != nil || err == nil {
					t.Fatal("unowned remote packet stop", position)
				}
			}
			if outcome == "server" {
				remote, err := f.runtime.NewRemoteCandidatePlanContext(t.Context(), 2, inventory)
				if err != nil {
					t.Fatal(err)
				}
				original := remote.packet
				clone, err := NewNodeChain(original.chain.sourceJSON)
				if err != nil {
					t.Fatal(err)
				}
				replacement, err := clone.NewMultipleImportedCandidatePlan(2, inventory)
				if err != nil || replacement.capture != original.capture || replacement.chain == original.chain {
					t.Fatal("independent equal-byte packet source not constructed", err)
				}
				remote.packet = replacement
				if remote.current(t.Context()) == nil {
					t.Fatal("equal-byte independent packet registry borrowed selected Server")
				}
				remote.packet = original
				if remote.current(t.Context()) != nil {
					t.Fatal("original packet owner lost after foreign observation")
				}
			}

			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if p, err := f.runtime.NewLocalCandidatePlanContext(ctx, 2, inventory); p != nil || err == nil {
				t.Fatal("cancelled Local packet stop")
			}
			if p, err := f.runtime.NewRemoteCandidatePlanContext(ctx, 2, inventory); p != nil || err == nil {
				t.Fatal("cancelled remote packet stop")
			}
		})
	}
}

// Cancel after the actual grant is in progress. A malformed DELETE receipt
// must retain the original candidate activity through an explicit close retry.
func TestNodeChainMultipleImportedExecutionCandidateCancellation(t *testing.T) {
	f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], "server")
	r := remoteCandidateFixtureAtPacket(t, f, "server", 2)
	original := selectedMultipleImportedLast(t, f.runtime)
	r.owner.stale.Store(true)
	id := strings.Repeat("d", 32)
	if err := r.measurement.Start(id, r.plan.packet.targets[0].ID); err == nil {
		t.Fatal("foreign inventory obtained a grant")
	}
	// Any loss of this catalog permanently retires this measurement. A fresh
	// service must be acquired from the still-current original selected plan.
	r.owner.stale.Store(false)
	if err := r.measurement.Start(id, r.plan.packet.targets[0].ID); err == nil {
		t.Fatal("invalidated candidate measurement revived")
	}
	if err := r.measurement.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	r.measurement, err = r.plan.NewMeasurementContext(t.Context(), r.owner)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.frontDelay = 20 * time.Millisecond
	r.badACK = true
	r.mu.Unlock()
	if err := r.measurement.Start(id, r.plan.packet.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		inFlight := r.admission != nil && r.admission.Snapshot().InFlight
		r.mu.Unlock()
		if inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original authenticated grant never entered")
		}
		time.Sleep(time.Millisecond)
	}
	r.measurement.Cancel(id)
	_ = r.wait(t)
	if r.measurement.Close() == nil || !r.owner.active.Load() {
		t.Fatal("inexact original stop released cancelled activity")
	}
	r.mu.Lock()
	r.badACK = false
	r.mu.Unlock()
	if err := r.measurement.Close(); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	put, deleted, usage := r.put, r.deleted, r.admission.Snapshot()
	r.mu.Unlock()
	if put != 1 || deleted < 2 || !usage.Drained || usage.Accepted >= 50 || r.owner.active.Load() || selectedMultipleImportedLast(t, f.runtime) != original {
		t.Fatal("cancel retry replaced the original route or lost its grant", put, deleted, usage)
	}
}

// Grant/status asks the actual worker for another fresh ordered lease receipt.
// A concurrent lease refresh must not invalidate it by adopting the next
// sequence before the original grant has returned.
func TestNodeChainMultipleImportedExecutionCandidateSharesOriginalLeaseRPC(t *testing.T) {
	f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], "server")
	r := remoteCandidateFixtureAtPacket(t, f, "server", 2)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	defer resume()
	r.mu.Lock()
	r.beforeGrant = func() { close(entered); <-release }
	r.mu.Unlock()
	id := strings.Repeat("e", 32)
	if err := r.measurement.Start(id, r.plan.packet.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original candidate did not issue its grant")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := r.plan.trial.status(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("a later lease observation overtook the original candidate grant", err)
	}
	resume()
	r.measurement.Cancel(id)
	_ = r.wait(t)
	if err := r.measurement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.plan.trial.status(t.Context(), true); err != nil {
		t.Fatal("joined grant did not release original lease", err)
	}
}

func TestNodeChainMultipleImportedCancelledCandidateRetainsLeaseRPCUntilWorkerJoins(t *testing.T) {
	f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], "server")
	r := remoteCandidateFixtureAtPacket(t, f, "server", 2)
	e := r.measurement.engine
	e.base.nextID = "cancelled-grant-before-write"
	e.target = r.plan.packet.targets[0]
	release, err := e.BeginMeasurementContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	e.mu.Lock()
	op := e.operation
	e.mu.Unlock()

	entered, held := make(chan struct{}), make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(held) }) }
	defer resume()
	op.control.current = func(call context.Context) error {
		close(entered)
		<-held
		return call.Err()
	}
	caller, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- op.verify(caller) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate did not enter the original HTTP worker")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled candidate caller lost its original error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled candidate caller waited for the held worker")
	}
	op.control.mu.Lock()
	pending := op.control.pending
	op.control.mu.Unlock()
	if pending == nil {
		t.Fatal("cancelled HTTP worker was detached")
	}
	short, stop := context.WithTimeout(t.Context(), 100*time.Millisecond)
	err = r.plan.trial.status(short, true)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lease status overtook the cancelled candidate's unjoined worker", err)
	}
	resume()
	if err := pending.wait(t.Context()); err != nil {
		t.Fatal("original worker failed to join", err)
	}
	if err := r.plan.trial.status(t.Context(), true); err != nil {
		t.Fatal("joined candidate worker did not restore lease status", err)
	}
}

func TestNodeChainMultipleImportedCandidateCanonicalObservations(t *testing.T) {
	for _, field := range []string{"policy-source", "request-key", "request-position", "request-user", "server-member", "front-user", "local-proof", "server-proof", "physical", "policy-config", "projection-config", "transition", "packet-input", "packet-config", "packet-metadata", "packet-profile", "packet-mode", "packet-seal", "packet-owner"} {
		t.Run(field, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], "server")
			projection := f.runtime.projection
			policy := projection.policy
			local := policy.local
			node := local.nodes[0]
			p1, p2 := policy.originalSeal, projection.originalSeal
			if p1 == nil || p2 == nil || local.importedNodes.localSeal.packets[0] == nil {
				t.Fatal("missing original canonical comparison")
			}
			policy.originalSeal, projection.originalSeal = nil, nil
			if policy.captureSeal() != p1.seal || projection.captureSeal() != p2.seal {
				t.Fatal("canonical policy/projection seals diverged")
			}
			policy.originalSeal, projection.originalSeal = p1, p2
			switch field {
			case "policy-source":
				policy.source.LocalSource += " "
			case "request-key":
				policy.source.Request.LocalPacketPublicKeys[0] += "A"
			case "request-position":
				policy.source.Request.LocalPacketPositions[0]++
			case "request-user":
				policy.source.Request.Users[0].Username += "x"
			case "server-member":
				policy.source.Server.Members[0].ProfileID += "x"
			case "front-user":
				policy.front.Users[0].Password += "x"
			case "local-proof":
				policy.localProofs[0].ProfileID += "x"
			case "server-proof":
				policy.serverProofs[0].Tag += "x"
			case "physical":
				policy.physical[0].Port++
			case "policy-config":
				policy.config += " "
			case "projection-config":
				projection.config += " "
			case "transition":
				projection.transition.AddedOutbounds[0] += "x"
			case "packet-input":
				node.inputs.ProfileJSON += " "
			case "packet-config":
				node.config += " "
			case "packet-metadata":
				node.metadata += " "
			case "packet-profile":
				node.profile["nested-change"] = map[string]any{"value": true}
			case "packet-mode":
				node.mode = "awg2-fast"
			case "packet-seal":
				node.desktopSeal += "x"
			case "packet-owner":
				copied := *node
				local.nodes[0] = &copied
			}
			if projection.validateCapture() == nil {
				t.Fatal("derived data borrowed original selected source", field)
			}
		})
	}
}

func TestNodeChainMultipleImportedCandidateFreshJSONValues(t *testing.T) {
	type spelling json.Number
	for _, row := range []struct {
		name            string
		value, original any
		fast, canonical bool
	}{
		{"same-nested", map[string]any{"v": []any{nil, true, "x", float64(0)}}, map[string]any{"v": []any{nil, true, "x", float64(0)}}, true, true},
		{"negative-zero", math.Copysign(0, -1), float64(0), false, false},
		{"nil-array", []any(nil), []any{}, false, false},
		{"nil-object", map[string]any(nil), map[string]any{}, false, false},
		{"number-spelling", json.Number("7.0"), float64(7), false, false},
		{"named-string", spelling("7"), "7", false, true},
		{"equivalent-number-type", int(7), float64(7), false, true},
		{"changed-key", map[string]any{"new": nil}, map[string]any{"old": nil}, false, false},
		{"changed-item", []any{float64(2)}, []any{float64(1)}, false, false},
		{"not-json", make(chan int), nil, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := sameMultipleImportedJSON(row.value, row.original)
			a, ae := json.Marshal(row.value)
			b, be := json.Marshal(row.original)
			same := ae == nil && be == nil && bytes.Equal(a, b)
			if got != row.fast || same != row.canonical || got && !same {
				t.Fatal("live value skipped canonical difference", got, same)
			}
		})
	}
	original, _, _ := multipleImportedExecutionFixture(t, multipleImportedServerLayouts[1], "wg", "", "auto", "")
	member := original.importedNodes.members[1]
	s := member.multipleSeal
	profile := member.selection.Profile
	ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
	port := ss["port"].(float64)
	ss["port"] = int(port)
	if !s.matches(member) {
		t.Fatal("canonically identical dynamic scalar rejected")
	}
	ss["port"] = json.Number(fmt.Sprintf("%.1f", port))
	if s.matches(member) {
		t.Fatal("distinct JSON number spelling accepted")
	}
	ss["port"] = port
	profile["nested"] = profile
	if s.matches(member) {
		t.Fatal("cycle borrowed original capture")
	}
	delete(profile, "nested")
	if !s.matches(member) {
		t.Fatal("original mutable source failed after restoration")
	}
}

// An original can encode a value that a JSON float cannot reproduce. Build the
// actual packet seal from that spelling and then substitute the decoded float.
func TestNodeChainMultipleImportedCandidateOriginalNumberSpelling(t *testing.T) {
	for _, row := range []struct {
		name     string
		original any
		rounded  float64
	}{
		{"decimal", json.Number("7.0"), 7},
		{"large-integer", int64(9007199254740993), 9007199254740992},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[2], "server")
			chain := f.runtime.projection.policy.local
			node := chain.nodes[0]
			node.profile["snapshot-number"] = row.original
			if err := node.sealNodeDesktopCapture(); err != nil {
				t.Fatal(err)
			}
			seal := newNodeChainMultipleImportedPacketSeal(node)
			if seal == nil {
				t.Fatal("original number lost its byte-preserving packet seal")
			}
			chain.importedNodes.localSeal.packets[0] = seal
			if err := chain.validateOriginalPacket(0, node); err != nil {
				t.Fatal("original exact numeric encoding was refused", err)
			}
			node.profile["snapshot-number"] = row.rounded
			if chain.validateOriginalPacket(0, node) == nil {
				t.Fatal("rounded number borrowed a different original packet seal")
			}
			selection := [2]externalPolicyCapture{{Profile: map[string]any{"v": row.original}}, {}}
			raw, err := json.Marshal(selection)
			if err != nil || decodeMultipleImportedOriginal[[2]externalPolicyCapture](raw) != nil {
				t.Fatal("lossy original imported member acquired a decoded shortcut", err)
			}
		})
	}
}

func TestSelectedPrivateStreamEntryCandidate(t *testing.T) {
	for _, outcome := range []string{"server", "compare-local", "compare-server"} {
		t.Run(outcome, func(t *testing.T) {
			requested := "auto"
			if outcome == "server" {
				requested = "server"
			}
			f := multipleImportedExecutionRuntimeFixture(t, selectedPrivateStreamLayout(9, 2), requested)
			entryRun(t, f, outcome)
			t.Cleanup(func() {
				if err := closeRemoteCandidateRuntime(f.runtime); err != nil {
					t.Error(err)
				}
			})
			inventory, _ := entryInventory(t)
			entry, err := f.runtime.NewEntryCandidatePlanContext(t.Context(), 0, inventory)
			if err != nil || entry.plan.multiple == nil || entry.plan.multiple.original.selectedPrivateStreamPosition() != 2 {
				t.Fatal("selected entry lost its original private-stream source", err)
			}
			if plan, err := f.runtime.NewLocalCandidatePlanContext(t.Context(), 2, inventory); err == nil || plan != nil {
				t.Fatal("private stream acquired selected Local response authority")
			}
			if plan, err := f.runtime.NewRemoteCandidatePlanContext(t.Context(), 2, inventory); err == nil || plan != nil {
				t.Fatal("private stream acquired selected Server response authority")
			}
		})
	}
}
