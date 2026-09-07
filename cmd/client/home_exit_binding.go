package main

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"

	"router-vpn/internal/common"
)

// Every lifecycle invalidation also advances an epoch. Merely deleting the
// cached value would let an in-flight request re-adopt its old proof after a
// fast recheck/rollback restored identical state between observer ticks.
type homeExitProofCache struct {
	sync.Map
	generations sync.Map
}

func (c *homeExitProofCache) counter(key any) *atomic.Uint64 {
	counter, _ := c.generations.LoadOrStore(key, &atomic.Uint64{})
	return counter.(*atomic.Uint64)
}

func (c *homeExitProofCache) generation(key any) uint64 { return c.counter(key).Load() }

func (c *homeExitProofCache) Delete(key any) {
	c.counter(key).Add(1)
	c.Map.Delete(key)
}

// Both tracker.mu and app.mu are held, in that order. Validation must not call
// snapshot or another app-locking helper while adopting the durable result.
func validateHomeExitBindingLocked(a *app, session *connectionSession, proof *homeExitProof) error {
	if session == nil || proof == nil || proof.SessionID == "" || proof.RouterID == "" ||
		session.ID != proof.SessionID || session.RouterID != proof.RouterID ||
		!session.Connected || session.Phase != "connected" || session.PathProof != "passed" ||
		session.ActualMode != proof.Runtime || session.ActualBase != proof.Base {
		return errors.New("Home public-exit proof no longer belongs to the live VPN session")
	}
	if homeExitProofs.generation(a) != proof.Generation {
		return errors.New("Home public-exit proof was invalidated by a VPN lifecycle transition")
	}
	if !a.state.Connected || a.state.RouterID != proof.RouterID || mtuStateSnapshotToken(a.state) != proof.StateToken {
		return errors.New("Home public-exit proof no longer belongs to the active runtime path")
	}
	runtimeID := strings.TrimSpace(a.state.RuntimeMode)
	if runtimeID == "" && a.state.Mode != "off" {
		runtimeID = strings.TrimSpace(a.state.Mode)
	}
	if strings.TrimSpace(a.state.Phase) != "connected" || runtimeID != session.ActualMode || a.state.Base != session.ActualBase || proof.Multihop != (a.state.Mode == "multihop") {
		return errors.New("Home public-exit proof refused a lagging session tracker or mismatched runtime")
	}
	if proof.Profiles[proof.RouterID] == "" {
		return errors.New("Home public-exit proof has no captured node profile")
	}
	if proof.Multihop {
		graph, ok := getActiveMultihopGraph(a)
		if err := validateActiveMultihopSpeedGraph(a.state, graph, ok, proof.Graph.EntryID, proof.Graph.ExitID); err != nil {
			return err
		}
		if !sameActiveMultihopGraph(graph, proof.Graph) || proof.Profiles[graph.EntryID] == "" {
			return errors.New("Home public-exit proof belongs to a replaced multihop graph")
		}
	}
	return validateMeasurementProfilesLocked(a, proof.Profiles)
}

func (a *app) validateHomeExitBinding(proof *homeExitProof) error {
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	return validateHomeExitBindingLocked(a, tracker.session, proof)
}

func (a *app) homeExitProofCurrent(proof *homeExitProof, profile common.RouterProfile, observed connectionSession) bool {
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	valid := proof != nil && proof.IP != "" && !proof.At.IsZero() &&
		profile.ID == proof.RouterID && asyncMeasurementProfileToken(profile) == proof.Profiles[profile.ID] &&
		validateHomeExitBindingLocked(a, &observed, proof) == nil &&
		validateHomeExitBindingLocked(a, tracker.session, proof) == nil
	if !valid && proof != nil {
		// A concurrent newer proof must not be removed by an older summary read.
		homeExitProofs.CompareAndDelete(a, proof)
	}
	return valid
}
