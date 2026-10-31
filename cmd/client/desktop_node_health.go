package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"router-vpn/internal/common"
)

// The owned graph already captured and validated its private node, credentials
// and selected DNS. Its HTTP proof must not reopen today's saved WG bundle or
// borrow another node's global fallback URL during SMART/Speed Lab restoration.
// The native DNS/TUN receipt and the same active protection generation bracket
// the real HTTP exchange; neither a source ID nor a historical receipt is proof.
func (a *app) testDesktopOwnedNodeHealth(parent context.Context, profile common.RouterProfile, launch *desktopNodeLaunch) (time.Duration, error) {
	if a == nil || parent == nil || parent.Err() != nil || launch == nil || launch.ownedNode == nil {
		return 0, errors.New("native Router proof has no captured connection")
	}
	operation := a.connectionOperationContextOrBackground()
	owned := launch.ownedNode
	if owned.policy == nil || owned.policy.Validate() != nil || owned.slot == nil || owned.attempt == nil ||
		desktopOwnedNodeProfileToken(profile) != owned.profileToken {
		return 0, errors.New("native Router proof changed its captured profile")
	}
	original := owned.policy.OriginalProfile()
	if original == nil {
		return 0, errors.New("native Router proof lost its sealed original graph")
	}
	source, err := original.LaunchInput()
	if err != nil || validateDesktopOwnedNodeSourceProfile(profile, launch.endpoint, source) != nil {
		return 0, errors.Join(err, errors.New("native Router proof belongs to another sealed source"))
	}
	var envelope struct {
		ProfileJSON string `json:"profile_json"`
	}
	var captured common.RouterProfile
	if json.Unmarshal([]byte(source), &envelope) != nil || json.Unmarshal([]byte(envelope.ProfileJSON), &captured) != nil {
		return 0, errors.New("native Router proof cannot recover its original private profile")
	}
	node := owned.policy.Metadata().NodeID
	if !common.ValidNodeProofID(node) || node != captured.NodeProofID || captured.ID != launch.profileID {
		return 0, errors.New("native Router proof changed its original node identity")
	}
	if strings.TrimSpace(captured.PathProbeURL) == "" {
		captured.PathProbeURL = strings.TrimRight(captured.RouterAPI, "/") + "/health"
	}
	slot := owned.slot
	slot.mu.Lock()
	generation := slot.generation
	target := copyDesktopNodeProtectionTarget(owned.attempt.prepared)
	slot.mu.Unlock()
	if target == nil {
		return 0, errors.New("native Router proof preceded its accepted protection target")
	}
	current := func() error {
		if err := a.checkCapturedConnectionOperation(operation); err != nil {
			return err
		}
		if err := parent.Err(); err != nil {
			return err
		}
		if _, err := a.readDesktopOwnedNodeReady(launch, false); err != nil {
			return err
		}
		slot.mu.Lock()
		defer slot.mu.Unlock()
		if slot.generation != generation || slot.active != owned.attempt || slot.retirement != nil || slot.off != nil ||
			owned.attempt.prepared == nil || *owned.attempt.prepared != *target || slot.backend.prepared == nil {
			return errors.New("native Router proof changed its active protection generation")
		}
		if err := slot.backend.prepared(parent, *target); err != nil {
			return err
		}
		if !a.desktopOwnedNodeCurrent(launch, true) {
			return errors.New("native Router proof lost its exact native owner")
		}
		return a.checkCapturedConnectionOperation(operation)
	}
	if err := current(); err != nil {
		return 0, err
	}
	elapsed, err := a.testHealthContextWithProof(parent, captured, func(body []byte) error { return validateCapturedNodeProof(node, body) })
	if ownershipErr := current(); ownershipErr != nil {
		return 0, errors.Join(err, ownershipErr)
	}
	return elapsed, err
}
