package main

import (
	"errors"
	"fmt"
	"strings"
)

// ALL preserves the established TLS-first order, honoring the selected base
// within each transport family. These are complete graphs, not aliases for
// the raw dual-transport mode. Every attempt uses the ordinary captured native
// constructor, selected-node/DNS proof and owned retirement path.
func desktopNodeALLCandidates(preferred string) []runtimeCandidate {
	first, second := "wg", "awg"
	if normalizeBase(preferred) == "awg" {
		first, second = second, first
	}
	return []runtimeCandidate{
		{RuntimeID: "max-tls-" + first, Base: first},
		{RuntimeID: "max-tls-" + second, Base: second},
		{RuntimeID: "max-quic-" + first, Base: first},
		{RuntimeID: "max-quic-" + second, Base: second},
	}
}

func (a *app) startDesktopNodeALL(requestedBase string) (runtimeCandidate, error) {
	operation := a.connectionOperationContextOrBackground()
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return runtimeCandidate{}, err
	}
	profile, err := a.activeProfile()
	if err != nil {
		return runtimeCandidate{}, err
	}
	profileToken := desktopOwnedNodeProfileToken(profile)
	stopped := false
	var failures []string
	for _, candidate := range desktopNodeALLCandidates(a.preferredBase(requestedBase)) {
		if err := a.checkCapturedConnectionOperation(operation); err != nil {
			return runtimeCandidate{}, err
		}
		current, err := a.activeProfile()
		if err != nil || desktopOwnedNodeProfileToken(current) != profileToken {
			return runtimeCandidate{}, errors.Join(err, errors.New("ALL captured profile changed between native attempts"))
		}
		transition := &modeAttemptTransition{}
		err = a.startModeAttempt(candidate.RuntimeID, true, transition)
		stopped = stopped || transition.StopBegun
		if cancelled := a.checkCapturedConnectionOperation(operation); cancelled != nil {
			return runtimeCandidate{}, errors.Join(err, cancelled)
		}
		if err == nil {
			return candidate, nil
		}
		if errors.Is(err, errConnectionOperationCancelled) || errors.Is(err, errDesktopNodeOperationReplaced) {
			return runtimeCandidate{}, err
		}
		failures = append(failures, fmt.Sprintf("%s: %v", candidate.RuntimeID, err))
		if transition.StopBegun {
			a.mu.Lock()
			commandRetained := a.cmd != nil
			a.mu.Unlock()
			_, ownerRetained := desktopNodeOwners.Load(a)
			if commandRetained || ownerRetained {
				return runtimeCandidate{}, errors.Join(err, errors.New("ALL cannot replace an unjoined native attempt"))
			}
		}
	}
	// A preflight-only refusal has not acquired a transition to release. Once
	// Stop has begun, release only this same operation's joined transition;
	// Always and unresolved native retirement remain governed by their owners.
	if stopped {
		if err := a.checkCapturedConnectionOperation(operation); err != nil {
			return runtimeCandidate{}, err
		}
		if err := a.releaseTransitionKillSwitch(); err != nil {
			failures = append(failures, err.Error())
		}
	}
	return runtimeCandidate{}, fmt.Errorf("ALL native candidates unavailable: %s", strings.Join(failures, " • "))
}
