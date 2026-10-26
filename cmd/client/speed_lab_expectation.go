package main

import (
	"errors"
	"strings"
)

var errSpeedLabSelectionChanged = errors.New("Speed Lab node selection changed or its captured source revisions are incomplete; reload Speed Lab")

func (q speedLabRequest) hasExpectedProfiles() bool {
	return q.ExpectedSelectedNodeID != "" || q.ExpectedProfileTokens != nil
}

// Called with a.mu held. The owning operation also holds operationMu before a
// temporary path can capture or suspend its predecessor. Legacy callers may
// omit both fields; a supplied revision map must cover every requested owner.
func (a *app) validateSpeedLabExpectedProfilesLocked(q speedLabRequest, current *speedLabPath) error {
	if !q.hasExpectedProfiles() {
		return nil
	}
	if q.ExpectedProfileTokens == nil || len(q.ExpectedProfileTokens) > 64 || q.ExpectedSelectedNodeID != a.profiles.SelectedID {
		return errSpeedLabSelectionChanged
	}
	required := []string{}
	if q.ExpectedSelectedNodeID != "" {
		required = append(required, q.ExpectedSelectedNodeID)
	}
	if strings.EqualFold(strings.TrimSpace(q.Scope), "temporary") {
		switch strings.ToLower(strings.TrimSpace(q.Topology)) {
		case "", "router", "direct":
			required = append(required, q.NodeID)
		case "multihop":
			required = append(required, q.EntryID, q.ExitID)
		case "external":
			required = append(required, q.NodeID)
			if q.EntryID != "" {
				required = append(required, q.EntryID)
			}
		case "system-direct":
		default:
			return errSpeedLabSelectionChanged
		}
	} else if current != nil {
		for _, id := range []string{current.NodeID, current.EntryID, current.ExitID} {
			if id != "" {
				required = append(required, id)
			}
		}
	}
	for _, id := range required {
		if id == "" || q.ExpectedProfileTokens[id] == "" {
			return errSpeedLabSelectionChanged
		}
	}
	for id, token := range q.ExpectedProfileTokens {
		profile, exists := a.profileByIDLocked(id)
		if !validProfileID(id) || !validStartupProfileToken(token) || !exists || token != publicProfileToken(profile) {
			return errSpeedLabSelectionChanged
		}
	}
	return nil
}

func (a *app) validateSpeedLabExpectedProfiles(q speedLabRequest, current *speedLabPath) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.validateSpeedLabExpectedProfilesLocked(q, current)
}

func (a *app) captureExpectedSpeedLabIdentity(q speedLabRequest) (speedLabPathIdentity, speedLabPath, error) {
	if !q.hasExpectedProfiles() {
		return captureSpeedLabIdentity(a)
	}
	// Hold the mutation lock only while binding the requested public revisions
	// to the actual proved runtime. Release it before any measurement so an
	// explicit Disconnect can still cancel the existing live-path observer.
	release, err := a.beginNodeBoundOperation()
	if err != nil {
		return speedLabPathIdentity{}, speedLabPath{}, err
	}
	defer release()
	if err := a.validateSpeedLabExpectedProfiles(q, nil); err != nil {
		return speedLabPathIdentity{}, speedLabPath{}, err
	}
	identity, path, err := captureSpeedLabIdentity(a)
	if err != nil {
		return identity, path, err
	}
	if err := a.validateSpeedLabExpectedProfiles(q, &path); err != nil {
		return speedLabPathIdentity{}, speedLabPath{}, err
	}
	return identity, path, nil
}
