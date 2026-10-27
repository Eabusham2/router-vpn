package main

import (
	"errors"
	"strings"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
)

// A connection request captures a private source independently from the
// effective runtime policy. Capturing Direct/entry choices never rewrites the
// reusable imported Tor node or copies a Router's credentials into that node.
// Only a successfully proved public Connect can later save its chosen path.
type desktopTorSelection struct {
	profile      common.RouterProfile
	policy       common.RouterProfile
	profileToken string
	predecessor  *desktopTorPredecessorCapture
}

// Empty execution is the historical Local capture. Server is always explicit;
// a Compare preference has no proved Tor winner and cannot be restored as one.
func desktopTorExecution(value string) string {
	switch value {
	case "", "local":
		return "local"
	case "server":
		return "server"
	default:
		return ""
	}
}

func captureDesktopTorSelection(a *app, profile common.RouterProfile, q externalProfileConnectRequest, lookup applexray.Lookup) (*desktopTorSelection, error) {
	if a == nil || profile.ID == "" || strings.TrimSpace(q.ProfileID) != profile.ID {
		return nil, errors.New("Tor selection requires its exact captured external node")
	}
	profile = cloneRouterProfile(profile)
	if _, _, _, _, err := torBridgeProfile(cloneRouterProfile(profile)); err != nil {
		return nil, err
	}
	base := q.Base
	switch base {
	case "", "auto":
		base = ""
	case "wg", "awg":
	default:
		return nil, errors.New("Tor entry base must be auto, wg or awg")
	}
	entryID := strings.TrimSpace(q.EntryID)
	direct := true
	if q.Direct != nil {
		direct = *q.Direct
		if direct && entryID != "" {
			return nil, errors.New("direct Tor cannot apply a different entry node")
		}
	} else {
		direct = entryID == "" && !profile.MultihopEnabled
	}
	if !direct && entryID == "" {
		if profile.MultihopExitID != profile.ID {
			return nil, errors.New("saved Tor exit reference does not match the captured node")
		}
		entryID = profile.MultihopEntryID
	}
	if direct && (q.EntryMode != "" || base != "") {
		return nil, errors.New("direct Tor cannot apply a Router entry mode or base")
	}
	execution, err := externalExecutionChoice(profile, q.Execution, direct)
	if err != nil {
		return nil, err
	}
	if desktopTorExecution(execution) == "" || direct && execution != "local" {
		return nil, errors.New("Tor Compare requires distinct owned last-node and external measurements; Direct Tor requires Local execution")
	}
	policy, err := externalRuntimePolicy(profile)
	if err != nil {
		return nil, err
	}
	policy.MultihopEnabled, policy.MultihopEntryID, policy.MultihopExitID = !direct, "", ""
	policy.MultihopEntryMode, policy.MultihopExecution = "", execution
	selection := &desktopTorSelection{profile: profile, policy: policy, profileToken: desktopTorSourceIdentityToken(profile)}
	entry := common.RouterProfile{}
	if !direct {
		if !validProfileID(entryID) || entryID == profile.ID {
			return nil, errors.New("Tor requires two distinct valid entry and exit references")
		}
		a.mu.Lock()
		var found bool
		entry, found = a.profileByIDLocked(entryID)
		entry = cloneRouterProfile(entry)
		a.mu.Unlock()
		if !found {
			return nil, errors.New("Tor entry must be a linked node with its complete native transport")
		}
		if execution == "server" && (entry.External != nil || entry.NodeKind != "" && entry.NodeKind != "router-vpn") {
			return nil, errors.New("Tor Server requires an authenticated private Router entry with the exact paired Tor source")
		}
		mode, err := desktopTorEntryMode(profile, entry, q.EntryMode, base)
		if err != nil {
			return nil, err
		}
		policy.MultihopEntryID, policy.MultihopExitID, policy.MultihopEntryMode = entry.ID, profile.ID, mode
	}
	// Resolver selection belongs to this exact path before its ordinary lower
	// transport is compiled. Home remains available only through a Router owner.
	policy, err = externalDNSPolicyForPath(policy, entry, direct)
	if err != nil {
		return nil, err
	}
	if !direct {
		selection.predecessor, err = captureDesktopTorPredecessor(a, policy, lookup)
		if err != nil {
			return nil, err
		}
		// Capture came from the registry independently of the earlier policy
		// read. Never combine its newer credentials with the prior entry data.
		if selection.predecessor == nil || desktopTorSourceIdentityToken(entry) != selection.predecessor.profileToken {
			return nil, errors.New("Tor predecessor changed during capture")
		}
	}
	selection.policy = policy
	if err := selection.current(a); err != nil {
		return nil, err
	}
	return selection, nil
}

func (selection *desktopTorSelection) currentLocked(a *app) error {
	if selection == nil || a == nil || selection.profileToken == "" {
		return errors.New("Tor selection has no captured source owner")
	}
	profile, found := a.profileByIDLocked(selection.profile.ID)
	if !found || desktopTorSourceIdentityToken(profile) != selection.profileToken {
		return errors.New("Tor profile credentials or policy changed during preparation")
	}
	return selection.predecessor.currentLocked(a)
}

func (selection *desktopTorSelection) current(a *app) error {
	if a == nil {
		return errors.New("Tor selection has no application owner")
	}
	a.mu.Lock()
	err := selection.currentLocked(a)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	if err := selection.predecessor.current(a); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return selection.currentLocked(a)
}
