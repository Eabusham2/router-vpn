//go:build linux

package main

import (
	"context"
	"errors"

	"router-vpn/internal/common"
)

// The initial Linux host contract is deliberately the same bounded graph as
// the independently sealed native child. Eligibility is not public admission.
func desktopLinuxImportedEligible(selection multihopSelection) bool {
	policy := desktopOwnedNodeProtectionPolicy(selection.Control)
	return selection.Base == "native" && selection.EntryMode == "wireguard" && selection.ExitMode == "shadowsocks" &&
		selection.Entry.NodeKind == "external" && selection.Entry.External != nil && selection.Entry.External.Protocol == "wireguard" &&
		selection.Entry.ID != "" && selection.Entry.ID != selection.Exit.ID && selection.Control.ID == selection.Exit.ID &&
		selection.Exit.External == nil && (selection.Exit.NodeKind == "" || selection.Exit.NodeKind == "router-vpn") &&
		(selection.Entry.StartLayer == "" || selection.Entry.StartLayer == "off") &&
		(selection.Exit.StartLayer == "" || selection.Exit.StartLayer == "off") &&
		mtuProfileSnapshotToken(selection.Control) == mtuProfileSnapshotToken(selection.Exit) &&
		(policy == "always" || policy == "on-connect")
}

// Original and applied profile projections are separate states. Once staging
// begins, only the applied projection and the same temporary owner can admit
// the transaction; reverting the saved original is never a fallback match.
type desktopLinuxImportedSources struct {
	selection      multihopSelection
	selected       string
	original       map[string]string
	options        [3]bool
	appliedOptions [3]bool
	temporary      *speedLabTemporaryOwner
	preparation    *speedLabMultihopPreparation
}

func captureDesktopLinuxImportedSourcesLocked(ctx context.Context, a *app, selection multihopSelection) (*desktopLinuxImportedSources, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || !desktopLinuxImportedEligible(selection) {
		return nil, errors.New("Linux imported source requires its original WG entry and paired SS final with both Start Layers Off")
	}
	selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
	s := &desktopLinuxImportedSources{selection: selection, selected: a.profiles.SelectedID, original: make(map[string]string),
		options:        [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks},
		appliedOptions: [3]bool{selection.Control.DAITAEnabled, selection.Control.JumboTUN, selection.Control.SocksEnabled}}
	if prepared, ok := ctx.Value(desktopImportedPreparationContextKey{}).(*speedLabMultihopPreparation); ok {
		if prepared == nil || prepared.app != a || prepared.owner == nil || prepared.selection.Entry.ID != selection.Entry.ID ||
			prepared.selection.Exit.ID != selection.Exit.ID || prepared.selection.ExitMode != selection.ExitMode ||
			mtuProfileSnapshotToken(prepared.selection.Control) != mtuProfileSnapshotToken(selection.Control) || prepared.currentLocked(a, false) != nil {
			return nil, errors.New("Linux imported source lost its exact temporary preparation")
		}
		s.temporary, s.preparation = prepared.owner, prepared
		for id, token := range prepared.sources {
			s.original[id] = token
		}
	} else {
		if s.selected != selection.Control.ID || s.options != s.appliedOptions {
			return nil, errors.New("Linux imported source changed its selected final or runtime options")
		}
		for _, profile := range []common.RouterProfile{selection.Entry, selection.Control, selection.Exit} {
			s.original[profile.ID] = mtuProfileSnapshotToken(profile)
		}
	}
	if err := s.currentLocked(a, false); err != nil {
		return nil, err
	}
	return s, nil
}

// Caller holds app.mu. This comparison deliberately requires no live-host
// capability so the original capture can also be checked before Stop.
func (s *desktopLinuxImportedSources) currentLocked(a *app, applied bool) error {
	if s == nil || a == nil || !desktopLinuxImportedEligible(s.selection) || len(s.original) < 2 {
		return errors.New("Linux imported source lost its independently captured profiles")
	}
	selected, options := s.selected, s.options
	if s.temporary != nil {
		p := s.preparation
		if p == nil || p.app != a || p.owner != s.temporary || p.operation == nil || p.caller == nil ||
			p.operation.Err() != nil || p.caller.Err() != nil || a.connectionContext != p.operation ||
			a.connectionCancelIntent == p.operation || !a.speedLabOwnerCurrentLocked(s.temporary) || a.cmd != s.temporary.runtime {
			return errors.New("Linux imported source lost its original temporary owner or caller")
		}
		if applied {
			selected, options = s.selection.Control.ID, s.appliedOptions
			if !s.temporary.mutated {
				return errors.New("Linux imported source projection preceded original suspension")
			}
		}
	}
	if a.profiles.SelectedID != selected || [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != options {
		return errors.New("Linux imported source changed its selected projection or runtime options")
	}
	for id, expected := range s.original {
		profile, exists := a.profileByIDLocked(id)
		if s.temporary != nil && applied && id == s.selection.Control.ID {
			expected = liveMeasurementProfileToken(s.selection.Control)
		}
		actual := mtuProfileSnapshotToken(profile)
		if s.temporary != nil {
			actual = liveMeasurementProfileToken(profile)
		}
		if !exists || actual != expected {
			return errors.New("Linux imported source replaced an independent saved profile or applied projection")
		}
	}
	return nil
}
