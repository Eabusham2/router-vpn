//go:build linux

package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"router-vpn/internal/mobilemtu"
)

// This is one read-only snapshot of the retained native host. The live TUN
// record is observed under its original session and host gates; neither a
// saved EffectiveMTU nor a view request can create that native ownership.
type desktopLinuxMTUView struct {
	identity     mtuViewIdentity
	live         desktopNodeMTURecord
	auto         bool
	busy         bool
	hasOperation bool
	operation    mobilemtu.Status
}

func captureDesktopLinuxMTUView(ctx context.Context, a *app, request string) (view desktopLinuxMTUView, handled bool, failure error) {
	if ctx == nil || ctx.Err() != nil {
		return view, true, errors.New("MTU status request ended before native observation")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	handled, failure = withDesktopLinuxNodeMTUHost(ctx, a, func(_ *desktopLinuxNodeSession, h *desktopLinuxNodeHost) error {
		_, live, err := h.readReadyLocked(ctx, false)
		if err != nil {
			return err
		}
		profile, err := h.capturedProofProfile()
		if err != nil {
			return err
		}
		session := sessionTrackerFor(a).snapshot(0)
		if session.ID == "" || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" ||
			session.EndedAt != nil || session.RouterID != h.launch.profileID || session.ActualMode != h.launch.mode {
			return errors.New("MTU status lost its original proved connection identity")
		}
		if h.mtu != nil && h.mtu.originalLocked() != nil || live.Active && h.mtu == nil {
			return errors.New("MTU status has no original owner for its pending native lease")
		}
		view.identity = mtuViewIdentity{Session: session.ID, Profile: h.launch.profileID}
		view.live, view.busy = live, h.mtu != nil || live.Active
		view.auto = strings.EqualFold(strings.TrimSpace(profile.MTUPolicy), "auto")
		if operation := lookupMTUViewOperation(a, view.identity, request); operation != nil {
			operation.mu.Lock()
			view.hasOperation, view.operation = true, operation.status
			view.operation.Candidates = append([]mobilemtu.Candidate(nil), operation.status.Candidates...)
			operation.mu.Unlock()
		}
		// The native read and view lookup can overlap an application change.
		// Recheck the original native owner, then compare the complete current
		// application capture under its mutex before publishing this snapshot.
		if err := h.current(ctx); err != nil {
			return err
		}
		a.mu.Lock()
		err = desktopLinuxMTUViewAppCurrentLocked(a, h, view.identity)
		a.mu.Unlock()
		return errors.Join(err, ctx.Err())
	})
	return
}

// Caller holds the original host gate and app mutex. A matching public node
// name or command alone cannot preserve a changed DNS, Fixed/Auto policy,
// private profile, controller, or separately selected runtime option.
func desktopLinuxMTUViewAppCurrentLocked(a *app, h *desktopLinuxNodeHost, identity mtuViewIdentity) error {
	if a == nil || h == nil || h.parent == nil || h.parent.app != a || h.process == nil || h.launch == nil ||
		h.process.command == nil || identity.Session == "" || identity.Profile != h.launch.profileID || identity.Native ||
		h.parent.currentAppLocked(false) != nil {
		return errors.New("MTU status lost its original application owner")
	}
	profile, exists := a.profileByIDLocked(h.launch.profileID)
	_, duplicate := desktopNodeOwners.Load(a)
	current := a.state
	if !exists || desktopOwnedNodeProfileToken(profile) != h.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.savedOptions ||
		[3]bool{current.DAITA, current.Jumbo, current.Socks} != h.options || duplicate ||
		a.cmd != h.process.command || !current.Connected || current.Phase != "connected" ||
		current.RouterID != identity.Profile || current.RuntimeMode != h.launch.mode {
		return errors.New("MTU connection changed during native observation")
	}
	return nil
}

// A retained completed measurement is displayed only while its actual value
// is still current and no later lease is pending. An unlabelled internal lease
// has no view cancellation token; it must not borrow an older request's token.
func writeDesktopLinuxMTUCapturedView(w http.ResponseWriter, view desktopLinuxMTUView, request, session string) {
	if session != "" && session != view.identity.Session {
		http.Error(w, "MTU connection was replaced", http.StatusConflict)
		return
	}
	if view.hasOperation {
		status := view.operation
		if view.busy && !status.Running {
			view.hasOperation = false
		} else if status.Running {
			status.EffectiveMTU, status.Source = view.live.MTU, "live-captured-interface"
			status.Complete, status.Measured = false, false
			writeMTUViewStatus(w, view.identity, true, false, view.auto, status)
			return
		} else if status.EffectiveMTU == view.live.MTU {
			writeMTUViewStatus(w, view.identity, true, false, view.auto, status)
			return
		} else if request != "" {
			http.Error(w, "MTU result no longer matches the running interface", http.StatusConflict)
			return
		}
	}
	if request != "" {
		http.Error(w, "MTU request has not started or was replaced", http.StatusNotFound)
		return
	}
	status := mobilemtu.Status{Phase: "idle", EffectiveMTU: view.live.MTU, Source: "live-captured-interface", Candidates: []mobilemtu.Candidate{}}
	if view.busy {
		status.Phase, status.Running = "busy", true
	}
	writeMTUViewStatus(w, view.identity, false, false, view.auto, status)
}

func (a *app) writeDesktopPlatformMTUViewStatus(w http.ResponseWriter, r *http.Request, request, session string) bool {
	if a.writeLinuxStandardServiceMTUViewStatus(w, r, request, session) {
		return true
	}
	view, handled, err := captureDesktopLinuxMTUView(r.Context(), a, request)
	if !handled {
		return false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	writeDesktopLinuxMTUCapturedView(w, view, request, session)
	return true
}
