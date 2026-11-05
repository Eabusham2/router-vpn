//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"

	"router-vpn/internal/mobiletor"
)

type linuxStandardServiceProtectionData struct {
	Token               string `json:"token"`
	ProfileID           string `json:"profile_id"`
	ProfileRevision     string `json:"profile_revision"`
	ResultRevision      string `json:"result_revision"`
	Policy              string `json:"policy"`
	Owned               bool   `json:"owned"`
	Active              bool   `json:"active"`
	Pending             bool   `json:"pending"`
	Removed             bool   `json:"removed"`
	AbsenceProved       bool   `json:"absence_proved"`
	StandardScopeAbsent bool   `json:"standard_scope_absent"`
	ProfileSaved        bool   `json:"profile_saved"`
	Failure             string `json:"failure,omitempty"`
}

// A view token compares a request with this live service object. Neither its
// wire representation nor saved settings can reconstruct slot/kernel authority.
type linuxStandardServiceProtection struct {
	data linuxStandardServiceProtectionData
	slot *legacyExitProtectionSlot
	peer *linuxStandardServicePeer
}

func (s *linuxStandardService) protectionAbsent(ctx context.Context, lease *legacyExitMutationLease) error {
	if err := legacyExitStateAbsent(lease); err != nil {
		return err
	}
	tun := s.tunAbsent
	if tun == nil {
		tun = legacyExitTUNAbsent
	}
	if err := tun(); err != nil {
		return err
	}
	absent := s.protectionAbsence
	if absent == nil {
		absent = mobiletor.ReadDesktopLinuxProtectionAbsence
	}
	if err := absent(ctx); err != nil {
		return err
	}
	if err := legacyExitStateAbsent(lease); err != nil {
		return err
	}
	return lease.Current()
}

func (s *linuxStandardService) protectionRequest(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
	if ctx == nil || ctx.Err() != nil || peer == nil || request.MTU != nil || request.Reverse != nil || request.Transfer != nil || request.Schema != 1 || !validControllerOwnerToken(request.Session) || request.Release || request.Directory != "" || request.ConfigSHA256 != "" || request.ProfileSHA256 != "" || request.Endpoint != "" || request.RuntimeMode != "" || request.Base != "" || request.NetworkID != "" || request.RouterID != "" {
		return nil, errors.New("standard protection request changed its captured scope")
	}
	if err := peer.Current(ctx); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.transferPending() {
		return nil, errors.New("standard protection remains reserved for its original Node transfer")
	}
	if s.quiescing {
		return nil, errors.New("standard protection owner is retiring")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(ns, s.namespace) {
		return nil, errors.Join(err, errors.New("standard protection left its original namespace"))
	}
	if s.reversePending() {
		return nil, errors.New("reverse guard transfer must resolve before protection changes")
	}
	if err = s.loadProfiles(); err != nil {
		return nil, err
	}
	var slot *legacyExitProtectionSlot
	if raw, exists := legacyStandardProtectionOwners.Load(s.app); exists {
		var valid bool
		slot, valid = raw.(*legacyExitProtectionSlot)
		if !valid || slot == nil {
			return nil, errors.New("standard protection has another live owner")
		}
	} else if s.boot != nil && !s.boot.closed {
		slot = s.boot
	}
	view := s.protectionView
	if request.Action == "protection-view" {
		if request.ProfileID != "" || request.ProfileRevision != "" || request.ResultRevision != "" {
			return nil, errors.New("standard protection view cannot select another source")
		}
		profileID := s.app.profiles.SelectedID
		if slot != nil {
			profileID = slot.profileID
		}
		if view != nil && view.data.Pending {
			profileID = view.data.ProfileID
		}
		profile, exists := s.app.profileByIDLocked(profileID)
		if !exists {
			return nil, errors.New("standard protection lost original profile selection")
		}
		revision := profileStartupSettingsToken(profile)
		completed := view != nil && view.data.ProfileSaved && slot == nil && view.data.ResultRevision == revision
		if view == nil || !view.data.Pending && !completed && (view.slot != slot || view.data.ProfileRevision != revision) {
			if view != nil && view.peer.record != peer.record {
				retired, err := view.peer.Retired()
				if err != nil || !retired {
					return nil, errors.Join(err, errors.New("standard protection cannot replace a live original controller view"))
				}
			}
			token, err := randomHex(16)
			if err != nil {
				return nil, err
			}
			result, err := profileProtectionOffResult(profile)
			if err != nil {
				return nil, err
			}
			if view != nil && view.peer != peer && (s.session == nil || s.session.peer != view.peer) {
				if err = view.peer.Close(); err != nil {
					return nil, err
				}
			}
			view = &linuxStandardServiceProtection{slot: slot, peer: peer, data: linuxStandardServiceProtectionData{Token: token, ProfileID: profileID, ProfileRevision: revision, ResultRevision: profileStartupSettingsToken(result)}}
			s.protectionView = view
		} else if view.peer.record != peer.record {
			retired, err := view.peer.Retired()
			if err != nil || !retired {
				return nil, errors.Join(err, errors.New("standard protection is still bound to another original controller"))
			}
			if err = view.peer.Close(); err != nil {
				return nil, err
			}
			view.peer = peer
		}
		view.data.Owned = view.slot != nil && (!view.slot.closed || view.data.Pending)
		view.data.Active = s.session != nil && !s.session.joined
		view.data.Failure = ""
		view.data.StandardScopeAbsent = false
		if view.slot != nil {
			view.data.Policy = view.slot.policy
			view.data.Removed = view.slot.removed
		} else {
			view.data.Policy = "off"
		}
		lease, err := acquireLegacyExitMutationLease(ctx, s.root)
		if err == nil {
			if view.data.Pending {
				if slot != nil && slot != view.slot {
					err = errors.New("accepted standard Off cannot replace another creator")
				}
				if err == nil && view.slot.closed {
					err = s.protectionAbsent(ctx, lease)
					view.data.AbsenceProved = err == nil
				}
			} else if view.slot != nil && !completed {
				err = view.slot.current(ctx, lease)
			} else {
				err = s.protectionAbsent(ctx, lease)
				view.data.AbsenceProved = err == nil
				if err == nil {
					view.data.StandardScopeAbsent = true
				} else if stateErr := legacyExitStateAbsent(lease); stateErr == nil {
					// This narrower read says nothing about the independent Node
					// family or TUN. Only a controller retaining that actual Node
					// parent may use it to compose the two read-only views.
					scopeErr := mobiletor.ReadDesktopLinuxStandardAndLegacyProtectionAbsence(ctx)
					view.data.StandardScopeAbsent = scopeErr == nil && legacyExitStateAbsent(lease) == nil
				}
			}
			lease.Close()
		}
		if err != nil {
			view.data.Failure = err.Error()
		}
		result := view.data
		return &result, nil
	}
	if request.Action != "protection-release" && request.Action != "protection-complete" && request.Action != "protection-finish" {
		return nil, errors.New("standard protection action unavailable")
	}
	if view == nil || view.slot == nil || view.data.Token != request.Session || view.peer.record != peer.record || view.data.ProfileID != request.ProfileID || view.data.ProfileRevision != request.ProfileRevision || view.data.ResultRevision != request.ResultRevision {
		return nil, errors.New("standard Off request lost its original creator or source revision")
	}
	if s.session != nil && (!s.session.joined || s.session.cleanupPending) {
		return nil, errors.New("disconnect the original standard engine before releasing protection")
	}
	if slot != nil && slot != view.slot {
		return nil, errors.New("standard Off cannot release a newer protection owner")
	}
	profile, exists := s.app.profileByIDLocked(view.data.ProfileID)
	if !exists || s.app.profiles.SelectedID != view.data.ProfileID {
		return nil, errors.New("standard Off changed its original selected profile")
	}
	revision := profileStartupSettingsToken(profile)
	if revision != view.data.ProfileRevision && (!view.data.Pending || revision != view.data.ResultRevision) {
		return nil, errors.New("standard Off source settings changed before native release")
	}
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	if request.Action == "protection-release" {
		view.data.Pending = true
		if err = view.slot.release(ctx, lease); err != nil {
			view.data.Removed = view.slot.removed
			view.data.Failure = err.Error()
			return nil, err
		}
		view.data.Removed = view.slot.removed
		if err = s.protectionAbsent(ctx, lease); err != nil {
			view.data.Failure = err.Error()
			return nil, err
		}
		view.data.AbsenceProved = true
		if s.boot == view.slot {
			s.boot = nil
		}
	} else {
		if request.Action == "protection-finish" && !view.data.ProfileSaved {
			return nil, errors.New("standard Off must verify its saved result before final completion")
		}
		if !view.data.Pending && !view.data.ProfileSaved || !view.data.Removed || !view.data.AbsenceProved || revision != view.data.ResultRevision || profile.KillSwitchPolicy != "off" || profile.KillSwitch {
			return nil, errDesktopProtectionOffUnsaved
		}
		if err = s.protectionAbsent(ctx, lease); err != nil {
			return nil, err
		}
		view.data.ProfileSaved = true
		if request.Action == "protection-finish" {
			view.data.Pending = false
			view.data.Owned = false
		}
	}
	view.data.Failure = ""
	result := view.data
	return &result, ctx.Err()
}

var linuxStandardServiceProtectionClients sync.Map // map[*app]*linuxStandardServiceProtectionClient
type linuxStandardServiceProtectionClient struct {
	mu               sync.Mutex
	app              *app
	controller       *ownedDesktopController
	image, namespace os.FileInfo
	peer             *linuxStandardServicePeer
	exchange         func(context.Context, linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error)
}

type linuxStandardServiceProtectionCapture struct {
	linuxStandardServiceProtectionData
	Available     bool
	Absent        bool // Independently observed full absence; never an authenticated service reply.
	ScopedAbsent  bool // Standard/shared legacy absence beside the captured native Node parent only.
	Failure       error
	client        *linuxStandardServiceProtectionClient
	launch        *linuxStandardServiceLaunch
	launchSession string
	launchCleared bool
}

func (a *app) captureLinuxStandardServiceProtection(ctx context.Context) *linuxStandardServiceProtectionCapture {
	return a.captureLinuxStandardServiceProtectionForParent(ctx, nil)
}

func (a *app) captureLinuxStandardServiceProtectionForParent(ctx context.Context, parent *desktopPlatformProtectionCapture) *linuxStandardServiceProtectionCapture {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	controller := a.localController
	a.mu.Unlock()
	raw, exists := linuxStandardServiceProtectionClients.Load(a)
	var client *linuxStandardServiceProtectionClient
	if exists {
		client, _ = raw.(*linuxStandardServiceProtectionClient)
	} else {
		if controller == nil {
			return nil
		}
		image, err := os.Stat("/proc/self/exe")
		if err != nil {
			return &linuxStandardServiceProtectionCapture{Failure: err}
		}
		runtime.LockOSThread()
		namespace, err := os.Stat("/proc/thread-self/ns/net")
		runtime.UnlockOSThread()
		if err != nil {
			return &linuxStandardServiceProtectionCapture{Failure: err}
		}
		client = &linuxStandardServiceProtectionClient{app: a, controller: controller, image: image, namespace: namespace}
		actual, _ := linuxStandardServiceProtectionClients.LoadOrStore(a, client)
		client = actual.(*linuxStandardServiceProtectionClient)
	}
	if client == nil || client.app != a || client.controller != controller {
		return &linuxStandardServiceProtectionCapture{Failure: errors.New("standard protection lost original controller")}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	session, err := randomHex(16)
	if err != nil {
		return &linuxStandardServiceProtectionCapture{client: client, Failure: err}
	}
	data, err := client.request(ctx, linuxStandardServiceRequest{Schema: 1, Action: "protection-view", Session: session})
	view := &linuxStandardServiceProtectionCapture{client: client, Failure: err, Available: err == nil}
	if err != nil && client.exchange == nil && errors.Is(err, os.ErrNotExist) {
		if absenceErr := client.observeAbsent(ctx, parent); absenceErr == nil {
			view.Failure = nil
			view.Absent, view.ScopedAbsent = parent == nil, parent != nil
		} else {
			view.Failure = errors.Join(err, absenceErr)
		}
	}
	a.mu.Lock()
	if raw, exists := linuxStandardServiceOwners.Load(a); exists {
		view.launch, _ = raw.(*linuxStandardServiceLaunch)
		if view.launch == nil {
			view.Available = false
			view.Failure = errors.New("standard protection view found another controller runtime")
		} else {
			view.launchSession = view.launch.request.Session
		}
	}
	a.mu.Unlock()
	if data != nil {
		view.linuxStandardServiceProtectionData = *data
		if data.Failure != "" {
			view.Failure = errors.New(data.Failure)
		}
		if client.exchange == nil && parent != nil && view.Available && !data.Owned && !data.Active && !data.Pending && data.StandardScopeAbsent {
			if parent.failure == nil && parent.controller == controller && parent.session != nil && parent.session.parent != nil {
				if err := parent.session.parent.Current(ctx); err == nil {
					view.ScopedAbsent, view.Failure = true, nil
				} else {
					view.Failure = err
				}
			}
		}
	}
	return view
}

func (c *linuxStandardServiceProtectionClient) request(ctx context.Context, request linuxStandardServiceRequest) (*linuxStandardServiceProtectionData, error) {
	if c.exchange != nil {
		return c.exchange(ctx, request)
	} // Explicit test fixture; production always authenticates the native channel.
	response, err := linuxStandardServiceRPC(ctx, c.image, c.namespace, &c.peer, request, nil, nil)
	if err != nil {
		return nil, err
	}
	if response.Reverse != nil || response.Protection == nil || !validControllerOwnerToken(response.Protection.Token) {
		return nil, errors.New("standard protection response lost its original view")
	}
	return response.Protection, nil
}

func (c *linuxStandardServiceProtectionCapture) same(other *linuxStandardServiceProtectionCapture) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.Available && other.Available && c.Failure == nil && other.Failure == nil && c.client == other.client && c.launch == other.launch && c.launchSession == other.launchSession && c.Token == other.Token && c.ProfileID == other.ProfileID && c.ProfileRevision == other.ProfileRevision && c.ResultRevision == other.ResultRevision && c.Policy == other.Policy
}
func (c *linuxStandardServiceProtectionCapture) currentAppLocked(a *app) bool {
	if c == nil {
		return true
	}
	raw, exists := linuxStandardServiceProtectionClients.Load(a)
	launch, present := linuxStandardServiceOwners.Load(a)
	sameLaunch := !present && c.launch == nil || present && launch == c.launch && c.launch != nil && c.launch.request.Session == c.launchSession
	return c.Available && c.Failure == nil && c.client != nil && c.client.app == a && c.client.controller == a.localController && exists && raw == c.client && a.nodeProtection == nil && sameLaunch
}
func (c *linuxStandardServiceProtectionCapture) Release(ctx context.Context) error {
	return c.change(ctx, "protection-release")
}
func (c *linuxStandardServiceProtectionCapture) Complete(ctx context.Context) error {
	return c.change(ctx, "protection-complete")
}
func (c *linuxStandardServiceProtectionCapture) change(ctx context.Context, action string) error {
	if c == nil || !c.Available || c.client == nil || !c.Owned && !c.Pending && !(action == "protection-complete" && c.ProfileSaved) {
		return errors.New("standard protection has no captured original Off owner")
	}
	client := c.client
	client.mu.Lock()
	defer client.mu.Unlock()
	data, err := client.request(ctx, linuxStandardServiceRequest{Schema: 1, Action: action, Session: c.Token, ProfileID: c.ProfileID, ProfileRevision: c.ProfileRevision, ResultRevision: c.ResultRevision})
	if err != nil {
		return err
	}
	if data == nil || data.Token != c.Token || data.ProfileID != c.ProfileID || data.ProfileRevision != c.ProfileRevision || data.ResultRevision != c.ResultRevision {
		return errors.New("standard Off response changed its original source")
	}
	c.linuxStandardServiceProtectionData = *data
	c.Failure = nil
	if action == "protection-complete" {
		if err := c.clearJoined(); err != nil {
			return err
		}
		finished, err := client.request(ctx, linuxStandardServiceRequest{Schema: 1, Action: "protection-finish", Session: c.Token, ProfileID: c.ProfileID, ProfileRevision: c.ProfileRevision, ResultRevision: c.ResultRevision})
		if err != nil {
			return err
		}
		if finished == nil || finished.Token != c.Token || finished.ProfileID != c.ProfileID || !finished.ProfileSaved || finished.Pending || finished.Owned {
			return errors.New("standard Off did not finish its original saved release")
		}
		c.linuxStandardServiceProtectionData = *finished
	}
	return nil
}

func (c *linuxStandardServiceProtectionCapture) clearJoined() error {
	client := c.client
	if raw, exists := linuxStandardServiceOwners.Load(client.app); exists {
		owner, ok := raw.(*linuxStandardServiceLaunch)
		if !ok || owner != c.launch || owner.request.Session != c.launchSession {
			return errors.New("standard Off found another controller owner")
		}
		owner.mu.Lock()
		defer owner.mu.Unlock()
		client.app.mu.Lock()
		defer client.app.mu.Unlock()
		if !owner.joined || client.app.cmd != nil || owner.prepared.protectionProfileID != c.ProfileID {
			return errors.New("standard Off cannot clear a newer controller runtime")
		}
		if owner.peer != nil {
			if client.peer != nil && owner.peer.record != client.peer.record {
				return errors.New("standard Off completion came from another service")
			}
			if err := owner.peer.Close(); err != nil {
				return err
			}
			owner.peer = nil
		}
		if !linuxStandardServiceOwners.CompareAndDelete(client.app, owner) {
			return errors.New("standard Off lost its original joined controller owner")
		}
		c.launchCleared = true
	} else if c.launch != nil && !c.launchCleared {
		return errors.New("standard Off lost its captured controller runtime before completion")
	}
	return nil
}
