//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/standardengine"
)

// Captured before native startup, not reconstructed from the currently selected
// node after a temporary test. This value is retained only by its launch.
type linuxStandardServicePolicy struct {
	request       standardExitConnectRequest
	profile       common.RouterProfile
	profileDigest string
	exitRaw       string
}

func (o *linuxStandardServiceLaunch) CaptureStandardServicePolicy(ctx context.Context, request standardExitConnectRequest, profile common.RouterProfile, exit standardExit) error {
	if o == nil {
		return errors.New("standard service policy has no original launch")
	}
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if o.registered || o.attempted || o.prepared == nil || o.speedLabPolicy != nil || profile.ID != o.request.ProfileID || "standard:"+exit.ID != o.request.RouterID || strings.TrimSpace(request.StandardExitID) != exit.ID || !request.Direct {
		return errors.New("standard service policy capture changed original preparation")
	}
	digest, err := linuxStandardProfileDigest(profile)
	if err != nil || digest != o.request.ProfileSHA256 {
		return errors.Join(err, errors.New("standard service policy differs from its original sealed capture"))
	}
	raw, err := json.Marshal(exit)
	if err != nil || string(raw) != o.mtuExitRaw {
		return errors.Join(err, errors.New("standard service exit differs from its original graph"))
	}
	request.StandardExitID = exit.ID
	frozen := &linuxStandardServicePolicy{request: request, profile: common.CloneRouterProfile(profile), profileDigest: digest, exitRaw: string(raw)}
	if err := ctx.Err(); err != nil {
		return err
	}
	o.speedLabPolicy = frozen
	return nil
}

func standardServiceStoreDigest(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", errors.New("standard exit store has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	store, err := loadStandardExitStore()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(store)
	if err != nil {
		return "", err
	}
	return standardengine.SHA256(raw), ctx.Err()
}

// Options expose the policy profile and actual exit as separate identities.
// This is source metadata, not a fresh path proof; Run validates the retained
// native path independently. The selected profile may differ from this owner.
func standardServiceSpeedLabCurrentOptions(ctx context.Context, a *app, st state, command *exec.Cmd) (map[string]string, error) {
	launch, handled, err := linuxStandardMTULaunch(a)
	if !handled || err != nil || !st.Connected || st.Phase != "connected" {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &launch.mu); err != nil {
		return nil, err
	}
	defer launch.mu.Unlock()
	if launch.speedLabPolicy == nil || launch.mtuExit == nil || launch.joined || launch.copiesClosed || launch.Command() != command || st.RouterID != launch.request.RouterID || st.Mode != "standard-exit" {
		return nil, errors.New("Speed Lab options lost original installed-service metadata")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	actual, exists := linuxStandardServiceOwners.Load(a)
	profile, found := a.profileByIDLocked(launch.request.ProfileID)
	current := exists && actual == launch && a.cmd == command && mtuStateSnapshotToken(a.state) == mtuStateSnapshotToken(st)
	a.mu.Unlock()
	digest, err := linuxStandardProfileDigest(profile)
	if !current || !found || err != nil || digest != launch.speedLabPolicy.profileDigest || launch.mtuExitRaw != launch.speedLabPolicy.exitRaw || st.RouterID != "standard:"+launch.mtuExit.ID {
		return nil, errors.Join(err, errors.New("Speed Lab options policy changed from its original service"))
	}
	return map[string]string{"policy_profile_id": profile.ID, "standard_exit_id": launch.mtuExit.ID, "exit_id": launch.mtuExit.ID, "execution": "local"}, ctx.Err()
}

type linuxStandardServiceSpeedLabPath struct {
	owner         *linuxStandardServiceLaunch
	policy        *linuxStandardServicePolicy
	measurement   *linuxStandardServiceMTUOwner
	live          mobilemtu.State
	profile       common.RouterProfile
	profileDigest string
	storeDigest   string
	identity      speedLabPathIdentity
}

func captureStandardServiceSpeedLab(a *app) (speedLabPathIdentity, speedLabPath, bool, error) {
	return captureStandardServiceSpeedLabCallerContext(context.Background(), a)
}

func captureStandardServiceSpeedLabCallerContext(parent context.Context, a *app) (identity speedLabPathIdentity, path speedLabPath, handled bool, failure error) {
	launch, handled, failure := linuxStandardMTULaunch(a)
	if !handled || failure != nil {
		return identity, path, handled, failure
	}
	if parent == nil {
		return identity, path, true, errors.New("Speed Lab service capture has no original caller")
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	return captureStandardServiceSpeedLabContext(ctx, a, launch)
}

// Read only the original retained tracker. Do not create an observational loop
// during admission or wait on its mutex beyond the captured caller's deadline.
func standardServiceSpeedLabSession(ctx context.Context, a *app) (connectionSession, error) {
	raw, found := sessionTrackers.Load(a)
	tracker, valid := raw.(*sessionTracker)
	if !found || !valid || tracker == nil || tracker.a != a {
		return connectionSession{}, errors.New("Speed Lab service lost its original session tracker")
	}
	if err := desktopnetwork.LockContext(ctx, &tracker.mu); err != nil {
		return connectionSession{}, err
	}
	defer tracker.mu.Unlock()
	actual, retained := sessionTrackers.Load(a)
	if !retained || actual != tracker || tracker.session == nil {
		return connectionSession{}, errors.New("Speed Lab service session tracker was replaced")
	}
	s := tracker.session
	return connectionSession{ID: s.ID, RouterID: s.RouterID, Phase: s.Phase, Connected: s.Connected, PathProof: s.PathProof, EndedAt: s.EndedAt}, ctx.Err()
}

func captureStandardServiceSpeedLabContext(ctx context.Context, a *app, launch *linuxStandardServiceLaunch) (identity speedLabPathIdentity, path speedLabPath, handled bool, failure error) {
	if launch == nil || a == nil {
		return identity, path, true, errors.New("Speed Lab has no captured service")
	}
	if err := desktopnetwork.LockContext(ctx, &launch.mu); err != nil {
		return identity, path, true, err
	}
	captured, st, err := captureStandardServiceSpeedLabLocked(ctx, a, launch)
	launch.mu.Unlock()
	if err != nil {
		return identity, path, true, err
	}
	session, err := standardServiceSpeedLabSession(ctx, a)
	if err != nil {
		return identity, path, true, err
	}
	identity = speedLabPathIdentity{Standard: captured, SessionID: session.ID, StateToken: mtuStateSnapshotToken(st), RouterID: st.RouterID, Command: launch.Command(), Network: launch.request.NetworkID, ProfileToken: captured.profileDigest, Execution: "local", Options: [3]bool{st.DAITA, st.Jumbo, st.Socks}}
	captured.identity = identity
	exit := launch.mtuExit
	path = speedLabPath{Scope: "current", Topology: "external", NodeID: captured.profile.ID, NodeName: captured.profile.Name, StandardExitID: exit.ID, ExitID: exit.ID, ExitName: exit.Name, RuntimeMode: st.RuntimeMode, LogicalMode: st.LogicalMode, Base: st.Base, Execution: "local", ExternalProtocol: exit.Protocol, Description: "captured installed-service exit with selected DNS and measurements through its actual retained TUN"}
	if err := captured.current(ctx, a, identity); err != nil {
		return speedLabPathIdentity{}, speedLabPath{}, true, err
	}
	return identity, path, true, nil
}

// Caller owns the original launch gate. A gap between candidate commands still
// belongs to its original run until both observers and the actual child close it.
func standardServiceSpeedLabMTUBusy(owner *linuxStandardServiceMTUOwner) bool {
	if owner == nil {
		return false
	}
	run := owner.run.Load()
	return owner.pending != nil || owner.sockets.Load() != 0 || run != nil && !run.closed.Load()
}

// Caller owns the original launch gate. The measurement adapter is read-only:
// Fixed/Jumbo captures never create an optimizer or rewrite their policy.
func captureStandardServiceSpeedLabLocked(ctx context.Context, a *app, launch *linuxStandardServiceLaunch) (*linuxStandardServiceSpeedLabPath, state, error) {
	var st state
	if launch.app != a || launch.speedLabPolicy == nil || launch.joined || launch.copiesClosed || standardServiceSpeedLabMTUBusy(launch.mtuOwner) {
		return nil, st, errors.New("Speed Lab standard service has no settled original capture")
	}
	live, profile, activation, err := captureLinuxStandardServiceMTUReadbackLocked(ctx, launch)
	if err != nil {
		return nil, st, err
	}
	digest, err := linuxStandardProfileDigest(profile)
	if err != nil || digest != launch.speedLabPolicy.profileDigest || launch.mtuExitRaw != launch.speedLabPolicy.exitRaw {
		return nil, st, errors.Join(err, errors.New("Speed Lab standard policy changed after startup"))
	}
	store, err := standardServiceStoreDigest(ctx)
	if err != nil {
		return nil, st, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, st, err
	}
	st = a.state
	command := a.cmd
	a.mu.Unlock()
	if command != launch.Command() || !st.Connected || st.Phase != "connected" || st.RouterID != launch.request.RouterID {
		return nil, st, errors.New("Speed Lab standard connection changed during capture")
	}
	measurement := &linuxStandardServiceMTUOwner{launch: launch, connection: activation.operation, activation: activation, exitRaw: launch.mtuExitRaw, path: live.Path}
	return &linuxStandardServiceSpeedLabPath{owner: launch, policy: launch.speedLabPolicy, measurement: measurement, live: live, profile: common.CloneRouterProfile(profile), profileDigest: digest, storeDigest: store}, st, nil
}

func (p *linuxStandardServiceSpeedLabPath) current(ctx context.Context, a *app, identity speedLabPathIdentity) error {
	if ctx == nil {
		return errors.New("Speed Lab service observation has no original caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if p == nil || p.owner == nil || p.owner.app != a || identity.Standard != p || identity.External != nil || identity.Tor != nil || identity.Node != nil || identity.Linux != nil || identity.GraphOK || identity.TorEntry != nil {
		return errors.New("Speed Lab standard capture mixed original owners")
	}
	o := p.owner
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if o.speedLabPolicy != p.policy || o.joined || o.copiesClosed || !o.dnsProved || standardServiceSpeedLabMTUBusy(o.mtuOwner) {
		return errors.New("Speed Lab standard owner retired or has unsettled MTU work")
	}
	live, profile, activation, err := captureLinuxStandardServiceMTUReadbackLocked(ctx, o)
	if err != nil {
		return err
	}
	digest, err := linuxStandardProfileDigest(profile)
	if err != nil || digest != p.profileDigest || identity.ProfileToken != digest || live != p.live || activation != p.measurement.activation {
		return errors.Join(err, errors.New("Speed Lab standard source or actual TUN changed"))
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	st, command := a.state, a.cmd
	a.mu.Unlock()
	if !st.Connected || st.Phase != "connected" || st.RouterID != identity.RouterID || command != identity.Command || command != o.Command() || mtuStateSnapshotToken(st) != identity.StateToken || identity.Network != o.request.NetworkID || identity.Execution != "local" || [3]bool{st.DAITA, st.Jumbo, st.Socks} != identity.Options {
		return errors.New("Speed Lab standard connection changed")
	}
	session, err := standardServiceSpeedLabSession(ctx, a)
	if err != nil {
		return err
	}
	if session.ID == "" || session.ID != identity.SessionID || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" || session.RouterID != identity.RouterID || session.EndedAt != nil {
		return errors.New("Speed Lab standard path proof changed")
	}
	return o.call(ctx, linuxStandardServiceRequest{Schema: 1, Action: "current", Session: o.request.Session}, nil)
}

func (p *linuxStandardServiceSpeedLabPath) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := p.current(ctx, p.owner.app, p.identity); err != nil {
		return nil, err
	}
	return p.measurement.dialThroughTunnelLifetime(ctx, p.live, network, address, speedLabDialLifetime(ctx))
}
func (p *linuxStandardServiceSpeedLabPath) verify(ctx context.Context, a *app, identity speedLabPathIdentity) error {
	if ctx == nil {
		return errors.New("Speed Lab service proof has no original caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if err := p.current(ctx, a, identity); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.owner.mu); err != nil {
		return err
	}
	dnsErr := p.owner.call(ctx, linuxStandardServiceRequest{Schema: 1, Action: "dns-current", Session: p.owner.request.Session}, nil)
	p.owner.mu.Unlock()
	if dnsErr != nil {
		return dnsErr
	}
	if err := p.measurement.VerifyExternal(ctx, p.live); err != nil {
		return err
	}
	return p.current(ctx, a, identity)
}
func (p *linuxStandardServiceSpeedLabPath) restorePlan(ctx context.Context, a *app) (speedLabRestorePlan, error) {
	if err := p.current(ctx, a, p.identity); err != nil {
		return speedLabRestorePlan{}, err
	}
	if digest, err := standardServiceStoreDigest(ctx); err != nil || digest != p.storeDigest {
		return speedLabRestorePlan{}, errors.Join(err, errors.New("standard service restore exit store changed during capture"))
	}
	saved := &linuxStandardServiceSpeedLabRestore{policy: p.policy, profile: common.CloneRouterProfile(p.profile), profileDigest: p.profileDigest, storeDigest: p.storeDigest, network: p.owner.request.NetworkID, mtu: p.live.MTU}
	return speedLabRestorePlan{profile: common.CloneRouterProfile(p.profile), standard: saved}, nil
}

type linuxStandardServiceSpeedLabRestore struct {
	policy                              *linuxStandardServicePolicy
	profile                             common.RouterProfile
	profileDigest, storeDigest, network string
	mtu                                 int
}

func (s *linuxStandardServiceSpeedLabRestore) sourceCurrent(ctx context.Context, a *app, intent context.Context) error {
	if s == nil || s.policy == nil || s.mtu < 1280 || s.mtu > 9000 || !s.policy.request.Direct || s.network == "" {
		return errors.New("standard service restore has no complete original capture")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	intentErr := a.checkCapturedConnectionOperationLocked(intent)
	a.mu.Unlock()
	if intentErr != nil {
		return intentErr
	}
	if digest, err := standardServiceStoreDigest(ctx); err != nil || digest != s.storeDigest {
		return errors.Join(err, errors.New("standard service restoration refuses a changed exit store"))
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	profile, exists := a.profileByIDLocked(s.profile.ID)
	selected := a.profiles.SelectedID
	a.mu.Unlock()
	digest, err := linuxStandardProfileDigest(profile)
	original, originalErr := linuxStandardProfileDigest(s.policy.profile)
	if !exists || selected != s.profile.ID || err != nil || originalErr != nil || digest != s.profileDigest || original != s.profileDigest || s.policy.profileDigest != s.profileDigest {
		return errors.New("standard service restoration refuses changed original policy")
	}
	return ctx.Err()
}
func (s *linuxStandardServiceSpeedLabRestore) restart(ctx context.Context, a *app) error {
	if err := s.sourceCurrent(ctx, a, ctx); err != nil {
		return err
	}
	suspended, err := mtuSuspendedContext(ctx, a)
	if err != nil || !suspended {
		return errors.Join(err, errors.New("standard service restoration has no original MTU suspension"))
	}
	body, err := json.Marshal(s.policy.request)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(body))
	if err != nil {
		return err
	}
	response := &standardServiceRestoreResponse{header: make(http.Header)}
	a.platformStandardExitConnectCaptured(response, request, defaultPlatformStandardExitRuntime(), ctx)
	if err := a.speedLabCheckLaunchedRuntime(); err != nil {
		return err
	}
	if response.code != http.StatusOK {
		return errors.New("standard service restoration failed: " + response.body.String())
	}
	launch, found, err := linuxStandardMTULaunch(a)
	if err != nil || !found || launch.request.NetworkID != s.network || launch.request.ProfileID != s.profile.ID || launch.speedLabPolicy == nil || launch.speedLabPolicy.exitRaw != s.policy.exitRaw {
		return errors.Join(err, errors.New("standard service restoration changed captured source or physical path"))
	}
	if err := s.sourceCurrent(ctx, a, ctx); err != nil {
		return err
	}
	live, profile, lifetime, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
	if err != nil {
		return err
	}
	automatic := strings.EqualFold(profile.MTUPolicy, "auto") && !profile.JumboTUN
	if !automatic {
		if live.MTU != s.mtu {
			return errors.New("restored Fixed/Jumbo interface differs from captured live MTU")
		}
		return ctx.Err()
	}
	// Retain the proved value exactly. Re-running Auto would select a different
	// result while claiming restoration. This private hold also excludes Retest.
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	owner, err := newLinuxStandardServiceMTUOwner(bounded, launch)
	if err != nil {
		return err
	}
	var restored mobilemtu.State
	var ui *linuxStandardServiceMTUUI
	err = owner.RunOperationContext(bounded, "speed-lab-restore", func(work context.Context) error {
		if err := owner.PrepareRetestContext(work); err != nil {
			return err
		}
		plan, err := mobilemtu.NewPlan(owner.config, live.MTU)
		if err != nil {
			return err
		}
		restoredConfig, err := plan.Config(s.mtu)
		if err != nil {
			return err
		}
		restored, err = owner.ChangeMTU(work, live, s.mtu)
		if err != nil {
			return err
		}
		if restored.MTU != s.mtu || restored.Session != live.Session || restored.Path != live.Path {
			return errors.New("standard service did not restore captured native MTU")
		}
		if err := owner.VerifyExternal(work, restored); err != nil {
			return err
		}
		actual, err := owner.CaptureContext(work)
		if err != nil || actual != restored {
			return errors.Join(err, errors.New("standard service restored MTU failed actual readback"))
		}
		if err := s.sourceCurrent(work, a, ctx); err != nil {
			return err
		}
		// Prepare one controller from the exact restored graph, but publish it
		// only after this run's original child and both observers have closed.
		if err := desktopnetwork.LockContext(work, &a.mu); err != nil {
			return err
		}
		cacheDirectory := filepath.Dir(a.cfg.ProfilesFile)
		a.mu.Unlock()
		cache, err := openLinuxStandardMTUCache(work, cacheDirectory)
		if err != nil {
			return err
		}
		controller, err := mobilemtu.NewExternalContext(work, owner, restoredConfig, owner.authority, cache)
		if err != nil {
			return err
		}
		ui = &linuxStandardServiceMTUUI{launch: launch, owner: owner, controller: controller, identity: mtuViewIdentity{Session: restored.Session, Profile: profile.ID, Native: true}, path: restored.Path, lifetime: lifetime, completed: true, autoAttempted: true, activation: owner.activation, profileToken: s.profileDigest}
		return work.Err()
	})
	if err != nil {
		return err
	}
	if err := s.sourceCurrent(bounded, a, ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(bounded, &launch.mu); err != nil {
		return err
	}
	defer launch.mu.Unlock()
	actual, err := owner.currentLocked(bounded)
	run := owner.run.Load()
	if err != nil || actual != restored || ui == nil || run == nil || !run.closed.Load() || standardServiceSpeedLabMTUBusy(owner) {
		return errors.Join(err, errors.New("standard service restoration did not close its original MTU run"))
	}
	if _, loaded := linuxStandardServiceMTUUIs.LoadOrStore(launch, ui); loaded {
		return errors.New("standard service restore encountered another MTU controller")
	}
	if err := bounded.Err(); err != nil {
		linuxStandardServiceMTUUIs.CompareAndDelete(launch, ui)
		return err
	}
	return nil
}

type standardServiceRestoreResponse struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (r *standardServiceRestoreResponse) Header() http.Header { return r.header }
func (r *standardServiceRestoreResponse) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}
func (r *standardServiceRestoreResponse) Write(raw []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if left := 4096 - r.body.Len(); left > 0 {
		_, _ = r.body.Write(raw[:min(left, len(raw))])
	}
	return len(raw), nil
}
