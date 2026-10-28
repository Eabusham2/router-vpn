package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/routechoice"
)

// The driver freezes both private sources once. Trial start/proof/measurement
// never saves a profile, Startup Last record or Connected state. Final adoption
// is a separate transaction after routechoice repeats both winning probes.
type desktopTorComparisonDriver struct {
	app        *app
	profile    common.RouterProfile
	request    externalProfileConnectRequest
	startup    *startupPolicyCapture
	operation  context.Context
	selected   string
	network    string
	runtime    desktopTorConnectRuntime
	selections map[routechoice.Execution]*desktopTorSelection
	candidates []routechoice.Candidate
	last       *desktopTorComparisonSession
}

type desktopTorComparisonSession struct {
	driver    *desktopTorComparisonDriver
	candidate routechoice.Candidate
	selection *desktopTorSelection
	command   *exec.Cmd
	prelaunch *torBridgePrelaunch
	probe     mobiletor.Comparison
	identity  string
	target    string

	mu                 sync.Mutex
	cleanup            sync.Mutex
	measurementDrained bool
	closed             bool
}

var _ routechoice.TargetDriver = (*desktopTorComparisonDriver)(nil)
var _ routechoice.Session = (*desktopTorComparisonSession)(nil)

func cloneDesktopTorConnectRequest(q externalProfileConnectRequest) externalProfileConnectRequest {
	if q.Direct != nil {
		value := *q.Direct
		q.Direct = &value
	}
	if q.ExpectedSelectedNodeID != nil {
		value := *q.ExpectedSelectedNodeID
		q.ExpectedSelectedNodeID = &value
	}
	if q.ExpectedProfileTokens != nil {
		copy := make(map[string]string, len(q.ExpectedProfileTokens))
		for name, token := range q.ExpectedProfileTokens {
			copy[name] = token
		}
		q.ExpectedProfileTokens = copy
	}
	return q
}

func desktopTorRequestedExecution(profile common.RouterProfile, q externalProfileConnectRequest) (string, error) {
	direct := strings.TrimSpace(q.EntryID) == "" && !profile.MultihopEnabled
	if q.Direct != nil {
		direct = *q.Direct
	}
	return externalExecutionChoice(profile, q.Execution, direct)
}

func newDesktopTorComparisonDriver(a *app, profile common.RouterProfile, request externalProfileConnectRequest, startup *startupPolicyCapture, runtime desktopTorConnectRuntime) (*desktopTorComparisonDriver, error) {
	if a == nil {
		return nil, errors.New("Tor comparison requires a captured application owner")
	}
	request = cloneDesktopTorConnectRequest(request)
	profile = cloneRouterProfile(profile)
	execution, err := desktopTorRequestedExecution(profile, request)
	if err != nil || execution != "auto" {
		return nil, errors.New("Tor comparison requires an explicit or saved Compare choice through a private Router entry")
	}
	a.mu.Lock()
	operation, selected := a.connectionContext, a.profiles.SelectedID
	err = desktopTorOperationCurrentLocked(a, operation, selected)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	lookup := runtime.lookup
	if lookup == nil {
		lookup = desktopTorEndpointLookup
	}
	driver := &desktopTorComparisonDriver{app: a, profile: profile, request: request, startup: startup,
		operation: operation, selected: selected, network: physicalNetworkIdentity(), runtime: runtime,
		selections: make(map[routechoice.Execution]*desktopTorSelection)}
	if driver.network == "" {
		return nil, errors.New("Tor comparison could not capture the current physical network identity")
	}
	for _, execution := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
		choice := cloneDesktopTorConnectRequest(request)
		choice.Execution = string(execution)
		selection, err := captureDesktopTorSelection(a, profile, choice, lookup)
		if err != nil {
			return nil, err
		}
		entry := selection.predecessor
		if entry == nil || entry.native == nil || !entry.native.IsRouter() {
			return nil, errors.New("Tor Compare requires independently captured Local and authenticated Server paths through the same private Router")
		}
		selection.preference = "auto"
		driver.selections[execution] = selection
		driver.candidates = append(driver.candidates, routechoice.Candidate{Execution: execution, Transport: profile.External.Protocol, EntryID: entry.entry.ID, ExitID: profile.ID})
	}
	local, server := driver.selections[routechoice.Local], driver.selections[routechoice.Server]
	localPolicy, serverPolicy := cloneRouterProfile(local.policy), cloneRouterProfile(server.policy)
	localPolicy.MultihopExecution, serverPolicy.MultihopExecution = "", ""
	if !reflect.DeepEqual(localPolicy, serverPolicy) ||
		local.predecessor.profileToken != server.predecessor.profileToken ||
		local.predecessor.assetsSHA256 != server.predecessor.assetsSHA256 || local.predecessor.mode != server.predecessor.mode {
		return nil, errors.New("Local and Server Tor captures differ in private source, resolver or protection policy")
	}
	if err := driver.current(); err != nil {
		return nil, err
	}
	return driver, nil
}

func (d *desktopTorComparisonDriver) current() error {
	if d == nil || d.app == nil || d.network == "" || physicalNetworkIdentity() != d.network {
		return errors.New("Tor comparison physical network changed")
	}
	d.app.mu.Lock()
	err := desktopTorOperationCurrentLocked(d.app, d.operation, d.selected)
	d.app.mu.Unlock()
	if err != nil {
		return err
	}
	for _, selection := range d.selections {
		if err := selection.current(d.app); err != nil {
			return err
		}
	}
	if err := d.app.validateExternalProfileExpectedProfiles(d.request, d.profile); err != nil {
		return err
	}
	if d.startup != nil {
		return d.startup.current(d.app)
	}
	return nil
}

func (d *desktopTorComparisonDriver) Open(context.Context, routechoice.Candidate) (routechoice.Session, error) {
	return nil, errors.New("Tor comparison startup requires the round's captured external target")
}

func (d *desktopTorComparisonDriver) OpenTarget(ctx context.Context, candidate routechoice.Candidate, target string) (routechoice.Session, error) {
	if ctx == nil || ctx.Err() != nil || !mobiletor.DesktopTorCompareTarget(target) || !candidate.Valid() {
		return nil, errors.New("Tor comparison startup has an invalid operation or external target")
	}
	if err := d.current(); err != nil {
		return nil, err
	}
	selection := d.selections[candidate.Execution]
	if selection == nil || candidate.ExitID != d.profile.ID || candidate.EntryID != selection.predecessor.entry.ID || candidate.Transport != selection.policy.External.Protocol {
		return nil, errors.New("Tor comparison cannot substitute a captured candidate")
	}
	if d.last != nil {
		d.last.mu.Lock()
		closed := d.last.closed
		d.last.mu.Unlock()
		if !closed {
			return nil, errors.New("previous Tor comparison candidate still owns native resources")
		}
	}
	runtime := d.runtime
	if runtime.capability == nil {
		runtime.capability = func() standardExitCapability { return desktopTorPolicyRuntimeCapability(selection.policy) }
	}
	if capability := runtime.capability(); !capability.Supported {
		return nil, errors.New(capability.Reason)
	}
	command, prelaunch, err := prepareTorBridgeCommandWithRuntime(d.app, selection.policy, d.profile, selection.predecessor, runtime)
	if err != nil {
		return nil, err
	}
	session := &desktopTorComparisonSession{driver: d, candidate: candidate, selection: selection, command: command, prelaunch: prelaunch, target: target}
	d.last = session // The caller must retain even a partially started result.
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if prelaunch.workspace.tor.network != d.network {
			return errors.New("Tor comparison preparation belongs to a changed network")
		}
		return d.current()
	}
	if err := check(); err != nil {
		return session, err
	}
	if err := prelaunch.start(check); err != nil {
		return session, err
	}
	a, launch := d.app, prelaunch.workspace
	a.mu.Lock()
	if a.cmd != nil {
		a.mu.Unlock()
		return session, errors.New("Tor comparison cannot replace a different active native command")
	}
	a.cmd = command
	a.state.Mode, a.state.LogicalMode, a.state.RuntimeMode = "external-node", "external-node", launch.mode
	a.state.Base, a.state.RouterID = desktopExternalEntryBase(selection.predecessor.mode), d.profile.ID
	a.state.Connected, a.state.Phase, a.state.LastError = false, "compare:"+string(candidate.Execution)+":proving-tor", ""
	a.mu.Unlock()
	if err := check(); err != nil {
		return session, err
	}
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		return session, err
	}
	if err := check(); err != nil {
		return session, err
	}
	create := runtime.comparison
	if create == nil {
		create = func(a *app, launch *desktopNodeLaunch, target string) (mobiletor.Comparison, error) {
			captured, err := newDesktopTorComparisonClient(a, launch, target)
			if captured == nil {
				return nil, err // A typed nil must not become an owned interface.
			}
			return captured, err
		}
	}
	session.probe, err = create(a, launch, target)
	if err != nil || session.probe == nil {
		return session, errors.Join(err, errors.New("native Tor comparison could not retain its exact measurement owner"))
	}
	if err := session.probe.Prepare(ctx); err != nil {
		return session, err
	}
	session.identity = session.probe.Identity()
	if session.identity == "" || check() != nil || session.Identity() == "" {
		return session, errors.New("Tor comparison preparation completed for a retired candidate")
	}
	return session, nil
}

func (s *desktopTorComparisonSession) Identity() string {
	if s == nil || s.driver == nil || s.prelaunch == nil || s.identity == "" || s.driver.current() != nil || s.driver.app.desktopTorCurrent(s.prelaunch.workspace) != nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.measurementDrained && (s.probe == nil || s.probe.Identity() != s.identity) {
		return ""
	}
	return s.identity
}

func (s *desktopTorComparisonSession) Verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s.Identity() == "" {
		return errors.New("Tor comparison cannot verify a retired candidate")
	}
	if err := s.probe.Verify(ctx); err != nil {
		return err
	}
	if s.Identity() == "" {
		return errors.New("Tor comparison proof completed for a changed path")
	}
	return ctx.Err()
}

func (s *desktopTorComparisonSession) ProbeLast(ctx context.Context) (time.Duration, error) {
	return s.measure(ctx, "")
}

func (s *desktopTorComparisonSession) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	if s == nil || target != s.target || !mobiletor.DesktopTorCompareTarget(target) {
		return 0, errors.New("Tor comparison external endpoint is not approved")
	}
	return s.measure(ctx, target)
}

func (s *desktopTorComparisonSession) measure(ctx context.Context, target string) (time.Duration, error) {
	if ctx == nil || ctx.Err() != nil || s.Identity() == "" {
		return 0, errors.New("Tor comparison cannot measure a retired candidate")
	}
	var duration time.Duration
	var err error
	if target == "" {
		duration, err = s.probe.ProbeLast(ctx)
	} else {
		duration, err = s.probe.ProbeExternal(ctx, target)
	}
	if err != nil || duration <= 0 || ctx.Err() != nil || s.Identity() == "" {
		return 0, errors.Join(err, errors.New("Tor comparison measurement failed, expired or changed path"))
	}
	return duration, nil
}

// Final activation drains only measurement resources; it does not rerun the
// selection or replace the proved VPN. The caller still has to save/adopt the
// current native proof, original private source and this actual execution.
func (s *desktopTorComparisonSession) retainPath(ctx context.Context) (desktopTorProof, error) {
	if s == nil || ctx == nil || !s.cleanup.TryLock() {
		return desktopTorProof{}, errors.New("Tor comparison cleanup is already pending")
	}
	defer s.cleanup.Unlock()
	if s.Identity() == "" || ctx.Err() != nil {
		return desktopTorProof{}, errors.New("Tor winning path retired before measurement cleanup")
	}
	if err := s.probe.Close(ctx); err != nil {
		return desktopTorProof{}, err
	}
	s.mu.Lock()
	s.measurementDrained = true
	s.mu.Unlock()
	if s.Identity() == "" || ctx.Err() != nil {
		return desktopTorProof{}, errors.New("Tor winning path changed while measurement cleanup completed")
	}
	return s.driver.app.readDesktopTorProof(s.prelaunch.workspace)
}

func (s *desktopTorComparisonSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("Tor comparison teardown requires a bounded operation")
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !s.cleanup.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	defer s.cleanup.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil
	}
	if s.probe != nil {
		s.probe.Cancel()
	}
	if s.command == nil || s.command.Process == nil {
		if err := s.prelaunch.cleanup(); err != nil {
			return err
		}
		s.prelaunch.close()
	} else {
		a, launch := s.driver.app, s.prelaunch.workspace
		if !a.ownsConnectionRuntime(s.command) {
			launch.tor.mu.Lock()
			acknowledged := launch.tor.stopAcknowledged
			launch.tor.mu.Unlock()
			if !acknowledged || !desktopNodeProcessExited(launch) {
				return errors.New("Tor comparison cannot stop a replacement connection or discard its old native owner")
			}
		} else {
			// Stop the complete candidate independently of measurement Close.
			// Unknown native capture drainage may require this exact process to
			// join; waiting for measurement Close first would deadlock that path.
			if err := requestDesktopTorStop(ctx, a, launch, s.command); err != nil {
				return err
			}
		}
		if s.probe != nil {
			if err := s.probe.Close(ctx); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.ownsConnectionRuntime(s.command) {
			if err := a.stopModeWithIntent(true); err != nil {
				return err
			}
		} else if registered, present := desktopNodeOwners.Load(a); present && registered == launch {
			// An earlier failed Stop may already have cleared app.cmd while
			// retaining this exact drained workspace. Finish that transaction
			// only when no replacement command exists.
			a.mu.Lock()
			vacant := a.cmd == nil
			a.mu.Unlock()
			if !vacant {
				return errors.New("Tor comparison workspace still belongs to an unfinished native stop")
			}
			if err := a.stopModeWithIntent(true); err != nil {
				return err
			}
		} else if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
			// Cleanup of an already joined old candidate never changes the
			// current app owner or its protection. Unknown old files stay owned.
			if err := cleanupDesktopTorLaunch(launch); err != nil {
				return err
			}
		}
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}
