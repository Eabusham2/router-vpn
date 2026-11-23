package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// Execution requires its own installed native lifecycle capability. Ordinary
// ordered admission on another platform cannot silently grant this API.
func nativeDesktopOrderedExecutionPlatformSupported() bool {
	return retainedNativeMultihopSelected() && (runtime.GOOS == "linux" || runtime.GOOS == "windows") &&
		(runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")
}

func desktopOrderedExecutionChoices() []string {
	if nativeDesktopOrderedExecutionPlatformSupported() {
		return []string{"local", "server", "auto"}
	}
	return []string{"local"}
}

// Requested execution is distinct from the child's selected execution. In
// particular a Compare Local winner remains an execution-owned connection.
func validDesktopOrderedExecution(value string) bool {
	return value == "local" || value == "server" || value == "auto"
}

func desktopOrderedExecutionSelection(nodes []common.MultihopNodeSelection, requested string) error {
	if !validDesktopOrderedExecution(requested) {
		return errors.New("ordered execution requires an explicit Local, Server or Compare choice")
	}
	if err := common.ValidateMultihopNodes(nodes); err != nil {
		return err
	}
	if requested != "local" && nodes[len(nodes)-1].Mode != "shadowsocks" && !desktopHysteriaExecutionNodes(nodes) {
		return errors.New("ordered Server and Compare require their captured Shadowsocks final or wholly paired Hysteria2 path")
	}
	if requested != "local" && desktopNodeChainHasOpenVPN(nodes) {
		if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainMaximumNodes || nodes[len(nodes)-2].Mode != "openvpn" {
			return errors.New("OpenVPN execution requires its original paired packet prefix and SS final")
		}
		for _, node := range nodes[:len(nodes)-2] {
			if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
				return errors.New("OpenVPN execution requires only paired packet prefixes")
			}
		}
	}
	if requested != "local" && desktopNodeChainHasSOCKS(nodes) {
		if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainMaximumNodes || nodes[len(nodes)-2].Mode != "socks5" {
			return errors.New("SOCKS Server and Compare require their original complete packet prefix and paired final")
		}
		for _, node := range nodes[:len(nodes)-2] {
			if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
				return errors.New("SOCKS Server and Compare require only paired WireGuard or AWG2 prefix members")
			}
		}
	}
	if requested != "local" && desktopNodeChainHasCONNECT(nodes) {
		if len(nodes) < 3 || len(nodes) > mobilemultihop.NodeChainMaximumNodes ||
			(nodes[len(nodes)-2].Mode != "http-connect" && nodes[len(nodes)-2].Mode != "https-connect") {
			return errors.New("CONNECT Server and Compare require their original complete packet prefix and paired final")
		}
		for _, node := range nodes[:len(nodes)-2] {
			if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
				return errors.New("CONNECT Server and Compare require only paired WireGuard or AWG2 prefix members")
			}
		}
	}
	return nil
}

// The registry retains partial startup and failed retirement as well as Ready.
// Neither an active graph nor a saved execution string can reconstruct it.
type desktopOrderedExecutionOwner struct {
	session       *desktopNodeChainExecutionSession
	stop          desktopRetainedStopCapture
	slot          *desktopNodeProtectionSlot
	nativeRetired bool
}

var desktopOrderedExecutionOwners sync.Map // *app -> *desktopOrderedExecutionOwner; operationMu serializes mutation

func (a *app) retainDesktopOrderedExecution(s *desktopNodeChainExecutionSession) (*desktopOrderedExecutionOwner, error) {
	if s == nil || s.app != a || s.launch == nil || s.execution == nil {
		return nil, errors.New("ordered execution lost its actual startup owner")
	}
	owner := &desktopOrderedExecutionOwner{session: s}
	if s.launch.ownedNode != nil {
		s.launch.workspaceMu.Lock()
		owner.slot = s.launch.ownedNode.slot
		s.launch.workspaceMu.Unlock()
	}
	if old, exists := desktopOrderedExecutionOwners.LoadOrStore(a, owner); exists {
		if prior, ok := old.(*desktopOrderedExecutionOwner); ok && prior.session == s {
			return prior, nil
		}
		return nil, errors.New("ordered execution cannot replace an unretired session")
	}
	return owner, nil
}

func (a *app) desktopOrderedExecutionOwner() (*desktopOrderedExecutionOwner, error) {
	raw, exists := desktopOrderedExecutionOwners.Load(a)
	if !exists {
		return nil, nil
	}
	owner, ok := raw.(*desktopOrderedExecutionOwner)
	if !ok || owner == nil || owner.session == nil || owner.session.app != a {
		return nil, errors.New("ordered execution registry lost its exact session")
	}
	return owner, nil
}

// This transaction never calls routechoice.Compare. The native session alone
// authenticates, measures, selects and re-proves its complete ordered path.
// Tests may model installed image/source acquisition and the child/controller
// boundary. Publication, selected-result checks and cleanup remain shipping code.
type desktopOrderedExecutionRuntime struct {
	startup     *startupPolicyCapture
	prepareLast func(context.Context, *app, multihopSelection, string, string) (*desktopNodeChainExecutionSession, error)
	capture     func(context.Context, *app, multihopSelection, []string) (multihopSelection, error)
	prepare     func(context.Context, *app, multihopSelection, string) (*desktopNodeChainExecutionSession, error)
}

// Preparation and preflight precede the captured transition guard. Startup is
// deliberately separate so an unsupported successor cannot stop the old path.
func prepareDesktopOrderedExecutionSession(ctx context.Context, a *app, selection multihopSelection, requested string) (*desktopNodeChainExecutionSession, error) {
	return prepareDesktopOrderedExecutionSessionWithLast(ctx, a, selection, requested, "")
}

func prepareDesktopOrderedExecutionSessionWithLast(ctx context.Context, a *app, selection multihopSelection, requested, saved string) (*desktopNodeChainExecutionSession, error) {
	launch, image, err := prepareDesktopNodeChainExecutionHostWithLast(ctx, a, selection, requested, saved)
	if launch == nil {
		return nil, err
	}
	s := &desktopNodeChainExecutionSession{app: a, launch: launch, execution: desktopNodeChainLaunchExecution(launch), selection: selection}
	if err == nil {
		err = preflightRetainedNativeMultihop(ctx, image, launch, runDesktopExternalPreflightCommand)
	}
	return s, err
}

// Failed unentered cleanup is separate from the active session. It may coexist
// with an old working child, and can never take that child's Stop authority.
var desktopOrderedExecutionPreparations sync.Map // *app -> *desktopNodeChainExecutionSession

func (a *app) retireDesktopOrderedExecutionPreparation(ctx context.Context, s *desktopNodeChainExecutionSession) error {
	if s == nil || s.app != a || s.launch == nil || s.execution == nil || s.launch.command != nil || s.graph != nil || s.native != nil {
		return errors.New("ordered preparation retirement lost its unentered original session")
	}
	if prior, exists := desktopOrderedExecutionPreparations.LoadOrStore(a, s); exists && prior != s {
		return errors.New("ordered preparation cannot replace an earlier cleanup owner")
	}
	if err := s.Close(ctx); err != nil {
		return err
	}
	if !desktopOrderedExecutionPreparations.CompareAndDelete(a, s) {
		return errors.New("ordered preparation cleanup owner changed")
	}
	return ctx.Err()
}

func (a *app) retirePendingDesktopOrderedExecutionPreparation(ctx context.Context) error {
	if ctx == nil {
		return errors.New("ordered pending retirement requires its original caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, exists := desktopOrderedExecutionPreparations.Load(a)
	if !exists {
		return nil
	}
	s, ok := raw.(*desktopNodeChainExecutionSession)
	if !ok || s == nil {
		return errors.New("ordered pending preparation lost its original cleanup owner")
	}
	return a.retireDesktopOrderedExecutionPreparation(ctx, s)
}

func (a *app) connectDesktopOrderedExecution(ctx context.Context, selection multihopSelection, requested string, usage bool) (*desktopNodeChainExecutionSession, error) {
	return a.connectDesktopOrderedExecutionWithRuntime(ctx, selection, requested, usage, nil)
}

func (a *app) connectDesktopOrderedExecutionWithRuntime(ctx context.Context, selection multihopSelection, requested string, usage bool, modeled *desktopOrderedExecutionRuntime) (*desktopNodeChainExecutionSession, error) {
	driver := desktopOrderedExecutionRuntime{capture: captureNativeMultihopForAppContext, prepare: prepareDesktopOrderedExecutionSession}
	if modeled != nil {
		driver = *modeled
	}
	if driver.capture == nil || driver.prepare == nil {
		return nil, errors.New("ordered execution lost its concrete native adapter")
	}
	if ctx == nil || a.checkCapturedConnectionOperation(ctx) != nil || !nativeDesktopOrderedExecutionSelectionPlatformSupported(selection.Nodes, requested) || requested == "local" {
		return nil, errors.New("ordered execution has no original admitted connection operation")
	}
	if err := desktopOrderedExecutionSelection(nodeChainSelectedReferences(selection.Nodes), requested); err != nil {
		return nil, err
	}
	if err := desktopOrderedExecutionMembers(selection.Nodes, requested); err != nil {
		return nil, err
	}
	if _, pending := desktopOrderedExecutionPreparations.Load(a); pending {
		return nil, errors.New("ordered preparation cleanup must finish before another connection")
	}
	if selection.Native == nil {
		var err error
		captureContext := ctx
		if driver.startup != nil {
			captureContext = driver.startup.nodeChain.compilerContext(ctx)
		}
		selection, err = driver.capture(captureContext, a, selection, []string{selection.ExitMode})
		if err != nil {
			return nil, err
		}
	}
	// The successor must prove its concrete transition capability before Stop.
	// Preparation has no child and cannot replace the active product owner.
	if err := driver.startupSelectedCurrent(ctx, a, selection, requested); err != nil {
		return nil, err
	}
	var s *desktopNodeChainExecutionSession
	var err error
	if driver.startup != nil && driver.startup.nodeChain.selectedLast != "" {
		if driver.prepareLast == nil {
			return nil, errors.New("selected startup has no original Last adapter")
		}
		s, err = driver.prepareLast(ctx, a, selection, requested, driver.startup.nodeChain.selectedLast)
	} else {
		s, err = driver.prepare(ctx, a, selection, requested)
	}
	if err == nil && (s == nil || s.app != a || s.launch == nil || s.execution == nil || s.launch.command != nil || s.graph != nil || s.native != nil) {
		err = errors.New("ordered preparation did not return its unused original session")
	}
	if err == nil {
		err = driver.checkPreparedStartup(ctx, a, s, requested)
	}
	if err == nil {
		err = a.guardDesktopOwnedNodeTransitionContext(ctx, s.launch)
	}
	if err == nil {
		err = a.stopModeWithIntent(true)
	}
	if err == nil {
		err = a.checkCapturedConnectionOperation(ctx)
	}
	if err == nil {
		err = driver.startupSelectedCurrent(ctx, a, selection, requested)
	}
	if err != nil {
		if s != nil {
			cleanup, cancel := desktopNodeChainRetirementContext()
			err = errors.Join(err, a.retireDesktopOrderedExecutionPreparation(cleanup, s))
			cancel()
		}
		return s, err
	}
	sessionTrackerFor(a).declareRequest("multihop", selection.Base)
	err = s.startContext(ctx)
	_, retainErr := a.retainDesktopOrderedExecution(s)
	err = errors.Join(err, retainErr)
	if s != nil && s.launch.command != nil && a.ownsConnectionRuntime(s.launch.command) {
		err = errors.Join(err, a.speedLabOwnRuntime(s.launch.command))
	}
	if err == nil {
		err = s.Verify(ctx)
	}
	if err == nil {
		err = driver.checkStartupReady(ctx, a, s, requested)
	}
	if err == nil {
		err = a.publishDesktopOrderedExecutionWithStartup(ctx, s, usage, driver.startup)
	}
	if err != nil {
		// A cancelled caller cannot prevent the exact old child joining. Failed
		// retirement keeps the registry for the next explicit captured Stop.
		if s != nil {
			cleanup, cancel := desktopNodeChainRetirementContext()
			closeErr := s.Close(cleanup)
			cancel()
			// Even a joined child may retain On-connect protection. Keep the
			// exact owner until captured Stop settles the requested intent.
			err = errors.Join(err, closeErr)
		}
		return s, err
	}
	return s, nil
}

func (a *app) publishDesktopOrderedExecution(ctx context.Context, s *desktopNodeChainExecutionSession, usage bool) error {
	return a.publishDesktopOrderedExecutionWithStartup(ctx, s, usage, nil)
}

func (a *app) publishDesktopOrderedExecutionWithStartup(ctx context.Context, s *desktopNodeChainExecutionSession, usage bool, startup *startupPolicyCapture) error {
	if s == nil || s.app != a {
		return errors.New("ordered publication lost its actual session")
	}
	if err := s.Current(ctx); err != nil {
		return err
	}
	result, err := s.Result(ctx)
	if err != nil || result.Winner == nil || s.graph == nil || string(result.Winner.Execution) != s.graph.Execution {
		return errors.Join(err, errors.New("ordered publication lost its child's selected proof"))
	}
	var last *startupSelection
	if usage && a.startupStatePath() != "" {
		proved, err := a.selectedStartupSelectionAtReady(ctx, s, startup)
		if err != nil {
			return err
		}
		last = &proved
		if err := s.Current(ctx); err != nil {
			return err
		}
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	current := func() error {
		owner, ownerErr := a.desktopOrderedExecutionOwner()
		if ownerErr != nil || owner == nil || owner.session != s || a.cmd != s.launch.command ||
			a.checkCapturedConnectionOperationLocked(ctx) != nil || s.execution.publicationCurrentLocked(ctx, a, s.launch, s.selection) != nil {
			return errors.Join(ownerErr, errors.New("ordered publication changed its operation, source or native owner"))
		}
		if last != nil && (a.state.Mode != "multihop" || a.state.RouterID != last.RouterID || a.state.RuntimeMode != last.RuntimeMode ||
			a.state.LogicalMode != last.LogicalMode || a.state.Base != last.Base) {
			return errors.New("selected Last lost its original route before publication")
		}
		return ctx.Err()
	}
	if err := current(); err != nil {
		return err
	}
	previous := cloneRouterProfileStore(a.profiles)
	if usage {
		used := make(map[string]bool, len(s.selection.Nodes))
		for _, node := range s.selection.Nodes {
			used[node.Profile.ID] = true
		}
		now := time.Now().UTC().Format(time.RFC3339)
		for i := range a.profiles.Profiles {
			if used[a.profiles.Profiles[i].ID] {
				a.profiles.Profiles[i].UseCount++
				a.profiles.Profiles[i].LastUsedAt = now
			}
		}
		if err := a.persistProfilesLocked(); err != nil {
			a.rollbackProfilesLocked(previous)
			return err
		}
		if last != nil {
			// Commit the frozen Last under the same operation immediately before
			// publishing Connected. A failed private rename retains the old
			// Last; undo this attempt's usage and let its owner retire the child.
			if err := a.saveStartupSelectionCurrent(*last, current); err != nil {
				a.rollbackProfilesLocked(previous)
				return errors.Join(fmt.Errorf("could not commit selected startup Last: %w", err), a.persistProfilesLocked())
			}
		}
	}
	// Surface the authenticated child result without rerunning measurement.
	progress := &comparisonOwner{value: routeComparisonProgress{
		ID: s.launch.chain.policy.Metadata().SessionID, Stage: "selected", Complete: true,
		Execution: s.graph.Execution, Measurements: result.Measurements,
	}}
	desktopComparisons.Store(a, progress)
	a.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""
	return nil
}

func (a *app) runDesktopOrderedExecution(w http.ResponseWriter, r *http.Request, operation context.Context, selection multihopSelection, requested string, driver *desktopOrderedExecutionRuntime) {
	s, err := a.connectDesktopOrderedExecutionWithRuntime(operation, selection, requested, true, driver)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	a.startRouterNodeAutomaticMTU()
	if !desktopMultihopPlatformLaunch(s.launch) {
		a.monitorDesktopOwnedNodeRuntime(s.launch)
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": "multihop", "requested_execution": requested,
		"execution": s.graph.Execution, "nodes": nodeChainSelectedReferences(s.selection.Nodes),
		"entry_id": s.selection.Entry.ID, "exit_id": s.selection.Exit.ID, "exit_path_proof": "authenticated-original-ordered-execution-owner"})
}

type desktopOrderedExecutionStop struct {
	owner     *desktopOrderedExecutionOwner
	operation context.Context
	command   *exec.Cmd
}

func (a *app) captureDesktopOrderedExecutionStopContext(ctx context.Context) (desktopRetainedStopCapture, error) {
	if ctx == nil {
		return nil, errors.New("ordered Stop capture requires its original caller")
	}
	owner, err := a.desktopOrderedExecutionOwner()
	if err != nil || owner == nil {
		return nil, err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	stop := &desktopOrderedExecutionStop{owner: owner, operation: a.connectionContext, command: a.cmd}
	a.mu.Unlock()
	if stop.command != nil && stop.command != owner.session.launch.command {
		return nil, errors.New("ordered Stop cannot adopt a replacement command")
	}
	// Capture the concrete Linux transaction before MTU drain and preserve it
	// across failed release. Windows carries its exact original slot instead.
	if !owner.nativeRetired && owner.session.launch.chain.platform != nil {
		platform, supported := any(owner.session.launch.chain.platform).(interface {
			captureExecutionProductStop(context.Context, *desktopNodeChainExecutionSession) (desktopRetainedStopCapture, error)
		})
		if !supported {
			return nil, errors.New("ordered platform has no captured execution Stop capability")
		}
		captureCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		owner.stop, err = platform.captureExecutionProductStop(captureCtx, owner.session)
		cancel()
		if err != nil {
			return nil, err
		}
		if owner.stop == nil {
			// The exact platform proved that this preparation owns neither a
			// child nor a native transaction. Retire only this registry, then
			// let ordinary captured Stop settle any earlier retained baseline.
			if !desktopOrderedExecutionOwners.CompareAndDelete(a, owner) {
				return nil, errors.New("unentered execution cleanup owner changed")
			}
			return a.captureDesktopRetainedStopWithoutExecution()
		}
	}
	return stop, nil
}

func (stop *desktopOrderedExecutionStop) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if ctx == nil || stop == nil || stop.owner == nil || stop.owner.session == nil {
		return errors.New("ordered Stop lost its captured session")
	}
	owner, s := stop.owner, stop.owner.session
	a := s.app
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	current, ok := desktopOrderedExecutionOwners.Load(a)
	matched := ok && current == owner && a.connectionContext == stop.operation && a.cmd == stop.command && command == stop.command
	a.mu.Unlock()
	if !matched {
		return errors.New("ordered Stop belongs to a replaced operation or child")
	}
	saved, err := a.speedLabOrderedExecutionRestore(ctx, owner)
	if err != nil {
		return err
	}
	if saved != nil {
		if disconnect {
			return errors.New("ordered temporary restore cannot release its retained native baseline")
		}
		if err := saved.retire(ctx); err != nil {
			return err
		}
	} else if owner.stop != nil {
		if !owner.nativeRetired {
			if err := owner.stop.Retire(ctx, command, disconnect); err != nil {
				return err
			}
			owner.nativeRetired = true
		}
		if err := desktopnetwork.LockContext(ctx, &s.mu); err != nil {
			return err
		}
		s.captureDNSPublication()
		err := s.finishRetirementLocked(ctx)
		s.mu.Unlock()
		if err != nil {
			return err
		}
	} else {
		if err := s.Close(ctx); err != nil {
			return err
		}
		if disconnect && owner.slot != nil {
			if err := a.releaseCapturedDesktopNodeProtectionContext(ctx, owner.slot); err != nil {
				return err
			}
		}
	}
	desktopOrderedExecutionOwners.CompareAndDelete(a, owner)
	return ctx.Err()
}
