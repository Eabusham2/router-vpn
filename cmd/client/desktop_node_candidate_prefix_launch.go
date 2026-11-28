package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

const desktopNodeCandidateAppendExecutionCommand = "routervpn-node-candidate-append-execution"

// This is a separate, never-connected native purpose. The complete saved graph
// is retained in selection only for immutable inventory and explicit Save
// provenance; it supplies no runnable final or ordinary Ready record.
type desktopNodeCandidatePrefixLaunch struct {
	preparation         *orderedCandidatePreparation
	policy              *mobilemultihop.DesktopNodeCandidatePreparationPolicy
	executionPolicy     *mobilemultihop.DesktopNodeCandidateAppendExecutionPolicy
	executionOriginal   *mobilemultihop.NodeChainCandidateAppendExecutionPreparation
	executionReady      *mobilemultihop.DesktopNodeCandidateAppendExecutionReadyRecord
	executionReadyInfo  os.FileInfo
	executionReadyRaw   []byte
	executionStarted    time.Time
	selection           multihopSelection
	input               string
	capture             *desktopNodeChainHostCapture
	platform            desktopNodeCandidatePrefixPlatform
	mu                  sync.Mutex
	ready               *mobilemultihop.DesktopNodeCandidatePreparationReadyRecord
	mtuPath             string
	measurementMu       sync.Mutex
	candidateGeneration uint64
	candidateLast       string
	candidatePending    *desktopNodeCandidatePrefixRetirement
}

func (owner *desktopNodeCandidatePrefixLaunch) commandName() string {
	if owner == nil {
		return ""
	}
	if owner.executionPolicy != nil {
		return desktopNodeCandidateAppendExecutionCommand
	}
	return "routervpn-node-candidate-prefix"
}

func (owner *desktopNodeCandidatePrefixLaunch) sourceInput() string {
	if owner == nil || owner.policy == nil {
		return ""
	}
	if owner.executionPolicy != nil {
		return owner.executionPolicy.Source()
	}
	return owner.policy.Source()
}

// The execution wrapper is additive. The original Local policy still owns the
// physical path, closed TUN and finite inventory; a Server capture cannot replace it.
func (owner *desktopNodeCandidatePrefixLaunch) executionPolicyCurrent() bool {
	if owner == nil || owner.policy == nil {
		return false
	}
	if owner.executionPolicy == nil {
		return owner.executionOriginal == nil && owner.executionReady == nil && owner.executionReadyInfo == nil && len(owner.executionReadyRaw) == 0 && owner.executionStarted.IsZero() &&
			(owner.preparation == nil || owner.preparation.appendExecutionPreparation == nil)
	}
	wrapper, original := owner.executionPolicy, owner.executionOriginal
	if wrapper.Validate() != nil || original == nil || original.OriginalPreparation() == nil || wrapper.LocalPolicy() != owner.policy || wrapper.Preparation() != owner.policy.Preparation() {
		return false
	}
	projected := wrapper.ExecutionPreparation()
	meta := owner.policy.Metadata()
	return projected != nil && projected.OriginalPreparation() == owner.policy.Preparation() && projected.Source() == original.Source() &&
		projected.SourceSHA256() == original.SourceSHA256() && projected.OriginalSourceSHA256() == original.OriginalSourceSHA256() &&
		meta.PreparationSHA256 == original.OriginalPreparation().SourceSHA256() && meta.OriginalCaptureSHA256 == original.OriginalPreparation().CaptureSHA256() &&
		(owner.preparation == nil || owner.preparation.appendExecutionPreparation == original && owner.preparation.prefixPreparation == original.OriginalPreparation())
}

type desktopNodeCandidatePrefixPlatform interface {
	guard(context.Context, *app, *desktopNodeLaunch) error
	stage(context.Context) error
	start(context.Context) error
	current(context.Context) error
	activate(context.Context) error
	close(context.Context) error
	closePreparation(context.Context, *orderedCandidatePreparation) error
	processDone() <-chan struct{}
}

func newDesktopNodeCandidatePrefixLaunchForPurpose(ctx context.Context, selection multihopSelection, session, target string,
	p *orderedCandidatePreparation) (*desktopNodeLaunch, error) {
	if ctx == nil || ctx.Err() != nil || p == nil || p.prefixPreparation == nil || p.selection.Native != selection.Native ||
		selection.Native == nil || selection.Native.chain == nil || validateDesktopCandidatePurposeSelection(ctx, selection, p.prefixPreparation) != nil || !p.closedPurposeCurrent() || target != "linux" && target != "windows" && target != "darwin" {
		return nil, errors.New("candidate prefix launch requires its original closed purpose and supported native host")
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return nil, err
	}
	var policy *mobilemultihop.DesktopNodeCandidatePreparationPolicy
	var execution *mobilemultihop.DesktopNodeCandidateAppendExecutionPolicy
	var err error
	if p.appendExecutionPreparation != nil {
		if p.appendExecutionPreparation.OriginalPreparation() != p.prefixPreparation || !p.appendExecutionSourceCurrent() {
			return nil, errors.New("append execution launch lost its original Local preparation")
		}
		execution, err = mobilemultihop.NewDesktopNodeCandidateAppendExecutionPolicy(p.appendExecutionPreparation, session, target, selection.restoreMTU)
		if err == nil {
			policy = execution.LocalPolicy()
		}
	} else {
		policy, err = mobilemultihop.NewDesktopNodeCandidatePreparationPolicy(p.prefixPreparation, session, target, selection.restoreMTU)
	}
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("candidate prefix lost its typed Local policy")
	}
	meta := policy.Metadata()
	if meta.PrefixPosition != p.request.Position || meta.OriginalSourceSHA256 != selection.Native.source || meta.PreparationSHA256 != p.prefixPreparation.SourceSHA256() {
		return nil, errors.New("candidate prefix launch changed its saved graph or captured finite inventory")
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
	selection.Nodes = cloneDesktopNodeChainMembers(selection.Nodes)
	launch := &desktopNodeLaunch{root: selection.Native.root, endpoint: selection.Native.endpoint, profileID: meta.ProfileID,
		policyProfileID: selection.Control.ID, mode: meta.Mode, config: []byte(policy.Config()), metadata: raw,
		configSHA256: meta.ConfigSHA256, mtuSession: session,
		candidatePrefix: &desktopNodeCandidatePrefixLaunch{policy: policy, executionPolicy: execution, executionOriginal: p.appendExecutionPreparation, selection: selection}}
	launch.candidatePrefix.input = launch.candidatePrefix.sourceInput()
	_, _, physical, err := policy.PhysicalReadValidated()
	if err != nil {
		return nil, err
	}
	for _, root := range physical.PhysicalRoots {
		launch.nodePhysicalEgress = append(launch.nodePhysicalEgress, root.Destinations...)
	}
	if err := p.bindCandidatePrefixLaunch(ctx, launch); err != nil {
		clear(launch.config)
		clear(launch.metadata)
		return nil, err
	}
	return launch, nil
}

func validateDesktopNodeCandidatePrefixLaunch(ctx context.Context, launch *desktopNodeLaunch) error {
	if ctx == nil || ctx.Err() != nil || launch == nil || launch.candidatePrefix == nil || launch.chain != nil || launch.importedEntry || launch.importedPlatform != nil || launch.external != nil || launch.tor != nil {
		return errors.New("candidate prefix changed its concrete native purpose")
	}
	owner := launch.candidatePrefix
	selection := owner.selection
	if owner.policy == nil || owner.policy.Validate() != nil || !owner.executionPolicyCurrent() || selection.Native == nil || selection.Native.chain == nil || validateDesktopCandidatePurposeSelection(ctx, selection, owner.policy.Preparation()) != nil {
		return errors.New("candidate prefix lost its sealed source")
	}
	meta := owner.policy.Metadata()
	actual := string(launch.config)
	if actual == "" && launch.command != nil && launch.directory != "" {
		raw, err := readDesktopRuntimeFileContext(ctx, launch, "sing-box.json", mobilemultihop.NodeChainInputLimit)
		if err != nil {
			return err
		}
		actual = string(raw)
		clear(raw)
	}
	if owner.policy.Config() != actual || owner.sourceInput() != owner.input || meta.SourceSHA256 == "" ||
		meta.ConfigSHA256 != launch.configSHA256 || meta.SessionID != launch.mtuSession || meta.ProfileID != launch.profileID ||
		meta.Mode != launch.mode || meta.PolicyProfileID != selection.Control.ID || launch.policyProfileID != selection.Control.ID || meta.OriginalSourceSHA256 != selection.Native.source ||
		launch.root != selection.Native.root || launch.endpoint != selection.Native.endpoint || meta.ApplicationOpen || meta.DNSOpen ||
		owner.capture != nil && selection.Native.chain.host != owner.capture {
		return errors.New("candidate prefix changed its original projected input or full saved provenance")
	}
	if owner.preparation != nil && (owner.preparation.prefixPreparation == nil || owner.preparation.selection.Native != selection.Native ||
		meta.PreparationSHA256 != owner.preparation.prefixPreparation.SourceSHA256() || meta.OriginalCaptureSHA256 != owner.preparation.prefixPreparation.CaptureSHA256() || meta.PrefixPosition != owner.preparation.request.Position) {
		return errors.New("candidate prefix belongs to another original preparation")
	}
	return ctx.Err()
}

func (p *orderedCandidatePreparation) bindCandidatePrefixLaunch(ctx context.Context, launch *desktopNodeLaunch) error {
	if p == nil || p.prefixPreparation == nil || launch == nil || launch.candidatePrefix == nil || launch.candidatePrefix.preparation != nil ||
		launch.command != nil || launch.directory != "" || launch.candidatePrefix.ready != nil || launch.candidatePrefix.executionReady != nil ||
		launch.candidatePrefix.executionOriginal != p.appendExecutionPreparation || launch.candidatePrefix.selection.Native != p.selection.Native {
		return errors.New("candidate prefix purpose requires its unused original launch")
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return err
	}
	if err := validateDesktopNodeCandidatePrefixLaunch(ctx, launch); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &p.mu); err != nil {
		return err
	}
	defer p.mu.Unlock()
	if p.launch != nil || p.down {
		return errors.New("candidate prefix purpose already owns a launch or retirement")
	}
	if err := desktopnetwork.LockContext(ctx, &p.app.mu); err != nil {
		return err
	}
	defer p.app.mu.Unlock()
	if err := p.currentLocked(); err != nil {
		return err
	}
	if p.app.cmd != nil || p.app.state != p.state {
		return errors.New("candidate prefix lost its original idle Home state")
	}
	p.launch, launch.candidatePrefix.preparation = launch, p
	return ctx.Err()
}

// Callers bracket this private receipt with their original process/protection
// capability. The separate record cannot satisfy ordinary node/full readiness.
func readDesktopNodeCandidatePrefixReadyContext(ctx context.Context, launch *desktopNodeLaunch, transfer string,
	started time.Time, fresh bool, live desktopNodeMTURecord) (mobilemultihop.DesktopNodeCandidatePreparationReadyRecord, error) {
	var empty mobilemultihop.DesktopNodeCandidatePreparationReadyRecord
	if launch == nil || launch.candidatePrefix == nil || ctx == nil || ctx.Err() != nil {
		return empty, errors.New("prefix readiness lost its typed original launch")
	}
	owner := launch.candidatePrefix
	if err := desktopnetwork.LockContext(ctx, &owner.mu); err != nil {
		return empty, err
	}
	defer owner.mu.Unlock()
	raw, err := readDesktopRuntimeFileContext(ctx, launch, "node-candidate-prefix-ready.json", mobilemultihop.DesktopNodeCandidatePreparationReadyLimit)
	if err != nil {
		return empty, err
	}
	record, err := mobilemultihop.ParseDesktopNodeCandidatePreparationReadyRecord(raw, owner.policy, transfer)
	if err != nil {
		return empty, err
	}
	now := time.Now()
	if started.IsZero() || record.ObservedAt < started.UnixMilli() || record.ObservedAt > now.UnixMilli() || now.UnixMilli()-record.ObservedAt > 1500 ||
		live.Session != record.Identity.SessionID || live.Config != record.Identity.ConfigSHA256 || live.Reader != record.Reader || live.Interface != record.InterfaceName ||
		live.Index != int(record.InterfaceIndex) || live.MTU != record.MTU || live.Active || live.Failure != "" || !desktopMTUPathPattern.MatchString(live.Path) ||
		owner.mtuPath != "" && owner.mtuPath != live.Path || !fresh && owner.ready == nil {
		return empty, errors.New("prefix readiness changed its actual native reader or freshness")
	}
	if previous := owner.ready; previous != nil {
		before, next := *previous, record
		before.ObservedAt, next.ObservedAt = 0, 0
		if !reflect.DeepEqual(before, next) {
			return empty, errors.New("prefix readiness replaced its original private proof or native reader")
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var execution *mobilemultihop.DesktopNodeCandidateAppendExecutionReadyRecord
	var executionInfo os.FileInfo
	var executionRaw []byte
	if owner.executionPolicy != nil {
		if !owner.executionPolicyCurrent() {
			return empty, errors.New("append discovery lost its original typed preparation")
		}
		executionRaw, executionInfo, err = readDesktopNodeCandidateAppendExecutionReadySnapshot(ctx, launch)
		if err != nil {
			return empty, err
		}
		observed, readErr := mobilemultihop.ParseDesktopNodeCandidateAppendExecutionReadyRecord(executionRaw, owner.executionPolicy, transfer, record)
		now = time.Now()
		executionStarted := owner.executionStarted
		if executionStarted.IsZero() {
			executionStarted = started
		}
		if readErr != nil || observed.ObservedAt < executionStarted.UnixMilli() || observed.ObservedAt > now.UnixMilli() || now.UnixMilli()-observed.ObservedAt > 1500 || !fresh && owner.executionReady == nil {
			return empty, errors.Join(readErr, errors.New("append discovery changed its original freshness or native reader"))
		}
		if previous := owner.executionReady; previous != nil {
			before, after := *previous, observed
			before.ObservedAt, after.ObservedAt = 0, 0
			if !reflect.DeepEqual(before, after) || observed.ObservedAt < previous.ObservedAt || owner.executionStarted.IsZero() || owner.executionReadyInfo == nil ||
				os.SameFile(owner.executionReadyInfo, executionInfo) && (!bytes.Equal(owner.executionReadyRaw, executionRaw) || owner.executionReadyInfo.Size() != executionInfo.Size() || !owner.executionReadyInfo.ModTime().Equal(executionInfo.ModTime())) {
				return empty, errors.New("append discovery replaced its original runtime identity or immutable publication")
			}
		}
		execution = &observed
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	copy := record
	owner.ready = &copy
	if execution != nil {
		if owner.executionStarted.IsZero() {
			owner.executionStarted = started
		}
		owner.executionReady, owner.executionReadyInfo = execution, executionInfo
		owner.executionReadyRaw = append(owner.executionReadyRaw[:0], executionRaw...)
	}
	owner.mtuPath = live.Path
	return record, nil
}

// Observe a single atomic sidecar publication through the already retained
// runtime directory. The native owner may replace the file between observations;
// it cannot mutate an accepted inode or redirect the original directory handle.
func readDesktopNodeCandidateAppendExecutionReadySnapshot(ctx context.Context, launch *desktopNodeLaunch) ([]byte, os.FileInfo, error) {
	if launch == nil || launch.candidatePrefix == nil || launch.candidatePrefix.executionPolicy == nil {
		return nil, nil, errors.New("append discovery has no original native launch")
	}
	if err := desktopnetwork.LockContext(ctx, &launch.workspaceMu); err != nil {
		return nil, nil, err
	}
	defer launch.workspaceMu.Unlock()
	if err := desktopExternalDirectoryCurrent(launch); err != nil {
		return nil, nil, err
	}
	const name = "node-candidate-append-execution-ready.json"
	for attempt := 0; attempt < 3; attempt++ {
		before, err := launch.directoryRoot.Lstat(name)
		if err != nil {
			return nil, nil, err
		}
		raw, err := readDesktopRuntimeSnapshot(launch.directoryRoot, name, mobilemultihop.DesktopNodeCandidateAppendExecutionReadyLimit)
		if errors.Is(err, errDesktopRuntimeSnapshotChanged) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		after, err := launch.directoryRoot.Lstat(name)
		if err != nil {
			return nil, nil, err
		}
		if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			continue
		}
		if err := desktopExternalDirectoryCurrent(launch); err != nil {
			return nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		return raw, after, nil
	}
	return nil, nil, errDesktopRuntimeSnapshotChanged
}
