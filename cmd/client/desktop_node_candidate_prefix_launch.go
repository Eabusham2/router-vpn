package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// This is a separate, never-connected native purpose. The complete saved graph
// is retained in selection only for immutable inventory and explicit Save
// provenance; it supplies no runnable final or ordinary Ready record.
type desktopNodeCandidatePrefixLaunch struct {
	preparation         *orderedCandidatePreparation
	policy              *mobilemultihop.DesktopNodeCandidatePreparationPolicy
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
		selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil || target != "linux" && target != "windows" && target != "darwin" {
		return nil, errors.New("candidate prefix launch requires its original closed purpose and supported native host")
	}
	if err := p.sourceCurrent(ctx); err != nil {
		return nil, err
	}
	policy, err := mobilemultihop.NewDesktopNodeCandidatePreparationPolicy(p.prefixPreparation, session, target, selection.restoreMTU)
	if err != nil {
		return nil, err
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
		candidatePrefix: &desktopNodeCandidatePrefixLaunch{policy: policy, selection: selection, input: policy.Source()}}
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
	if owner.policy == nil || owner.policy.Validate() != nil || selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil {
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
	if owner.policy.Config() != actual || owner.policy.Source() != owner.input || meta.SourceSHA256 == "" ||
		meta.ConfigSHA256 != launch.configSHA256 || meta.SessionID != launch.mtuSession || meta.ProfileID != launch.profileID ||
		meta.Mode != launch.mode || meta.PolicyProfileID != selection.Control.ID || launch.policyProfileID != selection.Control.ID || meta.OriginalSourceSHA256 != selection.Native.source ||
		launch.root != selection.Native.root || launch.endpoint != selection.Native.endpoint || meta.ApplicationOpen || meta.DNSOpen ||
		owner.capture != nil && selection.Native.chain.host != owner.capture {
		return errors.New("candidate prefix changed its original projected input or full saved provenance")
	}
	if owner.preparation != nil && (owner.preparation.prefixPreparation == nil || owner.preparation.selection.Native != selection.Native ||
		meta.PreparationSHA256 != owner.preparation.prefixPreparation.SourceSHA256() || meta.PrefixPosition != owner.preparation.request.Position) {
		return errors.New("candidate prefix belongs to another original preparation")
	}
	return ctx.Err()
}

func (p *orderedCandidatePreparation) bindCandidatePrefixLaunch(ctx context.Context, launch *desktopNodeLaunch) error {
	if p == nil || p.prefixPreparation == nil || launch == nil || launch.candidatePrefix == nil || launch.candidatePrefix.preparation != nil ||
		launch.command != nil || launch.directory != "" || launch.candidatePrefix.ready != nil || launch.candidatePrefix.selection.Native != p.selection.Native {
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
	copy := record
	owner.ready = &copy
	owner.mtuPath = live.Path
	return record, nil
}
