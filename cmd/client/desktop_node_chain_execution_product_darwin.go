//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"

	"router-vpn/internal/mobilemtu"
)

// Retain the original platform's actual Stop transaction before the shared
// product owner drains MTU. A graph, ready label, or same-byte source cannot
// select a replacement host, and revoked profile data cannot prevent cleanup.
func (platform *desktopNodeChainPlatformRuntime) captureExecutionProductStop(ctx context.Context, s *desktopNodeChainExecutionSession) (desktopRetainedStopCapture, error) {
	if ctx == nil || platform == nil || platform.host == nil ||
		s == nil || s.app == nil || s.launch == nil || s.launch.chain == nil || s.execution == nil ||
		s.launch.chain.platform != platform || s.launch.chain.execution != s.execution || s.execution.original != s.launch.chain {
		return nil, errors.New("ordered macOS Stop lost its original platform execution")
	}
	if err := mobilemtu.LockContext(ctx, &s.mu); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	h := platform.host
	if h.runtime != platform || h.launch != s.launch || h.parent == nil || h.parent.parent == nil ||
		h.parent.app != s.app || h.execution != s.execution || h.executionPreparation == nil || h.executionPhysical == nil ||
		h.executionPreparation != s.execution.preparation || h.executionPhysical != s.execution.physical ||
		h.launch.chain.selection.Native != s.selection.Native {
		return nil, errors.New("ordered macOS Stop changed its captured preparation or parent")
	}
	if err := h.enter(ctx); err != nil {
		return nil, err
	}
	closed, published := h.closed, h.published
	h.gate <- struct{}{}
	if s.closed && !closed {
		return nil, errors.New("ordered macOS session closed before its original native host")
	}
	if closed {
		return h.captureRetiredExecutionProductStop(ctx, s)
	}
	if !published {
		return h.captureUnpublishedExecutionProductStop(ctx, s)
	}
	if !platform.registered {
		return nil, errors.New("ordered macOS Stop has no registered original host")
	}
	captured, err := h.parent.parent.captureNodeChainStopContext(ctx, s.app)
	if err != nil {
		return nil, err
	}
	stop, exact := captured.(*desktopMacOSNodeChainStopCapture)
	if !exact || stop == nil || stop.host != h || stop.command != s.launch.command {
		return nil, errors.New("ordered macOS Stop captured a replacement native transaction")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return stop, nil
}

// Construction returns its exact partial launch even if registration or stage
// fails. It has no public Stop slot yet; retain that private cleanup authority
// without pretending that registration, process or protection ever existed.
type desktopMacOSExecutionUnpublishedStop struct {
	host       *desktopMacOSNodeChainHost
	session    *desktopNodeChainExecutionSession
	operation  context.Context
	registered bool
}

func (h *desktopMacOSNodeChainHost) captureUnpublishedExecutionProductStop(ctx context.Context, s *desktopNodeChainExecutionSession) (desktopRetainedStopCapture, error) {
	if err := h.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { h.gate <- struct{}{} }()
	operation, err := h.unpublishedExecutionProductCurrentLocked(ctx, s, nil, h.runtime.registered)
	if err != nil {
		return nil, err
	}
	return &desktopMacOSExecutionUnpublishedStop{host: h, session: s, operation: operation, registered: h.runtime.registered}, nil
}

// Caller holds the execution session and host locks. Only construction/stage
// may precede publication; child, PF and MTU ownership all require publication.
func (h *desktopMacOSNodeChainHost) unpublishedExecutionProductCurrentLocked(ctx context.Context, s *desktopNodeChainExecutionSession, operation context.Context, registered bool) (context.Context, error) {
	bad := errors.New("ordered macOS unpublished Stop lost its original construction")
	if ctx == nil || s == nil || h == nil || s.closed || h.closed || h.published || h.entered || h.proved || h.activated ||
		h.process != nil || h.mtu != nil || h.baselineEntered || h.baselineRetired || h.baseline != nil ||
		h.bound != nil || h.graph != nil || h.executionProof != nil ||
		h.runtime == nil || h.runtime.host != h || h.runtime.registered != registered || h.launch != s.launch ||
		h.parent == nil || h.parent.app != s.app || h.parent.parent == nil || s.launch == nil || s.launch.command != nil ||
		s.launch.chain == nil || s.launch.chain.platform != h.runtime || s.launch.chain.execution != s.execution ||
		s.execution == nil || h.execution != s.execution || s.execution.original != s.launch.chain ||
		h.executionPreparation == nil || h.executionPhysical == nil || h.executionPreparation != s.execution.preparation ||
		h.executionPhysical != s.execution.physical || h.launch.chain.selection.Native != s.selection.Native ||
		!registered && (h.staged || h.stageDirectory != "" || h.launch.directory != "") {
		return nil, bad
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	a, p := s.app, h.parent.parent
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	if a.localController != h.parent.controller || a.cmd != nil || a.connectionContext == nil ||
		operation != nil && a.connectionContext != operation {
		return nil, bad
	}
	if _, exists := nativeMultihopOwners.Load(a); exists {
		return nil, bad
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		return nil, bad
	}
	if _, exists := desktopExternalRetainedLaunches.Load(a); exists {
		return nil, bad
	}
	if _, exists := getActiveMultihopGraph(a); exists {
		return nil, bad
	}
	if err := p.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { p.gate <- struct{}{} }()
	parentSession := h.parent.session
	if p.originalSession != parentSession || parentSession == nil || parentSession.parent != p ||
		p.stopping || p.closed || parentSession.stopping || parentSession.closed ||
		parentSession.nodeChain != nil || parentSession.external != nil || parentSession.candidatePrefix != nil {
		return nil, bad
	}
	_, retained := parentSession.dependents[h]
	expectedDependents := 0
	if registered {
		expectedDependents = 1
	}
	if retained != registered || len(parentSession.dependents) != expectedDependents {
		return nil, bad
	}
	return a.connectionContext, ctx.Err()
}

func (captured *desktopMacOSExecutionUnpublishedStop) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if ctx == nil || captured == nil || captured.host == nil || captured.session == nil || command != nil {
		return errors.New("ordered macOS unpublished Stop changed its original command")
	}
	h, s := captured.host, captured.session
	if err := mobilemtu.LockContext(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if err := h.enter(ctx); err != nil {
		return err
	}
	_, err := h.unpublishedExecutionProductCurrentLocked(ctx, s, captured.operation, captured.registered)
	h.gate <- struct{}{}
	if err != nil {
		return err
	}
	if err := h.closeWithIntent(ctx, !disconnect); err != nil {
		return err
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if _, err := h.retiredExecutionProductCurrentLocked(ctx, s, captured.operation); err != nil {
		return err
	}
	return s.finishRetirementLocked(ctx)
}

// A completed native host may still own its exact held deny receipt. Retain
// that transaction explicitly; a closed session alone never grants absence.
type desktopMacOSExecutionProtectionStop struct {
	host      *desktopMacOSNodeChainHost
	session   *desktopNodeChainExecutionSession
	operation context.Context
	receipt   *desktopMacOSNodeChainReceipt
	value     desktopMacOSNodeChainReceipt
}

// Caller holds the execution session mutex. The host's construction fields
// remain immutable after Close; its terminal progress is read under its gate.
func (h *desktopMacOSNodeChainHost) captureRetiredExecutionProductStop(ctx context.Context, s *desktopNodeChainExecutionSession) (desktopRetainedStopCapture, error) {
	if err := h.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { h.gate <- struct{}{} }()
	operation, err := h.retiredExecutionProductCurrentLocked(ctx, s, nil)
	if err != nil {
		return nil, err
	}
	// A prior native Close may have joined before its caller was canceled at
	// the final session bookkeeping lock. Complete only that proved retirement;
	// this neither restarts a child nor substitutes a new source or PF owner.
	if !s.closed {
		if err := s.finishRetirementLocked(ctx); err != nil {
			return nil, err
		}
	}
	if !h.baselineEntered || h.baseline.Phase == "retired" && !h.baseline.Baseline.Present {
		// Exact native/workspace retirement and released protection were proved.
		// The shared product may drop only its own registry and use ordinary Stop.
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &desktopMacOSExecutionProtectionStop{host: h, session: s, operation: operation,
		receipt: h.baseline, value: *h.baseline}, nil
}

// Caller holds both the execution session mutex and the original host gate.
// Check actual joined cleanup and absence of any replacement before handing
// off an empty owner or settling its original captured protection receipt.
func (h *desktopMacOSNodeChainHost) retiredExecutionProductCurrentLocked(ctx context.Context, s *desktopNodeChainExecutionSession, operation context.Context) (context.Context, error) {
	bad := errors.New("ordered macOS retired Stop lost its exact terminal owner")
	if ctx == nil || s == nil || h == nil || !h.closed || !h.nativeRetired || !h.workspaceRetired || h.mtu != nil ||
		h.runtime == nil || h.runtime.host != h || h.launch != s.launch || h.parent == nil || h.parent.app != s.app || h.parent.parent == nil ||
		s.launch == nil || s.launch.chain == nil || s.launch.chain.platform != h.runtime || s.launch.chain.execution != s.execution ||
		s.execution == nil || h.execution != s.execution || s.execution.original != s.launch.chain ||
		h.executionPreparation == nil || h.executionPhysical == nil || h.executionPreparation != s.execution.preparation ||
		h.executionPhysical != s.execution.physical || h.launch.chain.selection.Native != s.selection.Native {
		return nil, bad
	}
	if h.process != nil {
		p := h.process
		if err := p.enter(ctx); err != nil {
			return nil, err
		}
		joined := !p.started.Load()
		if p.started.Load() {
			select {
			case <-p.joined:
				joined = p.nativeAcknowledged && p.nativeStopped && p.waitErr == nil
			default:
			}
		}
		original := p.closed && joined && p.parent == h.parent && p.command == h.launch.command &&
			p.execution == h.executionPreparation && p.executionPhysical == h.executionPhysical
		p.gate <- struct{}{}
		if !original {
			return nil, bad
		}
	}
	directory := h.launch.directory
	if h.stageDirectory != "" && directory != h.stageDirectory {
		return nil, bad
	}
	if directory != "" {
		if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(err, errors.New("ordered macOS retired workspace is present or unproved"))
		}
	}
	if h.baselineEntered {
		if !h.baselineRetired || h.baseline == nil || h.baseline.Phase != "held" && h.baseline.Phase != "retired" {
			return nil, bad
		}
		raw, err := json.Marshal(h.baseline)
		if err != nil {
			return nil, err
		}
		if _, err := decodeDesktopMacOSNodeChainReceipt(raw, h.selection, h.baseline.Phase); err != nil {
			return nil, err
		}
	} else if h.baseline != nil || h.baselineRetired {
		return nil, bad
	}
	if err := h.parent.cleanupCurrent(ctx); err != nil {
		return nil, err
	}
	a, p := s.app, h.parent.parent
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	defer a.mu.Unlock()
	if a.localController != h.parent.controller || a.cmd != nil || a.connectionContext == nil ||
		operation != nil && a.connectionContext != operation {
		return nil, bad
	}
	if _, exists := nativeMultihopOwners.Load(a); exists {
		return nil, bad
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		return nil, bad
	}
	if _, exists := desktopExternalRetainedLaunches.Load(a); exists {
		return nil, bad
	}
	if _, exists := getActiveMultihopGraph(a); exists {
		return nil, bad
	}
	if err := p.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { p.gate <- struct{}{} }()
	parentSession := h.parent.session
	if p.originalSession != parentSession || parentSession == nil || parentSession.parent != p ||
		p.stopping || p.closed || parentSession.stopping || parentSession.closed ||
		parentSession.nodeChain != nil || parentSession.external != nil || parentSession.candidatePrefix != nil || len(parentSession.dependents) != 0 {
		return nil, bad
	}
	return a.connectionContext, ctx.Err()
}

func (captured *desktopMacOSExecutionProtectionStop) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	if ctx == nil || captured == nil || captured.host == nil || captured.session == nil || command != nil {
		return errors.New("ordered macOS protection Stop lost its joined original child")
	}
	h, s := captured.host, captured.session
	if err := mobilemtu.LockContext(ctx, &s.mu); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if _, err := h.retiredExecutionProductCurrentLocked(ctx, s, captured.operation); err != nil {
		return err
	}
	if h.baseline != captured.receipt || h.baseline == nil || *h.baseline != captured.value || h.baselineRun == nil {
		return errors.New("ordered macOS protection Stop replaced its exact retired receipt")
	}
	action, phase := "retire", "held"
	if disconnect {
		action, phase = "release", "retired"
	}
	value, err := h.baselineRun(ctx, h.parent, h.selection, action, captured.receipt, nil)
	if err != nil {
		return err
	}
	if value == nil || value.Token != captured.value.Token {
		return errors.New("ordered macOS protection Stop changed its original native reference")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := decodeDesktopMacOSNodeChainReceipt(raw, h.selection, phase); err != nil {
		return err
	}
	h.baseline, captured.receipt, captured.value = value, value, *value
	_, err = h.retiredExecutionProductCurrentLocked(ctx, s, captured.operation)
	return err
}
