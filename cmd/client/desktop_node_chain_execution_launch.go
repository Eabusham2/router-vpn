package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// This adjunct derives execution from the original complete Local capture. It
// grants no process/TUN authority; Each supported platform retains its existing
// native owners. The physical policy is the sealed preparation object itself.
type desktopNodeChainExecutionLaunch struct {
	original    *desktopNodeChainLaunch
	operation   context.Context
	preparation *mobilemultihop.NodeChainExecutionPreparation
	physical    *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy
	mu          sync.Mutex
	adoption    string
	projection  *mobilemultihop.NodeChainExecutionProjection
	identity    mobilemultihop.NodeChainIdentity
	ready       *mobilemultihop.DesktopNodeChainExecutionReadyRecord
	mtuPath     string
	started     time.Time
}

func desktopNodeChainLaunchExecution(launch *desktopNodeLaunch) *desktopNodeChainExecutionLaunch {
	if launch == nil || launch.chain == nil {
		return nil
	}
	return launch.chain.execution
}

func newDesktopNodeChainExecutionSource(original *desktopNodeChainLaunch, requested string) (*desktopNodeChainExecutionLaunch, error) {
	if original == nil || original.policy == nil || original.socksPolicy != nil || original.preparation != nil || !original.originalPolicyCurrent() {
		return nil, errors.New("execution preparation requires its complete original paired Local source")
	}
	meta := original.policy.Metadata()
	if meta.TargetOS != "linux" && meta.TargetOS != "windows" && meta.TargetOS != "darwin" {
		return nil, errors.New("execution host has no supported native target")
	}
	prep, err := mobilemultihop.NewDesktopNodeChainExecutionPreparation(original.policy, requested)
	if err != nil {
		return nil, err
	}
	physical, err := prep.DesktopPhysicalPolicy()
	if err != nil {
		return nil, err
	}
	result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, physical: physical}
	return result, result.validateSource()
}

func (e *desktopNodeChainExecutionLaunch) validateSource() error {
	bad := errors.New("execution launch changed its exact original source or physical preparation")
	if e == nil || e.original == nil || e.preparation == nil || e.physical == nil || e.original.policy == nil ||
		!e.original.hasPolicy() || e.original.socksPolicy != nil || e.original.preparation != nil || e.original.selection.Native == nil ||
		e.original.selection.Native.chain == nil || e.original.selection.Native.validate(e.original.selection) != nil {
		return bad
	}
	if e.original.execution != nil && e.original.execution != e {
		return bad
	}
	physical, err := e.preparation.DesktopPhysicalPolicy()
	if err != nil || physical != e.physical {
		return bad
	}
	original, err := physical.OriginalDesktopPolicy()
	if err != nil || original != e.original.policy || original.OriginalChain() != e.original.selection.Native.chain.chain {
		return bad
	}
	meta := original.Metadata()
	if meta.TargetOS != "linux" && meta.TargetOS != "windows" && meta.TargetOS != "darwin" {
		return bad
	}
	return nil
}

// This is a descriptive view for the common ordered host's source comparisons.
// Native policy admission must use e.physical, never this metadata value.
func (e *desktopNodeChainExecutionLaunch) readPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, mobilemultihop.DesktopPhysicalCapture, error) {
	if err := e.validateSource(); err != nil {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, mobilemultihop.DesktopPhysicalCapture{}, err
	}
	config, physical, capture, err := e.physical.PhysicalReadValidated()
	meta := e.original.policy.Metadata()
	if err != nil || physical.ConfigSHA256 != e.preparation.ConfigSHA256() || physical.SourceSHA256 != meta.SourceSHA256 ||
		physical.SessionID != meta.SessionID || physical.TargetOS != meta.TargetOS || physical.Kind != "node-chain-execution" {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, mobilemultihop.DesktopPhysicalCapture{}, errors.New("execution physical capture differs from its original desktop policy")
	}
	meta.ConfigSHA256, meta.FinalTag = physical.ConfigSHA256, mobilemultihop.SelectorTag
	return config, meta, capture, nil
}

func (e *desktopNodeChainExecutionLaunch) bound(launch *desktopNodeLaunch) error {
	if err := e.validateSource(); err != nil {
		return err
	}
	if launch == nil || launch.chain != e.original || launch.chain.execution != e || launch.configSHA256 != e.preparation.ConfigSHA256() ||
		launch.mtuSession != e.original.policy.Metadata().SessionID || e.original.input != e.preparation.Source() {
		return errors.New("execution observation lost its exact staged parent launch")
	}
	return nil
}

// Attach before any platform owner, process, protection attempt or private
// workspace is constructed. The original paired policy remains the immutable
// source; only its sealed execution physical policy may reach native admission.
func (e *desktopNodeChainExecutionLaunch) attach(launch *desktopNodeLaunch) error {
	if e.validateSource() != nil || launch == nil || launch.chain != e.original || e.original.execution != nil ||
		launch.command != nil || launch.directory != "" || launch.directoryRoot != nil || launch.ownedNode != nil ||
		e.original.platform != nil || launch.candidatePrefix != nil || launch.importedEntry || launch.external != nil || launch.tor != nil {
		return errors.New("execution source cannot replace an entered original native launch")
	}
	config, metadata, _, err := e.readPolicy()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	clear(launch.config)
	clear(launch.metadata)
	launch.config, launch.metadata, launch.configSHA256 = []byte(config), raw, metadata.ConfigSHA256
	e.original.input, e.original.execution = e.preparation.Source(), e
	return e.bound(launch)
}
