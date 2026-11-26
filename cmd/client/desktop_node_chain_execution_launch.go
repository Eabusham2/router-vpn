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
	draftPurpose     *orderedCandidatePreparation
	original         *desktopNodeChainLaunch
	operation        context.Context
	preparation      *mobilemultihop.NodeChainExecutionPreparation
	physical         *mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy
	connectPhysical  *mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy
	socksPhysical    *mobilemultihop.DesktopNodeChainSOCKSExecutionPhysicalPolicy
	openvpnPhysical  *mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy
	multiplePhysical *mobilemultihop.DesktopNodeChainMultipleImportedExecutionPhysicalPolicy
	mu               sync.Mutex
	adoption         string
	projection       *mobilemultihop.NodeChainExecutionProjection
	identity         mobilemultihop.NodeChainIdentity
	ready            *mobilemultihop.DesktopNodeChainExecutionReadyRecord
	mtuPath          string
	started          time.Time
}

func desktopNodeChainLaunchExecution(launch *desktopNodeLaunch) *desktopNodeChainExecutionLaunch {
	if launch == nil || launch.chain == nil {
		return nil
	}
	return launch.chain.execution
}

func newDesktopNodeChainExecutionSource(original *desktopNodeChainLaunch, requested string) (*desktopNodeChainExecutionLaunch, error) {
	if original == nil || original.preparation != nil || !original.originalPolicyCurrent() {
		return nil, errors.New("execution preparation requires its complete original typed Local source")
	}
	meta, err := desktopNodeChainExecutionOriginalMetadata(original)
	if err != nil {
		return nil, err
	}
	if meta.TargetOS != "linux" && meta.TargetOS != "windows" && meta.TargetOS != "darwin" {
		return nil, errors.New("execution host has no supported native target")
	}
	if desktopNodeChainMultipleImportedExecutionSource(original) {
		prep, err := mobilemultihop.NewDesktopNodeChainMultipleImportedExecutionPreparation(original.policy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.MultipleImportedDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, multiplePhysical: physical}
		return result, result.validateSource()
	}
	if desktopNodeChainHasOpenVPN(nodeChainSelectedReferences(original.selection.Nodes)) {
		if original.policy == nil || original.socksPolicy != nil || original.connectPolicy != nil {
			return nil, errors.New("OpenVPN execution requires its original generic Local owner")
		}
		prep, err := mobilemultihop.NewDesktopNodeChainOpenVPNExecutionPreparation(original.policy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.OpenVPNDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, openvpnPhysical: physical}
		return result, result.validateSource()
	}
	if original.socksPolicy != nil {
		prep, err := mobilemultihop.NewDesktopNodeChainSOCKSExecutionPreparation(original.socksPolicy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.SOCKSDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, socksPhysical: physical}
		return result, result.validateSource()
	}
	if original.connectPolicy != nil {
		prep, err := mobilemultihop.NewDesktopNodeChainCONNECTExecutionPreparation(original.connectPolicy, requested)
		if err != nil {
			return nil, err
		}
		physical, err := prep.CONNECTDesktopPhysicalPolicy()
		if err != nil {
			return nil, err
		}
		result := &desktopNodeChainExecutionLaunch{original: original, preparation: prep, connectPhysical: physical}
		return result, result.validateSource()
	}
	var prep *mobilemultihop.NodeChainExecutionPreparation
	if meta.ExternalFinal != nil {
		prep, err = mobilemultihop.NewDesktopNodeChainExternalFinalExecutionPreparation(original.policy, requested)
	} else {
		prep, err = mobilemultihop.NewDesktopNodeChainExecutionPreparation(original.policy, requested)
	}
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
	_, _, err := e.readSourceValidated()
	return err
}

// One observation reads each immutable source through its original typed
// owner. This avoids repeating the same full validation through several
// getters; it stores no reusable validation or live process/network receipt.
type desktopExecutionSourceObservation struct {
	policy   mobilemultihop.DesktopPhysicalPolicy
	metadata mobilemultihop.DesktopNodeChainMetadata
	config   string
	physical mobilemultihop.DesktopPhysicalMetadata
	capture  mobilemultihop.DesktopPhysicalCapture
}

func (p *orderedCandidatePreparation) ownsSelectedDraft(launch *desktopNodeLaunch, e *desktopNodeChainExecutionLaunch) bool {
	return p != nil && p.request.Scope == orderedCandidateSelectedDraftScope && orderedCandidateDraftScopeMatches(p.request.Scope, p.request.draft) &&
		p.prefixPreparation == nil && p.launch == launch && launch != nil && launch.chain != nil && launch.chain.preparation == p &&
		launch.chain.execution == e && e != nil && e.original == launch.chain && e.draftPurpose == p && e.operation == p.operation &&
		e.preparation != nil && e.preparation.Execution() == p.request.draft.Execution && p.selection.Native != nil && p.selection.Native == launch.chain.selection.Native
}

func (e *desktopNodeChainExecutionLaunch) readSourceValidated() (mobilemultihop.DesktopPhysicalPolicy, mobilemultihop.DesktopNodeChainMetadata, error) {
	observed, err := e.readSourceObservation(false)
	return observed.policy, observed.metadata, err
}

func (e *desktopNodeChainExecutionLaunch) readSourceObservation(physicalRead bool) (desktopExecutionSourceObservation, error) {
	bad := func() (desktopExecutionSourceObservation, error) {
		return desktopExecutionSourceObservation{}, errors.New("execution launch changed its exact original source or physical preparation")
	}
	if e == nil || e.original == nil || e.preparation == nil || desktopNodeChainExecutionPhysicalCountWithMultiple(e.physical, e.connectPhysical, e.socksPhysical, e.openvpnPhysical, e.multiplePhysical) != 1 ||
		!e.original.hasPolicy() || e.original.preparation != e.draftPurpose ||
		e.draftPurpose != nil && !e.draftPurpose.ownsSelectedDraft(e.draftPurpose.launch, e) || e.original.selection.Native == nil ||
		e.original.selection.Native.chain == nil || e.original.selection.Native.validate(e.original.selection) != nil {
		return bad()
	}
	if e.original.execution != nil && e.original.execution != e {
		return bad()
	}
	selected := e.original.selection.Native.chain
	var observed desktopExecutionSourceObservation
	var policy mobilemultihop.DesktopPhysicalPolicy
	var meta mobilemultihop.DesktopNodeChainMetadata
	if e.multiplePhysical != nil {
		if e.original.policy == nil || e.original.connectPolicy != nil || e.original.socksPolicy != nil || selected.chain == nil || selected.connect != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainPolicy
		var source *mobilemultihop.NodeChain
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.multiplePhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.multiplePhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.policy || source != selected.chain {
			return bad()
		}
		policy, meta = e.multiplePhysical, metadata
	} else if e.openvpnPhysical != nil {
		if e.original.policy == nil || e.original.connectPolicy != nil || e.original.socksPolicy != nil || selected.chain == nil || selected.connect != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainPolicy
		var source *mobilemultihop.NodeChain
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.openvpnPhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.openvpnPhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.policy || source != selected.chain {
			return bad()
		}
		policy, meta = e.openvpnPhysical, metadata
	} else if e.socksPhysical != nil {
		if e.original.socksPolicy == nil || e.original.policy != nil || e.original.connectPolicy != nil || selected.socks == nil || selected.chain != nil || selected.connect != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainSOCKSPolicy
		var source *mobilemultihop.NodeChainSOCKSSource
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.socksPhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.socksPhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.socksPolicy || source != selected.socks.source {
			return bad()
		}
		policy, meta = e.socksPhysical, metadata
	} else if e.connectPhysical != nil {
		if e.original.connectPolicy == nil || e.original.policy != nil || selected.connect == nil || selected.chain != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainCONNECTPolicy
		var source *mobilemultihop.NodeChainCONNECTSource
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.connectPhysical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.connectPhysical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.connectPolicy || source != selected.connect.source {
			return bad()
		}
		policy, meta = e.connectPhysical, metadata
	} else {
		if e.original.policy == nil || e.original.connectPolicy != nil || selected.chain == nil || selected.connect != nil || selected.socks != nil {
			return bad()
		}
		var original *mobilemultihop.DesktopNodeChainPolicy
		var source *mobilemultihop.NodeChain
		var metadata mobilemultihop.DesktopNodeChainMetadata
		var err error
		if physicalRead {
			original, source, metadata, observed.config, observed.physical, observed.capture, err = e.physical.ReadExecutionValidated(e.preparation)
		} else {
			original, source, metadata, err = e.physical.ReadOriginalSourceValidated(e.preparation)
		}
		if err != nil || original != e.original.policy || source != selected.chain {
			return bad()
		}
		policy, meta = e.physical, metadata
	}
	if meta.TargetOS != "linux" && meta.TargetOS != "windows" && meta.TargetOS != "darwin" {
		return bad()
	}
	observed.policy, observed.metadata = policy, meta
	return observed, nil
}

// This descriptive view never substitutes for either sealed physical owner.
// Read the retained Local policy directly to avoid recursing through execution.
func desktopNodeChainExecutionOriginalMetadata(original *desktopNodeChainLaunch) (mobilemultihop.DesktopNodeChainMetadata, error) {
	if original == nil || !original.hasPolicy() {
		return mobilemultihop.DesktopNodeChainMetadata{}, errors.New("execution metadata lost its original typed policy")
	}
	if original.socksPolicy != nil {
		_, meta, _, err := original.socksPolicy.ReadValidated()
		return meta.DesktopNodeChainMetadata, err
	}
	if original.connectPolicy != nil {
		_, meta, _, err := original.connectPolicy.ReadValidated()
		return meta.DesktopNodeChainMetadata, err
	}
	_, meta, _, err := original.policy.ReadValidated()
	return meta, err
}

func (e *desktopNodeChainExecutionLaunch) physicalPolicy() (mobilemultihop.DesktopPhysicalPolicy, error) {
	policy, _, err := e.readSourceValidated()
	return policy, err
}

func (e *desktopNodeChainExecutionLaunch) projectionPhysicalCurrent(projection *mobilemultihop.NodeChainExecutionProjection) error {
	if e.validateSource() != nil || projection == nil {
		return errors.New("execution projection lost its original typed physical source")
	}
	if e.multiplePhysical != nil {
		physical, err := projection.MultipleImportedDesktopPhysicalPolicy()
		if err != nil || physical != e.multiplePhysical {
			return errors.New("multiple imported execution replaced its original physical source")
		}
		return nil
	}
	if e.openvpnPhysical != nil {
		physical, err := projection.OpenVPNDesktopPhysicalPolicy()
		if err != nil || physical != e.openvpnPhysical {
			return errors.New("OpenVPN execution replaced its original physical source")
		}
		return nil
	}
	if e.socksPhysical != nil {
		physical, err := projection.SOCKSDesktopPhysicalPolicy()
		if err != nil || physical != e.socksPhysical {
			return errors.New("SOCKS execution replaced its original physical source")
		}
		return nil
	}
	if e.connectPhysical != nil {
		physical, err := projection.CONNECTDesktopPhysicalPolicy()
		if err != nil || physical != e.connectPhysical {
			return errors.New("CONNECT execution replaced its original physical source")
		}
		return nil
	}
	physical, err := projection.DesktopPhysicalPolicy()
	if err != nil || physical != e.physical {
		return errors.New("paired execution replaced its original physical source")
	}
	return nil
}

// This is a descriptive view for the common ordered host's source comparisons.
// Native policy admission must use the original concrete physicalPolicy owner,
// never this metadata value.
func (e *desktopNodeChainExecutionLaunch) readPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, mobilemultihop.DesktopPhysicalCapture, error) {
	observation, err := e.readPolicyCapture()
	return observation.config, observation.metadata, observation.capture, err
}

func (e *desktopNodeChainExecutionLaunch) readPolicyCapture() (desktopExecutionSourceObservation, error) {
	observed, err := e.readSourceObservation(true)
	if err != nil {
		return desktopExecutionSourceObservation{}, err
	}
	meta, physical := observed.metadata, observed.physical
	kind := "node-chain-execution"
	if e.multiplePhysical != nil {
		kind = "node-chain-multiple-imported-execution"
	} else if e.openvpnPhysical != nil {
		kind = "node-chain-openvpn-execution"
	} else if e.socksPhysical != nil {
		kind = "node-chain-socks-execution"
	} else if e.connectPhysical != nil {
		kind = "node-chain-connect-execution"
	}
	if err != nil || physical.ConfigSHA256 != e.preparation.ConfigSHA256() || physical.SourceSHA256 != meta.SourceSHA256 ||
		physical.SessionID != meta.SessionID || physical.TargetOS != meta.TargetOS || physical.Kind != kind {
		return desktopExecutionSourceObservation{}, errors.New("execution physical capture differs from its original desktop policy")
	}
	observed.metadata.ConfigSHA256, observed.metadata.FinalTag = physical.ConfigSHA256, mobilemultihop.SelectorTag
	return observed, nil
}

func (e *desktopNodeChainExecutionLaunch) bound(launch *desktopNodeLaunch) error {
	_, meta, err := e.readSourceValidated()
	if err != nil || launch == nil || launch.chain != e.original || launch.chain.execution != e || launch.configSHA256 != e.preparation.ConfigSHA256() ||
		launch.mtuSession != meta.SessionID || e.original.input != e.preparation.Source() {
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
