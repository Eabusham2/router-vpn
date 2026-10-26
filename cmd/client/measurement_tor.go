package main

import "errors"

// A retained Tor proof depends on the exact native process and private entry
// assets as well as the two public node references. These identifiers are
// runtime-only; neither credentials nor source contents enter observer state.
type desktopTorMeasurementBinding struct {
	launch                           *desktopNodeLaunch
	predecessor                      *desktopTorPredecessorCapture
	session, source, config, network string
	profileToken                     string
}

func captureDesktopTorMeasurementBinding(a *app, st state) (*desktopTorMeasurementBinding, error) {
	if st.Mode != "external-node" || st.RuntimeMode != "external-tor-bridge" {
		return nil, nil
	}
	if a == nil {
		return nil, errors.New("Tor measurement has no application owner")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, found := desktopNodeOwners.Load(a)
	launch, typed := raw.(*desktopNodeLaunch)
	if !found || !typed || launch == nil || launch.tor == nil || launch.external != nil || launch.profileID != st.RouterID {
		return nil, errors.New("Tor measurement has no captured native owner")
	}
	owner, expected := launch.tor, launch.tor.expected
	bound := &desktopTorMeasurementBinding{launch: launch, predecessor: owner.predecessor,
		session: expected.SessionID, source: expected.SourceSHA256, config: expected.ConfigSHA256,
		network: owner.network, profileToken: owner.sourceIdentityToken()}
	if err := bound.currentLocked(a); err != nil {
		return nil, err
	}
	return bound, nil
}

// The caller holds app.mu (and, for terminal adoption, tracker.mu first).
// Read the bounded original assets directly; entry.current would reacquire
// app.mu and would leave a validation gap before the terminal state write.
func (bound *desktopTorMeasurementBinding) currentLocked(a *app) error {
	if bound == nil || a == nil || bound.launch == nil || bound.launch.tor == nil {
		return errors.New("Tor measurement lost its captured native owner")
	}
	launch, owner := bound.launch, bound.launch.tor
	registered, found := desktopNodeOwners.Load(a)
	if !found || registered != launch || launch.external != nil || launch.command == nil || launch.command.Process == nil || a.cmd != launch.command || launch.mode != "external-tor-bridge" || owner.predecessor != bound.predecessor {
		return errors.New("Tor measurement native process or predecessor changed")
	}
	expected := owner.expected
	if bound.session == "" || bound.source == "" || bound.config == "" || bound.network == "" || bound.profileToken == "" || expected.SessionID != bound.session || expected.SourceSHA256 != bound.source || expected.ConfigSHA256 != bound.config || expected.NodeID != launch.profileID || owner.network != bound.network || owner.currentNetworkIdentity() != bound.network || owner.sourceIdentityToken() != bound.profileToken {
		return errors.New("Tor measurement source, session or physical network changed")
	}
	profile, exists := a.profileByIDLocked(launch.profileID)
	if !exists || desktopTorSourceIdentityToken(profile) != bound.profileToken || owner.entryCurrentLocked(a) != nil {
		return errors.New("Tor measurement captured node policy or credentials changed")
	}
	if entry := bound.predecessor; entry != nil {
		assets, err := startupExternalSourceToken(a, entry.entry, entry.mode)
		if err != nil || assets != entry.assetsSHA256 {
			return errors.New("Tor measurement private entry source changed")
		}
	}
	if desktopNodeProcessExited(launch) {
		return errors.New("Tor measurement native process exited")
	}
	return desktopExternalDirectoryCurrent(launch)
}
