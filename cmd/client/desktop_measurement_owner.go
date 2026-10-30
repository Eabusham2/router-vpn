package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Measurement mailboxes share a wire contract while the ordinary and Tor
// engines retain separate proofs, process ownership and teardown paths.
// These pointers refer only to the captured launch; selection cannot retarget
// an in-flight MTU operation or a fresh-path verification.
type desktopMeasurementRuntime struct {
	session, source, config, node, entry string
	network, measuredSource              string
	mu                                   *sync.Mutex
	mtu                                  **desktopMTUSession
	pathMu                               *sync.Mutex
	pathGeneration                       *uint64
	pathFailed                           *bool
}

func capturedDesktopMeasurementRuntime(launch *desktopNodeLaunch) (desktopMeasurementRuntime, error) {
	var identity desktopMeasurementRuntime
	if launch == nil || launch.external != nil && launch.tor != nil {
		return identity, errors.New("native measurement requires one captured runtime owner")
	}
	if owner := launch.tor; owner != nil {
		metadata := owner.expected
		identity = desktopMeasurementRuntime{session: metadata.SessionID, source: metadata.SourceSHA256, config: metadata.ConfigSHA256, node: metadata.NodeID, entry: metadata.EntryID,
			network: owner.network, measuredSource: "measured-tor-system-tun-transfer", mu: &owner.mu, mtu: &owner.mtu,
			pathMu: &owner.pathMu, pathGeneration: &owner.pathGeneration, pathFailed: &owner.pathFailed}
	} else if owner := launch.external; owner != nil {
		source, config, err := desktopExternalMeasurementIdentity(owner)
		if err != nil {
			return identity, err
		}
		identity = desktopMeasurementRuntime{session: owner.session, source: source, config: config, node: owner.expected.ExitID, entry: owner.expected.EntryID,
			network: owner.network, measuredSource: "measured-public-system-tun-transfer", mu: &owner.mu, mtu: &owner.mtu,
			pathMu: &owner.pathMu, pathGeneration: &owner.pathGeneration, pathFailed: &owner.pathFailed}
	} else {
		return identity, errors.New("native measurement has no captured external or Tor runtime")
	}
	if !desktopMTURequestPattern.MatchString(identity.session) || !desktopMTUPathPattern.MatchString(identity.source) || !desktopMTUPathPattern.MatchString(identity.config) || identity.node == "" {
		return desktopMeasurementRuntime{}, errors.New("native measurement runtime identity is incomplete")
	}
	return identity, nil
}

func desktopMeasurementMTUSession(launch *desktopNodeLaunch) *desktopMTUSession {
	identity, err := capturedDesktopMeasurementRuntime(launch)
	if err != nil {
		return nil
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	return *identity.mtu
}

func desktopMeasurementSessionMatches(launch *desktopNodeLaunch, session string) bool {
	identity, err := capturedDesktopMeasurementRuntime(launch)
	return err == nil && identity.session == session
}

func (a *app) desktopMeasurementCurrentProof(launch *desktopNodeLaunch) error {
	if _, err := capturedDesktopMeasurementRuntime(launch); err != nil {
		return err
	}
	if launch.tor != nil {
		_, err := a.readDesktopTorProof(launch)
		if err != nil {
			if a.desktopTorMTUTransitionPending(launch) {
				return errDesktopTorMTUTransitionPending
			}
			// A fresh atomic proof can replace the transition's old base
			// between these reads. It must pass the full strict validator.
			_, err = a.readDesktopTorProof(launch)
		}
		return err
	}
	_, err := a.readDesktopExternalProof(launch)
	return err
}

func (a *app) waitDesktopMeasurementProof(ctx context.Context, launch *desktopNodeLaunch) error {
	if ctx == nil {
		return errors.New("native measurement proof requires a bounded operation context")
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := a.desktopMeasurementCurrentProof(launch)
		if !errors.Is(err, errDesktopTorMTUTransitionPending) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func desktopMeasurementViewIdentity(launch *desktopNodeLaunch) (mtuViewIdentity, error) {
	identity, err := capturedDesktopMeasurementRuntime(launch)
	if err != nil {
		return mtuViewIdentity{}, err
	}
	return mtuViewIdentity{Session: identity.session, Profile: identity.node, Native: true}, nil
}

func desktopMeasurementProcessDone(launch *desktopNodeLaunch) <-chan struct{} {
	if launch != nil && launch.external != nil {
		return desktopExternalProcessDone(launch)
	}
	return desktopNodeProcessDone(launch)
}

func desktopMeasurementProcessExited(launch *desktopNodeLaunch) bool {
	select {
	case <-desktopMeasurementProcessDone(launch):
		return true
	default:
		return false
	}
}

func desktopMeasurementNativeClosed(launch *desktopNodeLaunch) bool {
	if launch != nil && launch.tor != nil {
		return desktopDNSNativeClosed(launch)
	}
	return launch != nil && launch.external != nil && desktopPathNativeClosed(launch)
}

func (a *app) prepareDesktopMeasurementStop(launch *desktopNodeLaunch) error {
	if _, err := capturedDesktopMeasurementRuntime(launch); err != nil {
		return err
	}
	if launch.tor != nil {
		return prepareDesktopTorStop(a, launch.command)
	}
	return prepareDesktopExternalStop(a, launch.command)
}
