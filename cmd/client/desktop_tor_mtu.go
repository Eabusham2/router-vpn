package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/mobiletor"
)

type desktopTorMTUAuthority struct {
	generation uint64
	request    string
}

func validDesktopTorMTUReadback(readback *mobiletor.DesktopBridgeMTUReadback) bool {
	if readback == nil || readback.Generation == 0 || !desktopMTURequestPattern.MatchString(readback.RequestID) ||
		readback.InterfaceName == "" || len(readback.InterfaceName) > 64 || readback.InterfaceIndex <= 0 || readback.EffectiveMTU < 1280 || readback.EffectiveMTU > 9000 {
		return false
	}
	for _, value := range readback.InterfaceName {
		if value <= 0x20 || value == 0x7f {
			return false
		}
	}
	return true
}

func sameDesktopTorMTUInterface(left, right *mobiletor.DesktopBridgeMTUReadback) bool {
	return left != nil && right != nil && left.InterfaceName == right.InterfaceName && left.InterfaceIndex == right.InterfaceIndex && left.EffectiveMTU == right.EffectiveMTU
}

// The caller holds owner.mu. Only a command issued to this exact connection
// can authorize a changed reader. The last accepted receipt remains valid
// while the next request is admitted; it cannot authorize another revision.
func desktopTorMTUReadbackAllowedLocked(owner *desktopTorRuntime, readback *mobiletor.DesktopBridgeMTUReadback, adopt bool) bool {
	if owner == nil || owner.adopted == nil || owner.mtu == nil || !validDesktopTorMTUReadback(readback) {
		return false
	}
	if expected := owner.expected.InterfaceName; expected != "" && readback.InterfaceName != expected {
		return false
	}
	previous := owner.mtuReadback
	if owner.mtuAuthority.generation != readback.Generation || owner.mtuAuthority.request != readback.RequestID {
		return previous != nil && *previous == *readback
	}
	if previous != nil {
		if readback.Revision < previous.Revision || readback.Revision == previous.Revision && !sameDesktopTorMTUInterface(readback, previous) {
			return false
		}
	} else if readback.Revision == 0 && (readback.InterfaceName != owner.adopted.InterfaceName || readback.InterfaceIndex != owner.adopted.InterfaceIndex || readback.EffectiveMTU != owner.adopted.EffectiveMTU) {
		return false
	}
	if adopt {
		captured := *readback
		owner.mtuReadback = &captured
	}
	return true
}

func desktopTorProofReadbackLocked(owner *desktopTorRuntime, proof desktopTorProof) bool {
	if proof.MTUReadback == nil {
		if owner.mtuReadback != nil || proof.EffectiveMTU != owner.expected.ConfiguredMTU {
			return false
		}
		adopted := owner.adopted
		return adopted == nil || proof.InterfaceName == adopted.InterfaceName && proof.InterfaceIndex == adopted.InterfaceIndex && proof.EffectiveMTU == adopted.EffectiveMTU
	}
	readback := proof.MTUReadback
	return readback.InterfaceName == proof.InterfaceName && readback.InterfaceIndex == proof.InterfaceIndex && readback.EffectiveMTU == proof.EffectiveMTU && desktopTorMTUReadbackAllowedLocked(owner, readback, true)
}

func authorizeDesktopTorMTURequest(launch *desktopNodeLaunch, request desktopMTURequest) error {
	bad := errors.New("Tor MTU request differs from its captured native operation")
	if launch == nil || launch.tor == nil || launch.external != nil || request.Generation == 0 || !desktopMTURequestPattern.MatchString(request.Request) {
		return bad
	}
	owner := launch.tor
	owner.mu.Lock()
	defer owner.mu.Unlock()
	expected := owner.expected
	if request.Schema != 1 || request.Session != expected.SessionID || request.SourceSHA256 != expected.SourceSHA256 || request.ConfigSHA256 != expected.ConfigSHA256 || owner.adopted == nil || owner.mtu == nil {
		return bad
	}
	previous := owner.mtuAuthority
	if request.Generation < previous.generation || request.Generation > previous.generation+1 || request.Generation == previous.generation && request.Request != previous.request {
		return bad
	}
	if request.Generation != previous.generation && owner.mtuReadback != nil {
		captured := *owner.mtuReadback
		owner.mtuPriorReadback = &captured
	}
	owner.mtuAuthority = desktopTorMTUAuthority{generation: request.Generation, request: request.Request}
	return nil
}

func validateDesktopTorMTURecord(launch *desktopNodeLaunch, record desktopMTURecord) error {
	bad := errors.New("native MTU readback belongs to another Tor operation or interface")
	if launch == nil {
		return bad
	}
	if launch.tor == nil {
		if record.MTUReadback != nil {
			return bad
		}
		return nil
	}
	owner := launch.tor
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if record.Generation == 0 {
		initial := owner.adopted
		status := record.Status
		if initial == nil || initial.MTUReadback != nil || initial.InterfaceIndex <= 0 || initial.InterfaceName == "" ||
			initial.EffectiveMTU != owner.expected.ConfiguredMTU || status.EffectiveMTU != initial.EffectiveMTU ||
			record.MTUReadback != nil || record.WaitingCommit || record.RestoredMTU != 0 || status.Request != "" ||
			status.Phase != "idle" || status.Source != "configured-unmeasured" || status.Running || status.Complete || status.Measured || status.Restored ||
			status.OriginalMTU != 0 || status.PathKey != "" || status.Failure != "" || len(status.Candidates) != 0 {
			return bad
		}
		// This snapshot can briefly lag the first operation's heartbeat. Its
		// value is always the adopted initial TUN, never new reader authority.
		return nil
	}
	readback := record.MTUReadback
	if !validDesktopTorMTUReadback(readback) || readback.Generation != record.Generation || readback.RequestID != record.Status.Request ||
		record.WaitingCommit && readback.EffectiveMTU != record.PreparedMTU || record.Status.Complete && readback.EffectiveMTU != record.Status.EffectiveMTU {
		return bad
	}
	if prior := owner.mtuPriorReadback; prior != nil && *readback == *prior {
		return nil // A separate atomic status write can lag the next heartbeat.
	}
	if owner.mtuAuthority.generation != readback.Generation || owner.mtuAuthority.request != readback.RequestID {
		return bad
	}
	// A status snapshot may precede a newer proof snapshot. It grants no
	// interface authority: every winner/rollback must match a fresh live proof
	// before adoption. Equal revisions must always name the same reader.
	if accepted := owner.mtuReadback; accepted != nil && readback.Revision < accepted.Revision {
		return nil
	}
	if !desktopTorMTUReadbackAllowedLocked(owner, readback, false) {
		return bad
	}
	return nil
}

// Restoration snapshots cannot turn an old status into current interface
// state. The caller holds the measurement suspension while capturing; require
// the status to agree with the connection's last accepted native proof.
func desktopTorMTUCaptureCurrent(launch *desktopNodeLaunch, record desktopMTURecord) bool {
	if launch == nil || launch.tor == nil {
		return true
	}
	owner := launch.tor
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if record.MTUReadback == nil {
		return record.Generation == 0 && owner.adopted != nil && owner.mtuAuthority.generation == 0 && owner.mtuReadback == nil &&
			record.Status.EffectiveMTU == owner.adopted.EffectiveMTU && record.Status.EffectiveMTU == owner.expected.ConfiguredMTU
	}
	return owner.mtuReadback != nil && *record.MTUReadback == *owner.mtuReadback && record.Status.EffectiveMTU == owner.mtuReadback.EffectiveMTU
}

// The terminal/selected interface receipt must also appear in the live proof.
// An independently written status file cannot substitute for the retained TUN.
func (a *app) waitDesktopTorMTUReadback(parent context.Context, launch *desktopNodeLaunch, record desktopMTURecord) error {
	if launch == nil || launch.tor == nil {
		return nil
	}
	if err := validateDesktopTorMTURecord(launch, record); err != nil {
		return err
	}
	if record.MTUReadback == nil && record.Generation != 0 {
		return errors.New("Tor MTU result has no captured interface readback")
	}
	// The connection-owned native control/readback can use five seconds;
	// allow its atomic proof publication to follow without accepting status
	// alone as proof. The caller's earlier cancellation still takes precedence.
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		proof, err := a.readDesktopTorProof(launch)
		if err != nil {
			if a.desktopTorMTUTransitionPending(launch) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-tick.C:
					continue
				}
			}
			// Completion can replace the historical transition base after
			// the first read; retry once under the unchanged strict rules.
			proof, err = a.readDesktopTorProof(launch)
			if err != nil {
				return err
			}
		}
		if record.Generation == 0 {
			if proof.MTUReadback == nil && proof.EffectiveMTU == record.Status.EffectiveMTU {
				return nil
			}
			return errors.New("initial Tor MTU status no longer names the live native reader")
		}
		if proof.MTUReadback != nil && *proof.MTUReadback == *record.MTUReadback {
			return nil
		}
		if proof.MTUReadback != nil && proof.MTUReadback.Revision > record.MTUReadback.Revision {
			return errors.New("Tor MTU result was replaced by a later native reader")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
