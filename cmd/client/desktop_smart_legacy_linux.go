//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"syscall"

	"router-vpn/internal/common"
)

// A rejected preflight has not stopped the old helper. Retain its presentation
// only while the original process handle, operation, selection and policy are
// unchanged. This grants no native transfer, protection or new path authority;
// a legacy fixed guard must still pass the existing transition checks.
// The SMART transaction holds operationMu throughout capture and retention.
func (a *app) captureSmartLegacyPredecessor(operation context.Context, profile common.RouterProfile, mode string) (*desktopSmartLegacyCapture, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	command, previous := a.cmd, a.state
	if command == nil || !previous.Connected {
		return nil, nil
	}
	var wrapper *desktopNodeLaunch
	if _, external := desktopExternalRetainedLaunches.Load(a); external {
		return nil, errors.New("SMART predecessor has a retained external runtime")
	}
	if raw, registered := desktopNodeOwners.Load(a); registered {
		wrapper, _ = raw.(*desktopNodeLaunch)
		if wrapper == nil || wrapper.command != command ||
			wrapper.profileID != profile.ID || wrapper.mode != mode || wrapper.mtuSession == "" || wrapper.configSHA256 == "" ||
			wrapper.ownedNode != nil || wrapper.pairedNode != nil || wrapper.chain != nil || wrapper.candidatePrefix != nil ||
			wrapper.external != nil || wrapper.tor != nil || wrapper.importedEntry {
			return nil, errors.New("SMART predecessor has another native runtime owner")
		}
	}
	if _, standard := linuxStandardServiceOwners.Load(a); standard {
		return nil, errors.New("SMART legacy witness cannot adopt an installed standard service")
	}
	if err := a.checkCapturedConnectionOperationLocked(operation); err != nil {
		return nil, err
	}
	selected, exists := a.profileByIDLocked(profile.ID)
	if !exists || a.profiles.SelectedID != profile.ID || previous.RouterID != profile.ID ||
		previous.Phase != "connected" || mode == "" || previous.RuntimeMode != mode || previous.Mode != mode ||
		desktopOwnedNodeProfileToken(selected) != desktopOwnedNodeProfileToken(profile) || command.Process == nil {
		return nil, errors.New("SMART legacy predecessor has no unchanged proved source and command")
	}
	process := command.Process
	alive := func() error {
		err := desktopSmartLegacyProcessAlive(process)
		if errors.Is(err, os.ErrProcessDone) {
			a.state.Connected, a.state.Phase = false, "failed"
			a.state.LastError = "SMART predecessor process exited; disconnect before retrying."
		}
		return err
	}
	if err := alive(); err != nil {
		return nil, err
	}
	revision, err := a.candidateCatalogRevisionLocked()
	if err != nil {
		return nil, err
	}
	controller, protection := a.localController, a.nodeProtection
	return &desktopSmartLegacyCapture{wrapper: wrapper, currentLocked: func(phase string) error {
		if err := a.checkCapturedConnectionOperationLocked(operation); err != nil {
			return err
		}
		currentRevision, err := a.candidateCatalogRevisionLocked()
		expected := previous
		expected.Phase = phase
		current, registered := desktopNodeOwners.Load(a)
		sameOwner := !registered && wrapper == nil || registered && wrapper != nil && current == wrapper
		_, external := desktopExternalRetainedLaunches.Load(a)
		_, standard := linuxStandardServiceOwners.Load(a)
		if err != nil || !sameOwner || external || standard || phase == "" ||
			a.cmd != command || command.Process != process || a.state != expected ||
			a.localController != controller || a.nodeProtection != protection || currentRevision != revision {
			return errors.Join(err, errors.New("SMART legacy predecessor changed during candidate preflight"))
		}
		return alive()
	}}, nil
}

// Signal(0) also succeeds for an exited, unreaped child. Observe the original
// pidfd instead: readability means exit, without reaping it or reopening a PID.
// The configured Go toolchain supplies WithHandle; an older runtime or kernel
// without a retained process handle cannot authorize this retention shortcut.
func desktopSmartLegacyProcessAlive(process *os.Process) error {
	if process == nil {
		return errors.New("SMART predecessor has no original process handle")
	}
	handles, ok := any(process).(interface{ WithHandle(func(uintptr)) error })
	if !ok {
		return errors.New("SMART predecessor needs the configured process-handle toolchain")
	}
	observed := errors.New("SMART predecessor process handle was not observed")
	err := handles.WithHandle(func(handle uintptr) {
		if handle > 1<<31-1 {
			observed = errors.New("SMART predecessor process handle is out of range")
			return
		}
		fd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
		if err != nil {
			observed = err
			return
		}
		defer syscall.Close(fd)
		if err := syscall.EpollCtl(fd, syscall.EPOLL_CTL_ADD, int(handle), &syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(handle)}); err != nil {
			observed = err
			return
		}
		var events [1]syscall.EpollEvent
		n, err := syscall.EpollWait(fd, events[:], 0)
		if err != nil {
			observed = err
		} else if n != 0 {
			observed = os.ErrProcessDone
		} else {
			observed = nil
		}
	})
	return errors.Join(err, observed)
}
