//go:build darwin

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"sync"
	"time"
)

type desktopMacOSPairedNodeSavedSource struct {
	mu                                           sync.Mutex
	parent                                       *desktopMacOSSessionCapture
	original                                     *desktopMacOSPairedNodeHost
	source                                       []byte
	digest                                       [32]byte
	sourceSHA, endpoint, mode, network, revision string
	options, savedOptions                        [3]bool
	mtu                                          int
	entered, cleared                             bool
	restored                                     *desktopMacOSPairedNodeHost
}

func (h *desktopMacOSPairedNodeHost) CaptureRestore(ctx context.Context, profile common.RouterProfile) (desktopMacOSPairedNodeRestore, error) {
	if err := h.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { h.gate <- struct{}{} }()
	if !h.activated || !h.proved || desktopOwnedNodeProfileToken(profile) != h.revision || h.mtu != nil {
		return nil, errors.New("macOS Router restore has no original proved idle source")
	}
	_, live, err := h.readReadyLocked(ctx, false)
	if err != nil {
		return nil, err
	}
	if live.Active || live.Failure != "" {
		return nil, errors.New("macOS Router restore conflicts with original native MTU lease")
	}
	saved := &desktopMacOSPairedNodeSavedSource{parent: h.parent, original: h, source: append([]byte(nil), h.source...), sourceSHA: h.policy.OriginalProfile().SourceSHA256(), endpoint: h.launch.endpoint, mode: h.launch.mode, network: h.network, revision: h.revision, options: h.options, savedOptions: h.savedOptions, mtu: live.MTU}
	saved.digest = sha256.Sum256(saved.source)
	if _, _, err := saved.compiled(profile); err != nil {
		clear(saved.source)
		return nil, err
	}
	return saved, nil
}
func (saved *desktopMacOSPairedNodeSavedSource) compiled(profile common.RouterProfile) (*mobilemultihop.NodeProfile, common.RouterProfile, error) {
	if saved == nil || saved.cleared || len(saved.source) == 0 || len(saved.source) > mobilemultihop.NodeLaunchInputLimit || sha256.Sum256(saved.source) != saved.digest || desktopOwnedNodeProfileToken(profile) != saved.revision || [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != saved.savedOptions || saved.mtu < 1280 || saved.mtu > 9000 {
		return nil, common.RouterProfile{}, errors.New("macOS Router restore changed its original sealed source")
	}
	profile = cloneRouterProfile(profile)
	profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled = saved.options[0], saved.options[1], saved.options[2]
	original, err := mobilemultihop.ParseNodeLaunchInput(string(saved.source))
	if err != nil || original == nil || original.SourceSHA256() != saved.sourceSHA || validateDesktopOwnedNodeSourceProfile(profile, saved.endpoint, string(saved.source)) != nil {
		return nil, common.RouterProfile{}, errors.Join(err, errors.New("macOS Router restore substituted another paired graph"))
	}
	if _, err := mobilemultihop.NewDesktopNodePolicyWithMTU(original, "00000000000000000000000000000000", "darwin", saved.mtu); err != nil {
		return nil, common.RouterProfile{}, err
	}
	return original, profile, nil
}
func (saved *desktopMacOSPairedNodeSavedSource) clear() {
	if saved == nil {
		return
	}
	saved.mu.Lock()
	defer saved.mu.Unlock()
	clear(saved.source)
	saved.source = nil
	saved.cleared = true
}
func (saved *desktopMacOSPairedNodeSavedSource) restart(ctx context.Context, a *app, profile common.RouterProfile) (failure error) {
	if saved == nil || ctx == nil || a == nil {
		return errors.New("macOS Router restoration lost its bounded original caller")
	}
	saved.mu.Lock()
	defer saved.mu.Unlock()
	if saved.entered || saved.parent == nil || saved.parent.app != a || saved.original == nil || saved.original.parent != saved.parent {
		return errors.New("macOS Router restoration cannot replace its original retained parent")
	}
	original, profile, err := saved.compiled(profile)
	if err != nil {
		return err
	}
	if err := saved.parent.Current(ctx); err != nil {
		return err
	}
	network, err := physicalNetworkIdentityContext(ctx)
	if err != nil || network != saved.network {
		return errors.Join(err, errors.New("macOS Router restore changed its original physical network"))
	}
	if err := saved.original.enter(ctx); err != nil {
		return err
	}
	retired := saved.original.closed && saved.original.nativeRetired && saved.original.workspaceRetired
	saved.original.gate <- struct{}{}
	if !retired {
		return errors.New("macOS Router restoration preceded original native retirement")
	}
	operation := a.connectionOperationContextOrBackground()
	if err := a.checkCapturedConnectionOperation(operation); err != nil {
		return err
	}
	a.mu.Lock()
	current, exists := a.profileByIDLocked(profile.ID)
	beforeCommand, beforeState, beforeSelected := a.cmd, a.state, a.profiles.SelectedID
	valid := exists && desktopOwnedNodeProfileToken(current) == saved.revision && [3]bool{current.DAITAEnabled, current.JumboTUN, current.SocksEnabled} == saved.savedOptions && [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} == saved.options && a.cmd == nil && !a.state.Connected && a.profiles.SelectedID == profile.ID
	a.mu.Unlock()
	if !valid {
		return errors.New("macOS Router restore changed its saved source, selection or command")
	}
	saved.entered = true
	h, err := newDesktopMacOSPairedNodeHost(ctx, saved.parent, operation, profile, saved.mode, original, saved.endpoint, saved.network, saved.savedOptions, saved.mtu)
	saved.restored = h
	if h != nil {
		h.beforeCommand, h.beforeState, h.beforeSelected = beforeCommand, beforeState, beforeSelected
		defer func() {
			if failure != nil {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
				defer cancel()
				failure = errors.Join(failure, h.closeWithIntent(cleanup, true))
			}
		}()
	}
	if err != nil {
		return err
	}
	if err := h.Stage(ctx); err != nil {
		return err
	}
	if err := h.Start(ctx); err != nil {
		return err
	}
	if err := a.speedLabOwnRuntime(h.launch.command); err != nil {
		return err
	}
	ready, cancel := context.WithTimeout(ctx, 25*time.Second)
	err = h.WaitReady(ready)
	cancel()
	if err != nil {
		return err
	}
	if _, err := h.Prove(ctx); err != nil {
		return err
	}
	if err := h.Activate(ctx); err != nil {
		return err
	}
	return h.Monitor(ctx)
}
