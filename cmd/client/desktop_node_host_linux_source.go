//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

// Both ordinary preparation and sealed restoration construct a fresh host
// here. The supplied source is already compiled and sealed; it is never a
// saved process, firewall receipt, path measurement or admission capability.
// The actual original parent and current request/profile/options are checked
// before registration and again after it. Partial registration remains owned
// by that parent so a cancelled caller cannot lose its cleanup responsibility.
func newDesktopLinuxNodeHostWithSource(ctx context.Context, parent *desktopLinuxNodeParentCapture,
	operation context.Context, profile common.RouterProfile, mode string, original *mobilemultihop.NodeProfile,
	endpoint, network string, savedOptions [3]bool, restoredMTU int) (*desktopLinuxNodeHost, error) {
	if ctx == nil || ctx.Err() != nil || parent == nil || parent.app == nil || parent.parent == nil ||
		operation == nil || operation.Err() != nil || original == nil || mode != "shadowsocks" ||
		profile.StartLayer != "" && profile.StartLayer != "off" || desktopOwnedNodeProtectionPolicy(profile) == "off" {
		return nil, errors.New("Linux source construction requires its original supported prepared graph")
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	policy, err := mobilemultihop.NewDesktopNodePolicyWithMTU(original, session, "linux", restoredMTU)
	if err != nil {
		return nil, err
	}
	physical, err := captureDesktopLinuxNodeRunningPath(policy)
	if err != nil {
		return nil, err
	}
	meta := policy.Metadata()
	selection := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	input, err := original.LaunchInput()
	if err != nil || selection.Validate() != nil || meta.ProfileID != profile.ID || meta.Mode != mode || meta.TargetOS != "linux" ||
		validateDesktopOwnedNodeSourceProfile(profile, endpoint, input) != nil {
		return nil, errors.Join(err, errors.New("Linux source construction substituted its sealed private graph"))
	}
	metadata, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	host := &desktopLinuxNodeHost{gate: make(chan struct{}, 1), parent: parent, operation: operation, policy: policy,
		monitor:   &atomic.Pointer[desktopLinuxNodeMonitor]{},
		selection: selection, source: []byte(input), network: network, revision: desktopOwnedNodeProfileToken(profile),
		options: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, savedOptions: savedOptions, physical: physical,
		launch: &desktopNodeLaunch{root: linuxOwnedControllerRoot, endpoint: endpoint, profileID: profile.ID, mode: mode,
			config: []byte(policy.Config()), metadata: metadata, configSHA256: meta.ConfigSHA256, mtuSession: session}}
	discard := func() {
		clear(host.source)
		clear(host.launch.config)
		clear(host.launch.metadata)
	}
	if err := host.current(ctx); err != nil {
		discard()
		return nil, err
	}
	p := parent.parent
	select {
	case <-ctx.Done():
		discard()
		return nil, ctx.Err()
	case <-p.gate:
	}
	if err := p.currentLocked(true); err != nil {
		p.gate <- struct{}{}
		discard()
		return nil, err
	}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.dependents[host] = struct{}{}
	p.gate <- struct{}{}
	host.gate <- struct{}{}
	if err := host.current(ctx); err != nil {
		return host, err
	}
	return host, nil
}
