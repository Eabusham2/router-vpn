//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// The Linux host retains the actual installed controller and sealed private
// profile before stopping an existing connection. Neither staging nor argv
// construction is permission to launch, create protection or report Connected.
// The generated child and the original transaction must establish those facts.
type desktopLinuxNodeHost struct {
	gate                      chan struct{}
	parent                    *desktopLinuxNodeParentCapture
	operation                 context.Context
	policy                    *mobilemultihop.DesktopNodePolicy
	external                  *mobilemultihop.DesktopExternalPolicy
	externalProof             *desktopLinuxExternalProof
	externalPersistedRevision string
	externalEntryRevision     string
	externalEntryOptions      [3]bool
	selection                 linuxprotection.NodeSelection
	launch                    *desktopNodeLaunch
	process                   *desktopLinuxNodeProcess
	standardTransfer          *linuxStandardServiceNodeTransfer
	transaction               *desktopLinuxNodeTransaction
	source                    []byte
	network                   string
	revision                  string
	options                   [3]bool
	savedOptions              [3]bool
	physical                  mobiletor.DesktopLinuxNodeRunningSelection
	ready                     *mobilemultihop.DesktopNodeReadyRecord
	proof                     *desktopLinuxNodeProof
	activation                *desktopLinuxNodeActivation
	monitor                   *atomic.Pointer[desktopLinuxNodeMonitor] // Immutable holder, allocated before host publication.
	mtu                       *desktopLinuxNodeMTUOwner
	stageEntered              bool
	startEntered              bool
	started                   time.Time
	staged                    bool
	closing                   bool
	closed                    bool
	released                  bool
}

func prepareDesktopLinuxNodeHost(operation context.Context, a *app, profile common.RouterProfile, mode string, restoredMTU int) (*desktopLinuxNodeHost, error) {
	return prepareDesktopLinuxNodeHostWith(operation, a, profile, mode, restoredMTU, verifyBundledNativeContext,
		func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		})
}

// Tests can model package build metadata and DNS lookup only. Controller,
// installation, private source, operation and native namespace captures are
// the same shipping owners. There is no environment or request override.
func prepareDesktopLinuxNodeHostWith(operation context.Context, a *app, profile common.RouterProfile, mode string, restoredMTU int,
	verify func(context.Context, string) (string, error), lookup applexray.Lookup) (*desktopLinuxNodeHost, error) {
	if operation == nil || operation.Err() != nil || a == nil || verify == nil ||
		!mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(mode, profile.StartLayer) || desktopOwnedNodeProtectionPolicy(profile) == "off" {
		return nil, errors.New("Linux Node host requires its captured supported protected graph")
	}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(operation, 30*time.Second)
	stopParent := context.AfterFunc(parent.lifetime, cancel)
	defer func() { stopParent(); cancel() }()
	network := physicalNetworkIdentity()
	revision := desktopOwnedNodeProfileToken(profile)
	options := [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}
	a.mu.Lock()
	saved, exists := a.profileByIDLocked(profile.ID)
	savedOptions := [3]bool{saved.DAITAEnabled, saved.JumboTUN, saved.SocksEnabled}
	selectedOptions := [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks}
	a.mu.Unlock()
	if !exists || desktopOwnedNodeProfileToken(saved) != revision || selectedOptions != options {
		return nil, errors.New("Linux Node preparation changed its saved profile or selected runtime options")
	}
	current := func() error {
		if ctx.Err() != nil || network == "" || physicalNetworkIdentity() != network {
			return errors.Join(ctx.Err(), errors.New("Linux Node preparation lost its captured physical network"))
		}
		if err := parent.Current(ctx); err != nil {
			return err
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		actual, exists := a.profileByIDLocked(profile.ID)
		if a.checkCapturedConnectionOperationLocked(operation) != nil || a.connectionCancelIntent == operation || !exists ||
			desktopOwnedNodeProfileToken(actual) != revision || [3]bool{actual.DAITAEnabled, actual.JumboTUN, actual.SocksEnabled} != savedOptions ||
			[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != options {
			return errors.New("Linux Node preparation changed its original request or complete private profile")
		}
		return nil
	}
	if err := current(); err != nil {
		return nil, err
	}
	image, err := verify(ctx, linuxOwnedControllerRoot)
	if err != nil || filepath.Clean(image) != filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()) {
		return nil, errors.Join(err, errors.New("Linux Node preparation verified another installed runtime"))
	}
	if err := current(); err != nil {
		return nil, err
	}
	files, err := readDesktopNodeAssets(linuxOwnedControllerRoot, profile.ID, mode)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	start, err := readDesktopNodeStartAssets(linuxOwnedControllerRoot, profile, mode)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, body := range start {
			clear(body)
		}
	}()
	compile, stopCompile := context.WithTimeout(ctx, 10*time.Second)
	defer stopCompile()
	original, endpoint, err := compileDesktopNode(compile, profile, mode, files, start, lookup)
	if err != nil {
		return nil, err
	}
	if err := current(); err != nil {
		return nil, err
	}
	return newDesktopLinuxNodeHostWithSource(ctx, parent, operation, profile, mode, original, endpoint, network, savedOptions, restoredMTU)
}

func (h *desktopLinuxNodeHost) enter(ctx context.Context) error {
	if h == nil || ctx == nil || ctx.Err() != nil || h.gate == nil {
		return errors.New("Linux Node host has no bounded original caller")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.gate:
		if ctx.Err() != nil {
			h.gate <- struct{}{}
			return ctx.Err()
		}
		return nil
	}
}

func (h *desktopLinuxNodeHost) current(ctx context.Context) error {
	if h != nil && h.external != nil {
		return h.currentExternal(ctx)
	}
	if h == nil || ctx == nil || ctx.Err() != nil || h.operation == nil || h.closing || h.closed ||
		h.parent == nil || h.policy == nil || h.policy.Validate() != nil || h.launch == nil || h.network == "" || physicalNetworkIdentity() != h.network {
		return errors.New("Linux Node host no longer owns its captured operation and policy")
	}
	if h.activation == nil {
		if h.operation.Err() != nil {
			return errors.New("Linux Node host lost its original live startup request")
		}
	} else if err := h.activation.matches(h); err != nil {
		return err
	}
	if err := h.parent.Current(ctx); err != nil {
		return err
	}
	meta := h.policy.Metadata()
	wanted := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	if meta.TargetOS != "linux" || h.selection != wanted || h.launch.root != linuxOwnedControllerRoot ||
		h.launch.profileID != meta.ProfileID || h.launch.mode != meta.Mode || h.launch.mtuSession != meta.SessionID || h.launch.configSHA256 != meta.ConfigSHA256 {
		return errors.New("Linux Node host changed its original sealed command")
	}
	a := h.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(meta.ProfileID)
	if !exists || desktopOwnedNodeProfileToken(profile) != h.revision ||
		[3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled} != h.savedOptions ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != h.options {
		return errors.New("Linux Node host belongs to a replaced request or private node")
	}
	if h.activation == nil {
		if a.checkCapturedConnectionOperationLocked(h.operation) != nil || a.connectionCancelIntent == h.operation {
			return errConnectionOperationCancelled
		}
	} else if a.cmd != h.process.command || a.state.RouterID != meta.ProfileID || a.state.RuntimeMode != meta.Mode ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != h.options {
		return errors.New("Linux active Node host belongs to another original connection")
	}
	return nil
}

func (h *desktopLinuxNodeHost) Stage(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.current(ctx); err != nil {
		return err
	}
	if h.stageEntered || h.staged || h.launch.directory != "" {
		return errors.New("Linux Node staging cannot reuse an entered workspace")
	}
	h.stageEntered = true
	directory, err := newPrivateRuntimeDir(linuxOwnedControllerRoot, "native-node")
	if err != nil {
		return err
	}
	if err := captureDesktopRuntimeDirectory(h.launch, directory); err != nil {
		return err
	}
	for _, input := range h.privateInputs() {
		if err := h.current(ctx); err != nil {
			return err
		}
		if err := writeDesktopRuntimeFile(h.launch, input.name, input.body, false); err != nil {
			return err
		}
	}
	if err := h.current(ctx); err != nil {
		return err
	}
	h.staged = true
	return nil
}

// No private credential, resolver, target selector or caller-provided handle is
// encoded in argv. The existing launcher adds only its actual inherited owners.
func (h *desktopLinuxNodeHost) Arguments(ctx context.Context) ([]string, string, error) {
	if err := h.enter(ctx); err != nil {
		return nil, "", err
	}
	defer func() { h.gate <- struct{}{} }()
	return h.argumentsLocked(ctx)
}

func (h *desktopLinuxNodeHost) argumentsLocked(ctx context.Context) ([]string, string, error) {
	if err := h.current(ctx); err != nil {
		return nil, "", err
	}
	if !h.staged {
		return nil, "", errors.New("Linux Node command preceded complete private staging")
	}
	for _, input := range h.privateInputs() {
		actual, err := readDesktopRuntimeFile(h.launch, input.name, int64(len(input.body)))
		matches := err == nil && bytes.Equal(actual, input.body)
		clear(actual)
		if !matches {
			return nil, "", errors.Join(err, errors.New("Linux Node command changed a captured private input"))
		}
	}
	control, err := h.selection.ControlSHA256()
	if err != nil {
		return nil, "", err
	}
	capture, err := h.selection.CaptureSHA256()
	if err != nil {
		return nil, "", err
	}
	command := "routervpn-node"
	if h.external != nil {
		command = "routervpn-external"
	}
	arguments := []string{command, "--runtime-dir", h.launch.directory, "--session", h.selection.SessionID,
		"--config-sha256", h.selection.ConfigSHA256, "--physical-source-sha256", h.selection.SourceSHA256, "--physical-transfer-sha256", control}
	if h.policy != nil && h.policy.Metadata().RestoredMTU != 0 {
		arguments = append(arguments, "--physical-mtu", strconv.Itoa(h.policy.Metadata().RestoredMTU))
	}
	arguments, err = validateDesktopLinuxProtectedArguments(arguments, h.launch.directory)
	if err != nil {
		return nil, "", err
	}
	return arguments, capture, h.current(ctx)
}

// Retirement joins the original launched transaction before touching private
// inputs. A retained closed predecessor remains with that transaction; it is
// not released by workspace cleanup. Replaced paths are always refused.
func (h *desktopLinuxNodeHost) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if err := h.stopMonitorBeforeRetirement(ctx); err != nil {
		return err
	}
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.closed && h.released {
		return nil
	}
	h.closing = true
	if err := h.retireLocked(ctx, false); err != nil {
		return err
	}
	if !h.closed {
		if h.external != nil && h.launch != nil {
			desktopExternalRetainedLaunches.CompareAndDelete(h.parent.app, h.launch)
		}
		if err := cleanupDesktopNodeLaunch(h.launch); err != nil {
			return err
		}
		clear(h.source)
		if h.launch != nil {
			clear(h.launch.config)
			clear(h.launch.metadata)
			h.launch.config, h.launch.metadata = nil, nil
		}
		h.source, h.policy, h.external = nil, nil, nil
		h.closed = true
	}
	if !h.released {
		if err := h.parent.parent.releaseDependent(ctx, h); err != nil {
			return err
		}
		h.released = true
	}
	return nil
}

// The installed controller retains this host through the real child, selected
// DNS/TUN proof and its separate Router authentication or external-exit proof.
var _ ownedDesktopNodeParent = (*desktopLinuxNodeHost)(nil)
