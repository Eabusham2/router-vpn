//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/standardengine"
)

// The authenticated service copies these exact original bytes. Neither the
// controller nor the service reconstructs a routing receipt from a snapshot.
type linuxStandardServiceStartup struct {
	Capture []byte `json:"capture"`
	Ready   []byte `json:"ready"`
}

type linuxStandardRequestEpoch struct {
	owner                       *linuxLegacyStandardExitOwner
	observer                    linuxStandardStartupObserver
	lifetime                    context.Context
	cancel                      context.CancelFunc
	failure                     error
	bound, begun, ready, closed bool
	dns                         *legacyStandardDNS
	launch                      *desktopNodeLaunch
	source, sealed, namespace   *os.File
	session, digest, mode       string
	namespaceInfo               os.FileInfo
	profileDigest               string
	shape                       standardengine.TUN
	startup                     *linuxStandardServiceStartup
}

func openLinuxStandardRequestObserver(operation, lifetime context.Context) (linuxStandardStartupObserver, error) {
	return desktopnetwork.OpenWithLifetime(operation, lifetime, nil)
}

// The caller pins its original namespace thread. Retain the partial observer
// before inspecting workspace/configuration sources or TUN absence.
func (o *linuxLegacyStandardExitOwner) openRequestEpoch(ctx context.Context, open func(context.Context, context.Context) (linuxStandardStartupObserver, error)) error {
	if o.requestEpoch != nil || open == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("standard controller epoch lost original preparation")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	n := &linuxStandardRequestEpoch{owner: o, namespace: o.namespace, namespaceInfo: o.namespaceInfo, lifetime: lifetime, cancel: cancel}
	o.requestEpoch = n
	n.observer, n.failure = open(ctx, lifetime)
	if n.failure == nil && n.observer == nil {
		n.failure = errors.New("standard controller preparation omitted original network observer")
	}
	return n.failure
}

func (n *linuxStandardRequestEpoch) fail(err error) error {
	if n == nil {
		return err
	}
	if n.failure == nil && err != nil {
		n.failure = err
	}
	return n.failure
}

func (n *linuxStandardRequestEpoch) bind(ctx context.Context, profileDigest string) error {
	if n == nil || n.owner == nil || n.bound || n.closed || n.failure != nil {
		return errors.New("standard controller epoch cannot bind another preparation")
	}
	o := n.owner
	n.dns, n.launch, n.source, n.sealed = o.dns, o.launch, o.sourceConfig, o.config
	n.session, n.digest, n.mode = o.session, o.digest, o.runtimeMode
	n.profileDigest = profileDigest
	raw, err := standardengine.ReadSealed(n.sealed, standardengine.MaxConfig)
	if err == nil {
		n.shape, err = standardengine.Config(raw, n.mode)
	}
	if err != nil {
		return n.fail(err)
	}
	n.bound = true
	return n.current(ctx, false)
}

// Caller holds the original launch lock. This remains a source and namespace
// check even while Begin is retaining startup events for the eventual ledger.
func (n *linuxStandardRequestEpoch) namespaceCurrent() error {
	if n.owner.namespace != n.namespace || n.namespace == nil || n.namespaceInfo == nil || !os.SameFile(n.namespaceInfo, n.owner.namespaceInfo) {
		return errors.New("standard controller lost its original namespace capability")
	}
	actual, err := n.namespace.Stat()
	if err != nil || !os.SameFile(actual, n.namespaceInfo) {
		return errors.New("standard controller original namespace descriptor changed")
	}
	return n.owner.namespaceCurrent()
}

func (n *linuxStandardRequestEpoch) sources(ctx context.Context) error {
	if n == nil || n.owner == nil || ctx == nil || ctx.Err() != nil || !n.bound || n.closed || n.lifetime.Err() != nil || n.observer == nil {
		return errors.New("standard controller lost its original network epoch")
	}
	o := n.owner
	if o.requestEpoch != n || o.namespace != n.namespace || o.dns != n.dns || o.launch != n.launch || o.sourceConfig != n.source || o.config != n.sealed ||
		o.session != n.session || o.digest != n.digest || o.runtimeMode != n.mode || n.dns == nil || n.source == nil || n.sealed == nil || n.dns.source != n.source || n.dns.sealed != n.sealed {
		return errors.New("standard controller epoch changed its original source capability")
	}
	if err := n.namespaceCurrent(); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(n.launch); err != nil {
		return err
	}
	opened, err := n.source.Stat()
	named, namedErr := n.launch.directoryRoot.Lstat("sing-box.json")
	if err != nil || namedErr != nil || !named.Mode().IsRegular() || !os.SameFile(opened, named) {
		return errors.New("standard controller configuration source was replaced")
	}
	raw, err := readDesktopRuntimeFile(n.launch, "sing-box.json", standardengine.MaxConfig)
	if err != nil || standardengine.SHA256(raw) != n.digest {
		return errors.New("standard controller configuration changed after original capture")
	}
	sealed, err := standardengine.ReadSealed(n.sealed, standardengine.MaxConfig)
	if err != nil || standardengine.SHA256(sealed) != n.digest {
		return errors.New("standard controller lost its original sealed configuration")
	}
	o.app.mu.Lock()
	profile, found := o.app.profileByIDLocked(n.dns.profileID)
	o.app.mu.Unlock()
	digest, digestErr := linuxStandardProfileDigest(profile)
	if !found || digestErr != nil || digest != n.profileDigest || asyncMeasurementProfileToken(profile) != n.dns.profileToken {
		return errors.New("standard controller source policy changed after original capture")
	}
	return n.namespaceCurrent()
}

func (n *linuxStandardRequestEpoch) current(ctx context.Context, ready bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.sources(ctx); err != nil {
		return n.fail(err)
	}
	if n.failure != nil {
		return n.failure
	}
	if ready && !n.ready || n.begun && !n.ready {
		return errors.New("standard controller has no completed original startup epoch")
	}
	if err := n.observer.CurrentContext(ctx); err != nil {
		return n.fail(err)
	}
	return n.fail(n.sources(ctx))
}

func (n *linuxStandardRequestEpoch) begin(ctx context.Context) error {
	if n == nil || n.begun || n.ready {
		return errors.New("standard controller startup transition was reused")
	}
	if err := n.current(ctx, false); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.sources(ctx); err != nil {
		return n.fail(err)
	}
	if err := n.observer.Begin(ctx, nil); err != nil {
		return n.fail(err)
	}
	n.begun = true
	return nil
}

func (n *linuxStandardRequestEpoch) admit(ctx context.Context, startup *linuxStandardServiceStartup, transmittedDeadline int64) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if n == nil || !n.begun || n.ready || startup == nil || transmittedDeadline < 1 {
		return errors.New("standard controller has no original child startup response")
	}
	if err := n.sources(ctx); err != nil {
		return n.fail(err)
	}
	if n.failure != nil {
		return n.failure
	}
	captureSHA := standardengine.SHA256(startup.Capture)
	capture, err := standardengine.DecodeCapture(startup.Capture, captureSHA)
	if err != nil || capture.Session != n.session || capture.ConfigSHA256 != n.digest || capture.Mode != n.mode || capture.DeadlineNS > transmittedDeadline || capture.DeadlineNS <= time.Now().UnixNano() {
		return n.fail(errors.New("standard controller received another source or deadline's startup capture"))
	}
	if deadline, ok := ctx.Deadline(); ok && capture.DeadlineNS > deadline.UnixNano() {
		return n.fail(errors.New("standard controller child capture renewed its original deadline"))
	}
	ready, err := standardengine.DecodeReady(startup.Ready, captureSHA)
	if err != nil {
		return n.fail(err)
	}
	receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(ready.NetworkReceipt)
	if err != nil || receipt.TargetOS != "linux" || receipt.Name != n.shape.Name || receipt.MTU != n.shape.MTU {
		return n.fail(errors.New("standard controller startup ledger changed original native TUN policy"))
	}
	if err := n.observer.Record(receipt); err != nil {
		return n.fail(err)
	}
	if err := n.observer.End(ctx, &receipt); err != nil {
		return n.fail(err)
	}
	n.ready = true
	n.startup = &linuxStandardServiceStartup{Capture: append([]byte(nil), startup.Capture...), Ready: append([]byte(nil), startup.Ready...)}
	return n.current(ctx, true)
}

// Join the original stream before asking the service to generate teardown
// effects. A failed native join remains attached to this exact retry owner.
func (n *linuxStandardRequestEpoch) close(ctx context.Context) error {
	if n == nil || n.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || n.owner == nil || n.owner.requestEpoch != n || n.owner.namespace != n.namespace {
		return errors.New("standard controller epoch cleanup lost its original owner or budget")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := n.namespaceCurrent(); err != nil {
		return err
	}
	if n.observer != nil {
		_ = n.observer.CurrentContext(ctx)
		if err := n.observer.Close(); err != nil {
			return err
		}
	}
	n.cancel()
	n.closed = true
	return ctx.Err()
}

// Caller holds the same gate which admitted the original Start. Only the
// original service/child/bootstrap and successful native epoch can supply this.
func (s *linuxStandardService) startupResponse(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest) (*linuxStandardServiceStartup, error) {
	session := s.session
	if session == nil || peer == nil || session.peer == nil || session.peer != peer && session.peer.record != peer.record || session.request.Session != request.Session || session.joined || session.cleanupPending || session.owner == nil {
		return nil, errors.New("standard startup response lost its original service session")
	}
	o := session.owner
	n := o.native
	if n == nil || n.owner != o || !n.ready || n.closed || !n.adopted || n.capture == nil || len(n.readyBody) == 0 || o.session != request.Session || o.digest != request.ConfigSHA256 || o.runtimeMode != request.RuntimeMode || session.network == nil || session.network.observer != n.tracker {
		return nil, errors.New("standard startup response has no original successful child ledger")
	}
	finish := s.operation(ctx)
	defer finish()
	if err := peer.Current(ctx); err != nil {
		return nil, err
	}
	if err := o.Current(ctx); err != nil {
		return nil, err
	}
	if err := s.networkCurrent(ctx, session, true); err != nil {
		return nil, err
	}
	capture, err := standardengine.ReadSealed(n.capture, 2048)
	if err != nil || standardengine.SHA256(capture) != n.captureSHA {
		return nil, errors.New("standard startup response lost original sealed capture")
	}
	if _, err := standardengine.DecodeReady(n.readyBody, n.captureSHA); err != nil {
		return nil, err
	}
	if err := n.current(ctx); err != nil {
		return nil, err
	}
	if err := peer.Current(ctx); err != nil {
		return nil, err
	}
	return &linuxStandardServiceStartup{Capture: capture, Ready: append([]byte(nil), n.readyBody...)}, ctx.Err()
}
