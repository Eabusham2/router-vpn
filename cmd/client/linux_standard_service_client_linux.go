//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
)

var linuxStandardServiceOwners sync.Map // map[*app]*linuxStandardServiceLaunch

type linuxStandardServiceLaunch struct {
	exchange                                    func(context.Context, linuxStandardServiceRequest, *os.File, func()) (linuxStandardServiceResponse, error) // explicit native test channel; nil uses fixed installed RPC
	mu                                          sync.Mutex
	app                                         *app
	prepared                                    *linuxLegacyStandardExitOwner
	request                                     linuxStandardServiceRequest
	image                                       os.FileInfo
	peer                                        *linuxStandardServicePeer
	registered, attempted, joined, copiesClosed bool
	dnsProved                                   bool
	mtuExit                                     *standardExit
	mtuExitRaw                                  string
	mtuOwner                                    *linuxStandardServiceMTUOwner
}

func prepareLinuxStandardServiceLaunch(a *app, local *linuxLegacyStandardExitOwner) (legacyStandardExitLaunch, error) {
	if a.localController == nil {
		return local, nil
	}
	if local == nil || local.protectionRoot != linuxOwnedControllerRoot {
		return nil, errors.New("standard service requires the original installed runtime")
	}
	image, err := os.Stat("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(local.protectionProfileID)
	a.mu.Unlock()
	digest, err := linuxStandardProfileDigest(profile)
	if err != nil || !ok || local.requestEpoch == nil || digest != local.requestEpoch.profileDigest {
		return nil, errors.Join(err, errors.New("standard service lost the original selected profile"))
	}
	request := linuxStandardServiceRequest{Schema: 1, Action: "start", Session: local.session,
		Directory: local.launch.directory, ConfigSHA256: local.digest, ProfileID: local.protectionProfileID, ProfileSHA256: digest,
		Endpoint: local.protectionEndpoint, RuntimeMode: local.runtimeMode, Base: local.base, RouterID: local.routerID, NetworkID: local.dns.networkID}
	return &linuxStandardServiceLaunch{app: a, prepared: local, request: request, image: image}, nil
}

// Capture the exact exit that compiled the original native graph, before start.
func (o *linuxStandardServiceLaunch) CaptureMTUExit(exit standardExit) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.attempted || o.mtuExit != nil || o.prepared == nil || o.prepared.routerID != "standard:"+exit.ID || o.prepared.runtimeMode != "standard-"+exit.Protocol {
		return errors.New("standard MTU exit does not belong to original launch")
	}
	raw, err := json.Marshal(exit)
	if err != nil {
		return err
	}
	var frozen standardExit
	if err := json.Unmarshal(raw, &frozen); err != nil {
		return err
	}
	o.mtuExit, o.mtuExitRaw = &frozen, string(raw)
	return nil
}

// Command is only the original launch request identity in the controller.
// Its Process remains nil: the service creates and joins the actual engine,
// and this retained adapter supplies every process/protection lifecycle check.
func (o *linuxStandardServiceLaunch) Command() *exec.Cmd { return o.prepared.command }

func (o *linuxStandardServiceLaunch) currentIntent(operation context.Context, command *exec.Cmd) error {
	o.app.mu.Lock()
	defer o.app.mu.Unlock()
	return o.currentIntentLocked(operation, command)
}

// The observer budget and the exact connection-operation identity are distinct.
// Stop may legitimately retain a nil operation after Connect has completed.
func (o *linuxStandardServiceLaunch) currentIntentContext(ctx, operation context.Context, command *exec.Cmd) error {
	if err := desktopnetwork.LockContext(ctx, &o.app.mu); err != nil {
		return err
	}
	defer o.app.mu.Unlock()
	return errors.Join(o.currentIntentLocked(operation, command), ctx.Err())
}
func (o *linuxStandardServiceLaunch) currentIntentLocked(operation context.Context, command *exec.Cmd) error {
	actual, ok := linuxStandardServiceOwners.Load(o.app)
	if !ok || actual != o || o.app.cmd != command || (command != nil && command != o.Command()) || o.app.connectionContext != operation {
		return errors.New("standard service request belongs to a replaced controller operation")
	}
	return nil
}

func (o *linuxStandardServiceLaunch) call(ctx context.Context, request linuxStandardServiceRequest, directory *os.File) error {
	if request.Action != "start" && request.Action != "stop" {
		if err := o.prepared.requestEpoch.current(ctx, true); err != nil {
			return err
		}
	}
	exchange := o.exchange
	if exchange == nil {
		exchange = func(ctx context.Context, request linuxStandardServiceRequest, directory *os.File, beforeWrite func()) (linuxStandardServiceResponse, error) {
			return linuxStandardServiceRPC(ctx, o.image, o.prepared.namespaceInfo, &o.peer, request, directory, beforeWrite)
		}
	}
	response, err := exchange(ctx, request, directory, func() {
		if request.Action == "start" {
			o.attempted = true
		}
	})
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if response.authenticatedPeer == nil || response.authenticatedPeer != o.peer {
		return errors.New("standard service completion lost its original authenticated peer")
	}
	if err := o.peer.Current(ctx); err != nil {
		return err
	}
	if response.Protection != nil {
		return errors.New("standard runtime response supplied unrelated protection view")
	}
	if request.Action == "start" {
		if err := o.currentIntent(ctx, o.Command()); err != nil {
			return err
		}
		if err := o.prepared.requestEpoch.admit(ctx, response.Startup, response.transmittedDeadline); err != nil {
			return err
		}
		return o.peer.Current(ctx)
	}
	if request.Action != "stop" {
		return o.prepared.requestEpoch.current(ctx, true)
	}
	return nil
}

func linuxStandardServiceRPC(ctx context.Context, image, namespace os.FileInfo, originalPeer **linuxStandardServicePeer, request linuxStandardServiceRequest, directory *os.File, beforeWrite func()) (response linuxStandardServiceResponse, failure error) {
	if ctx == nil || ctx.Err() != nil {
		return response, errors.New("standard service call was cancelled before admission")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	budget := time.Until(deadline)
	if budget <= 0 {
		return response, context.DeadlineExceeded
	}
	if budget > 120*time.Second {
		budget = 120 * time.Second
	}
	request.BudgetMS = budget.Milliseconds()
	request.DeadlineNS = deadline.UnixNano()
	if request.BudgetMS < 1 {
		return response, context.DeadlineExceeded
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unixpacket", linuxStandardServiceSocket)
	if err != nil {
		return response, err
	}
	defer connection.Close()
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		return response, errors.New("standard service did not return its native Unix channel")
	}
	return linuxStandardServiceExchange(ctx, channel, image, namespace, originalPeer, request, directory, []string{filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"), linuxStandardServiceArgument}, beforeWrite)
}

// Production always supplies its fixed service role. Native tests can exercise
// this same framed exchange with original inherited channels and exact peer args.
func linuxStandardServiceExchange(ctx context.Context, channel *net.UnixConn, image, namespace os.FileInfo, originalPeer **linuxStandardServicePeer, request linuxStandardServiceRequest, directory *os.File, arguments []string, beforeWrite func()) (response linuxStandardServiceResponse, failure error) {
	finish, err := linuxStandardServiceDeadline(ctx, channel)
	if err != nil {
		return response, err
	}
	defer finish()
	peer, err := captureLinuxStandardServicePeer(ctx, channel, image, arguments, namespace)
	if err != nil {
		return response, err
	}
	if (*originalPeer) == nil {
		(*originalPeer) = peer
	} else {
		defer peer.Close()
		if err = (*originalPeer).Current(ctx); err != nil {
			return response, err
		}
		if peer.record != (*originalPeer).record {
			return response, errors.New("standard service response came from a replacement process")
		}
	}
	if beforeWrite != nil {
		beforeWrite()
	}
	if err = linuxStandardServiceWrite(channel, request, directory); err != nil {
		return response, err
	}
	body, files, err := linuxStandardServiceRead(channel)
	for _, file := range files {
		_ = file.Close()
	}
	if err != nil {
		return response, err
	}
	if len(files) != 0 {
		return response, errors.New("standard service response supplied unexpected native authority")
	}
	if err = linuxStandardServiceDecode(body, &response); err != nil {
		return response, err
	}
	if response.Schema != 1 || response.Session != request.Session || response.Action != request.Action || response.Complete == (response.Error != "") || len(response.Error) > 2048 {
		return response, errors.New("standard service returned another request's completion")
	}
	if err = (*originalPeer).Current(ctx); err != nil {
		return response, err
	}
	if response.Startup != nil && (request.Action != "start" || !response.Complete) || response.Complete && request.Action == "start" && response.Startup == nil {
		return response, errors.New("standard service response changed original startup ledger scope")
	}
	mtuAction := strings.HasPrefix(request.Action, "mtu-")
	if response.MTU != nil && !mtuAction || mtuAction && (response.Startup != nil || response.Protection != nil || response.Complete && response.MTU == nil) {
		return response, errors.New("standard service response changed original MTU scope")
	}
	response.transmittedDeadline = request.DeadlineNS
	response.authenticatedPeer = *originalPeer
	if !response.Complete {
		return response, errors.New(response.Error)
	}
	return response, ctx.Err()
}

func (o *linuxStandardServiceLaunch) Start(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.registered || ctx == nil || ctx.Err() != nil {
		return errors.New("standard service launch was cancelled or reused")
	}
	if err := desktopExternalDirectoryCurrent(o.prepared.launch); err != nil {
		return err
	}
	var prior *linuxStandardServiceLaunch
	o.app.mu.Lock()
	if o.app.cmd != nil || o.app.checkCapturedConnectionOperationLocked(ctx) != nil || o.app.connectionCancelIntent == ctx {
		o.app.mu.Unlock()
		return errors.New("standard service cannot replace another captured operation")
	}
	if old, exists := linuxStandardServiceOwners.Load(o.app); exists {
		previous, ok := old.(*linuxStandardServiceLaunch)
		if !ok || !previous.joined || !linuxStandardServiceOwners.CompareAndSwap(o.app, previous, o) {
			o.app.mu.Unlock()
			return errors.New("standard service already has a retained unjoined owner")
		}
		prior = previous
	} else if _, loaded := linuxStandardServiceOwners.LoadOrStore(o.app, o); loaded {
		o.app.mu.Unlock()
		return errors.New("standard service owner changed before admission")
	}
	o.app.cmd = o.Command()
	o.app.state.Mode, o.app.state.LogicalMode, o.app.state.RuntimeMode, o.app.state.Base, o.app.state.RouterID = "standard-exit", "standard-exit", o.prepared.runtimeMode, o.prepared.base, o.prepared.routerID
	o.app.state.Connected, o.app.state.Phase, o.app.state.LastError = false, "standard-exit:starting", ""
	o.registered = true
	o.app.mu.Unlock()
	if prior != nil {
		// Continue through the original authenticated service capability. A
		// successor never forgets a retained peer and then trusts a replacement
		// service solely because it occupies the same socket path.
		prior.mu.Lock()
		o.peer, prior.peer = prior.peer, nil
		prior.mu.Unlock()
	}
	if err := o.prepared.requestEpoch.begin(ctx); err != nil {
		return err
	}
	if err := o.call(ctx, o.request, o.prepared.directory); err != nil {
		return err
	}
	if err := o.currentIntent(ctx, o.Command()); err != nil {
		return err
	}
	o.app.mu.Lock()
	cancelled := o.app.connectionCancelIntent == ctx
	o.app.mu.Unlock()
	if cancelled {
		return errConnectionOperationCancelled
	}
	return ctx.Err()
}

func (o *linuxStandardServiceLaunch) Current(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.joined || ctx == nil || ctx.Err() != nil {
		return errors.New("standard service engine is not current")
	}
	if err := o.currentIntent(ctx, o.Command()); err != nil {
		return err
	}
	if err := desktopExternalDirectoryCurrent(o.prepared.launch); err != nil {
		return err
	}
	request := linuxStandardServiceRequest{Schema: 1, Action: "current", Session: o.request.Session}
	if err := o.call(ctx, request, nil); err != nil {
		return err
	}
	return o.currentIntent(ctx, o.Command())
}

func (o *linuxStandardServiceLaunch) closeCopies() error {
	if o.copiesClosed {
		return nil
	}
	if o.prepared.requestEpoch != nil && !o.prepared.requestEpoch.closed {
		return errors.New("standard controller copies retain an unjoined original observer")
	}
	if o.prepared.closedFiles == nil {
		o.prepared.closedFiles = make(map[*os.File]bool)
	}
	for _, file := range []*os.File{o.prepared.image, o.prepared.config, o.prepared.sourceImage, o.prepared.sourceConfig, o.prepared.directory, o.prepared.namespace} {
		if file == nil || o.prepared.closedFiles[file] {
			continue
		}
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			return err
		}
		o.prepared.closedFiles[file] = true
	}
	if o.prepared.launch.directoryRoot != nil {
		if err := o.prepared.launch.directoryRoot.Close(); err != nil {
			return err
		}
		o.prepared.launch.directoryRoot = nil
	}
	o.copiesClosed = true
	return nil
}

func (o *linuxStandardServiceLaunch) Discard() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.registered {
		return nil
	}
	return o.prepared.Discard()
}

type linuxStandardServiceStop struct {
	owner     *linuxStandardServiceLaunch
	command   *exec.Cmd
	operation context.Context
}

func captureLinuxStandardServiceStop(a *app) (desktopRetainedStopCapture, error) {
	raw, ok := linuxStandardServiceOwners.Load(a)
	if !ok {
		return nil, nil
	}
	owner, ok := raw.(*linuxStandardServiceLaunch)
	if !ok || owner == nil {
		return nil, errors.New("standard service lost its retained launch owner")
	}
	a.mu.Lock()
	capture := &linuxStandardServiceStop{owner: owner, command: a.cmd, operation: a.connectionContext}
	a.mu.Unlock()
	return capture, owner.currentIntent(capture.operation, capture.command)
}

func (s *linuxStandardServiceStop) Retire(ctx context.Context, command *exec.Cmd, release bool) error {
	o := s.owner
	if command != s.command || ctx == nil || ctx.Err() != nil {
		return errors.New("standard service Stop lost its original deadline or command")
	}
	if err := o.currentIntentContext(ctx, s.operation, s.command); err != nil {
		return err
	}
	// The optimizer's original rollback needs the live activation and owner
	// mutex, so join it before cancelling the monitor or acquiring that mutex.
	if err := stopLinuxStandardServiceMTUUI(ctx, o); err != nil {
		return err
	}
	if err := o.stopMonitor(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &o.mu); err != nil {
		return err
	}
	defer o.mu.Unlock()
	if command != s.command || ctx == nil || ctx.Err() != nil {
		return errors.New("standard service Stop lost its original deadline or command")
	}
	if err := o.currentIntentContext(ctx, s.operation, s.command); err != nil {
		return err
	}
	// Stop joins an already admitted candidate before closing either observer.
	// Its own bounded teardown context cannot extend the native mutation deadline.
	if o.mtuOwner != nil && o.mtuOwner.pending != nil {
		_, drainErr := o.mtuOwner.finishStopLocked(ctx)
		if o.mtuOwner.pending != nil {
			return drainErr
		}
	}
	if err := o.prepared.requestEpoch.close(ctx); err != nil {
		return err
	}
	if o.attempted {
		request := linuxStandardServiceRequest{Schema: 1, Action: "stop", Session: o.request.Session, Release: release}
		if err := o.call(ctx, request, nil); err != nil {
			return err
		}
	} else {
		if err := o.prepared.discardContext(ctx); err != nil {
			return err
		}
		o.copiesClosed = true
	}
	if err := o.closeCopies(); err != nil {
		return err
	}
	if err := o.currentIntentContext(ctx, s.operation, s.command); err != nil {
		return err
	}
	held := o.attempted && (o.prepared.protectionPolicy == "always" || !release && o.prepared.protectionPolicy == "on-connect")
	if !held && o.peer != nil {
		if err := o.peer.Close(); err != nil {
			return err
		}
		o.peer = nil
	}
	if err := desktopnetwork.LockContext(ctx, &o.app.mu); err != nil {
		return err
	}
	defer o.app.mu.Unlock()
	if o.app.cmd != s.command || o.app.connectionContext != s.operation {
		return errors.New("standard service completion belongs to a replaced controller")
	}
	if !held && !linuxStandardServiceOwners.CompareAndDelete(o.app, o) {
		return errors.New("standard service cleanup cannot remove a replacement owner")
	}
	o.joined = true
	o.app.cmd = nil
	o.app.state.Connected = false
	o.app.state.Mode, o.app.state.RuntimeMode, o.app.state.LogicalMode, o.app.state.Base, o.app.state.Phase, o.app.state.LastError = "off", "off", "off", "", "off", ""
	return nil
}

func linuxStandardServiceFailureOwned(a *app, expected legacyStandardExitLaunch, retired bool) (bool, bool) {
	owner, ok := expected.(*linuxStandardServiceLaunch)
	if !ok {
		return false, false
	}
	actual, exists := linuxStandardServiceOwners.Load(a)
	// The shipping route holds a.mu across this guard and the state update.
	// Re-locking here would deadlock every remote Connect after Start.
	if retired {
		return (!exists || actual == owner && owner.joined) && a.cmd == nil, true
	}
	return exists && actual == owner && a.cmd == owner.Command(), true
}
