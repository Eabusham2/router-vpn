//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
)

type linuxStandardServiceSession struct {
	request        linuxStandardServiceRequest
	peer           *linuxStandardServicePeer
	owner          *linuxLegacyStandardExitOwner
	joined         bool
	cleanupPending bool
	cleanupError   string
	network        *linuxStandardServiceNetwork
	mtu            *linuxStandardServiceMTU
}

// The app here is the service's actual process/state owner. Its commands are
// created, started and waited by this process, never reconstructed from a
// client's PID or represented by a controller-side exec.Cmd.Process.
type linuxStandardService struct {
	gate              chan struct{}
	app               *app
	root              string
	image, namespace  os.FileInfo
	session           *linuxStandardServiceSession
	boot              *legacyExitProtectionSlot
	legacyBoot        *linuxStandardServiceLegacyBoot
	retired           map[string]struct{}
	prepare           func(*app, *exec.Cmd, string, string, string) (legacyStandardExitLaunch, error)
	workers           sync.WaitGroup
	quiescing         bool
	shutdown          chan struct{}
	shutdownOnce      sync.Once
	bootFailure       error
	readiness         string
	bootRetryAfter    time.Time
	protectionView    *linuxStandardServiceProtection
	protectionAbsence func(context.Context) error
	tunAbsent         func() error
	openNetwork       func(context.Context, context.Context) (linuxStandardNetworkObserver, error) // explicit native-observer fixture boundary; nil uses the kernel
}

func newLinuxStandardService(root string, image, namespace os.FileInfo) *linuxStandardService {
	s := &linuxStandardService{gate: make(chan struct{}, 1), root: root, image: image, namespace: namespace,
		app:     &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ScriptsDir: filepath.Join(root, "modes"), StateFile: filepath.Join(root, "state.json")}},
		prepare: prepareLegacyStandardExitOwnerWithLocalRuntime, retired: make(map[string]struct{}), shutdown: make(chan struct{})}
	s.gate <- struct{}{}
	return s
}

// This private constructor always keeps the engine inside the service. The
// public preparation dispatcher may select a remote owner in a GUI controller.
func prepareLegacyStandardExitOwnerWithLocalRuntime(a *app, command *exec.Cmd, mode, base, id string) (legacyStandardExitLaunch, error) {
	return prepareLegacyStandardExitOwnerWithEngine(a, command, mode, base, id, legacyExitTUNAbsent, physicalNetworkIdentity, true)
}

func linuxStandardProfileDigest(profile common.RouterProfile) (string, error) {
	body, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func (s *linuxStandardService) loadProfiles() error {
	body, err := readPrivateRegular(filepath.Join(s.root, "routers.json"), maxPrivateStoreBytes)
	if err != nil {
		return err
	}
	var store common.RouterProfileStore
	if err = decodeRelayControlJSON(body, &store); err != nil {
		return err
	}
	for i := range store.Profiles {
		if !validProfileID(store.Profiles[i].ID) {
			return errors.New("standard service profile store has an invalid identity")
		}
		applyProfileDefaults(&store.Profiles[i])
	}
	s.app.mu.Lock()
	s.app.profiles = store
	s.app.mu.Unlock()
	return nil
}

func (s *linuxStandardService) operation(ctx context.Context) func() {
	// The service gate is held for this entire real authenticated operation.
	// A fresh bounded request never borrows another request's cancellation.
	s.app.mu.Lock()
	s.app.connectionContext = ctx
	s.app.connectionCancelIntent = nil
	s.app.mu.Unlock()
	return func() {
		s.app.mu.Lock()
		if s.app.connectionContext == ctx {
			s.app.connectionContext = nil
			s.app.connectionCancelIntent = nil
		}
		s.app.mu.Unlock()
	}
}

func (s *linuxStandardService) retire(ctx context.Context, release bool) (failure error) {
	if s.session == nil {
		return nil
	}
	defer func() {
		s.session.cleanupPending = failure != nil
		if failure != nil {
			s.session.cleanupError = failure.Error()
		} else {
			s.session.cleanupError = ""
		}
	}()
	finish := s.operation(ctx)
	defer finish()
	if err := s.session.mtu.drainForStop(ctx); err != nil {
		return err
	}
	if err := s.closeNetwork(ctx, s.session); err != nil {
		return err
	}
	if s.session.joined {
		// A previous hold-protection Stop joined the engine but can still own
		// On-connect policy. A later ordinary Stop must use that same retained
		// detached creator; it cannot report release just from joined=true.
		stop, err := captureLegacyExitDetachedProtectionStop(s.app)
		if err != nil || stop == nil {
			return err
		}
		return stop.Retire(ctx, nil, release)
	}
	owner := s.session.owner
	if owner == nil {
		return errors.New("standard service retained an incomplete original engine preparation")
	}
	if !owner.registered {
		if err := owner.discardContext(ctx); err != nil {
			return err
		}
		s.session.joined = true
		s.retired[s.session.request.Session] = struct{}{}
		return nil
	}
	stop, err := captureLegacyStandardExitStop(s.app)
	if err != nil || stop == nil {
		return errors.Join(err, errors.New("standard service lost its original engine Stop owner"))
	}
	if err = stop.Retire(ctx, owner.command, release); err != nil {
		return err
	}
	s.session.joined = true
	s.retired[s.session.request.Session] = struct{}{}
	return nil
}

func (s *linuxStandardService) previous(ctx context.Context, peer *linuxStandardServicePeer, session string) error {
	if s.session == nil {
		return nil
	}
	old := s.session
	if old.request.Session == session && old.peer.record == peer.record {
		return nil
	}
	if old.peer.record != peer.record {
		dead, err := old.peer.Retired()
		if err != nil {
			return err
		}
		if !dead {
			return errors.New("standard service cannot transfer a live original controller's ownership")
		}
	}
	if !old.joined {
		dead, err := old.peer.Retired()
		if err != nil {
			return err
		}
		if !dead {
			return errors.New("standard service still owns another live controller's engine")
		}
		// Losing the original controller is not an explicit Disconnect. Hold
		// its protection until the successor creator has been established.
		if err = s.retire(ctx, false); err != nil {
			return err
		}
	}
	if (s.protectionView == nil || s.protectionView.peer != old.peer) && old.peer != peer {
		if err := old.peer.Close(); err != nil {
			return err
		}
	}
	if old.peer.record != peer.record {
		s.retired = make(map[string]struct{})
	}
	s.session = nil
	return nil
}

func (s *linuxStandardService) start(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest, directory *os.File) error {
	if s.protectionView != nil && s.protectionView.data.Pending {
		return errors.New("finish the accepted original standard protection Off change before connecting")
	}
	if _, retired := s.retired[request.Session]; retired {
		return errors.New("standard service Start was cancelled or already retired")
	}
	if len(s.retired) >= 4096 {
		return errors.New("standard service controller request inventory is full; restart the idle controller")
	}
	if directory == nil || filepath.Clean(request.Directory) != request.Directory ||
		!strings.HasPrefix(request.Directory, filepath.Join(s.root, "run", "native-standard-exit")+string(os.PathSeparator)) ||
		!validProfileID(request.ProfileID) || request.Base != "external" || !strings.HasPrefix(request.RuntimeMode, "standard-") || !strings.HasPrefix(request.RouterID, "standard:") || !validProfileID(strings.TrimPrefix(request.RouterID, "standard:")) || request.NetworkID == "" ||
		len(request.RuntimeMode) > 64 || strings.ContainsAny(request.RuntimeMode, "/\\\x00") {
		return errors.New("standard service launch escaped its captured direct runtime")
	}
	if err := s.previous(ctx, peer, request.Session); err != nil {
		return err
	}
	if s.session != nil {
		original := s.session.request
		original.BudgetMS = request.BudgetMS
		original.DeadlineNS = request.DeadlineNS
		if !reflect.DeepEqual(original, request) || s.session.joined {
			return errors.New("standard service launch identity was reused for different work")
		}
		finish := s.operation(ctx)
		defer finish()
		if err := s.session.owner.Current(ctx); err != nil {
			return err
		}
		return s.networkCurrent(ctx, s.session, false)
	}
	if s.bootFailure != nil {
		if err := s.repairBoot(ctx); err != nil {
			return err
		}
	}
	if err := s.loadProfiles(); err != nil {
		return err
	}
	s.app.mu.Lock()
	profile, ok := s.app.profileByIDLocked(request.ProfileID)
	s.app.mu.Unlock()
	digest, err := linuxStandardProfileDigest(profile)
	if err != nil || !ok || digest != request.ProfileSHA256 {
		return errors.Join(err, errors.New("standard service selected profile changed before original launch"))
	}
	actual, err := directory.Stat()
	named, namedErr := os.Lstat(request.Directory)
	if err != nil || namedErr != nil || !actual.IsDir() || !os.SameFile(actual, named) || !ownedDesktopInfo(actual) {
		return errors.Join(err, namedErr, errors.New("standard service lost the original transferred workspace"))
	}
	command := exec.Command("bash", filepath.Join(s.root, "modes", "native-standard-exit-linux.sh"), "up", request.Directory, request.Endpoint, request.ProfileID)
	command.Dir = s.root
	command.Env = []string{"HOME=/root", "LANG=C.UTF-8", "PATH=" + filepath.Join(s.root, "bin") + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOMEVPN_ROOT=" + s.root, "HOMEVPN_PROFILE_ID=" + request.ProfileID, "HOMEVPN_POLICY_PROFILE_ID=" + request.ProfileID, "HOMEVPN_STANDARD_ENGINE=stock", "HOMEVPN_ENDPOINT=" + request.Endpoint}
	finish := s.operation(ctx)
	defer finish()
	prepared, err := s.prepare(s.app, command, request.RuntimeMode, request.Base, request.RouterID)
	if err != nil {
		if original, ok := prepared.(*linuxLegacyStandardExitOwner); ok && original != nil {
			original.session = request.Session
			s.session = &linuxStandardServiceSession{request: request, peer: peer, owner: original}
		}
		return err
	}
	owner, ok := prepared.(*linuxLegacyStandardExitOwner)
	if !ok || owner == nil {
		if prepared != nil {
			_ = prepared.Discard()
		}
		return errors.New("standard service preparation did not retain its actual engine")
	}
	// Retain the original prepared observer/files before any later source
	// validation can fail. Cleanup uses this same owner and peer on retry.
	owner.session = request.Session
	s.session = &linuxStandardServiceSession{request: request, peer: peer, owner: owner}
	if owner.digest != request.ConfigSHA256 {
		return errors.New("standard service captured another configuration")
	}
	if owner.dns == nil || owner.dns.networkID != request.NetworkID {
		return errors.New("standard service physical network changed since controller preparation")
	}
	if err = desktopExternalDirectoryCurrent(owner.launch); err != nil {
		return err
	}
	captured, err := owner.directory.Stat()
	if err != nil || !os.SameFile(captured, actual) {
		return errors.Join(err, errors.New("standard service workspace changed while sealing original engine"))
	}
	if owner.native != nil {
		native := owner.native
		s.session.network = &linuxStandardServiceNetwork{session: s.session, owner: owner, observer: native.tracker, lifetime: native.lifetime, cancel: native.cancel}
		native.adopted = true
		if err = native.prepareStart(ctx); err != nil {
			return err
		}
	}
	if err = peer.Current(ctx); err != nil {
		return err
	}
	if err = owner.Start(ctx); err != nil {
		return err
	}
	if owner.native != nil {
		if err = owner.native.finishStart(ctx); err != nil {
			return err
		}
	}
	if s.boot != nil && s.boot.closed {
		s.boot = nil
	}
	return errors.Join(ctx.Err(), peer.Current(ctx))
}

func (s *linuxStandardService) handle(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest, files []*os.File) (failure error) {
	return s.handleWithStartup(ctx, peer, request, files, nil)
}

func (s *linuxStandardService) handleWithStartup(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest, files []*os.File, startup **linuxStandardServiceStartup) (failure error) {
	if request.ProfileRevision != "" || request.ResultRevision != "" || request.MTU != nil {
		return errors.New("runtime request supplied unrelated protection source")
	}
	if request.Schema != 1 || !validControllerOwnerToken(request.Session) || request.BudgetMS < 1 || request.BudgetMS > 120000 || request.DeadlineNS <= time.Now().UnixNano() {
		return errors.New("standard service request has invalid bounded identity")
	}
	if err := peer.Current(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.quiescing {
		return errors.New("standard service is retiring its original idle lifetime")
	}
	defer func() {
		if failure != nil && request.Action == "start" && s.session != nil && s.session.request.Session == request.Session && s.session.peer.record == peer.record {
			s.session.cleanupPending = true
			s.session.cleanupError = failure.Error()
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(current, s.namespace) {
		return errors.Join(err, errors.New("standard service left its original network namespace"))
	}
	if request.Action == "start" {
		if len(files) != 1 {
			return errors.New("standard service Start requires its original workspace descriptor")
		}
		if err := s.start(ctx, peer, request, files[0]); err != nil {
			return err
		}
		if startup != nil {
			var err error
			*startup, err = s.startupResponse(ctx, peer, request)
			return err
		}
		return nil
	}
	if len(files) != 0 {
		return errors.New("standard service action supplied unexpected native authority")
	}
	if request.Directory != "" || request.ConfigSHA256 != "" || request.ProfileID != "" || request.ProfileSHA256 != "" || request.Endpoint != "" || request.RuntimeMode != "" || request.Base != "" || request.NetworkID != "" || request.RouterID != "" {
		return errors.New("standard service action changed its original launch parameters")
	}
	if request.Action == "stop" && s.session == nil {
		// Stop can overtake Start after a lost response. Retain its exact
		// cancellation so a late Start cannot execute after the absent ack.
		s.session = &linuxStandardServiceSession{request: request, peer: peer, joined: true}
		s.retired[request.Session] = struct{}{}
		return nil
	}
	if s.session == nil || s.session.request.Session != request.Session || s.session.peer.record != peer.record {
		return errors.New("standard service request does not own its original engine")
	}
	switch request.Action {
	case "stop":
		return s.retire(ctx, request.Release)
	case "current":
		if s.session.cleanupPending {
			return fmt.Errorf("standard service retains incomplete original cleanup: %s", s.session.cleanupError)
		}
		if request.Release || s.session.joined {
			return errors.New("standard service engine is already retired")
		}
		finish := s.operation(ctx)
		defer finish()
		if err := s.session.owner.Current(ctx); err != nil {
			return err
		}
		return s.networkCurrent(ctx, s.session, false)
	case "observe":
		if request.Release || s.session.joined || s.session.cleanupPending {
			return errors.New("standard service original runtime is retired or needs cleanup")
		}
		if err := s.loadProfiles(); err != nil {
			return err
		}
		if err := s.networkCurrent(ctx, s.session, true); err != nil {
			return err
		}
		if err := s.session.owner.legacyDNSCurrent(ctx); err != nil {
			return err
		}
		return s.networkCurrent(ctx, s.session, true)
	case "prove-dns", "dns-current":
		if request.Release || s.session.joined || s.session.cleanupPending {
			return errors.New("standard service DNS has no original live engine")
		}
		finish := s.operation(ctx)
		defer finish()
		if err := s.loadProfiles(); err != nil {
			return err
		}
		if request.Action == "prove-dns" {
			return s.proveDNSWithNetwork(ctx)
		}
		if err := s.networkCurrent(ctx, s.session, true); err != nil {
			return err
		}
		if err := linuxStandardServiceDNSReceiptCurrent(ctx, s.session.owner); err != nil {
			return err
		}
		return s.networkCurrent(ctx, s.session, true)
	default:
		return errors.New("standard service action is unavailable")
	}
}

func (s *linuxStandardService) connection(connection *net.UnixConn) {
	s.connectionWithRoles(connection, []string{filepath.Join(s.root, "router-vpn-client"), linuxOwnedControllerArgument}, []string{filepath.Join(s.root, "router-vpn-client"), linuxStandardServiceUpgradeArgument})
}

// Production supplies the fixed installed controller role. Native fixtures
// supply their exact test executable arguments while retaining the same actual
// Unix peer, image, namespace and original pidfd authentication.
func (s *linuxStandardService) connectionWithArguments(connection *net.UnixConn, arguments []string) {
	s.connectionWithRoles(connection, arguments, nil)
}

func (s *linuxStandardService) connectionWithRoles(connection *net.UnixConn, arguments, upgradeArguments []string) {
	defer s.workers.Done()
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	peer, err := captureLinuxStandardServicePeer(ctx, connection, s.image, arguments, s.namespace)
	upgrade := false
	if err != nil && len(upgradeArguments) != 0 {
		peer, err = captureLinuxStandardServicePeer(ctx, connection, s.image, upgradeArguments, s.namespace)
		upgrade = err == nil
	}
	if err != nil {
		return
	}
	defer func() {
		<-s.gate
		retained := s.session != nil && s.session.peer == peer || s.protectionView != nil && s.protectionView.peer == peer
		s.gate <- struct{}{}
		if !retained {
			_ = peer.Close()
		}
	}()
	body, files, err := linuxStandardServiceRead(connection)
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	if err != nil {
		return
	}
	var request linuxStandardServiceRequest
	if linuxStandardServiceDecode(body, &request) != nil || request.BudgetMS < 1 || request.BudgetMS > 120000 {
		return
	}
	deadline := time.Unix(0, request.DeadlineNS)
	if maximum := time.Now().Add(time.Duration(request.BudgetMS) * time.Millisecond); maximum.Before(deadline) {
		deadline = maximum
	}
	if !time.Now().Before(deadline) {
		return
	}
	// Keep the transmitted absolute bound. Recomputing WithTimeout from a
	// previous time.Until would silently add elapsed admission time.
	operation, stop := context.WithDeadline(context.Background(), deadline)
	defer stop()
	if connection.SetDeadline(deadline) != nil {
		return
	}
	live, join := linuxStandardServiceChannelLifetime(operation, connection)
	shutdownAccepted := false
	var protection *linuxStandardServiceProtectionData
	var startup *linuxStandardServiceStartup
	var mtu *linuxStandardServiceMTUResponse
	if upgrade {
		err = s.handleIdleUpgrade(live, peer, request, files)
		shutdownAccepted = err == nil
	} else if strings.HasPrefix(request.Action, "protection-") {
		if len(files) != 0 {
			err = errors.New("standard protection request supplied unrelated native authority")
		} else {
			protection, err = s.protectionRequest(live, peer, request)
		}
	} else if strings.HasPrefix(request.Action, "mtu-") {
		if len(files) != 0 {
			err = errors.New("standard MTU request supplied unrelated native authority")
		} else {
			mtu, err = s.mtuRequest(live, peer, request)
		}
	} else {
		err = s.handleWithStartup(live, peer, request, files, &startup)
	}
	err = errors.Join(err, live.Err(), join(), operation.Err())
	if err != nil && request.Action == "start" {
		// Cancellation can happen after native execution but before delivery of
		// its completion. Use only the original remaining request deadline for
		// this immediate retirement. An incomplete cleanup remains retained and
		// queryable; a later service retry is a separate bounded operation.
		// A lost or failed Start response supplies no authority to release the
		// original guard. Only an authenticated explicit Stop may do that.
		cleanup, stopCleanup := context.WithDeadline(context.Background(), deadline)
		select {
		case <-cleanup.Done():
		case <-s.gate:
			if s.session != nil && s.session.request.Session == request.Session && s.session.peer.record == peer.record {
				s.session.cleanupPending = true
				s.session.cleanupError = err.Error()
				err = errors.Join(err, s.retire(cleanup, false))
			}
			s.gate <- struct{}{}
		}
		stopCleanup()
	}
	if err != nil {
		startup = nil
		mtu = nil
	}
	response := linuxStandardServiceResponse{Startup: startup, MTU: mtu, Schema: 1, Session: request.Session, Action: request.Action, Complete: err == nil, Protection: protection}
	if err != nil {
		response.Error = err.Error()
		if len(response.Error) > 2048 {
			response.Error = "standard owner service retained incomplete original cleanup"
		}
	}
	_ = linuxStandardServiceWrite(connection, response, nil)
	if shutdownAccepted {
		s.requestShutdown()
	}
}

func (s *linuxStandardService) handleIdleUpgrade(ctx context.Context, peer *linuxStandardServicePeer, request linuxStandardServiceRequest, files []*os.File) error {
	if request.Schema != 1 || request.Action != "shutdown-idle" || request.MTU != nil || request.Release || !validControllerOwnerToken(request.Session) || request.BudgetMS < 1 || request.BudgetMS > 120000 || request.DeadlineNS <= time.Now().UnixNano() || len(files) != 0 ||
		request.Directory != "" || request.ConfigSHA256 != "" || request.ProfileID != "" || request.ProfileSHA256 != "" || request.Endpoint != "" || request.RuntimeMode != "" || request.Base != "" || request.NetworkID != "" || request.RouterID != "" || request.ProfileRevision != "" || request.ResultRevision != "" {
		return errors.New("standard service idle-upgrade request changed its fixed scope")
	}
	if err := peer.Current(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	if s.quiescing {
		return errors.New("standard service already retired admission")
	}
	if err := s.prepareIdleShutdown(ctx); err != nil {
		return err
	}
	if err := peer.Current(ctx); err != nil {
		s.quiescing = false
		return err
	}
	return nil
}

func (s *linuxStandardService) requestShutdown() { s.shutdownOnce.Do(func() { close(s.shutdown) }) }

func (s *linuxStandardService) watch(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		select {
		case <-ctx.Done():
			return
		case <-s.gate:
		}
		s.retryBoot(ctx)
		if s.session != nil && (!s.session.joined || s.session.cleanupPending) {
			dead, err := s.session.peer.Retired()
			if err != nil {
				s.session.cleanupPending = true
				s.session.cleanupError = err.Error()
			}
			if !dead && !s.session.cleanupPending && s.session.owner != nil && s.session.owner.started {
				observation, cancel := context.WithTimeout(ctx, 4*time.Second)
				runtime.LockOSThread()
				err = s.session.peer.Current(observation)
				if err == nil {
					err = s.loadProfiles()
				}
				if err == nil {
					err = s.session.owner.legacyDNSCurrent(observation)
				}
				if err == nil {
					err = s.watchNetworkCurrent(observation, s.session)
				}
				runtime.UnlockOSThread()
				// Classify before canceling this observation ourselves. Pure read
				// expiry cannot retire an otherwise retained, proved engine; real
				// failure joined with expiry still requires original retirement.
				expired := common.ObservationContextExpired(observation, err)
				cancel()
				if err != nil && !expired {
					s.session.cleanupPending = true
					s.session.cleanupError = err.Error()
				}
			}
			if s.session.cleanupPending || err == nil && dead {
				retirement, cancel := context.WithTimeout(ctx, 30*time.Second)
				runtime.LockOSThread()
				// Engine, source, network or controller loss must fail closed.
				// Keep the original protection for an explicit Stop/Off or a
				// proved successor; retain any cleanup error for the next retry.
				_ = s.retire(retirement, false)
				runtime.UnlockOSThread()
				cancel()
			}
		}
		s.gate <- struct{}{}
	}
}

func (s *linuxStandardService) serve(ctx context.Context, listener *net.UnixListener) error {
	if ctx == nil || listener == nil {
		return errors.New("standard service requires its original installed listener")
	}
	ctx, cancel := context.WithCancel(ctx)
	listenerJoined := make(chan struct{})
	go func() {
		defer close(listenerJoined)
		select {
		case <-ctx.Done():
		case <-s.shutdown:
		}
		_ = listener.Close()
	}()
	defer func() { cancel(); <-listenerJoined }()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			s.workers.Wait()
			select {
			case <-s.shutdown:
				return nil
			default:
			}
			return fmt.Errorf("standard owner service listener stopped: %w", err)
		}
		s.workers.Add(1)
		go s.connection(connection)
	}
}
