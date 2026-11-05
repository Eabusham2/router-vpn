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
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"router-vpn/internal/mobiletor"
)

// Only policy selection survives reboot. The new service proves full native
// absence and creates a fresh exclusive table with its own acknowledgment,
// netlink endpoint and saved-file capability. It never imports an old creator.
func (s *linuxStandardService) reassert(ctx context.Context) error {
	return s.reassertDispatch(ctx, legacyExitTUNAbsent, mobiletor.ReadDesktopLinuxProtectionAbsence, createLegacyExitNativeProtection, s.reassertLegacy)
}

func (s *linuxStandardService) reassertDispatch(ctx context.Context, tunAbsent func() error, absence func(context.Context) error, create legacyExitProtectionFactory, legacy func(context.Context) error) error {
	if s.legacyBoot != nil {
		return s.joinLegacyBoot(ctx)
	}
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return err
	}
	expected, err := legacyExitCaptureState(lease)
	standard := false
	if err == nil && !expected.absent {
		standard, err = linuxStandardServiceStandardMarker(expected.body)
	}
	if expected != nil {
		err = errors.Join(err, expected.Close())
	}
	lease.Close()
	if err != nil {
		return err
	}
	if standard {
		return s.reassertWithObservers(ctx, tunAbsent, absence, create)
	}
	// The selected Home profile alone cannot select a standard exit. Preserve
	// the existing legacy reassert semantics for every unmarked graph.
	return legacy(ctx)
}

func (s *linuxStandardService) reassertWithObservers(ctx context.Context, tunAbsent func() error, absence func(context.Context) error, create legacyExitProtectionFactory) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	actual, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(actual, s.namespace) {
		return errors.Join(err, errors.New("standard boot owner lost its original namespace"))
	}
	if err = tunAbsent(); err != nil {
		return err
	}
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return err
	}
	defer lease.Close()
	expected, err := legacyExitCaptureState(lease)
	if err != nil {
		return err
	}
	retained := false
	defer func() {
		if !retained {
			_ = expected.Close()
		}
	}()
	boot, err := readDesktopLinuxNodeBootID()
	if err != nil {
		return err
	}
	var saved legacyExitProtectionState
	if expected.absent {
		return errors.New("standard boot requires its explicit prior-boot policy marker")
	}
	{
		marked, markerErr := linuxStandardServiceStandardMarker(expected.body)
		if markerErr != nil || !marked {
			return errors.Join(markerErr, errors.New("standard boot cannot infer standard ownership from a selected Home profile"))
		}
		if err = decodeRelayControlJSON(expected.body, &saved); err != nil {
			return errors.Join(err, errors.New("standard boot owner cannot read saved policy selection"))
		}
		if saved.Owner.BootID == boot {
			return errors.New("standard service restart has no transferred original creator; retain protection until authenticated live handoff")
		}
		if saved.Policy != "always" && saved.Policy != "on-connect" || !validProfileID(saved.PolicyProfileID) || saved.ProfileID != saved.PolicyProfileID || saved.Platform != "linux" || !saved.Enforced {
			return errors.New("standard boot policy lost its captured original selection")
		}
	}
	if err = absence(ctx); err != nil {
		return err
	}
	if err = s.loadProfiles(); err != nil {
		if expected.absent && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	profileID := saved.PolicyProfileID
	s.app.mu.Lock()
	if profileID == "" {
		profileID = s.app.profiles.SelectedID
	}
	profile, exists := s.app.profileByIDLocked(profileID)
	s.app.mu.Unlock()
	if !exists {
		if expected.absent {
			return nil
		}
		return errors.New("standard boot owner lost its saved policy profile")
	}
	if profile.KillSwitchPolicy != "always" {
		if expected.absent {
			return nil
		}
		_, err = legacyExitRemoveState(ctx, lease, expected)
		return err
	}
	endpoint := saved.Endpoint
	remote, err := netip.ParseAddr(strings.Trim(endpoint, "[]"))
	if err != nil || remote.Zone() != "" || remote.Is4In6() || remote.IsUnspecified() || remote.IsMulticast() || len(saved.EndpointIPs) != 1 || saved.EndpointIPs[0] != remote.String() {
		return errors.New("standard boot policy has no captured literal physical endpoint")
	}
	session, err := randomHex(16)
	if err != nil {
		return err
	}
	policy, err := json.Marshal(struct {
		BootID, ProfileID, Endpoint string
		LAN                         bool
	}{boot, profile.ID, remote.String(), profile.HomeLANAccess})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(policy)
	p := &legacyExitProtectionSlot{app: s.app, root: s.root, namespace: s.namespace, policy: "always", profileID: profile.ID, endpoint: remote.String(), homeLAN: profile.HomeLANAccess, boot: boot, expected: expected}
	p.kernel, err = create(ctx, session, hex.EncodeToString(digest[:]), []netip.Addr{remote}, profile.HomeLANAccess, lease.lock)
	if p.kernel == nil {
		return errors.Join(err, errors.New("standard boot protection has no original creator"))
	}
	// Keep every actual creator even when its acknowledgment/readback is
	// incomplete. A startup failure cannot turn it into absent state.
	s.boot = p
	retained = true
	if err != nil {
		return err
	}
	if err = p.publish(ctx, lease, lease.Current); err != nil {
		return err
	}
	p.detached = true
	return nil
}

func (s *linuxStandardService) repairBoot(ctx context.Context) (failure error) {
	defer func() { s.bootFailure = failure }()
	if s.boot == nil {
		if err := s.reassert(ctx); err != nil {
			return err
		}
	} else {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		lease, err := acquireLegacyExitMutationLease(ctx, s.root)
		if err != nil {
			return err
		}
		defer lease.Close()
		if s.boot.persisted {
			err = s.boot.current(ctx, lease)
		} else {
			err = s.boot.publish(ctx, lease, lease.Current)
		}
		if err != nil {
			return err
		}
		s.boot.detached = true
	}
	if s.readiness != "" {
		return s.notifyBoot(ctx, nil)
	}
	return nil
}

func (s *linuxStandardService) notifyBoot(ctx context.Context, failure error) error {
	if s.legacyBoot != nil && failure == nil {
		if !s.legacyBoot.complete || s.legacyBoot.err != nil {
			return errors.New("legacy boot helper has not completed successfully")
		}
		return linuxStandardServiceNotifyStatus(ctx, s.readiness, []byte("READY=1\nSTATUS=Legacy protection reassert completed; no retained standard creator adopted"))
	}
	return linuxStandardServiceNotifyContext(ctx, s.readiness, failure)
}

func linuxStandardServiceNotify(socket string, failure error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return linuxStandardServiceNotifyContext(ctx, socket, failure)
}

func linuxStandardServiceNotifyContext(ctx context.Context, socket string, failure error) error {
	body := []byte("READY=1\nSTATUS=Original standard protection owner is ready")
	if failure != nil {
		reason := strings.NewReplacer("\n", " ", "\r", " ").Replace(failure.Error())
		if len(reason) > 2048 {
			reason = reason[:2048]
		}
		body = []byte("STATUS=Protection startup incomplete; original operations retained: " + reason)
	}
	return linuxStandardServiceNotifyStatus(ctx, socket, body)
}

func linuxStandardServiceNotifyStatus(ctx context.Context, socket string, body []byte) error {
	if ctx == nil || ctx.Err() != nil || socket == "" {
		return errors.New("standard boot service requires its original live readiness channel")
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	address := socket
	if strings.HasPrefix(address, "@") {
		address = "\x00" + address[1:]
	}
	connection, err := (&net.Dialer{}).DialContext(bounded, "unixgram", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("standard service readiness lost its native Unix channel")
	}
	return linuxStandardServiceNotifyChannel(bounded, channel, body)
}

// The notification is part of its original repair budget. Cancellation wakes
// an actual blocked datagram write and joins that callback before returning.
func linuxStandardServiceNotifyChannel(ctx context.Context, channel *net.UnixConn, body []byte) error {
	if ctx == nil || ctx.Err() != nil || channel == nil || len(body) == 0 || len(body) > 4096 {
		return errors.New("standard service readiness has no original bounded notification")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("standard service readiness requires its original deadline")
	}
	if err := channel.SetWriteDeadline(deadline); err != nil {
		return err
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(joined); _ = channel.SetWriteDeadline(time.Now()) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := channel.Write(body)
	if err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if n != len(body) {
		return errors.New("standard service readiness was not completely sent")
	}
	return nil
}

func linuxStandardServiceUtility(arguments []string) (bool, error) {
	return runLinuxStandardServiceUtility(arguments, nil)
}

// The optional observer is an explicit in-process constructor boundary for the
// native installed-service fixture. Production supplies nil; no environment,
// wire request or saved record can install a runtime control callback.
func runLinuxStandardServiceUtility(arguments []string, observe func(context.Context, *linuxStandardService) (func() error, error)) (handled bool, failure error) {
	selected := false
	for _, argument := range arguments {
		if argument == linuxStandardServiceArgument {
			selected = true
		}
	}
	if !selected {
		return false, nil
	}
	if len(arguments) != 1 || arguments[0] != linuxStandardServiceArgument || os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, errors.New("standard protection service requires its fixed privileged launch")
	}
	if err := ownedDesktopAncestors(filepath.Dir(linuxOwnedControllerRoot)); err != nil {
		return true, err
	}
	install, err := ownedDesktopLock(linuxOwnedInstallLock, false)
	if err != nil {
		return true, err
	}
	defer install.Close()
	if err = ownedDesktopInstall(linuxOwnedControllerRoot); err != nil {
		return true, err
	}
	startup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	generation, err := captureLinuxStandardServiceGeneration(startup, linuxOwnedControllerRoot)
	if err != nil {
		return true, err
	}
	if generation != nil {
		defer generation.Close()
	}
	image, err := os.Stat("/proc/self/exe")
	installed, installedErr := os.Lstat(filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"))
	expectedImage := installed
	if generation != nil {
		expectedImage = generation.imageInfo
	}
	if err != nil || installedErr != nil {
		return true, errors.Join(err, installedErr, errors.New("standard service is not its original installed executable"))
	}
	var successor *linuxStandardImageUpgrade
	var inheritedOwner *os.File
	runtime.LockOSThread()
	initialNamespace, namespaceErr := os.Stat("/proc/thread-self/ns/net")
	runtime.UnlockOSThread()
	if namespaceErr != nil {
		return true, namespaceErr
	}
	if !os.SameFile(image, expectedImage) {
		if generation == nil {
			return true, errors.New("candidate has no original generation service")
		}
		generation, successor, inheritedOwner, err = captureLinuxStandardImageSuccessor(startup, linuxOwnedControllerRoot, generation, image, initialNamespace)
		if err != nil {
			return true, err
		}
		defer generation.Close()
	}
	socket := generation.socket(linuxStandardServiceDirectory)
	if err = os.Mkdir(linuxStandardServiceDirectory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return true, err
	}
	if err = ownedDesktopAncestors(linuxStandardServiceDirectory); err != nil {
		return true, err
	}
	info, err := os.Lstat(linuxStandardServiceDirectory)
	if err != nil || info.Mode().Perm() != 0700 {
		return true, errors.Join(err, errors.New("standard service directory is not private"))
	}
	owner := inheritedOwner
	if owner == nil {
		owner, err = ownedDesktopLock(filepath.Join(linuxStandardServiceDirectory, "owner.lock"), true)
	}
	if err != nil {
		return true, err
	}
	defer owner.Close()
	if _, err = os.Lstat(socket); err == nil {
		return true, errors.New("standard service listener already exists; original owner retirement has not been proved")
	} else if !errors.Is(err, os.ErrNotExist) {
		return true, err
	}
	readiness := os.Getenv("NOTIFY_SOCKET")
	os.Clearenv()
	for key, value := range map[string]string{"HOME": "/root", "LANG": "C.UTF-8", "HOMEVPN_ROOT": linuxOwnedControllerRoot, "PATH": linuxOwnedControllerRoot + "/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"} {
		if err = os.Setenv(key, value); err != nil {
			return true, err
		}
	}
	if err = os.Chdir(linuxOwnedControllerRoot); err != nil {
		return true, err
	}
	syscall.Umask(0077)
	runtime.LockOSThread()
	namespace, err := os.Stat("/proc/thread-self/ns/net")
	runtime.UnlockOSThread()
	if err != nil {
		return true, err
	}
	// Incoming controllers/helpers retain their canonical installed image.
	// This service separately retains its immutable generation image and lease.
	service := newLinuxStandardService(linuxOwnedControllerRoot, installed, namespace)
	service.readiness = readiness
	service.imageAuthority, err = captureLinuxStandardImageAuthority(generation, install, owner, linuxOwnedInstallLock)
	if err != nil {
		return true, err
	}
	defer service.imageAuthority.sourceIdentity.Close()
	service.imageUpgrade = successor
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		return true, err
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return true, err
	}
	originalSocket, err := os.Lstat(socket)
	if err != nil {
		return true, err
	}
	// An ordinary service stop signal must not discard retained creation or
	// engine authority. The authenticated idle-upgrade protocol proves actual
	// cleanup before requesting process retirement. Reboot destroys the native
	// namespace; the next boot creates new policy only after native absence.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	if successor != nil {
		bounded, stop := context.WithDeadline(startup, time.Unix(0, successor.envelope.DeadlineNS))
		service.bootFailure = service.prepareImageSuccessor(bounded)
		stop()
	} else {
		service.bootFailure = service.reassert(startup)
	}
	cancel()
	notification, finishNotification := context.WithTimeout(context.Background(), 5*time.Second)
	var notifyErr error
	if successor == nil {
		notifyErr = service.notifyBoot(notification, service.bootFailure)
	}
	finishNotification()
	if notifyErr != nil {
		service.bootFailure = errors.Join(service.bootFailure, notifyErr)
	}
	if service.bootFailure != nil {
		fmt.Fprintln(os.Stderr, service.bootFailure)
	}
	// The actual engine monitor belongs to this retained service lifetime,
	// including all listener-repair attempts. A foreign listener cannot make
	// original controller death or incomplete native cleanup unobserved.
	lifetime, stopLifetime := context.WithCancel(context.Background())
	watchJoined := make(chan struct{})
	go func() { defer close(watchJoined); service.watch(lifetime) }()
	var observerJoin func() error
	var observerFailure error
	var stopWatchOnce sync.Once
	stopWatch := func() {
		stopWatchOnce.Do(func() {
			stopLifetime()
			<-watchJoined
			if observerJoin != nil {
				observerFailure = errors.Join(observerFailure, observerJoin())
			}
		})
	}
	defer func() { stopWatch(); failure = errors.Join(failure, observerFailure) }()
	if observe != nil {
		observerJoin, err = observe(lifetime, service)
		if err != nil {
			return true, err
		}
	}
	for {
		err = service.serve(context.Background(), listener)
		select {
		case <-service.shutdown:
			stopWatch()
			if !service.quiescing {
				return true, errors.New("standard service shutdown lost its original idle proof")
			}
			if service.session != nil && service.session.peer != nil {
				if closeErr := service.session.peer.Close(); closeErr != nil {
					return true, closeErr
				}
			}
			if service.protectionView != nil && service.protectionView.peer != nil && (service.session == nil || service.session.peer != service.protectionView.peer) {
				if closeErr := service.protectionView.peer.Close(); closeErr != nil {
					return true, closeErr
				}
			}
			return true, errors.Join(err, linuxStandardServiceRemoveListener(socket, originalSocket))
		default:
		}
		// Unexpected listener failure never exits a process which may retain an
		// original creator. Recreate only its own still-identical socket inode;
		// a replacement remains untouched and the original owner stays alive.
		fmt.Fprintln(os.Stderr, "standard owner retained after listener failure:", err)
		removed := false
		for {
			if !removed {
				removed = linuxStandardServiceRemoveListener(socket, originalSocket) == nil
			}
			if removed {
				listener, err = net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
				if err == nil {
					listener.SetUnlinkOnClose(false)
					originalSocket, err = os.Lstat(socket)
					removed = false
					chmodErr := os.Chmod(socket, 0600)
					err = errors.Join(err, chmodErr)
					if err == nil {
						break
					}
					_ = listener.Close()
				}
			}
			time.Sleep(time.Second)
		}
	}
}

func linuxStandardServiceRemoveListener(path string, expected os.FileInfo) error {
	actual, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if expected == nil || actual.Mode()&os.ModeSocket == 0 || !ownedDesktopInfo(actual) || !os.SameFile(expected, actual) {
		return errors.New("standard service cannot unlink another listener inode")
	}
	return os.Remove(path)
}
