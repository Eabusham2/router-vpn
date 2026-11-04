//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"router-vpn/internal/mobiletor"
)

const linuxStandardServiceUpgradeArgument = "--linux-standard-owner-upgrade"

// The caller holds the service gate from admission through its shutdown reply.
// Nothing here retires a process or deletes protection. Upgrade can only yield
// an already idle owner after independent, complete native absence readback.
func (s *linuxStandardService) prepareIdleShutdown(ctx context.Context) error {
	return s.prepareIdleShutdownWithObservers(ctx, legacyExitTUNAbsent, mobiletor.ReadDesktopLinuxProtectionAbsence)
}

func (s *linuxStandardService) prepareIdleShutdownWithObservers(ctx context.Context, tunAbsent func() error, protectionAbsent func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || s == nil || s.namespace == nil || tunAbsent == nil || protectionAbsent == nil {
		return errors.New("standard service upgrade requires its original bounded owner")
	}
	if s.session != nil && (!s.session.joined || s.session.cleanupPending) {
		return errors.New("standard service upgrade requires completed original engine cleanup")
	}
	if s.legacyBoot != nil && !s.legacyBoot.complete {
		return errors.New("standard service upgrade retains its original legacy boot helper")
	}
	if s.protectionView != nil && s.protectionView.data.Pending {
		return errors.New("standard service upgrade retains an accepted Off profile-save operation; finish the original change first")
	}
	if _, exists := legacyStandardExitOwners.Load(s.app); exists {
		return errors.New("standard service upgrade retains an original engine owner")
	}
	if _, exists := legacyStandardProtectionOwners.Load(s.app); exists {
		return errors.New("standard service upgrade retains original Always protection; select Off and complete its owned cleanup first")
	}
	if s.boot != nil && !s.boot.closed {
		return errors.New("standard service upgrade retains its original boot protection creator")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(current, s.namespace) {
		return errors.Join(err, errors.New("standard service upgrade left its original network namespace"))
	}
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err = legacyExitStateAbsent(lease); err != nil {
		return err
	}
	if err = tunAbsent(); err != nil {
		return err
	}
	if err = protectionAbsent(ctx); err != nil {
		return err
	}
	if err = legacyExitStateAbsent(lease); err != nil {
		return err
	}
	after, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(after, s.namespace) || !os.SameFile(current, after) {
		return errors.Join(err, errors.New("standard service upgrade lost its original namespace during readback"))
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	s.quiescing = true
	return nil
}

// This is a fixed installed root helper, not an arbitrary service/PID stop
// command. Its shared installation lock remains held until the original
// authenticated service's pidfd proves retirement and its listener is absent.
func linuxStandardServiceUpgradeUtility(arguments []string) (bool, error) {
	selected := false
	for _, argument := range arguments {
		if argument == linuxStandardServiceUpgradeArgument {
			selected = true
		}
	}
	if !selected {
		return false, nil
	}
	if len(arguments) != 1 || arguments[0] != linuxStandardServiceUpgradeArgument || os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, errors.New("standard service upgrade requires its fixed privileged launch")
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
	image, err := os.Stat("/proc/self/exe")
	installed, installedErr := os.Lstat(filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"))
	if err != nil || installedErr != nil || !os.SameFile(image, installed) {
		return true, errors.Join(err, installedErr, errors.New("standard upgrade helper is not its original installed executable"))
	}
	runtime.LockOSThread()
	namespace, err := os.Stat("/proc/thread-self/ns/net")
	runtime.UnlockOSThread()
	if err != nil {
		return true, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = os.Lstat(linuxStandardServiceSocket); errors.Is(err, os.ErrNotExist) {
		// A clean idle predecessor may already have exited. Absence authorizes
		// only this fresh source-installation check, never adoption or deletion
		// of any persisted/native protection. The exclusive lifetime lock also
		// excludes a service that has not yet published its listener.
		if err = ownedDesktopAncestors(linuxStandardServiceDirectory); err != nil {
			return true, err
		}
		owner, lockErr := ownedDesktopLock(filepath.Join(linuxStandardServiceDirectory, "owner.lock"), true)
		if lockErr != nil {
			return true, lockErr
		}
		defer owner.Close()
		if _, err = os.Lstat(linuxStandardServiceSocket); !errors.Is(err, os.ErrNotExist) {
			return true, errors.Join(err, errors.New("standard upgrade cannot replace an original listener"))
		}
		service := newLinuxStandardService(linuxOwnedControllerRoot, image, namespace)
		return true, service.prepareIdleShutdown(ctx)
	} else if err != nil {
		return true, err
	}
	return true, linuxStandardServiceUpgrade(ctx, linuxStandardServiceSocket, image, namespace,
		[]string{filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"), linuxStandardServiceArgument})
}

func linuxStandardServiceUpgrade(ctx context.Context, socket string, image, namespace os.FileInfo, serviceArguments []string) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("standard service upgrade was cancelled before admission")
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return errors.New("standard service upgrade requires its original deadline")
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unixpacket", socket)
	if err != nil {
		return err
	}
	defer connection.Close()
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("standard service upgrade lost its actual native channel")
	}
	return linuxStandardServiceUpgradeChannel(ctx, channel, socket, image, namespace, serviceArguments)
}

func linuxStandardServiceUpgradeChannel(ctx context.Context, channel *net.UnixConn, socket string, image, namespace os.FileInfo, serviceArguments []string) error {
	if ctx == nil || ctx.Err() != nil || channel == nil {
		return errors.New("standard service upgrade lost its original bounded channel")
	}
	deadline, bounded := ctx.Deadline()
	remaining := time.Until(deadline)
	if !bounded || remaining < time.Millisecond || remaining > 120*time.Second {
		return errors.New("standard service upgrade has an invalid original budget")
	}
	session, err := randomHex(16)
	if err != nil {
		return err
	}
	finish, err := linuxStandardServiceDeadline(ctx, channel)
	if err != nil {
		return err
	}
	defer finish()
	peer, err := captureLinuxStandardServicePeer(ctx, channel, image, serviceArguments, namespace)
	if err != nil {
		return err
	}
	defer peer.Close()
	request := linuxStandardServiceRequest{Schema: 1, Action: "shutdown-idle", Session: session, BudgetMS: remaining.Milliseconds(), DeadlineNS: deadline.UnixNano()}
	if err = linuxStandardServiceWrite(channel, request, nil); err != nil {
		return err
	}
	body, files, err := linuxStandardServiceRead(channel)
	for _, file := range files {
		_ = file.Close()
	}
	if len(files) != 0 {
		err = errors.Join(err, errors.New("standard service upgrade response supplied unexpected authority"))
	}
	replyErr := err
	var response linuxStandardServiceResponse
	if replyErr == nil {
		replyErr = linuxStandardServiceDecode(body, &response)
		if replyErr == nil && (response.Schema != 1 || response.Session != session || response.Action != request.Action || response.Complete == (response.Error != "") || len(response.Error) > 2048) {
			replyErr = errors.New("standard service upgrade returned another operation's completion")
		}
		if replyErr == nil && !response.Complete {
			return errors.New(response.Error)
		}
	}
	// A protocol response is never process retirement. Observe only the exact
	// pidfd acquired from this authenticated connected service, never its PID.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		retired, err := peer.Retired()
		if err != nil {
			return errors.Join(replyErr, err)
		}
		if retired {
			break
		}
		select {
		case <-ctx.Done():
			return errors.Join(replyErr, ctx.Err())
		case <-ticker.C:
		}
	}
	if _, err = os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(replyErr, err, errors.New("original standard service did not retire its exact listener"))
	}
	// Even when the reply was lost, join the original process within the same
	// budget. Uncertain protocol completion still fails this install attempt.
	return errors.Join(replyErr, ctx.Err())
}
