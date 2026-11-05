//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"router-vpn/internal/mobiletor"
)

// An absent endpoint is not an authenticated service response. Only this
// independent readback can establish the narrower absence needed for an idle
// installation or alongside an already captured native Node parent.
func (c *linuxStandardServiceProtectionClient) observeAbsent(ctx context.Context, parent *desktopPlatformProtectionCapture) error {
	if c == nil || c.app == nil || c.controller == nil || c.namespace == nil {
		return errors.New("service absence lost its original installed controller")
	}
	if _, exists := linuxStandardServiceOwners.Load(c.app); exists {
		return errors.New("service absence cannot erase a retained controller runtime")
	}
	if c.peer != nil {
		retired, err := c.peer.Retired()
		if err != nil || !retired {
			return errors.Join(err, errors.New("service absence retains an unjoined original service"))
		}
	}
	c.app.mu.Lock()
	current := c.app.localController == c.controller && c.app.cfg.ProfilesFile == filepath.Join(linuxOwnedControllerRoot, "routers.json")
	c.app.mu.Unlock()
	if !current {
		return errors.New("service absence changed its original controller or source")
	}
	var originalParent func(context.Context) error
	native := mobiletor.ReadDesktopLinuxProtectionAbsence
	if parent != nil {
		if parent.failure != nil || parent.controller != c.controller || parent.session == nil || parent.session.parent == nil || parent.parent != c.controller.nodeParent {
			return errors.New("scoped service absence has no captured original native parent")
		}
		originalParent = parent.session.parent.Current
		native = mobiletor.ReadDesktopLinuxStandardAndLegacyProtectionAbsence
	}
	return observeLinuxStandardServiceAbsence(ctx, linuxOwnedControllerRoot, linuxStandardServiceDirectory, c.namespace, originalParent, legacyExitTUNAbsent, native)
}

// Production supplies fixed installed paths and actual native observers. The
// explicit arguments let fixtures test real flock/inode/namespace boundaries
// without pretending this workspace can read privileged nft or TUN state.
func observeLinuxStandardServiceAbsence(ctx context.Context, root, directory string, namespace os.FileInfo, parentCurrent func(context.Context) error, tunAbsent func() error, nativeAbsent func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || namespace == nil || tunAbsent == nil || nativeAbsent == nil {
		return errors.New("service absence requires its original bounded observations")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	currentNamespace := func() error {
		actual, err := os.Stat("/proc/thread-self/ns/net")
		if err != nil || !os.SameFile(actual, namespace) {
			return errors.Join(err, errors.New("service absence left its captured namespace"))
		}
		return ctx.Err()
	}
	if err := currentNamespace(); err != nil {
		return err
	}
	if err := ownedDesktopAncestors(filepath.Dir(directory)); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := ownedDesktopAncestors(directory); err != nil {
		return err
	}
	originalDirectory, err := os.Lstat(directory)
	if err != nil || originalDirectory.Mode().Perm()&0077 != 0 {
		return errors.Join(err, errors.New("service lifetime directory is not private"))
	}
	socket := filepath.Join(directory, "control.sock")
	noSocket := func() error {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "g-") && strings.HasSuffix(entry.Name(), ".sock") {
				return errors.New("service absence found a retained or foreign generation listener")
			}
		}
		if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(err, errors.New("service absence found an original or foreign listener"))
		}
		return nil
	}
	if err = noSocket(); err != nil {
		return err
	}
	lockPath := filepath.Join(directory, "owner.lock")
	owner, err := ownedDesktopLock(lockPath, true)
	if err != nil {
		return err
	}
	defer owner.Close()
	originalLock, err := owner.Stat()
	if err != nil {
		return err
	}
	current := func() error {
		if err := currentNamespace(); err != nil {
			return err
		}
		actualDirectory, err := os.Lstat(directory)
		actualLock, lockErr := owner.Stat()
		namedLock, nameErr := os.Lstat(lockPath)
		if err != nil || lockErr != nil || nameErr != nil || !os.SameFile(originalDirectory, actualDirectory) || !ownedDesktopInfo(actualDirectory) || !os.SameFile(originalLock, actualLock) || !os.SameFile(originalLock, namedLock) {
			return errors.Join(err, lockErr, nameErr, errors.New("service absence changed its original lifetime lock or directory"))
		}
		return noSocket()
	}
	if err = current(); err != nil {
		return err
	}
	lease, err := acquireLegacyExitMutationLease(ctx, root)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err = legacyExitStateAbsent(lease); err != nil {
		return err
	}
	if parentCurrent != nil {
		if err = parentCurrent(ctx); err != nil {
			return err
		}
	} else if err = tunAbsent(); err != nil {
		return err
	}
	if err = nativeAbsent(ctx); err != nil {
		return err
	}
	if parentCurrent != nil {
		if err = parentCurrent(ctx); err != nil {
			return err
		}
	} else if err = tunAbsent(); err != nil {
		return err
	}
	if err = legacyExitStateAbsent(lease); err != nil {
		return err
	}
	return current()
}
