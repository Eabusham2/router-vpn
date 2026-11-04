//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"syscall"
)

// A prior-boot receipt selects the standard policy implementation only. Its
// fields never recreate native ownership; reassert still proves full absence
// and obtains a fresh creator before changing any saved state.
func linuxStandardServiceStandardMarker(body []byte) (bool, error) {
	var row map[string]json.RawMessage
	if err := decodeRelayControlJSON(body, &row); err != nil {
		return false, err
	}
	raw, exists := row["linux_standard_owner"]
	if !exists {
		return false, nil
	}
	var marker legacyExitProtectionMarker
	if err := decodeRelayControlJSON(raw, &marker); err != nil {
		return false, err
	}
	r := marker.Receipt
	validHex := func(value string, size int) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(value) == size && hex.EncodeToString(decoded) == value
	}
	bounded := func(value uint64) bool { return value > 0 && value < 1<<53 }
	if marker.Schema != 1 || !regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).MatchString(marker.BootID) ||
		!validHex(r.Session, 32) || !validHex(r.ConfigSHA256, 64) || !validHex(r.BaselineSHA256, 64) || r.Table != "router_vpn_standard_"+r.Session ||
		!bounded(r.NamespaceDevice) || !bounded(r.NamespaceInode) || !bounded(r.TableHandle) || !bounded(r.ChainHandle) || r.CreationGeneration == 0 {
		return false, errors.New("standard boot selection has an invalid prior creation marker")
	}
	var baseline map[string]json.RawMessage
	if err := decodeRelayControlJSON(r.Baseline, &baseline); err != nil || len(baseline) < 5 || len(baseline) > 22 {
		return false, errors.Join(err, errors.New("standard boot selection lost its bounded prior baseline"))
	}
	for key := range baseline {
		handle, err := strconv.ParseUint(key, 10, 64)
		if err != nil || !bounded(handle) || strconv.FormatUint(handle, 10) != key || handle == r.ChainHandle {
			return false, errors.New("standard boot selection has an invalid prior rule identity")
		}
	}
	canonical, err := json.Marshal(baseline)
	digest := sha256.Sum256(canonical)
	if err != nil || hex.EncodeToString(digest[:]) != r.BaselineSHA256 {
		return false, errors.Join(err, errors.New("standard boot selection lost its prior baseline digest"))
	}
	return true, nil
}

// The service retains this exact created helper through deadline expiry. It
// never kills it and assumes its nft child disappeared, nor starts a replacement
// while its original Wait/pidfd and mutation lease remain unresolved.
type linuxStandardServiceLegacyBoot struct {
	command          *exec.Cmd
	pidfd            *os.File
	originalPIDFD    *os.File
	pidInfo          os.FileInfo
	done             chan struct{}
	err              error
	joined, complete bool
}

func (s *linuxStandardService) reassertLegacy(ctx context.Context) error {
	if s.root != linuxOwnedControllerRoot {
		return errors.New("legacy boot helper requires its fixed installed source")
	}
	if s.legacyBoot == nil {
		// The fixed child inherits its own reference to the installation lease.
		// Unexpected service death cannot let an installer rename its source
		// while that original helper is still executing.
		source, err := ownedDesktopLock(linuxOwnedInstallLock, false)
		if err != nil {
			return err
		}
		defer source.Close()
		command := exec.Command("/usr/bin/python3", "-Es", filepath.Join(linuxOwnedControllerRoot, "modes", "kill-switch.py"), "reassert")
		command.ExtraFiles = []*os.File{source}
		command.Dir = linuxOwnedControllerRoot
		command.Env = []string{"HOME=/root", "LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOMEVPN_LEGACY_BOOT_ONLY=1", "HOMEVPN_ROOT=" + linuxOwnedControllerRoot}
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := s.startLegacyBoot(ctx, command); err != nil {
			return err
		}
	}
	return s.joinLegacyBoot(ctx)
}

// command is constructed only by the fixed production wrapper above. The
// argument is also the explicit real-child test boundary, not a wire input.
func (s *linuxStandardService) startLegacyBoot(ctx context.Context, command *exec.Cmd) error {
	if ctx == nil || ctx.Err() != nil || s.legacyBoot != nil || command == nil {
		return errors.New("legacy boot lost its original bounded child admission")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("legacy boot helper requires its original deadline")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	namespace, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(namespace, s.namespace) {
		return errors.Join(err, errors.New("legacy boot helper left its original namespace"))
	}
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err = command.Start(); err != nil {
		return err
	}
	owner := &linuxStandardServiceLegacyBoot{command: command, done: make(chan struct{})}
	s.legacyBoot = owner
	if pidfd >= 0 {
		owner.pidfd = os.NewFile(uintptr(pidfd), "original-legacy-boot-helper")
		owner.originalPIDFD = owner.pidfd
		owner.pidInfo, err = owner.pidfd.Stat()
	}
	go func() { owner.err = command.Wait(); close(owner.done) }()
	if owner.pidfd == nil || err != nil {
		return errors.Join(err, errors.New("legacy boot helper creation lost its original pidfd"))
	}
	return nil
}

func (s *linuxStandardService) joinLegacyBoot(ctx context.Context) error {
	owner := s.legacyBoot
	if owner == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("legacy boot has no live original completion request")
	}
	if owner.complete {
		return owner.err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-owner.done:
	}
	if owner.pidfd == nil || owner.pidfd != owner.originalPIDFD || owner.pidInfo == nil {
		return errors.New("legacy boot completion changed its original child descriptor")
	}
	actual, err := owner.pidfd.Stat()
	if err != nil || !os.SameFile(actual, owner.pidInfo) {
		return errors.Join(err, errors.New("legacy boot completion changed its original child identity"))
	}
	if err := legacyExitPIDFDRetired(owner.pidfd); err != nil {
		return err
	}
	owner.joined = true
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	namespace, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil || !os.SameFile(namespace, s.namespace) {
		return errors.Join(err, errors.New("legacy boot join left its original namespace"))
	}
	// Python passes its original mutation descriptor to nft. Acquiring this
	// same lock proves no still-running mutation child retains that authority.
	lease, err := acquireLegacyExitMutationLease(ctx, s.root)
	if err != nil {
		return errors.Join(owner.err, err)
	}
	defer lease.Close()
	if err = lease.Current(); err != nil {
		return err
	}
	if err = owner.pidfd.Close(); err != nil {
		return err
	}
	owner.complete = true
	return errors.Join(owner.err, ctx.Err())
}
