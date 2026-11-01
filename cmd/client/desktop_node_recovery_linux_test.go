//go:build linux

package main

import (
	"context"
	"strings"
	"testing"

	"router-vpn/internal/linuxprotection"
)

// These values exercise comparison constraints only. Actual creator exit,
// retained locks, journal inodes and native absence run in the namespace gate.
func linuxEmptyRecoveryComparison() (linuxprotection.ParentRecord, linuxprotection.ParentRecord) {
	object := func(device, inode uint64, mode uint32) linuxprotection.NativeObject {
		return linuxprotection.NativeObject{Device: device, Inode: inode, Mode: mode}
	}
	old := linuxprotection.ParentRecord{Generation: strings.Repeat("1", 32), BootID: "11111111-2222-4333-8444-555555555555",
		ProcessID: 101, ProcProcessID: 301, StartTicks: 300, CallerUID: 1000,
		InstallationAnchor: object(1, 1, 0040755), Root: object(1, 2, 0040755), Image: object(1, 3, 0100755),
		Input: object(2, 4, 0010600), InstallLock: object(1, 5, 0100600), ProcessLock: object(1, 6, 0100600),
		NetworkNamespace: object(3, 7, 0100444), PIDNamespace: object(3, 8, 0100444)}
	old.Input.UID = old.CallerUID
	next := old
	next.Generation, next.ProcessID, next.ProcProcessID, next.StartTicks = strings.Repeat("2", 32), 102, 302, 400
	next.Input.Inode++
	return old, next
}

func TestDesktopLinuxEmptyRecoveryCreatorComparison(t *testing.T) {
	for name, change := range map[string]func(*linuxprotection.ParentRecord, *linuxprotection.ParentRecord){
		"distinct":        func(_, _ *linuxprotection.ParentRecord) {},
		"package-upgrade": func(_, next *linuxprotection.ParentRecord) { next.Root.Inode += 20; next.Image.Inode += 20 },
		"same-tick":       func(old, next *linuxprotection.ParentRecord) { next.StartTicks = old.StartTicks },
		"same-capture":    func(old, next *linuxprotection.ParentRecord) { next.Generation = old.Generation },
		"same-pid":        func(old, next *linuxprotection.ParentRecord) { next.ProcessID = old.ProcessID },
		"same-proc-pid":   func(old, next *linuxprotection.ParentRecord) { next.ProcProcessID = old.ProcProcessID },
		"future-creator":  func(old, next *linuxprotection.ParentRecord) { old.StartTicks = next.StartTicks + 1 },
		"boot":            func(_, next *linuxprotection.ParentRecord) { next.BootID = "21111111-2222-4333-8444-555555555555" },
		"caller":          func(_, next *linuxprotection.ParentRecord) { next.CallerUID++; next.Input.UID++ },
		"anchor":          func(_, next *linuxprotection.ParentRecord) { next.InstallationAnchor.Inode += 10 },
		"install-lock":    func(_, next *linuxprotection.ParentRecord) { next.InstallLock.Inode += 10 },
		"process-lock":    func(_, next *linuxprotection.ParentRecord) { next.ProcessLock.Inode += 10 },
		"network":         func(_, next *linuxprotection.ParentRecord) { next.NetworkNamespace.Inode += 10 },
		"pid-namespace":   func(_, next *linuxprotection.ParentRecord) { next.PIDNamespace.Inode += 10 },
		"old-invalid":     func(old, _ *linuxprotection.ParentRecord) { old.Input.Mode = 0100600 },
		"new-invalid":     func(_, next *linuxprotection.ParentRecord) { next.Image.Mode = 0100777 },
	} {
		t.Run(name, func(t *testing.T) {
			old, next := linuxEmptyRecoveryComparison()
			change(&old, &next)
			err := checkDesktopLinuxEmptyRecoveryCreator(old, next)
			valid := name == "distinct" || name == "package-upgrade" || name == "same-tick"
			if (err == nil) != valid {
				t.Fatal("creator comparison changed stable original-owner constraints", err)
			}
		})
	}
}

func TestDesktopLinuxEmptyRecoveryRequiresCapturedOwner(t *testing.T) {
	for name, recovery := range map[string]*desktopLinuxEmptyJournalRecovery{
		"absent": nil, "no-session": {}, "no-journal": {session: &desktopLinuxNodeSession{}},
		"foreign-session": {session: &desktopLinuxNodeSession{}, journal: &desktopLinuxNodeJournal{}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := recovery.current(context.Background(), false); err == nil {
				t.Fatal("comparison-only recovery manufactured native authority")
			}
		})
	}
	if err := (&app{}).initializeDesktopNodeRecovery(); err != nil {
		t.Fatal("unprivileged utility startup created an installed recovery owner", err)
	}
}
