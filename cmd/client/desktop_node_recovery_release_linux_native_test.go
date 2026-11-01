//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

var linuxReleaseRecoveryCases = []string{"startup", "restart", "cancel-retry", "cancel-shutdown",
	"live-controller", "zombie-controller", "different-birth-controller", "live-engine", "zombie-engine", "different-birth-engine",
	"live-guardian", "zombie-guardian", "different-birth-guardian", "native-still-present", "foreign-node", "fixed-legacy", "unrelated-policy",
	"always-release", "saved-off", "partial-record", "chain-mismatch", "creator-drift", "checkpoint-drift", "replaced-session",
	"replacement-owner", "root-replaced", "slot-replaced", "slot-bytes", "namespace-changed"}

// Reach the actual crash window with the shipping transaction primitives:
// authenticate the original installed engine, create its guardian and nft
// table, join both processes, durably append its release intent, and remove
// only that original baseline. Stop here, before the final empty append.
// Graph/TUN readiness remains the established transaction fixture boundary.
func linuxNodeReleaseRecoverySeed(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, scenario string) error {
	j, err := createDesktopLinuxNodeJournal(ctx, parent)
	if err != nil {
		return err
	}
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	transaction, cancel, directory, err := linuxTransactionStart(ctx, a, parent, j, nil, strings.Repeat("a", 32), "on-connect", "release-recovery")
	if err != nil {
		return err
	}
	defer cancel()
	if err := linuxTransactionPrepare(ctx, transaction, "release-recovery", directory, cancel); err != nil {
		return err
	}
	if err := linuxTransactionRetire(ctx, transaction, "release-recovery", directory); err != nil {
		return err
	}
	if err := transaction.enter(ctx); err != nil {
		return err
	}
	next := transaction.nextRecord()
	next.Phase = "intent"
	next.Intent = &linuxprotection.JournalIntent{Action: "release", RequestID: transaction.selection.SessionID,
		ProfileID: transaction.profileID, ProfileRevision: transaction.revision, ResultProfileRevision: transaction.revision}
	err = transaction.appendRecord(ctx, next)
	transaction.gate <- struct{}{}
	if err != nil {
		return err
	}
	if scenario != "seed-native-present" {
		if err := transaction.baseline.Release(ctx); err != nil {
			return err
		}
		if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
			return err
		}
	} else if transaction.baseline.ObserveClosed(ctx) != nil || mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) == nil {
		return errors.New("release crash fixture lost its original still-closed native baseline")
	}
	if !transaction.retired || !transaction.engineJoined || transaction.process.command.ProcessState == nil ||
		j.current.Incomplete || j.current.Record.Phase != "intent" || j.current.Record.Intent.Action != "release" ||
		j.current.Record.Committed.Engine != nil || j.current.Record.Committed.Target == nil || j.pending != nil {
		return errors.New("release crash fixture omitted actual original process joining or durable intent")
	}
	if scenario == "seed-live" {
		// This negative deliberately releases only fixture locks. The actual
		// original controller stays live and cannot be inferred dead from them.
		if err := errors.Join(j.lock.file.Close(), a.localController.processLock.Close()); err != nil {
			return err
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, "captured-release-checkpoint-ready"); err != nil {
		return err
	}
	gate := os.NewFile(3, "original-release-checkpoint-crash-gate")
	defer gate.Close()
	var forbidden [1]byte
	_, err = io.ReadFull(gate, forbidden[:])
	return errors.Join(err, errors.New("release crash fixture must end through its actual originating exec.Cmd"))
}

// Wait on an actual child of this test without reaping it. The recovery code
// must reject its real zombie pidfd, not treat successful exit as ESRCH.
func linuxReleaseRecoveryZombie(t *testing.T, child *exec.Cmd) {
	t.Helper()
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var info [128]byte
	_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1, uintptr(child.Process.Pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
	if errno != 0 || binary.NativeEndian.Uint32(info[0:4]) != uint32(syscall.SIGCHLD) || binary.NativeEndian.Uint32(info[8:12]) != 2 {
		t.Fatal("fixture did not retain its actual killed child as a zombie", errno)
	}
}

// These negative controls deliberately replace comparison identities in the
// original private files. A real unrelated live/zombie process occupies the
// recorded PID, simulating reuse without claiming that Linux recycled a PID
// on demand. The old birth/image claims must never override its live pidfd.
func linuxReleaseRecoveryRewrite(t *testing.T, role string, pid int) {
	t.Helper()
	root := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
	var records [2]linuxprotection.JournalRecord
	for index, name := range desktopLinuxNodeJournalSlots {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		records[index], err = linuxprotection.ParseJournalRecord(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	older, newer := 0, 1
	if records[0].Sequence > records[1].Sequence {
		older, newer = 1, 0
	}
	for index := range records {
		r := &records[index]
		switch role {
		case "controller":
			r.Controller.ProcessID = pid
		case "engine":
			r.Committed.Target.Guardian.ParentProcessID = pid
		case "guardian":
			r.Committed.Target.Guardian.ProcessID = pid
			r.Committed.Target.Native.Owner.ProcessID = uint32(pid)
		case "always":
			r.Committed.Target.Policy = "always"
			if r.Intent != nil {
				r.Intent.Candidate = linuxprotection.CloneState(r.Committed)
			}
		case "off":
			if r.Intent != nil {
				r.Intent.Action, r.Intent.ResultProfileRevision = "off", strings.Repeat("e", 64)
			}
		case "chain":
		case "partial":
		default:
			t.Fatal("unknown deliberate release record substitution", role)
		}
	}
	first, err := linuxprotection.CanonicalJournalRecord(records[older])
	if err != nil {
		t.Fatal(err)
	}
	previous, err := linuxprotection.JournalRecordSHA256(first)
	if err != nil {
		t.Fatal(err)
	}
	records[newer].PreviousSHA256 = previous
	if role == "chain" {
		records[newer].PreviousSHA256 = strings.Repeat("f", 64)
	}
	second, err := linuxprotection.CanonicalJournalRecord(records[newer])
	if err != nil {
		t.Fatal(err)
	}
	if role == "partial" {
		second = second[:len(second)/2]
	}
	for index, body := range map[int][]byte{older: first, newer: second} {
		if err := os.WriteFile(filepath.Join(root, desktopLinuxNodeJournalSlots[index]), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if role == "controller" {
		path := filepath.Join(root, desktopLinuxNodeJournalHeader)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		header, err := linuxprotection.ParseJournalHeader(body)
		if err != nil {
			t.Fatal(err)
		}
		header.Creator.ProcessID = pid
		body, err = linuxprotection.CanonicalJournalHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxOwnedControllerNamespaceReleaseJournalRecovery(t *testing.T) {
	// Require the existing explicit privileged namespace and private /opt
	// checks before this test creates any interface or native rule.
	_ = linuxJournalNamespaceInstall(t)
	// This group shares the controller runner's private network namespace.
	// Only this actual fixture-created interface is removed at group teardown.
	for _, args := range [][]string{{"link", "add", "rvpn-test", "type", "veth", "peer", "name", "rvpn-recv-peer"}, {"addr", "add", "198.18.0.1/24", "dev", "rvpn-test"}, {"link", "set", "rvpn-test", "up"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "link", "delete", "rvpn-test").CombinedOutput(); err != nil {
			t.Error(err, string(out))
		}
	})
	for _, scenario := range linuxReleaseRecoveryCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxJournalNamespaceInstall(t)
			seed, follow := "seed", scenario
			if scenario == "live-controller" {
				seed, follow = "seed-live", "live-creator"
			}
			if scenario == "zombie-controller" {
				follow = "live-creator"
			}
			if scenario == "native-still-present" {
				seed, follow = "seed-native-present", "nonempty-record"
			}
			first := startLinuxNodeParentProcess(t, installed, "empty-recovery/release-"+seed)
			line, err := first.reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "captured-release-checkpoint-ready" {
				t.Fatal("original controller did not reach its actual released checkpoint", line, err, first.diagnostic.String())
			}
			if scenario == "zombie-controller" {
				linuxReleaseRecoveryZombie(t, first.command)
			} else if scenario != "live-controller" {
				if err := first.command.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				if err := first.join(); err == nil {
					t.Fatal("original controller did not actually crash")
				}
			}
			if scenario == "native-still-present" {
				// This isolated fixture created the original table above. Recovery
				// must preserve it; only the test's explicit teardown removes it.
				name := "router_vpn_node_" + strings.Repeat("a", 32)
				t.Cleanup(func() {
					if out, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", name).CombinedOutput(); err != nil {
						t.Error("recovery removed original protection", err, string(out))
						return
					}
					if out, err := exec.Command("/usr/sbin/nft", "delete", "table", "inet", name).CombinedOutput(); err != nil {
						t.Error(err, string(out))
					}
				})
			}
			role := ""
			for _, candidate := range []string{"controller", "engine", "guardian"} {
				if strings.HasSuffix(scenario, "-"+candidate) && scenario != "live-controller" && scenario != "zombie-controller" {
					role = candidate
				}
			}
			if role != "" {
				child := exec.Command("sleep", "20")
				if err := child.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
				if strings.HasPrefix(scenario, "zombie-") {
					linuxReleaseRecoveryZombie(t, child)
				}
				linuxReleaseRecoveryRewrite(t, role, child.Process.Pid)
				follow = "live-creator"
			}
			switch scenario {
			case "always-release":
				linuxReleaseRecoveryRewrite(t, "always", 0)
				follow = "nonempty-record"
			case "saved-off":
				linuxReleaseRecoveryRewrite(t, "off", 0)
				follow = "intent-record"
			case "partial-record":
				linuxReleaseRecoveryRewrite(t, "partial", 0)
			case "chain-mismatch":
				linuxReleaseRecoveryRewrite(t, "chain", 0)
				follow = "open-error"
			}
			original := make(map[string][]byte)
			root := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
			for _, name := range append(desktopLinuxNodeJournalSlots[:], desktopLinuxNodeJournalHeader, desktopLinuxNodeJournalLock) {
				body, err := os.ReadFile(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				original[name] = body
			}
			second := startLinuxNodeParentProcess(t, installed, "empty-recovery/release-"+follow)
			if _, err := second.gate.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			line, err = second.reader.ReadString('\n')
			want := "captured-empty-recovery-rejected"
			success := scenario == "startup" || scenario == "restart" || scenario == "cancel-retry" || scenario == "cancel-shutdown" || scenario == "unrelated-policy"
			if success {
				want = "captured-empty-recovery-complete"
			}
			if err != nil || strings.TrimSpace(line) != want {
				second.cancel()
				_ = second.join()
				t.Fatal("actual release recovery changed its crash/owner boundary", line, err, second.diagnostic.String())
			}
			if err := second.join(); err != nil {
				t.Fatal(err, second.diagnostic.String())
			}
			if !success {
				for name, expected := range original {
					body, err := os.ReadFile(filepath.Join(root, name))
					if err != nil || !bytes.Equal(body, expected) {
						t.Fatal("rejected release recovery changed captured private bytes", name, err)
					}
				}
			}
		})
	}
}
