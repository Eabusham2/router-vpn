//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

func linuxJournalCheckpoint(selected linuxprotection.JournalSelection) linuxprotection.JournalRecord {
	next := linuxprotection.CloneRecord(selected.Record)
	next.Sequence++
	next.PreviousSHA256 = selected.SHA256
	return next
}

// This is deliberately only comparison data for a rejected alternate append.
// No engine, guardian, firewall object or working network is manufactured by
// these values; the test proves they cannot replace a pending actual write.
func linuxJournalRejectedAlternative(selected linuxprotection.JournalSelection) linuxprotection.JournalRecord {
	next := linuxJournalCheckpoint(selected)
	p := next.Controller
	engine := linuxprotection.ProcessRecord{BootID: p.BootID, ProcessID: p.ProcessID + 10000, ProcProcessID: p.ProcProcessID + 10000,
		ParentProcessID: p.ProcessID, StartTicks: p.StartTicks + 10, Image: p.Image, NetworkNamespace: p.NetworkNamespace, PIDNamespace: p.PIDNamespace}
	guardian := engine
	guardian.ProcessID++
	guardian.ProcProcessID++
	guardian.ParentProcessID = engine.ProcessID
	guardian.StartTicks++
	target := linuxprotection.ProtectionTarget{Policy: "always", ConfigSHA256: strings.Repeat("a", 64), Guardian: guardian,
		Native: mobiletor.DesktopLinuxProtectionRecord{Capture: mobiletor.DesktopSocketCapture{SessionID: strings.Repeat("b", 32), SourceSHA256: strings.Repeat("c", 64), NetworkID: strings.Repeat("d", 32)},
			Owner: mobiletor.DesktopSocketKernelOwner{Kind: "unix-isolated-uid", IdentitySHA256: strings.Repeat("e", 64), Generation: 1, ProcessID: uint32(guardian.ProcessID)},
			UID:   55001, PermitPrefix: "rvpn_" + strings.Repeat("f", 20), TableHandle: 1, ChainHandle: 2, BaselineSHA256: strings.Repeat("0", 64)}}
	next.Phase = "intent"
	next.Intent = &linuxprotection.JournalIntent{Action: "successor", RequestID: strings.Repeat("1", 32), ProfileID: "comparison-only", ProfileRevision: strings.Repeat("2", 64), ResultProfileRevision: strings.Repeat("2", 64),
		Candidate: linuxprotection.JournalState{Target: &target, ProfileID: "comparison-only", ProfileRevision: strings.Repeat("2", 64), Engine: &engine}}
	return next
}

func linuxJournalPartialWrite(j *desktopLinuxNodeJournal) error {
	selected, err := j.Snapshot(context.Background())
	if err != nil {
		return err
	}
	next := linuxJournalCheckpoint(selected)
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil || original.Cur < 512 {
		return errors.Join(err, errors.New("fixture has no bounded file-size limit"))
	}
	limited := original
	limited.Cur = 512
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		return err
	}
	_, writeErr := j.Append(context.Background(), selected.SHA256, next)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
		return err
	}
	if !errors.Is(writeErr, syscall.EFBIG) || j.pending == nil || j.current.SHA256 != selected.SHA256 {
		return errors.Join(writeErr, errors.New("actual partial file write was acknowledged or lost its immutable pending owner"))
	}
	partial, err := j.readFile(j.slots[j.pending.slot], linuxprotection.JournalRecordLimit)
	if err != nil || len(partial) != 512 || bytes.Equal(partial, j.pending.body) {
		return errors.Join(err, errors.New("file-size limit did not produce the expected real torn inactive slot"))
	}
	if _, err := j.Snapshot(context.Background()); err == nil {
		return errors.New("pending native write became a successful snapshot")
	}
	alternate := linuxJournalRejectedAlternative(selected)
	if err := linuxprotection.CheckJournalTransition(selected.Record, alternate); err != nil {
		return err
	}
	if _, err := j.Append(context.Background(), selected.SHA256, alternate); err == nil {
		return errors.New("a different valid record replaced the pending durable append")
	}
	saved, err := j.Append(context.Background(), selected.SHA256, next)
	if err != nil || saved.Record.Sequence != next.Sequence || j.pending != nil {
		return errors.Join(err, errors.New("exact native partial-write retry did not flush its captured record"))
	}
	return nil
}

func linuxJournalRetainsNativeCloseError(j *desktopLinuxNodeJournal, owner *ownedDesktopController) error {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil || limit.Max >= 1<<31-1 {
		return errors.Join(err, errors.New("journal close fixture has no provably unassigned native descriptor"))
	}
	// Preserve the real original file separately. The substituted descriptor
	// lies above the native hard limit and cannot name a live or reused file.
	// This produces an actual Close EBADF without raw-closing any real owner.
	original := j.slots[0].file
	defer original.Close()
	j.slots[0].file = os.NewFile(uintptr(1<<31-1), "unassigned-journal-close-fixture")
	if j.slots[0].file == nil {
		return errors.New("journal close fixture did not retain its native error wrapper")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := j.Close(context.Background()); !errors.Is(err, syscall.EBADF) || j.closeErr == nil || j.closed || j.released {
			return errors.Join(err, errors.New("native journal close failure became a joined durable owner"))
		}
		owner.close()
		if j.parent.parent.closed || j.lock == nil || j.lock.file == nil {
			return errors.New("failed journal join released its parent or stable lock")
		}
		for _, file := range []*os.File{original, j.lock.file, owner.input, owner.installLock, owner.processLock} {
			if _, err := file.Stat(); err != nil {
				return errors.Join(err, errors.New("failed journal join closed an original retained owner"))
			}
		}
	}
	other, err := os.OpenFile(filepath.Join("/opt", desktopLinuxNodeJournalDirectory, desktopLinuxNodeJournalLock), os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer other.Close()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		return errors.Join(err, errors.New("unjoined journal no longer excluded another actual file description"))
	}
	return nil
}

func linuxNodeJournalFixture(owner *ownedDesktopController, scenario string) error {
	a := &app{localController: owner, cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"),
		ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	capture, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	var journal *desktopLinuxNodeJournal
	if scenario == "open-restart" {
		journal, err = openDesktopLinuxNodeJournal(context.Background(), capture)
	} else {
		journal, err = createDesktopLinuxNodeJournal(context.Background(), capture)
	}
	if journal != nil {
		defer journal.Close(context.Background())
	}
	if scenario == "foreign-nft" {
		if err == nil || journal == nil {
			return errors.New("existing unowned nft table became initial journal absence")
		}
		if _, statErr := os.Lstat(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("rejected native absence created or adopted journal files")
		}
	} else if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(capture.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "linux-journal-fixture-gate")
	defer gate.Close()
	var one [1]byte
	if _, err := io.ReadFull(gate, one[:]); err != nil || one[0] != 1 {
		return errors.Join(err, errors.New("journal fixture lost its exact rendezvous"))
	}
	switch scenario {
	case "roundtrip":
		initial, err := journal.Snapshot(context.Background())
		if err != nil {
			return err
		}
		if initial.Record.Sequence != 1 || initial.Record.Controller != capture.record || initial.Incomplete {
			return errors.New("created journal lost actual native creator")
		}
		header := journal.header
		duplicate, err := openDesktopLinuxNodeJournal(context.Background(), capture)
		if duplicate != nil {
			if closeErr := duplicate.Close(context.Background()); closeErr != nil {
				return closeErr
			}
		}
		if err == nil {
			return errors.New("a second file description acquired the owned exclusive journal lock")
		}
		saved, err := journal.Append(context.Background(), initial.SHA256, linuxJournalCheckpoint(initial))
		if err != nil || saved.Record.Sequence != 2 {
			return errors.Join(err, errors.New("actual checkpoint append failed"))
		}
		if err := journal.Close(context.Background()); err != nil {
			return err
		}
		journal, err = openDesktopLinuxNodeJournal(context.Background(), capture)
		if err != nil {
			return err
		}
		defer journal.Close(context.Background())
		actual, err := journal.Snapshot(context.Background())
		if err != nil || actual.SHA256 != saved.SHA256 || journal.header != header {
			return errors.Join(err, errors.New("reopened native files changed their original immutable identity"))
		}
	case "partial-write":
		if err := linuxJournalPartialWrite(journal); err != nil {
			return err
		}
	case "cancelled-append":
		initial, err := journal.Snapshot(context.Background())
		if err != nil {
			return err
		}
		before, err := journal.readFile(journal.slots[1], linuxprotection.JournalRecordLimit)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := journal.Append(ctx, initial.SHA256, linuxJournalCheckpoint(initial)); err == nil {
			return errors.New("cancelled journal operation acknowledged a mutation")
		}
		after, err := journal.readFile(journal.slots[1], linuxprotection.JournalRecordLimit)
		if err != nil || !bytes.Equal(before, after) || journal.pending != nil {
			return errors.Join(err, errors.New("cancelled journal operation changed an untouched slot"))
		}
	case "open-restart":
		old, err := journal.Snapshot(context.Background())
		if err != nil {
			return err
		}
		if old.Record.Controller == capture.record || old.Record.Controller.Generation == capture.record.Generation || old.Record.Sequence != 2 {
			return errors.New("restart recreated the old native parent from journal JSON")
		}
		next := linuxJournalCheckpoint(old)
		if _, err := journal.Append(context.Background(), old.SHA256, next); err == nil {
			return errors.New("new parent appended under a dead decoded creator")
		}
		next.Controller = capture.record
		if _, err := journal.Append(context.Background(), old.SHA256, next); err == nil {
			return errors.New("ordinary append silently adopted another controller generation")
		}
		actual, err := journal.Snapshot(context.Background())
		if err != nil || actual.SHA256 != old.SHA256 {
			return errors.Join(err, errors.New("refused restart adoption changed durable records"))
		}
	case "parent-join":
		<-journal.gate
		finished := make(chan struct{})
		go func() { owner.close(); close(finished) }()
		select {
		case <-journal.ctx.Done():
		case <-time.After(3 * time.Second):
			journal.gate <- struct{}{}
			return errors.New("parent retirement did not cancel its retained journal")
		}
		for _, file := range []*os.File{owner.input, owner.installLock, owner.processLock} {
			if _, err := file.Stat(); err != nil {
				journal.gate <- struct{}{}
				return errors.Join(err, errors.New("parent released controller locks before journal join"))
			}
		}
		journal.gate <- struct{}{}
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			return errors.New("parent/journal retirement deadlocked its captured readback locks")
		}
		if !journal.closed || !journal.released || !capture.parent.closed {
			return errors.New("parent retirement did not join its actual registered journal")
		}
	case "closed-header":
		if err := journal.headerFile.file.Close(); err != nil {
			return err
		}
		if _, err := journal.Snapshot(context.Background()); !errors.Is(err, os.ErrClosed) {
			return errors.Join(err, errors.New("closed retained journal header remained readable authority"))
		}
	case "close-error":
		if err := linuxJournalRetainsNativeCloseError(journal, owner); err != nil {
			return err
		}
		// The fixture verified a retained failure, not successful retirement.
		// Process exit joins the remaining fixture descriptors afterward.
		_, err := fmt.Fprintln(os.Stdout, "captured-parent-retirement-retained")
		return err
	case "root", "header", "slot", "header-symlink", "slot-hardlink", "extra-file", "header-bytes", "slot-bytes":
		if _, err := journal.Snapshot(context.Background()); err == nil {
			return errors.New("journal accepted a replaced inode, immutable byte identity or inventory")
		}
	case "foreign-nft":
	default:
		return errors.New("unknown exact Linux journal native scenario")
	}
	if err := journal.Close(context.Background()); err != nil {
		return err
	}
	owner.close()
	if !capture.parent.closed || !journal.closed || !journal.released {
		return errors.New("journal fixture retained unjoined original native owners")
	}
	for _, file := range []*os.File{owner.input, owner.installLock, owner.processLock} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			return errors.Join(err, errors.New("joined journal left original controller descriptors open"))
		}
	}
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func linuxJournalNamespaceInstall(t *testing.T) string {
	t.Helper()
	installed := linuxControllerNamespaceInstall(t)
	for _, suffix := range []string{"", ".moved"} {
		if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory+suffix)); err != nil {
			t.Fatal(err)
		}
	}
	return installed
}

func TestLinuxOwnedControllerNamespaceJournalRetainsNativeFiles(t *testing.T) {
	for _, scenario := range []string{"roundtrip", "partial-write", "cancelled-append", "parent-join", "closed-header", "root", "header", "slot", "header-symlink", "slot-hardlink", "extra-file", "header-bytes", "slot-bytes"} {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxJournalNamespaceInstall(t)
			unrelated := filepath.Join("/opt", "unrelated-journal-owner")
			if err := os.WriteFile(unrelated, []byte("keep unrelated sibling"), 0600); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "journal/"+scenario)
			root := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
			switch scenario {
			case "root":
				if err := os.Rename(root, root+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			case "header", "slot", "header-symlink":
				name := desktopLinuxNodeJournalHeader
				if scenario == "slot" {
					name = desktopLinuxNodeJournalSlots[0]
				}
				path := filepath.Join(root, name)
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				retired := filepath.Join("/opt", "journal-retired-"+name)
				if err := os.Rename(path, retired); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(retired) })
				if scenario == "header-symlink" {
					err = os.Symlink(retired, path)
				} else {
					err = os.WriteFile(path, body, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "slot-hardlink":
				if err := os.Link(filepath.Join(root, desktopLinuxNodeJournalSlots[0]), filepath.Join("/opt", "journal-slot-link")); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(filepath.Join("/opt", "journal-slot-link")) })
			case "extra-file":
				if err := os.WriteFile(filepath.Join(root, "foreign.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "header-bytes":
				path := filepath.Join(root, desktopLinuxNodeJournalHeader)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				header, err := linuxprotection.ParseJournalHeader(raw)
				if err != nil {
					t.Fatal(err)
				}
				header.Creator.Generation = strings.Repeat("e", 32)
				raw, err = linuxprotection.CanonicalJournalHeader(header)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "slot-bytes":
				path := filepath.Join(root, desktopLinuxNodeJournalSlots[0])
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				record, err := linuxprotection.ParseJournalRecord(raw)
				if err != nil {
					t.Fatal(err)
				}
				record.Controller.Generation = strings.Repeat("e", 32)
				raw, err = linuxprotection.CanonicalJournalRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			child.retire(t, "")
			if body, err := os.ReadFile(unrelated); err != nil || string(body) != "keep unrelated sibling" {
				t.Fatal("journal touched an unrelated /opt owner", err)
			}
			if _, err := os.Lstat(root); err != nil {
				t.Fatal("journal Close deleted persistent or replacement recovery files", err)
			}
		})
	}
}

func TestLinuxOwnedControllerNamespaceJournalRequiresActualAbsence(t *testing.T) {
	installed := linuxJournalNamespaceInstall(t)
	command := exec.Command("/usr/sbin/nft", "add", "table", "inet", "router_vpn_killswitch")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("isolated foreign table fixture did not install", err, string(output))
	}
	t.Cleanup(func() {
		output, err := exec.Command("/usr/sbin/nft", "delete", "table", "inet", "router_vpn_killswitch").CombinedOutput()
		if err != nil {
			t.Errorf("isolated foreign table cleanup: %v %s", err, output)
		}
	})
	child := startLinuxNodeParentProcess(t, installed, "journal/foreign-nft")
	child.retire(t, "")
}

func TestLinuxOwnedControllerNamespaceJournalRetainsFailedRetirement(t *testing.T) {
	installed := linuxJournalNamespaceInstall(t)
	child := startLinuxNodeParentProcess(t, installed, "journal/close-error")
	if _, err := child.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	line, err := child.reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "captured-parent-retirement-retained" {
		child.cancel()
		_ = child.join()
		t.Fatal("actual failed journal retirement was not retained explicitly", line, err, child.diagnostic.String())
	}
	if err := child.join(); err != nil {
		t.Fatal("actual journal close-error fixture failed", err, child.diagnostic.String())
	}
}

func TestLinuxOwnedControllerNamespaceJournalSurvivesUpgradeWithoutAdoption(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "restart"
		if upgrade {
			name = "new-package-inodes"
		}
		t.Run(name, func(t *testing.T) {
			installed := linuxJournalNamespaceInstall(t)
			first := startLinuxNodeParentProcess(t, installed, "journal/roundtrip")
			first.retire(t, "")
			journalRoot := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
			before, err := os.Stat(journalRoot)
			if err != nil {
				t.Fatal(err)
			}
			if upgrade {
				lock, err := linuxOwnedLock(linuxOwnedInstallLock, true)
				if err != nil {
					t.Fatal(err)
				}
				old := linuxOwnedControllerRoot + ".moved"
				if err := os.Rename(linuxOwnedControllerRoot, old); err != nil {
					lock.Close()
					t.Fatal(err)
				}
				err = filepath.WalkDir(old, func(path string, entry os.DirEntry, failure error) error {
					if failure != nil {
						return failure
					}
					relative, err := filepath.Rel(old, path)
					if err != nil {
						return err
					}
					target := filepath.Join(linuxOwnedControllerRoot, relative)
					info, err := entry.Info()
					if err != nil {
						return err
					}
					if entry.IsDir() {
						return os.Mkdir(target, info.Mode().Perm())
					}
					body, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					return os.WriteFile(target, body, info.Mode().Perm())
				})
				closeErr := lock.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			second := startLinuxNodeParentProcess(t, installed, "journal/open-restart")
			if first.record.Generation == second.record.Generation || upgrade && (first.record.Root == second.record.Root || first.record.Image == second.record.Image) {
				t.Fatal("upgrade fixture did not create a distinct native controller/package")
			}
			second.retire(t, "")
			after, err := os.Stat(journalRoot)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("package replacement changed stable journal directory identity", err)
			}
		})
	}
}
