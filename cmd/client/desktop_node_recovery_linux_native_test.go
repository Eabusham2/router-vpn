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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

var linuxEmptyRecoveryCases = []string{"startup", "restart", "cancel-retry", "cancel-shutdown", "live-creator",
	"creator-drift", "replaced-session", "root-replaced", "slot-replaced", "slot-bytes", "namespace-changed", "foreign-node", "fixed-legacy", "unrelated-policy", "partial-record", "intent-record", "nonempty-record"}

func linuxEmptyRecoveryApp(owner *ownedDesktopController) *app {
	return &app{localController: owner, cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
		ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
		StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}, state: state{Mode: "off", Phase: "off"}}
}

func linuxNodeEmptyRecoveryFixture(owner *ownedDesktopController, scenario string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	a := linuxEmptyRecoveryApp(owner)
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if strings.HasPrefix(scenario, "seed") {
		return linuxNodeEmptyRecoverySeed(ctx, a, parent, scenario)
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "linux-empty-recovery-fixture-gate")
	defer gate.Close()
	var start [1]byte
	if _, err := io.ReadFull(gate, start[:]); err != nil || start[0] != 1 {
		return errors.Join(err, errors.New("empty recovery lost its actual fixture owner"))
	}
	if scenario == "startup" {
		if err := a.initializeDesktopNodeRecovery(); err != nil {
			return err
		}
		return linuxNodeEmptyRecoveryFresh(ctx, a, parent.parent.session)
	}
	s, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	locked := true
	defer func() {
		if locked {
			s.gate <- struct{}{}
		}
	}()
	if err := s.beginEmptyRecoveryLocked(ctx); err != nil {
		return err
	}
	r, j := s.emptyRecovery, s.emptyRecovery.journal
	if j == nil || r.original == parent.record || j.header.Creator != r.original {
		return errors.New("recovery fixture lost its two distinct actual controller identities")
	}
	originalBodies := make(map[string][]byte)
	for _, file := range []*desktopLinuxNodeJournalFile{j.slots[0], j.slots[1], j.headerFile, j.lock} {
		body, err := j.readFile(file, linuxprotection.JournalRecordLimit)
		if err != nil {
			return err
		}
		originalBodies[file.name] = body
	}
	root := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
	var restore func() error
	expectedSuccess := scenario == "restart" || scenario == "unrelated-policy"
	switch scenario {
	case "restart", "live-creator", "partial-record", "intent-record", "nonempty-record":
	case "creator-drift":
		before := r.original
		r.original.ProcessID = parent.record.ProcessID
		restore = func() error { r.original = before; return nil }
	case "replaced-session":
		p := parent.parent
		<-p.gate
		p.session = &desktopLinuxNodeSession{parent: s.parent}
		p.gate <- struct{}{}
		restore = func() error { <-p.gate; p.session = s; p.gate <- struct{}{}; return nil }
	case "root-replaced":
		if err := os.Rename(root, root+".moved"); err != nil {
			return err
		}
		if err := os.Mkdir(root, 0700); err != nil {
			return err
		}
		marker := filepath.Join(root, "unrelated")
		if err := os.WriteFile(marker, []byte("replacement must survive"), 0600); err != nil {
			return err
		}
		restore = func() error {
			body, err := os.ReadFile(marker)
			if err != nil || string(body) != "replacement must survive" {
				return errors.Join(err, errors.New("recovery changed replacement directory"))
			}
			if err := os.Remove(marker); err != nil {
				return err
			}
			if err := os.Remove(root); err != nil {
				return err
			}
			return os.Rename(root+".moved", root)
		}
	case "slot-replaced":
		path, moved := filepath.Join(root, j.slots[0].name), filepath.Join("/opt", "empty-recovery-original-slot")
		if err := os.Rename(path, moved); err != nil {
			return err
		}
		if err := os.WriteFile(path, originalBodies[j.slots[0].name], 0600); err != nil {
			return err
		}
		restore = func() error {
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, originalBodies[j.slots[0].name]) {
				return errors.Join(err, errors.New("recovery changed equal-content replacement slot"))
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Rename(moved, path)
		}
	case "slot-bytes":
		path := filepath.Join(root, j.slots[j.current.Slot].name)
		if err := os.WriteFile(path, []byte("unowned bytes"), 0600); err != nil {
			return err
		}
		restore = func() error {
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "unowned bytes" {
				return errors.Join(err, errors.New("recovery rewrote changed original bytes"))
			}
			return os.WriteFile(path, originalBodies[j.slots[j.current.Slot].name], 0600)
		}
	case "foreign-node", "fixed-legacy", "unrelated-policy":
		name := "router_vpn_node_unowned_restart_fixture"
		if scenario == "fixed-legacy" {
			name = "router_vpn_killswitch"
		}
		if scenario == "unrelated-policy" {
			name = "unrelated_household_fixture"
		}
		if output, err := exec.CommandContext(ctx, "/usr/sbin/nft", "add", "table", "inet", name).CombinedOutput(); err != nil {
			return fmt.Errorf("isolated recovery policy: %v %s", err, output)
		}
		restore = func() error {
			if output, err := exec.CommandContext(ctx, "/usr/sbin/nft", "list", "table", "inet", name).CombinedOutput(); err != nil {
				return fmt.Errorf("recovery removed a foreign policy: %v %s", err, output)
			}
			// Only this fixture retires the table it created in its private namespace.
			output, err := exec.CommandContext(ctx, "/usr/sbin/nft", "delete", "table", "inet", name).CombinedOutput()
			if err != nil {
				return fmt.Errorf("retire original fixture table: %v %s", err, output)
			}
			return nil
		}
	case "namespace-changed":
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		original, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			return err
		}
		defer original.Close()
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			return err
		}
		restore = func() error {
			raw, err := original.SyscallConn()
			if err != nil {
				return err
			}
			var failure syscall.Errno
			err = raw.Control(func(fd uintptr) {
				call := uintptr(308)
				if runtime.GOARCH == "arm64" {
					call = 268
				}
				_, _, failure = syscall.Syscall(call, fd, syscall.CLONE_NEWNET, 0)
			})
			if failure != 0 {
				return errors.Join(err, failure)
			}
			return err
		}
	case "cancel-retry", "cancel-shutdown":
		lifetime, stop := context.WithCancel(ctx)
		defer stop()
		observer := &linuxJournalUnlinkCancellation{Context: lifetime, cancel: stop, original: j.slots[0].file}
		err := s.finishEmptyRecoveryLocked(observer, false)
		if err == nil || lifetime.Err() == nil || j.removal == nil || j.removal.complete || !j.removal.files[0].removed || j.removal.files[1].removed ||
			r.ready || s.journalErr == nil || j.closed || j.released {
			return errors.Join(err, errors.New("partial recovery lost its exact original unlink owner"))
		}
		if err := j.Close(ctx); err == nil || j.closed || j.lock.file == nil {
			return errors.New("partial recovery released its original journal lock")
		}
		if err := s.beginEmptyRecoveryLocked(ctx); err == nil {
			return errors.New("partial recovery reopened a replacement journal")
		}
		s.gate <- struct{}{}
		locked = false
		if a.guardDesktopOwnedNodeTransition(nil) == nil {
			return errors.New("partial recovery admitted a competing legacy path")
		}
		if scenario == "cancel-shutdown" {
			if err := parent.parent.Close(ctx); err != nil || !parent.parent.closed || !r.ready || !j.closed || !j.released {
				return errors.Join(err, errors.New("terminal cleanup did not join only its accepted empty recovery"))
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				return errors.New("terminal empty recovery retained its acknowledged original checkpoint")
			}
			_, err := fmt.Fprintln(os.Stdout, "captured-empty-recovery-complete")
			return err
		}
		if err := a.resumeDesktopLinuxEmptyRecovery(ctx); err != nil {
			return err
		}
		return linuxNodeEmptyRecoveryFresh(ctx, a, s)
	default:
		return errors.New("unknown empty recovery native scenario")
	}
	err = s.finishEmptyRecoveryLocked(ctx, false)
	if (err == nil) != expectedSuccess {
		return errors.Join(err, fmt.Errorf("empty recovery outcome changed for %s", scenario))
	}
	if restore != nil {
		if err := restore(); err != nil {
			return err
		}
	}
	if !expectedSuccess {
		if r.ready || s.journalErr == nil || j.removal != nil || j.closed || j.released {
			return errors.New("rejected recovery lost its original blocked owner")
		}
		for _, file := range []*desktopLinuxNodeJournalFile{j.slots[0], j.slots[1], j.headerFile, j.lock} {
			body, err := io.ReadAll(io.NewSectionReader(file.file, 0, linuxprotection.JournalRecordLimit+1))
			if err != nil || !bytes.Equal(body, originalBodies[file.name]) {
				return errors.Join(err, errors.New("rejected recovery changed its original retained file"))
			}
		}
		s.gate <- struct{}{}
		locked = false
		if a.guardDesktopOwnedNodeTransition(nil) == nil {
			return errors.New("rejected empty recovery admitted a legacy replacement")
		}
		if err := parent.parent.Close(ctx); err != nil {
			return err
		}
		if _, err := os.Lstat(root); err != nil {
			return errors.Join(err, errors.New("rejected recovery deleted its persistent original checkpoint"))
		}
		_, err := fmt.Fprintln(os.Stdout, "captured-empty-recovery-rejected")
		return err
	}
	s.gate <- struct{}{}
	locked = false
	return linuxNodeEmptyRecoveryFresh(ctx, a, s)
}

func linuxNodeEmptyRecoveryFresh(ctx context.Context, a *app, s *desktopLinuxNodeSession) error {
	if s == nil {
		return errors.New("startup recovery did not retain its actual session")
	}
	if err := s.enter(ctx); err != nil {
		return err
	}
	if s.emptyRecovery == nil || !s.emptyRecovery.ready || s.journalErr != nil || s.journal != nil ||
		!s.emptyRecovery.journal.closed || !s.emptyRecovery.journal.released {
		s.gate <- struct{}{}
		return errors.New("empty recovery was reported complete before original descriptor retirement")
	}
	originalID := s.emptyRecovery.journal.header.JournalID
	j, err := createDesktopLinuxNodeJournal(ctx, s.parent)
	s.journal = j
	if err != nil {
		s.gate <- struct{}{}
		return err
	}
	if j.header.JournalID == originalID || j.header.Creator != s.parent.record || j.current.Record.Controller != s.parent.record {
		s.gate <- struct{}{}
		return errors.New("restart adopted an old journal creator instead of a fresh creation")
	}
	if _, err := s.selectedPredecessorLocked(ctx, nil); err != nil {
		s.gate <- struct{}{}
		return err
	}
	if err := s.emptyRecovery.current(ctx, false); err == nil {
		s.gate <- struct{}{}
		return errors.New("old recovery retained authority over a fresh session journal")
	}
	s.gate <- struct{}{}
	if err := a.guardDesktopOwnedNodeTransition(nil); err != nil {
		return err
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	if err := s.parent.parent.Close(ctx); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fresh controller failed its ordinary original-creator terminal cleanup")
	}
	_, err = fmt.Fprintln(os.Stdout, "captured-empty-recovery-complete")
	return err
}

func linuxNodeEmptyRecoverySeed(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, scenario string) error {
	j, err := createDesktopLinuxNodeJournal(ctx, parent)
	if err != nil {
		return err
	}
	if _, err := j.Append(ctx, j.current.SHA256, linuxJournalCheckpoint(j.current)); err != nil {
		return err
	}
	switch scenario {
	case "seed-intent", "seed-nonempty":
		// Negative comparison records only: no working engine or owned native
		// protection is claimed by these deliberately unadoptable values.
		intent := linuxJournalRejectedAlternative(j.current)
		if _, err := j.Append(ctx, j.current.SHA256, intent); err != nil {
			return err
		}
		if scenario == "seed-nonempty" {
			settled := linuxJournalCheckpoint(j.current)
			settled.Committed, settled.Phase, settled.Intent = linuxprotection.CloneState(intent.Intent.Candidate), "settled", nil
			settled.Committed.Engine = nil
			if _, err := j.Append(ctx, j.current.SHA256, settled); err != nil {
				return err
			}
		}
	case "seed-partial":
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
			return err
		}
		short := limit
		short.Cur = 512
		signal.Ignore(syscall.SIGXFSZ)
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &short); err != nil {
			return err
		}
		_, failure := j.Append(ctx, j.current.SHA256, linuxJournalCheckpoint(j.current))
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
			return err
		}
		if !errors.Is(failure, syscall.EFBIG) || j.pending == nil {
			return errors.Join(failure, errors.New("seed did not preserve an actual interrupted durable append"))
		}
	case "seed-live":
		// Deliberately release only this fixture's original descriptors while
		// its actual old controller stays alive. Lock acquisition alone must
		// never be mistaken for the independent original-process exit proof.
		if err := errors.Join(j.lock.file.Close(), a.localController.processLock.Close()); err != nil {
			return err
		}
	case "seed":
	default:
		return errors.New("unknown original recovery seed")
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, "captured-empty-checkpoint-ready"); err != nil {
		return err
	}
	gate := os.NewFile(3, "original-empty-checkpoint-crash-gate")
	defer gate.Close()
	var forbidden [1]byte
	_, err = io.ReadFull(gate, forbidden[:])
	return errors.Join(err, errors.New("crash fixture must end through its actual originating exec.Cmd"))
}

func TestLinuxOwnedControllerNamespaceEmptyJournalRecovery(t *testing.T) {
	for _, scenario := range linuxEmptyRecoveryCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxJournalNamespaceInstall(t)
			seed := "seed"
			switch scenario {
			case "live-creator":
				seed = "seed-live"
			case "partial-record":
				seed = "seed-partial"
			case "intent-record":
				seed = "seed-intent"
			case "nonempty-record":
				seed = "seed-nonempty"
			}
			first := startLinuxNodeParentProcess(t, installed, "empty-recovery/"+seed)
			line, err := first.reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "captured-empty-checkpoint-ready" {
				t.Fatal("original controller did not preserve its actual checkpoint", line, err, first.diagnostic.String())
			}
			crash := func() {
				if err := first.command.Process.Kill(); err != nil {
					t.Fatal("fixture failed to crash its actual created controller", err)
				}
				if err := first.join(); err == nil {
					t.Fatal("original controller did not actually crash")
				}
			}
			if scenario == "live-creator" {
				defer crash()
			} else {
				crash()
			}
			second := startLinuxNodeParentProcess(t, installed, "empty-recovery/"+scenario)
			if first.record.Generation == second.record.Generation || first.record.ProcessID == second.record.ProcessID {
				t.Fatal("restart did not create a distinct authenticated native parent")
			}
			if _, err := second.gate.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			line, err = second.reader.ReadString('\n')
			want := "captured-empty-recovery-rejected"
			if scenario == "startup" || scenario == "restart" || scenario == "cancel-retry" || scenario == "cancel-shutdown" || scenario == "unrelated-policy" {
				want = "captured-empty-recovery-complete"
			}
			if err != nil || strings.TrimSpace(line) != want {
				second.cancel()
				_ = second.join()
				t.Fatal("actual empty recovery outcome failed", line, err, second.diagnostic.String())
			}
			if err := second.join(); err != nil {
				t.Fatal("empty recovery did not join its original child", err, second.diagnostic.String())
			}
		})
	}
}
