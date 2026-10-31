//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func linuxNodeParentFixture(owner *ownedDesktopController, scenario string) error {
	a := &app{localController: owner, cfg: common.ClientConfig{
		ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"),
		ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json"),
	}}
	capture, err := captureDesktopLinuxNodeParent(a)
	if err != nil || capture == nil || capture.parent.input != owner.input || capture.parent.installLock != owner.installLock ||
		capture.parent.processLock != owner.processLock || capture.parent.ownerDone != owner.ownerDone {
		return errors.Join(err, errors.New("Linux Node parent did not retain the original bootstrap descriptors"))
	}
	if err := json.NewEncoder(os.Stdout).Encode(capture.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "linux-node-parent-fixture-gate")
	defer gate.Close()
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		return errors.Join(err, errors.New("Linux Node parent lost its fixture rendezvous"))
	}
	switch scenario {
	case "eof", "second-byte":
		select {
		case <-capture.lifetime.Done():
		case <-time.After(3 * time.Second):
			return errors.New("Linux Node parent retained authority after actual GUI retirement")
		}
	case "profile-root":
		a.cfg.ProfilesFile = filepath.Join(linuxOwnedControllerRoot, "another-routers.json")
	case "application-owner":
		a.localController = &ownedDesktopController{processID: owner.processID, callerUID: owner.callerUID,
			accessToken: owner.accessToken, ownerToken: owner.ownerToken, nodeParent: owner.nodeParent, ownerDone: owner.ownerDone}
	case "image-descriptor", "network-namespace-descriptor", "pid-namespace-descriptor":
		original := capture.parent.image
		if scenario == "network-namespace-descriptor" {
			original = capture.parent.networkNamespace
		} else if scenario == "pid-namespace-descriptor" {
			original = capture.parent.pidNamespace
		}
		if err := original.Close(); err != nil {
			return err
		}
		if err := capture.Current(context.Background()); !errors.Is(err, os.ErrClosed) {
			return errors.Join(err, errors.New("closed native descriptor witness was not refused"))
		}
	case "root-descriptor":
		if err := capture.parent.root.Close(); err != nil {
			return err
		}
		if err := capture.Current(context.Background()); !errors.Is(err, os.ErrClosed) {
			return errors.Join(err, errors.New("closed native directory witness was not refused"))
		}
	case "root", "image", "install-lock", "process-lock":
		// The isolated parent has already replaced this real namespace object.
	case "retire":
		if err := capture.Current(context.Background()); err != nil {
			return err
		}
		if err := capture.parent.Close(context.Background()); err != nil {
			return err
		}
		for _, original := range []*os.File{owner.input, owner.installLock, owner.processLock} {
			if _, err := original.Stat(); err != nil {
				return errors.Join(err, errors.New("native Node retirement closed a borrowed controller descriptor"))
			}
		}
	default:
		return errors.New("Linux Node parent fixture has no exact scenario")
	}
	if capture.Current(context.Background()) == nil {
		return errors.New("Linux Node parent accepted a replaced or retired native owner")
	}
	if scenario != "profile-root" && scenario != "application-owner" && capture.parent.ctx.Err() == nil {
		return errors.New("Linux Node parent native identity failure remained revivable")
	}
	if capture.record != capture.parent.record {
		return errors.New("Linux Node parent rewrote its original identity after failure")
	}
	if err := capture.parent.Close(context.Background()); err != nil {
		return err
	}
	if !capture.parent.closed || capture.parent.image != nil || capture.parent.networkNamespace != nil ||
		capture.parent.pidNamespace != nil || capture.parent.root != nil {
		return errors.New("Linux Node parent retained unjoined native witnesses after retirement")
	}
	for _, original := range []*os.File{owner.input, owner.installLock, owner.processLock} {
		if _, err := original.Stat(); err != nil {
			return errors.Join(err, errors.New("Node parent retirement released a borrowed native controller object"))
		}
	}
	owner.close()
	for _, original := range []*os.File{owner.input, owner.installLock, owner.processLock} {
		if _, err := original.Stat(); !errors.Is(err, os.ErrClosed) {
			return errors.Join(err, errors.New("joined native parent left original controller descriptors alive"))
		}
	}
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

type linuxNodeParentProcess struct {
	command      *exec.Cmd
	reader       *bufio.Reader
	writer, gate *os.File
	diagnostic   bytes.Buffer
	record       desktopLinuxNodeParentRecord
	joined       chan struct{}
	joinOnce     sync.Once
	joinErr      error
	cancel       context.CancelFunc
}

func (p *linuxNodeParentProcess) join() error {
	p.joinOnce.Do(func() { p.joinErr = p.command.Wait(); close(p.joined) })
	<-p.joined
	return p.joinErr
}

func startLinuxNodeParentProcess(t *testing.T, installed, scenario string) *linuxNodeParentProcess {
	t.Helper()
	reader, writer := linuxControllerUserPipe(t, installed)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	base := linuxControllerBootstrapCommand(installed, reader)
	command := exec.CommandContext(ctx, installed, base.Args[1:]...)
	command.Stdin, command.Env = reader, append(base.Env, "ROUTERVPN_CONTROLLER_NODE_PARENT_CASE="+scenario)
	command.ExtraFiles = []*os.File{gateRead}
	p := &linuxNodeParentProcess{command: command, writer: writer, gate: gateWrite, joined: make(chan struct{}), cancel: cancel}
	output, err := command.StdoutPipe()
	if err != nil {
		cancel()
		gateRead.Close()
		gateWrite.Close()
		t.Fatal(err)
	}
	p.reader = bufio.NewReaderSize(output, 8192)
	command.Stderr = &p.diagnostic
	if err := command.Start(); err != nil {
		cancel()
		gateRead.Close()
		gateWrite.Close()
		t.Fatal(err)
	}
	reader.Close()
	gateRead.Close()
	t.Cleanup(func() {
		writer.Close()
		gateWrite.Close()
		cancel()
		_ = p.join()
	})
	if _, err := writer.Write(testLinuxOwnedHandshake()); err != nil {
		t.Fatal(err)
	}
	raw, err := p.reader.ReadSlice('\n')
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &p.record) != nil ||
		p.record.ProcessID != command.Process.Pid || p.record.ProcProcessID == 0 || p.record.StartTicks == 0 ||
		p.record.CallerUID != linuxControllerFixtureUID || !validControllerOwnerToken(p.record.Generation) ||
		p.record.Root.Inode == 0 || p.record.Image.Inode == 0 || p.record.InstallLock.Inode == 0 || p.record.ProcessLock.Inode == 0 {
		cancel()
		_ = p.join()
		t.Fatal("actual installed Node parent did not return its bounded captured identity", err, p.diagnostic.String())
	}
	return p
}

func (p *linuxNodeParentProcess) retire(t *testing.T, ending string) {
	t.Helper()
	switch ending {
	case "eof":
		if err := p.writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "second-byte":
		if _, err := p.writer.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	line, err := p.reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "captured-parent-retired" {
		p.cancel()
		_ = p.join()
		t.Fatal("actual Node parent did not reject/join its original native owner", line, err, p.diagnostic.String())
	}
	if err := p.join(); err != nil {
		t.Fatal("actual Node parent failed its captured retirement", err, p.diagnostic.String())
	}
}

func TestLinuxOwnedControllerNamespaceNodeParentRetainsExactObjects(t *testing.T) {
	for _, scenario := range []string{"root", "image", "image-descriptor", "root-descriptor", "network-namespace-descriptor", "pid-namespace-descriptor", "install-lock", "process-lock", "profile-root", "application-owner", "retire"} {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			child := startLinuxNodeParentProcess(t, installed, scenario)
			switch scenario {
			case "root":
				if err := os.Rename(linuxOwnedControllerRoot, linuxOwnedControllerRoot+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(linuxOwnedControllerRoot, 0755); err != nil {
					t.Fatal(err)
				}
			case "image", "install-lock", "process-lock":
				path, mode := installed, os.FileMode(0755)
				if scenario == "install-lock" {
					path, mode = linuxOwnedInstallLock, 0600
				} else if scenario == "process-lock" {
					path, mode = linuxOwnedProcessLock, 0600
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".retired"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, mode); err != nil {
					t.Fatal(err)
				}
			}
			child.retire(t, "")
			// The stale child may retire its retained descriptors; it cannot
			// remove a replacement inode or a replacement installation tree.
			if _, err := os.Lstat(linuxOwnedControllerRoot); err != nil {
				t.Fatal("old native parent removed the current installation directory", err)
			}
		})
	}
}

func TestLinuxOwnedControllerNamespaceNodeParentLifetimeAndRestart(t *testing.T) {
	for _, ending := range []string{"eof", "second-byte"} {
		t.Run(ending, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			first := startLinuxNodeParentProcess(t, installed, ending)
			first.retire(t, ending)
			second := startLinuxNodeParentProcess(t, installed, "retire")
			if first.record.Generation == second.record.Generation || first.record.Input == second.record.Input ||
				first.record.Root != second.record.Root || first.record.Image != second.record.Image ||
				first.record.InstallLock != second.record.InstallLock || first.record.ProcessLock != second.record.ProcessLock {
				t.Fatal("restarted parent reused a retired lifetime or substituted its protected installation")
			}
			second.retire(t, "")
		})
	}
}
