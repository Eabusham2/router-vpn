//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

var linuxNodeHostStartCases = []string{"admitted", "active-connection", "retained-workspace", "cancelled-before-start",
	"source-replaced", "foreign-journal", "request-during-launch", "replacement-during-launch", "request-ended",
	"replacement-after-start", "shutdown", "always-successor"}

func linuxHostStartAssets(profile common.RouterProfile) error {
	directory := filepath.Join(linuxOwnedControllerRoot, "generated", profile.ID, "shadowsocks")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	graph, err := json.Marshal(map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": profile.Endpoint, "server_port": 8388,
			"method": mobilemultihop.NativeStartLayerMethod, "password": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{43}, 32))}},
		"route": map[string]any{"final": "proxy", "rules": []any{}},
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "sing-box.json"), graph, 0600)
}

// This composes the shipping host, actual launcher, authenticated native
// channel, durable transaction and real nft/guardian owners. The established
// transaction child models only graph readiness: no TUN/DNS/Router pass is
// claimed here, and the app must remain Starting after native admission.
func linuxNodeHostStartFixture(controller *ownedDesktopController, scenario string) error {
	if strings.HasPrefix(scenario, "session/") {
		return linuxNodeSessionFixture(controller, strings.TrimPrefix(scenario, "session/"))
	}
	policyName := "on-connect"
	if scenario == "always-successor" {
		policyName = "always"
	}
	profile, _, err := linuxTransactionProfile(policyName)
	if err != nil {
		return err
	}
	operation, endOperation := context.WithCancel(context.Background())
	defer endOperation()
	a := &app{localController: controller, connectionContext: operation, connectionCancel: endOperation,
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
			ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
			StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "host-start-rendezvous")
	defer gate.Close()
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		return errors.Join(err, errors.New("host start fixture lost its original rendezvous"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	if err := linuxHostStartAssets(profile); err != nil {
		return err
	}
	journal, err := createDesktopLinuxNodeJournal(ctx, parent)
	if journal != nil {
		defer journal.Close(context.Background())
	}
	if err != nil {
		return err
	}
	verifies := 0
	replacement := &exec.Cmd{}
	replacementState := state{Connected: true, RouterID: "replacement", Mode: "replacement", RuntimeMode: "replacement", Phase: "connected"}
	verify := func(context.Context, string) (string, error) {
		verifies++
		if verifies == 2 {
			a.mu.Lock()
			switch scenario {
			case "request-during-launch":
				a.connectionContext = context.Background()
			case "replacement-during-launch":
				a.cmd, a.state = replacement, replacementState
			}
			a.mu.Unlock()
		}
		return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
	}
	host, err := prepareDesktopLinuxNodeHostWith(operation, a, profile, "shadowsocks", 0, verify, nil)
	if host != nil {
		defer host.Close(context.Background())
	}
	if err != nil {
		return err
	}
	if err := host.Stage(ctx); err != nil {
		return err
	}
	workspace := host.launch.directory
	selectedJournal := journal
	switch scenario {
	case "active-connection":
		a.cmd, a.state = replacement, replacementState
	case "retained-workspace":
		old := &desktopNodeLaunch{}
		desktopNodeOwners.Store(a, old)
		defer desktopNodeOwners.CompareAndDelete(a, old)
	case "cancelled-before-start":
		endOperation()
	case "source-replaced":
		if err := os.WriteFile(filepath.Join(workspace, "node-source.json"), []byte("other private source"), 0600); err != nil {
			return err
		}
	case "foreign-journal":
		selectedJournal = &desktopLinuxNodeJournal{parent: &desktopLinuxNodeParentCapture{}}
	}
	environment := []string{linuxNodeTransactionMarker + "=1", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0"}
	startErr := host.startWithVerifier(ctx, selectedJournal, nil, environment, verify)
	rejectedBefore := scenario == "active-connection" || scenario == "retained-workspace" || scenario == "cancelled-before-start" ||
		scenario == "source-replaced" || scenario == "foreign-journal"
	rejectedAfter := scenario == "request-during-launch" || scenario == "replacement-during-launch"
	if rejectedBefore {
		if startErr == nil || host.process != nil || host.transaction != nil || host.startEntered || verifies != 1 {
			return errors.New("Linux prepared host launched before its original source and empty connection slot were proved")
		}
	} else if rejectedAfter {
		if startErr == nil || host.process == nil || !host.process.Started() || host.transaction != nil || verifies != 2 {
			return errors.New("Linux started host replaced the request or connection before durable admission")
		}
	} else {
		if startErr != nil || host.transaction == nil || !host.transaction.admitted || !host.transaction.nativeCommitted ||
			host.process == nil || !host.process.Started() || a.cmd != host.process.command || verifies != 2 ||
			a.state.Connected || a.state.Phase != "starting" || a.state.RouterID != profile.ID || a.state.RuntimeMode != "shadowsocks" {
			return errors.Join(startErr, errors.New("Linux host did not compose its original admitted transaction without claiming connection proof"))
		}
		if err := host.startWithVerifier(ctx, journal, nil, environment, verify); err == nil || verifies != 2 {
			return errors.New("Linux host reused an already entered native command")
		}
		if scenario == "request-ended" {
			endOperation()
			a.connectionContext, a.connectionCancel = nil, nil
		}
		if scenario == "replacement-after-start" {
			a.cmd, a.state = replacement, replacementState
		}
		if scenario == "shutdown" {
			a.closing = true
			if err := a.retireNativeNodeForShutdownContext(ctx); err != nil {
				return err
			}
		} else if err := host.Retire(ctx, true); err != nil {
			return err
		}
		if scenario == "always-successor" {
			previous := host.transaction
			if previous.baseline.ObserveClosed(ctx) != nil || previous.closed || previous.baselineReleased {
				return errors.New("Linux host disconnect discarded its original closed Always predecessor")
			}
			nextProfile, _, err := linuxTransactionProfile("on-connect")
			if err != nil {
				return err
			}
			nextOperation, stopNext := context.WithCancel(context.Background())
			defer stopNext()
			a.profiles.Profiles[0], a.connectionContext, a.connectionCancel = nextProfile, nextOperation, stopNext
			successor, err := prepareDesktopLinuxNodeHostWith(nextOperation, a, nextProfile, "shadowsocks", 0, verify, nil)
			if successor != nil {
				defer successor.Close(context.Background())
			}
			if err != nil {
				return err
			}
			if err := successor.Stage(ctx); err != nil {
				return err
			}
			if err := successor.startWithVerifier(ctx, journal, previous, environment, verify); err != nil {
				return err
			}
			if err := successor.Retire(ctx, true); err != nil {
				return err
			}
			if !previous.superseded || previous.successor != nil {
				return errors.New("Linux host succession lost its exact original predecessor reservation")
			}
			if err := successor.Close(ctx); err != nil {
				return err
			}
		}
	}
	if err := host.Close(ctx); err != nil {
		return err
	}
	if host.process != nil && host.process.Started() {
		select {
		case <-host.process.joined:
		default:
			return errors.New("Linux host removed its workspace before its original child joined")
		}
	}
	if _, err := os.Lstat(workspace); !errors.Is(err, os.ErrNotExist) {
		return errors.New("Linux host retained its joined private launch workspace")
	}
	if scenario == "active-connection" || scenario == "replacement-during-launch" || scenario == "replacement-after-start" {
		if a.cmd != replacement || !reflect.DeepEqual(a.state, replacementState) {
			return errors.New("Linux host retirement changed the replacement command or connection state")
		}
	} else if a.cmd != nil || a.state.Connected {
		return errors.New("Linux host retirement retained its original joined app command")
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return errors.Join(err, errors.New("Linux host completion lacks actual On-connect native absence"))
	}
	if scenario != "shutdown" {
		selected, err := journal.Snapshot(ctx)
		if err != nil || selected.Record.Phase != "settled" || selected.Record.Committed.Engine != nil || selected.Record.Committed.Target != nil {
			return errors.Join(err, errors.New("Linux host completion lacks its exact settled engine-free journal"))
		}
	}
	if err := journal.Close(ctx); err != nil {
		return err
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestDesktopLinuxGuardianKernelNodeHostStart(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node host start requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	for _, scenario := range linuxNodeHostStartCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "host-start/"+scenario)
			child.retire(t, "")
		})
	}
}
