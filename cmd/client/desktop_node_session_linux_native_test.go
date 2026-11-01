//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

var linuxNodeSessionCases = []string{"on-connect-repeat", "hold-on-connect", "always-successor", "failed-successor",
	"stale-retirement", "wrong-parent", "cancelled-preflight", "partial-journal", "terminal"}

// The actual authenticated controller creates and joins the actual engine,
// source, guardian and nft baseline. The established transaction child still
// models graph readiness; these cases make no TUN/DNS/Connected claim.
func linuxNodeSessionFixture(controller *ownedDesktopController, scenario string) error {
	initialPolicy := "on-connect"
	if scenario == "always-successor" || scenario == "failed-successor" {
		initialPolicy = "always"
	}
	profile, _, err := linuxTransactionProfile(initialPolicy)
	if err != nil {
		return err
	}
	operation, stopOperation := context.WithCancel(context.Background())
	defer func() { stopOperation() }()
	a := &app{localController: controller, connectionContext: operation, connectionCancel: stopOperation,
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
			ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
			StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}}
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "session-rendezvous")
	defer gate.Close()
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		return errors.Join(err, errors.New("Linux session fixture lost its original rendezvous"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := linuxNodeLauncherPackage(); err != nil {
		return err
	}
	if err := linuxHostStartAssets(profile); err != nil {
		return err
	}
	session, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	if same, err := captureDesktopLinuxNodeSession(ctx, a); err != nil || same != session || session.journal != nil {
		return errors.Join(err, errors.New("Linux session capture replaced its original owner or created a journal before Stop"))
	}
	verify := func(context.Context, string) (string, error) {
		return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
	}
	environment := []string{linuxNodeTransactionMarker + "=1", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0"}
	prepare := func() (*desktopLinuxNodeHost, error) {
		host, err := prepareDesktopLinuxNodeHostWith(operation, a, profile, "shadowsocks", 0, verify, nil)
		if err != nil {
			return host, err
		}
		return host, host.Stage(ctx)
	}
	nextRequest := func(policy string) error {
		stopOperation()
		var err error
		profile, _, err = linuxTransactionProfile(policy)
		if err != nil {
			return err
		}
		operation, stopOperation = context.WithCancel(context.Background())
		a.mu.Lock()
		a.connectionContext, a.connectionCancel = operation, stopOperation
		a.profiles.Profiles[0] = profile
		a.mu.Unlock()
		return nil
	}
	first, err := prepare()
	if err != nil {
		return err
	}
	if scenario == "wrong-parent" {
		foreign := *first
		foreignParent := *first.parent
		foreignParent.parent = &desktopLinuxNodeParent{}
		foreign.parent = &foreignParent
		if err := session.startWithVerifier(ctx, &foreign, environment, verify); err == nil ||
			session.active != nil || session.journal != nil || first.process != nil {
			return errors.New("Linux session accepted a copied host with another retained parent")
		}
	}
	if scenario == "cancelled-preflight" {
		stopOperation()
		if err := session.startWithVerifier(ctx, first, environment, verify); err == nil ||
			session.active != nil || session.journal != nil || first.process != nil {
			return errors.New("Linux session entered journal or process creation for a cancelled request")
		}
		if err := first.Close(ctx); err != nil {
			return err
		}
		if err := nextRequest("on-connect"); err != nil {
			return err
		}
		first, err = prepare()
		if err != nil {
			return err
		}
	}
	if scenario == "partial-journal" {
		path := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
		marker := filepath.Join(path, "unowned-record")
		if err := os.WriteFile(marker, []byte("must remain unchanged"), 0600); err != nil {
			return err
		}
		failure := session.startWithVerifier(ctx, first, environment, verify)
		if failure == nil || session.journalErr == nil || session.active != first || first.process != nil {
			return errors.New("Linux session did not retain its failed original journal constructor")
		}
		if err := session.Retire(ctx, first, true); err != failure || session.active != nil || !first.closed {
			return errors.New("Linux session cleanup erased or replaced its failed original journal result")
		}
		if err := nextRequest("on-connect"); err != nil {
			return err
		}
		next, err := prepare()
		if err != nil {
			return err
		}
		if err := session.startWithVerifier(ctx, next, environment, verify); err != failure || next.process != nil {
			return errors.New("Linux session retried an unowned partial journal by pathname")
		}
		if err := next.Close(ctx); err != nil {
			return err
		}
		body, err := os.ReadFile(marker)
		if err != nil || string(body) != "must remain unchanged" {
			return errors.New("Linux failed session altered another private journal workspace")
		}
	} else {
		if err := session.startWithVerifier(ctx, first, environment, verify); err != nil {
			return err
		}
		journal := session.journal
		if session.active != first || first.transaction == nil || !first.transaction.admitted || a.state.Connected {
			return errors.New("Linux session lost its original admitted child or fabricated connection proof")
		}
		if scenario == "terminal" {
			a.mu.Lock()
			a.closing = true
			a.mu.Unlock()
			if err := a.retireNativeNodeForShutdownContext(ctx); err != nil {
				return err
			}
		} else {
			hold := scenario != "on-connect-repeat" && scenario != "wrong-parent" && scenario != "cancelled-preflight"
			if err := session.Retire(ctx, first, !hold); err != nil {
				return err
			}
			if session.active != nil || !first.closed || a.cmd != nil || a.state.Connected {
				return errors.New("Linux session retired presentation before its captured command and workspace joined")
			}
			if hold {
				if session.predecessor != first.transaction || session.predecessor.baseline.ObserveClosed(ctx) != nil {
					return errors.New("Linux session lost its exact closed native predecessor")
				}
			} else if session.predecessor != nil || mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
				return errors.New("Linux On-connect session did not release its original native target")
			}
			if scenario == "hold-on-connect" {
				if err := session.Retire(ctx, nil, true); err != nil || session.predecessor != nil ||
					mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
					return errors.Join(err, errors.New("Linux explicit Disconnect did not release its captured held On-connect owner"))
				}
			}
			if err := nextRequest("on-connect"); err != nil {
				return err
			}
			next, err := prepare()
			if err != nil {
				return err
			}
			if scenario == "failed-successor" {
				stale := func(context.Context, string) (string, error) {
					a.mu.Lock()
					a.connectionContext = context.Background()
					a.mu.Unlock()
					return filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()), nil
				}
				if err := session.startWithVerifier(ctx, next, environment, stale); err == nil || session.active != next {
					return errors.New("Linux session accepted a successor whose launch replaced the initiating request")
				}
				if err := session.Retire(ctx, next, false); err != nil || session.predecessor != first.transaction ||
					first.transaction.baseline.ObserveClosed(ctx) != nil {
					return errors.Join(err, errors.New("Linux failed successor lost its original Always predecessor"))
				}
				if err := nextRequest("on-connect"); err != nil {
					return err
				}
				next, err = prepare()
				if err != nil {
					return err
				}
			}
			if err := session.startWithVerifier(ctx, next, environment, verify); err != nil {
				return err
			}
			if session.journal != journal || next.transaction.journal != journal || session.active != next {
				return errors.New("Linux new request replaced the retained original open journal")
			}
			if scenario == "stale-retirement" {
				command := a.cmd
				if err := session.Retire(ctx, first, true); err == nil || session.active != next || a.cmd != command ||
					next.process.Alive() != nil || next.transaction.control.Current(ctx) != nil {
					return errors.New("Linux old Stop changed its replacement's original live engine or control")
				}
			}
			if err := session.Retire(ctx, next, true); err != nil {
				return err
			}
			if session.active != nil || session.predecessor != nil || a.cmd != nil || a.state.Connected {
				return errors.New("Linux repeated connection retained an unjoined app or native owner")
			}
		}
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	if !session.closed || !session.released || a.cmd != nil || a.state.Connected ||
		mobiletor.ReadDesktopLinuxProtectionAbsence(ctx) != nil {
		return errors.New("Linux session terminal close lost its original joined owner or actual native absence")
	}
	controller.close()
	_, err = fmt.Fprintln(os.Stdout, "captured-parent-retired")
	return err
}

func TestDesktopLinuxGuardianKernelNodeSession(t *testing.T) {
	physical, err := net.InterfaceByName("rvpn-test")
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 || err != nil || physical.Index < 1 {
		t.Fatal("Node session requires its actual isolated guardian namespace", err)
	}
	t.Setenv(linuxControllerNamespaceMarker, "1")
	for _, scenario := range linuxNodeSessionCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			child := startLinuxNodeParentProcess(t, installed, "host-start/session/"+scenario)
			child.retire(t, "")
		})
	}
}
