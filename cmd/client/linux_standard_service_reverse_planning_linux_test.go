//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"router-vpn/internal/common"
	"testing"
	"time"
)

// These are shipping command/config planning tests. They do not model a native
// transfer as physical proof; installed reverse cases exercise that separately.
func TestStandardReversePlanningKeepsOriginalPreparation(t *testing.T) {
	for _, scenario := range []string{"hostname", "lookup-failure", "missing-helper", "changed-config", "changed-command", "replaced-directory", "held-app", "original-deadline"} {
		t.Run(scenario, func(t *testing.T) {
			root, a := standardBootstrapCommandFixture(t)
			profile, exit := standardPreparedPolicyFixture(t, "shadowsocks")
			exit.Server = "transport.example.test"
			operation, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			a.connectionContext = operation
			raw, _ := json.Marshal(exit)
			tr := &linuxStandardNodeReverseTransfer{session: &desktopLinuxNodeSession{parent: &desktopLinuxNodeParentCapture{app: a}}, operation: operation, deadline: time.Now().Add(800 * time.Millisecond), profile: profile, exitRaw: string(raw)}
			defer tr.DiscardPlanning()
			calls := 0
			lookupErr := errors.New("original resolver failed")
			bootstrap := standardExitBootstrap{network: func() string { return "original-network" }, lookup: func(call context.Context, host string) ([]netip.Addr, error) {
				calls++
				if host != exit.Server {
					t.Fatal("queried another destination", host)
				}
				deadline, ok := call.Deadline()
				if !ok || deadline.After(tr.deadline) {
					t.Fatal("renewed original planning deadline")
				}
				if scenario == "lookup-failure" {
					return nil, lookupErr
				}
				if scenario == "original-deadline" {
					<-call.Done()
					return nil, call.Err()
				}
				return []netip.Addr{netip.MustParseAddr("203.0.113.20")}, nil
			}}
			if scenario == "missing-helper" {
				if err := os.Remove(filepath.Join(root, "modes/native-standard-exit-linux.sh")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "held-app" || scenario == "original-deadline" {
				tr.deadline = time.Now().Add(25 * time.Millisecond)
			}
			if scenario == "held-app" {
				a.mu.Lock()
			}
			command, err := tr.prepareCommand(operation, bootstrap)
			if scenario == "held-app" {
				a.mu.Unlock()
			}
			if scenario == "lookup-failure" || scenario == "missing-helper" || scenario == "held-app" || scenario == "original-deadline" {
				if err == nil || command != nil {
					t.Fatal("failed planning returned runnable command", err)
				}
				if scenario == "held-app" && (!errors.Is(err, context.DeadlineExceeded) || calls != 0) {
					t.Fatal("held original app escaped deadline", err, calls)
				}
				if a.cmd != nil || tr.owner != nil || tr.native != nil {
					t.Fatal("failed planning mutated runtime ownership")
				}
				assertNoStandardBootstrapWorkspace(t, root)
				return
			}
			if err != nil || calls != 1 {
				t.Fatal("original hostname planning failed", err, calls)
			}
			workspace := &desktopNodeLaunch{}
			if err := captureDesktopRuntimeDirectory(workspace, tr.planning.directory); err != nil {
				t.Fatal(err)
			}
			defer workspace.directoryRoot.Close()
			// A comparison-only owner carries the exact fields produced by real service
			// preparation. No Start, registry publication, native commit or proof occurs.
			owner := &linuxStandardServiceLaunch{prepared: &linuxLegacyStandardExitOwner{command: command, launch: workspace, protectionRoot: command.Dir}, request: linuxStandardServiceRequest{Directory: tr.planning.directory, ConfigSHA256: tr.plannedConfig}}
			switch scenario {
			case "changed-config":
				if err := os.WriteFile(filepath.Join(tr.planning.directory, "sing-box.json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-command":
				command.Env = append(command.Env, "HOMEVPN_ENDPOINT=203.0.113.99")
			case "replaced-directory":
				original := tr.planning.directory + "-original"
				if err := os.Rename(tr.planning.directory, original); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(original)
				if err := os.Mkdir(tr.planning.directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			err = tr.adoptPlanning(operation, owner)
			if (err == nil) != (scenario == "hostname") {
				t.Fatal("original sealed admission mismatch", scenario, err)
			}
			if calls != 1 {
				t.Fatal("admission repeated hostname lookup after planning")
			}
			if tr.owner != nil || tr.native != nil {
				t.Fatal("comparison created transfer authority")
			}
		})
	}
}

func TestStandardReversePlanningRetainsPostConstructionCleanup(t *testing.T) {
	root, a := standardBootstrapCommandFixture(t)
	profile, exit := standardPreparedPolicyFixture(t, "shadowsocks")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tr := &linuxStandardNodeReverseTransfer{}
	command, err := nativeStandardExitCommandOwnedContext(ctx, a, profile, common.RouterProfile{}, exit, true, standardExitBootstrap{}, &tr.planning)
	if err != nil || tr.planning == nil || tr.planning.directoryRoot == nil {
		t.Fatal("builder omitted original workspace ownership", err)
	}
	directory := tr.planning.directory
	// Fail precisely the first post-construction root observation. The original
	// workspace is unchanged; an unrelated directory must remain untouched.
	foreign := filepath.Join(root, "foreign")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(foreign, "keep")
	if err := os.WriteFile(marker, []byte("original foreign bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	command.Dir = filepath.Join(root, "missing-root")
	if err = tr.capturePlannedCommand(command); err == nil {
		t.Fatal("missing root was accepted")
	}
	if err = tr.DiscardPlanning(); err != nil {
		t.Fatal("original post-construction workspace was orphaned", err)
	}
	if _, err = os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed planning left its credentials", err)
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "original foreign bytes" {
		t.Fatal("cleanup touched another owner", err)
	}
}

func TestStandardReversePlanningClosesAfterOwnerDiscard(t *testing.T) {
	_, a := standardBootstrapCommandFixture(t)
	profile, exit := standardPreparedPolicyFixture(t, "shadowsocks")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tr := &linuxStandardNodeReverseTransfer{}
	_, err := nativeStandardExitCommandOwnedContext(ctx, a, profile, common.RouterProfile{}, exit, true, standardExitBootstrap{}, &tr.planning)
	if err != nil {
		t.Fatal(err)
	}
	original := tr.planning.directoryRoot
	owner := &desktopNodeLaunch{}
	if err = captureDesktopRuntimeDirectory(owner, tr.planning.directory); err != nil {
		t.Fatal(err)
	}
	if err = cleanupDesktopNodeLaunch(owner); err != nil {
		t.Fatal(err)
	}
	_ = tr.DiscardPlanning() // The original owner already removed this directory.
	if _, err = original.Stat("."); !errors.Is(err, os.ErrClosed) {
		t.Fatal("planning duplicate survived owner discard", err)
	}
	if tr.planning.directoryRoot != nil {
		t.Fatal("closed planning descriptor remained reusable")
	}
}
