//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"sync"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

var linuxHostTUNCases = []string{"on-connect", "home-lan", "wrong-node", "resolver-failure", "wrong-key", "stale-ready", "cancelled-proof",
	"replaced-host", "request-ended", "shutdown", "always", "active-request-ended", "cancel-adoption", "active-profile-change",
	"active-network-change", "active-command-change"}

type linuxHostTUNResult struct {
	Stage             string                                 `json:"stage"`
	Scenario          string                                 `json:"scenario"`
	SessionID         string                                 `json:"session_id"`
	Outcome           string                                 `json:"outcome"`
	Ready             *mobilemultihop.DesktopNodeReadyRecord `json:"ready,omitempty"`
	Journal           *linuxprotection.JournalSelection      `json:"journal,omitempty"`
	ClosedTableSHA256 string                                 `json:"closed_table_sha256,omitempty"`
	Activation        string                                 `json:"activation,omitempty"`
}

func linuxHostTUNRendezvous(gate *os.File, expected byte) error {
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != expected {
		return errors.Join(err, errors.New("installed-host fixture lost its exact original rendezvous"))
	}
	return nil
}

// Reading the original retained journal files after shutdown compares actual
// bytes only. It cannot authorize an append or restore admission after the
// production stop latch has closed. The transaction must already be settled.
func linuxHostTUNJournal(ctx context.Context, journal *desktopLinuxNodeJournal, transaction *desktopLinuxNodeTransaction) (linuxprotection.JournalSelection, error) {
	if err := journal.enter(ctx); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	defer func() { journal.gate <- struct{}{} }()
	if journal.pending != nil || transaction.pending != nil || !transaction.engineJoined || !transaction.retired || transaction.retirement == nil ||
		transaction.process.command.ProcessState == nil || transaction.head.Record.Phase != "settled" || transaction.head.Record.Committed.Engine != nil {
		return linuxprotection.JournalSelection{}, errors.New("installed-host retirement omitted its original joined source or durable settlement")
	}
	if err := journal.verifyObjects(); err != nil {
		return linuxprotection.JournalSelection{}, err
	}
	actual, body, err := journal.readSelection()
	if err != nil || actual.Incomplete || !sameDesktopLinuxJournalSelection(actual, transaction.head.Record) || !bytes.Equal(body, journal.currentBytes) {
		return linuxprotection.JournalSelection{}, errors.Join(err, errors.New("installed-host retirement did not persist its exact original settled journal"))
	}
	return actual, nil
}

func linuxHostTUNTUNAbsent(record *mobilemultihop.DesktopNodeReadyRecord) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.Join(err, errors.New("installed-host TUN retirement requires a successful native inventory"))
	}
	for _, iface := range interfaces {
		if record == nil && iface.Name == "router-vpn" {
			return errors.New("failed installed-host readiness retained an actual TUN")
		}
		if record != nil && (iface.Index == int(record.InterfaceIndex) || iface.Name == record.InterfaceName) {
			return errors.New("joined installed host retained or substituted its original TUN index or name")
		}
	}
	return nil
}

// The actual protected installed controller owns every operation here. This
// fixture uses the ordinary completed bundle verifier and real generated
// executable, source, native channel, TUN, DNS, Router proof and journal.
// It changes no public capability predicate or verifier implementation.
func linuxNodeHostTUNFixture(controller *ownedDesktopController, scenario string) (failure error) {
	found := false
	for _, candidate := range linuxHostTUNCases {
		found = found || candidate == scenario
	}
	if !found {
		return errors.New("installed-host fixture has no captured scenario")
	}
	raw, err := os.ReadFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"))
	var profiles common.RouterProfileStore
	if err != nil || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &profiles) != nil || len(profiles.Profiles) != 1 || profiles.SelectedID != profiles.Profiles[0].ID {
		return errors.Join(err, errors.New("installed-host fixture lost its complete private saved profile"))
	}
	profile := profiles.Profiles[0]
	if profile.ID != "installed-linux-node" || profile.NodeProofID != linuxHostTUNNodeID || profile.RouterAPI != "http://10.77.0.1:8787" ||
		profile.DNSMode != "home" || profile.AdGuardIPv4 != "192.168.50.133" || profile.IPv6Mode != "on" || profile.MTUPolicy != "fixed" || profile.ManualMTU != 1376 {
		return errors.New("installed-host fixture changed its captured node, selected DNS or fixed MTU")
	}
	a := &app{localController: controller, profiles: profiles, state: state{Mode: "off", Phase: "off"},
		cfg: common.ClientConfig{AutoTestSeconds: 10, ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
			ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
			StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "installed-host-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 1); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	operation, finishOperation, err := a.beginConnectionTransaction()
	if err != nil {
		return err
	}
	var finished sync.Once
	finish := func() { finished.Do(finishOperation) }
	defer finish()
	journal, err := createDesktopLinuxNodeJournal(ctx, parent)
	if journal != nil {
		defer journal.Close(context.Background())
	}
	if err != nil {
		return err
	}
	host, err := prepareDesktopLinuxNodeHost(operation, a, profile, "shadowsocks", 0)
	if host != nil {
		defer host.Close(context.Background())
	}
	if err != nil {
		return fmt.Errorf("ordinary completed-bundle preparation: %w", err)
	}
	if err := host.Stage(ctx); err != nil {
		return err
	}
	workspace := host.launch.directory
	if err := host.Start(ctx, journal, nil); err != nil {
		return fmt.Errorf("actual installed child and durable admission: %w", err)
	}
	if host.process == nil || host.transaction == nil || !host.transaction.admitted || !host.transaction.nativeCommitted ||
		host.process.command != a.cmd || a.state.Connected || a.state.Phase != "starting" {
		return errors.New("installed-host fixture bypassed original native admission or claimed Connected before proof")
	}
	result := linuxHostTUNResult{Scenario: scenario, SessionID: host.selection.SessionID}
	ready, readyErr := host.WaitReady(ctx)
	failedReady := scenario == "wrong-key" || scenario == "resolver-failure"
	var replacement *exec.Cmd
	var replacementState state
	if failedReady {
		if readyErr == nil || ready != (mobilemultihop.DesktopNodeReadyRecord{}) || host.ready != nil || host.proof != nil || a.state.Connected {
			return errors.New("installed host accepted a failed encrypted key or selected resolver as ready")
		}
		result.Outcome = "rejected-ready"
	} else {
		if readyErr != nil || host.ready == nil || *host.ready != ready || ready.MTU != profile.ManualMTU || ready.DNSMilliseconds <= 0 {
			return errors.Join(readyErr, errors.New("installed host did not prove its actual selected DNS and fixed kernel MTU"))
		}
		result.Stage, result.Ready = "ready", &ready
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if err := linuxHostTUNRendezvous(gate, 2); err != nil {
			return err
		}
		proofContext := ctx
		var activation *desktopLinuxNodeActivation
		if scenario == "stale-ready" {
			stale := ready
			stale.ProvedAt = host.started.UnixMilli() - 1
			body, err := json.Marshal(stale)
			if err != nil || os.WriteFile(filepath.Join(workspace, "node-ready.json"), body, 0600) != nil {
				return errors.Join(err, errors.New("installed-host stale receipt control could not be written"))
			}
		}
		if scenario == "cancelled-proof" {
			short, stop := context.WithCancel(ctx)
			stop()
			proofContext = short
		}
		if scenario == "replaced-host" {
			replacement = exec.Command("/bin/sleep", "60")
			if err := replacement.Start(); err != nil {
				return err
			}
			defer func() { _ = replacement.Process.Kill(); _ = replacement.Wait() }()
			replacementState = state{Connected: true, RouterID: "replacement", Mode: "replacement", RuntimeMode: "replacement", Phase: "connected"}
			a.mu.Lock()
			a.cmd, a.state = replacement, replacementState
			a.mu.Unlock()
		}
		elapsed, proofErr := host.Prove(proofContext)
		failedProof := scenario == "wrong-node" || scenario == "stale-ready" || scenario == "cancelled-proof" || scenario == "replaced-host"
		if failedProof {
			if proofErr == nil || elapsed != 0 || host.proof != nil || scenario != "replaced-host" && a.state.Connected {
				return errors.New("installed host accepted a failed, stale, cancelled or replaced Router proof")
			}
			result.Outcome = "rejected-proof"
		} else {
			if proofErr != nil || elapsed <= 0 || host.proof == nil || host.proof.ready != ready || a.state.Connected {
				return errors.Join(proofErr, errors.New("installed host did not retain its actual routed private Router response"))
			}
			result.Outcome = "proved"
			if scenario == "cancel-adoption" {
				a.cancelConnectionOperation()
				if err := host.Activate(ctx); err == nil || a.state.Connected || host.activation != nil {
					return errors.New("cancelled original Connect adopted an installed native session")
				}
				result.Activation = "rejected-adoption"
			} else if strings.HasPrefix(scenario, "active-") {
				if host.Current(ctx) == nil || host.activation != nil {
					return errors.New("installed host inferred active ownership from readiness or proof alone")
				}
				if err := host.Activate(ctx); err != nil {
					return fmt.Errorf("activate original proved installed host: %w", err)
				}
				activation = host.activation
				finish()
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
				if operation.Err() == nil || a.connectionContext != nil || a.connectionCancel != nil ||
					!a.state.Connected || a.state.Phase != "connected" || a.cmd != host.process.command ||
					activation == nil || activation.operation != operation || activation.lifetime.Err() != nil {
					return errors.New("ordinary Connect completion discarded the original installed active owner")
				}
				if err := host.Current(ctx); err != nil {
					return fmt.Errorf("original active native readback after request completion: %w", err)
				}
				result.Activation = "retained-after-request"
				switch scenario {
				case "active-profile-change":
					a.mu.Lock()
					a.profiles.Profiles[0].AdGuardIPv4 = "192.168.50.134"
					a.mu.Unlock()
				case "active-network-change":
					command := exec.CommandContext(ctx, "ip", "addr", "add", "192.168.210.5/32", "dev", "rvpn-test")
					if output, err := command.CombinedOutput(); err != nil {
						return fmt.Errorf("owned active network replacement: %v: %s", err, output)
					}
					defer func() {
						cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						if output, err := exec.CommandContext(cleanup, "ip", "addr", "del", "192.168.210.5/32", "dev", "rvpn-test").CombinedOutput(); err != nil {
							failure = errors.Join(failure, fmt.Errorf("owned active network replacement cleanup: %v: %s", err, output))
						}
					}()
				case "active-command-change":
					replacement = exec.Command("/bin/sleep", "60")
					if err := replacement.Start(); err != nil {
						return err
					}
					defer func() { _ = replacement.Process.Kill(); _ = replacement.Wait() }()
					replacementState = state{Connected: true, RouterID: "replacement", Mode: "replacement", RuntimeMode: "replacement", Phase: "connected"}
					a.mu.Lock()
					a.cmd, a.state = replacement, replacementState
					a.mu.Unlock()
				}
				if scenario != "active-request-ended" {
					if err := host.Current(ctx); err == nil {
						return errors.New("retained installed host accepted a replaced active profile, network or command")
					}
					result.Activation = "rejected-active"
				}
			} else if scenario == "request-ended" {
				finish()
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
				if operation.Err() == nil || a.connectionContext != nil || a.state.Connected || a.cmd != host.process.command {
					return errors.New("ordinary Connect completion changed the original unactivated host")
				}
			}
		}
		if scenario == "shutdown" {
			a.mu.Lock()
			a.closing = true
			a.mu.Unlock()
			if err := a.retireNativeNodeForShutdownContext(ctx); err != nil {
				return fmt.Errorf("ordered original installed controller shutdown: %w", err)
			}
		} else if err := host.Retire(ctx, true); err != nil {
			return fmt.Errorf("joined original installed host retirement: %w", err)
		}
		if activation != nil && (activation.lifetime.Err() == nil || host.Current(ctx) == nil) {
			return errors.New("joined installed host retirement retained active session authority")
		}
		if replacement != nil && (a.cmd != replacement || !reflect.DeepEqual(a.state, replacementState) || replacement.Process.Signal(syscall.Signal(0)) != nil) {
			return errors.New("old installed host retirement changed or stopped the actual replacement command")
		}
	}
	if failedReady {
		if err := host.Retire(ctx, true); err != nil {
			return fmt.Errorf("failed-readiness original joined retirement: %w", err)
		}
	}
	if err := linuxHostTUNTUNAbsent(result.Ready); err != nil {
		return err
	}
	settled, err := linuxHostTUNJournal(ctx, journal, host.transaction)
	if err != nil {
		return err
	}
	result.Journal = &settled
	if scenario == "always" {
		if settled.Record.Committed.Target == nil || host.transaction.baseline.ObserveClosed(ctx) != nil || host.transaction.baselineReleased {
			return errors.New("installed host released its original closed Always protection")
		}
		closed, err := linuxShutdownTable(ctx, result.SessionID)
		if err != nil || len(closed) == 0 {
			return errors.Join(err, errors.New("installed Always host lost its original closed native table"))
		}
		digest := sha256.Sum256(closed)
		result.ClosedTableSHA256 = hex.EncodeToString(digest[:])
		// Retained Always remains a live transaction until the explicit
		// terminal stop latch joins its descriptors. Keep its original
		// journal and parent current through that ordered retirement.
		a.mu.Lock()
		a.closing = true
		a.mu.Unlock()
		if err := a.retireNativeNodeForShutdownContext(ctx); err != nil {
			return fmt.Errorf("ordered retained Always terminal shutdown: %w", err)
		}
		after, err := linuxShutdownTable(ctx, result.SessionID)
		if err != nil || !bytes.Equal(closed, after) || !host.transaction.closed || !host.transaction.released || host.transaction.baselineReleased {
			return errors.Join(err, errors.New("terminal Always shutdown changed its original closed table or retained owners"))
		}
		retained, err := linuxHostTUNJournal(ctx, journal, host.transaction)
		if err != nil || !reflect.DeepEqual(retained, settled) {
			return errors.Join(err, errors.New("terminal Always shutdown changed its exact settled durable checkpoint"))
		}
	} else if settled.Record.Committed.Target != nil || mobiletor.ReadDesktopLinuxNodeAbsence(ctx, result.SessionID) != nil {
		return errors.New("installed On-connect host did not release only its original settled protection")
	}
	if err := host.Close(ctx); err != nil {
		return err
	}
	if _, err := os.Lstat(workspace); !errors.Is(err, os.ErrNotExist) {
		return errors.New("joined installed host retained its private launch workspace")
	}
	if err := journal.Close(ctx); err != nil {
		return err
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	controller.close()
	if replacement != nil && (a.cmd != replacement || !reflect.DeepEqual(a.state, replacementState) || replacement.Process.Signal(syscall.Signal(0)) != nil) {
		return errors.New("original installed host cleanup changed or stopped the replacement command after retirement")
	}
	result.Stage = "retired"
	return json.NewEncoder(os.Stdout).Encode(result)
}

type linuxHostTUNController struct {
	command    *exec.Cmd
	input      *os.File
	gate       *os.File
	output     *os.File
	reader     *bufio.Reader
	diagnostic linuxHostTUNOutput
	done       chan struct{}
	waitErr    error
	cancel     context.CancelFunc
}

func linuxHostTUNStartController(t *testing.T, installed, scenario string) *linuxHostTUNController {
	t.Helper()
	reader, writer := linuxControllerUserPipe(t, installed)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	base := linuxControllerBootstrapCommand(installed, reader)
	command := exec.CommandContext(ctx, installed, base.Args[1:]...)
	command.Stdin, command.Env, command.ExtraFiles = reader, append(base.Env, "ROUTERVPN_CONTROLLER_NODE_PARENT_CASE=host-tun/"+scenario), []*os.File{gateRead}
	process := &linuxHostTUNController{command: command, input: writer, gate: gateWrite, done: make(chan struct{}), cancel: cancel}
	var outputWriter *os.File
	process.output, outputWriter, err = os.Pipe()
	if err != nil {
		cancel()
		gateRead.Close()
		gateWrite.Close()
		t.Fatal(err)
	}
	process.reader = bufio.NewReaderSize(process.output, 64<<10)
	command.Stdout, command.Stderr = outputWriter, &process.diagnostic
	if err := command.Start(); err != nil {
		cancel()
		gateRead.Close()
		gateWrite.Close()
		process.output.Close()
		outputWriter.Close()
		t.Fatal(err)
	}
	reader.Close()
	gateRead.Close()
	outputWriter.Close()
	go func() { process.waitErr = command.Wait(); close(process.done) }()
	t.Cleanup(func() {
		writer.Close()
		gateWrite.Close()
		cancel()
		<-process.done
		process.output.Close()
	})
	if _, err := writer.Write(testLinuxOwnedHandshake()); err != nil {
		t.Fatal(err)
	}
	if err := process.output.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := process.reader.ReadSlice('\n')
	var record desktopLinuxNodeParentRecord
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &record) != nil || record.ProcessID != command.Process.Pid || record.ProcProcessID == 0 ||
		record.StartTicks == 0 || record.CallerUID != linuxControllerFixtureUID || !validControllerOwnerToken(record.Generation) ||
		record.Root.Inode == 0 || record.Image.Inode == 0 || record.InstallLock.Inode == 0 || record.ProcessLock.Inode == 0 {
		t.Fatal("installed host did not return its actual authenticated original controller", err, process.diagnostic.String())
	}
	if err := process.output.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return process
}

func (process *linuxHostTUNController) read(t *testing.T, scenario string) linuxHostTUNResult {
	t.Helper()
	if err := process.output.SetReadDeadline(time.Now().Add(70 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer process.output.SetReadDeadline(time.Time{})
	raw, err := process.reader.ReadSlice('\n')
	var result linuxHostTUNResult
	if err != nil || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &result) != nil || result.Scenario != scenario ||
		!desktopMTURequestPattern.MatchString(result.SessionID) || result.Stage != "ready" && result.Stage != "retired" {
		t.Fatal("installed host lost its bounded actual lifecycle result", err, string(raw), process.diagnostic.String())
	}
	return result
}

func TestDesktopLinuxGuardianKernelNodeHostTUN(t *testing.T) {
	linuxHostTUNNamespace(t)
	for _, scenario := range linuxHostTUNCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			linuxHostTUNInstallBundle(t)
			peer := linuxHostTUNStartPeer(t)
			linuxHostTUNDirectHealth(t, peer)
			linuxHostTUNInstallProfile(t, peer, scenario)
			if scenario == "resolver-failure" {
				peer.observe(t, "fail-dns")
			}
			if scenario == "wrong-node" {
				peer.observe(t, "wrong-node")
			}
			process := linuxHostTUNStartController(t, installed, scenario)
			if _, err := process.gate.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			result := process.read(t, scenario)
			failedReady := scenario == "wrong-key" || scenario == "resolver-failure"
			var before linuxHostTUNPeerReply
			if !failedReady {
				if result.Stage != "ready" || result.Ready == nil || result.Ready.MTU != 1376 || result.Ready.DNSMilliseconds <= 0 {
					t.Fatal("installed host did not report its actual selected DNS and TUN")
				}
				if scenario == "home-lan" {
					// This direct same-node response is demonstrably available
					// after the TUN starts. Prove must still use the captured TUN.
					linuxHostTUNDirectHealth(t, peer)
				}
				before = peer.observe(t, "stats")
				if before.DNSQueries < 2 || before.RawUDP == 0 || before.PlainUDP == 0 || before.RouterQueries != 0 {
					t.Fatal("installed readiness bypassed the selected encrypted DNS path", before)
				}
				if _, err := process.gate.Write([]byte{2}); err != nil {
					t.Fatal(err)
				}
				result = process.read(t, scenario)
			}
			if result.Stage != "retired" || result.Journal == nil || result.Journal.Incomplete || result.Journal.Record.Validate() != nil ||
				result.Journal.Record.Phase != "settled" || result.Journal.Record.Committed.Engine != nil {
				t.Fatal("installed host omitted its actual source/process join and durable retirement", result)
			}
			select {
			case <-process.done:
			case <-time.After(5 * time.Second):
				t.Fatal("installed controller did not join after its original native retirement", process.diagnostic.String())
			}
			if process.waitErr != nil || process.command.ProcessState == nil || !process.command.ProcessState.Success() {
				t.Fatal("installed controller failed its actual native lifecycle", process.waitErr, process.diagnostic.String())
			}
			if err := linuxHostTUNTUNAbsent(result.Ready); err != nil {
				t.Fatal(err)
			}
			after := peer.observe(t, "stats")
			if failedReady {
				if result.Outcome != "rejected-ready" || result.Ready != nil || after.RouterQueries != 0 || scenario == "resolver-failure" && after.DNSQueries == 0 {
					t.Fatal("failed key/resolver fabricated readiness or a Router response", result, after)
				}
			} else {
				http := scenario != "stale-ready" && scenario != "cancelled-proof" && scenario != "replaced-host"
				expectedHTTP := before.RouterQueries
				if http {
					expectedHTTP++
				}
				if after.RouterQueries != expectedHTTP || after.DirectQueries != before.DirectQueries || http && (after.RawTCP <= before.RawTCP || after.PlainTCP <= before.PlainTCP) {
					t.Fatal("installed Router proof used the direct LAN response or bypassed its exact encrypted graph", before, after)
				}
			}
			if scenario == "always" {
				readContext, stopRead := context.WithTimeout(context.Background(), 2*time.Second)
				closed, err := linuxShutdownTable(readContext, result.SessionID)
				stopRead()
				digest := sha256.Sum256(closed)
				if err != nil || len(closed) == 0 || result.Journal.Record.Committed.Target == nil ||
					result.ClosedTableSHA256 == "" || hex.EncodeToString(digest[:]) != result.ClosedTableSHA256 {
					t.Fatal("original closed Always protection changed when the installed controller joined", err)
				}
			} else if result.Journal.Record.Committed.Target != nil || mobiletor.ReadDesktopLinuxNodeAbsence(context.Background(), result.SessionID) != nil {
				t.Fatal("installed On-connect retirement left an unowned native table")
			}
			activation := ""
			switch scenario {
			case "active-request-ended":
				activation = "retained-after-request"
			case "cancel-adoption":
				activation = "rejected-adoption"
			case "active-profile-change", "active-network-change", "active-command-change":
				activation = "rejected-active"
			}
			if result.Activation != activation {
				t.Fatal("installed host omitted its actual captured activation and lifetime result", result.Activation, activation)
			}
			if activation != "" {
				t.Log("verified installed host active lifetime:", scenario)
			}
			t.Log("verified installed host native lifecycle:", scenario)
		})
	}
}
