//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/standardengine"
)

var linuxHostTUNReverseCases = []string{"node-standard-original", "node-standard-lost-commit-reply", "node-standard-lost-prepare-reply", "node-standard-lost-start-reply", "node-standard-cancel-before-remove", "node-standard-longer-deadline", "node-standard-post-removal-failure", "node-standard-always-lost-prepare", "node-standard-always-cancel-before-remove"}

func linuxHostTUNReverseAlwaysCase(scenario string) bool {
	return scenario == "node-standard-always-lost-prepare" || scenario == "node-standard-always-cancel-before-remove"
}
func linuxHostTUNReverseAbortCase(scenario string) bool {
	return scenario == "node-standard-lost-prepare-reply" || scenario == "node-standard-cancel-before-remove" || scenario == "node-standard-longer-deadline" || linuxHostTUNReverseAlwaysCase(scenario)
}

func linuxHostTUNReverseCase(scenario string) bool {
	for _, candidate := range linuxHostTUNReverseCases {
		if candidate == scenario {
			return true
		}
	}
	return false
}

type linuxHostTUNReverseResult struct {
	Stage, Scenario, NodeSession                            string
	NodeReady                                               *mobilemultihop.DesktopNodeReadyRecord
	Intent                                                  *linuxprotection.NodeStandardTransfer
	Source, Destination                                     *mobiletor.DesktopLinuxClosedTransferSnapshot
	Startup                                                 *linuxStandardServiceStartup
	Prepared, SourceRemoved, Aborted, Faulted, PrivateProof bool
	AlwaysReleased                                          bool
	Journal                                                 *linuxprotection.JournalSelection
}

// This proof deliberately targets the private peer, rather than claiming public
// Internet identity. SO_BINDTODEVICE and exact retained Ready comparisons prevent
// the independently reachable same-identity LAN control from satisfying it.
func linuxHostTUNReversePrivateProof(ctx context.Context, owner *linuxStandardServiceLaunch) error {
	if err := owner.Current(ctx); err != nil {
		return err
	}
	epoch := owner.prepared.requestEpoch
	if epoch == nil || !epoch.ready || epoch.startup == nil || !owner.dnsProved {
		return errors.New("reverse proof omitted original child/DNS readiness")
	}
	ready, err := standardengine.DecodeReady(epoch.startup.Ready, standardengine.SHA256(epoch.startup.Capture))
	if err != nil {
		return err
	}
	receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(ready.NetworkReceipt)
	if err != nil {
		return err
	}
	observed, err := net.InterfaceByIndex(int(receipt.Index))
	if err != nil || observed.Name != receipt.Name || observed.MTU != receipt.MTU {
		return errors.Join(err, errors.New("reverse private proof changed actual TUN"))
	}
	dialer := &net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var failure error
		err := raw.Control(func(fd uintptr) {
			failure = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, receipt.Name)
		})
		return errors.Join(err, failure)
	}}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("private original proof cannot redirect")
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.77.0.1:8787/health", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > 4096 || response.StatusCode != http.StatusOK || validateCapturedNodeProof(linuxHostTUNNodeID, body) != nil {
		return errors.Join(readErr, closeErr, errors.New("reverse private encrypted proof failed"))
	}
	after, err := net.InterfaceByIndex(int(receipt.Index))
	if err != nil || after.Name != observed.Name || after.MTU != observed.MTU {
		return errors.Join(err, errors.New("reverse proof replaced original TUN"))
	}
	return owner.Current(ctx)
}

func linuxHostTUNReverseConnection(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, controller *ownedDesktopController, gate *os.File, scenario string) (failure error) {
	raw, err := readPrivateRegular(a.cfg.ModesFile, 256<<10)
	// The shipping catalog contains twenty raw runtimes plus SMART AUTO and CUSTOM.
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 22 {
		return errors.Join(err, errors.New("reverse fixture lost shipping mode catalog"))
	}
	node := httptest.NewRecorder()
	a.connect(node, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"shadowsocks"}`)).WithContext(ctx))
	if node.Code != http.StatusOK {
		return fmt.Errorf("reverse original public Node Connect: %d %s", node.Code, node.Body.String())
	}
	a.mu.Lock()
	command := a.cmd
	a.mu.Unlock()
	path, handled, err := captureDesktopLinuxNodePath(ctx, a, command)
	if err != nil || !handled || path == nil {
		return errors.Join(err, errors.New("reverse source lost actual retained Node"))
	}
	host, session, journal := path.host, path.session, path.journal
	result := linuxHostTUNReverseResult{Stage: "node-ready", Scenario: scenario, NodeSession: path.selection.SessionID, NodeReady: &path.ready}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if err = linuxHostTUNRendezvous(gate, 2); err != nil {
		return err
	}
	var captured *linuxStandardServiceLaunch
	prepare := func(a *app, command *exec.Cmd, mode, base, router string) (legacyStandardExitLaunch, error) {
		launch, e := prepareLegacyStandardExitOwner(a, command, mode, base, router)
		if e != nil {
			return launch, e
		}
		var ok bool
		captured, ok = launch.(*linuxStandardServiceLaunch)
		if !ok {
			return nil, errors.New("reverse namespace bypassed installed service")
		}
		captured.exchange = func(call context.Context, q linuxStandardServiceRequest, directory *os.File, before func()) (linuxStandardServiceResponse, error) {
			if scenario == "node-standard-post-removal-failure" && q.Action == "start" && !result.Faulted {
				result.Faulted = true
				return linuxStandardServiceResponse{}, errors.New("explicit lost transport before actual Start after native source removal")
			}
			response, e := linuxStandardServiceRPC(call, captured.image, captured.prepared.namespaceInfo, &captured.peer, q, directory, before)
			if e == nil && q.Action == "reverse-prepare" && response.Reverse != nil && response.Reverse.Phase == "prepared" {
				if q.Reverse == nil || response.Reverse.Destination == nil {
					return response, errors.New("actual prepared service omitted original guards")
				}
				if e = mobiletor.ReadDesktopLinuxClosedTransferCurrent(call, q.Reverse.Source); e != nil {
					return response, e
				}
				if e = mobiletor.ReadDesktopLinuxClosedTransferCurrent(call, *response.Reverse.Destination); e != nil {
					return response, e
				}
				intent, source, destination := q.Reverse.Intent, q.Reverse.Source, *response.Reverse.Destination
				result.Intent, result.Source, result.Destination = &intent, &source, &destination
				result.Prepared = true
			}
			if e == nil && q.Action == "reverse-commit" && response.Reverse != nil && response.Reverse.Committed {
				if e = mobiletor.ReadDesktopLinuxNodeAbsence(call, result.NodeSession); e != nil {
					return response, e
				}
				if result.Destination == nil {
					return response, errors.New("reverse commit lost captured successor")
				}
				if e = mobiletor.ReadDesktopLinuxClosedTransferCurrent(call, *result.Destination); e != nil {
					return response, e
				}
				result.SourceRemoved = true
			}
			if e == nil && q.Action == "start" && scenario == "node-standard-lost-start-reply" && !result.Faulted {
				if response.Startup == nil {
					return response, errors.New("lost Start control omitted actual native child readiness")
				}
				result.Startup = &linuxStandardServiceStartup{Capture: append([]byte(nil), response.Startup.Capture...), Ready: append([]byte(nil), response.Startup.Ready...)}
				result.Faulted = true
				return linuxStandardServiceResponse{}, io.ErrUnexpectedEOF
			}
			if e == nil && q.Action == "reverse-prepare" && !result.Faulted {
				if scenario == "node-standard-longer-deadline" {
					changed := *q.Reverse
					changed.Intent.DeadlineNS += int64(time.Minute)
					duplicate := q
					duplicate.Reverse = &changed
					if _, changedErr := linuxStandardServiceRPC(call, captured.image, captured.prepared.namespaceInfo, &captured.peer, duplicate, directory, nil); changedErr == nil {
						return response, errors.New("service accepted changed original immutable deadline")
					}
					result.Faulted = true
					return linuxStandardServiceResponse{}, errors.New("changed deadline rejected; resolve original prepared owner")
				}
				if scenario == "node-standard-cancel-before-remove" || scenario == "node-standard-always-cancel-before-remove" {
					result.Faulted = true
					a.cancelConnectionOperation()
				}
			}
			lose := scenario == "node-standard-lost-commit-reply" && q.Action == "reverse-commit" || (scenario == "node-standard-lost-prepare-reply" || scenario == "node-standard-always-lost-prepare") && q.Action == "reverse-prepare"
			if e == nil && lose && !result.Faulted {
				result.Faulted = true
				return linuxStandardServiceResponse{}, io.ErrUnexpectedEOF
			}
			return response, e
		}
		return launch, nil
	}
	request, _ := json.Marshal(standardExitConnectRequest{StandardExitID: "service-transfer-original", Direct: true})
	standard := httptest.NewRecorder()
	a.platformStandardExitConnectOwned(standard, httptest.NewRequest(http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(request)).WithContext(ctx), platformStandardExitRuntime{
		prepareLegacy: prepare,
		proveDNS: func(ctx context.Context, owner legacyStandardExitLaunch) error {
			return owner.(*linuxStandardServiceLaunch).ProveSelectedDNS(ctx)
		},
		prove: func(a *app, _ string) error {
			a.mu.Lock()
			operation := a.connectionContext
			a.mu.Unlock()
			e := linuxHostTUNReversePrivateProof(operation, captured)
			result.PrivateProof = e == nil
			return e
		},
		current: func(owner legacyStandardExitLaunch, ctx context.Context) error { return owner.Current(ctx) },
	})
	if captured == nil || captured.reverse == nil || captured.reverse.source != host.transaction || !result.Prepared || result.Intent == nil || !captured.reverse.resolved.Load() {
		return fmt.Errorf("reverse route lost exact prepared/settled owners: %d %s", standard.Code, standard.Body.String())
	}
	result.Aborted = !captured.reverse.committed.Load()
	if scenario == "node-standard-original" {
		if standard.Code != http.StatusOK || !result.SourceRemoved || result.Aborted || !result.PrivateProof || captured.prepared.requestEpoch.startup == nil || !captured.dnsProved || captured.Command().Process != nil {
			return fmt.Errorf("reverse public standard Start omitted actual child/DNS/private proof: %d %s", standard.Code, standard.Body.String())
		}
		startup := captured.prepared.requestEpoch.startup
		result.Startup = &linuxStandardServiceStartup{Capture: append([]byte(nil), startup.Capture...), Ready: append([]byte(nil), startup.Ready...)}
	} else {
		if standard.Code == http.StatusOK || !result.Faulted || result.PrivateProof || captured.prepared.requestEpoch.startup != nil {
			return errors.New("lost reverse reply fabricated a started standard engine")
		}
		expectedAbort := linuxHostTUNReverseAbortCase(scenario)
		if result.Aborted != expectedAbort || result.SourceRemoved == expectedAbort {
			return errors.New("lost reply changed actual native transaction outcome")
		}
		if expectedAbort && (session.predecessor != host.transaction || mobiletor.ReadDesktopLinuxClosedTransferCurrent(ctx, *result.Source) != nil) {
			return errors.New("actual abort discarded original Node guard")
		}
	}
	result.Stage = "transfer-resolved"
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if err = linuxHostTUNRendezvous(gate, 3); err != nil {
		return err
	}
	stop := httptest.NewRecorder()
	a.disconnect(stop, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil).WithContext(ctx))
	if stop.Code != http.StatusOK {
		return fmt.Errorf("reverse public Disconnect failed: %d %s", stop.Code, stop.Body.String())
	}
	if linuxHostTUNReverseAlwaysCase(scenario) {
		off, e := linuxHostTUNPublicProtectionOff(ctx, a, session, host, scenario)
		if e != nil || off == nil || !off.RetainedAlways || !off.NetworkReleased || !off.ProfileSaved || !off.JournalSettled {
			return errors.Join(e, errors.New("reverse Always abort did not preserve original until explicit saved Off"))
		}
		result.AlwaysReleased = true
	}
	a.mu.Lock()
	appJoined := a.cmd == nil && !a.state.Connected && a.state.Phase == "off"
	a.mu.Unlock()
	if _, present := linuxStandardServiceOwners.Load(a); present || !appJoined || !captured.joined || session.active != nil || session.predecessor != nil {
		return errors.New("reverse Disconnect retained an original runtime selection")
	}
	if err = mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	if err = linuxHostTUNTUNAbsent(result.NodeReady); err != nil {
		return err
	}
	if result.Startup != nil {
		ready, e := standardengine.DecodeReady(result.Startup.Ready, standardengine.SHA256(result.Startup.Capture))
		if e != nil {
			return e
		}
		receipt, e := desktopnetwork.ParseDesktopNetworkReceipt(ready.NetworkReceipt)
		if e != nil {
			return e
		}
		if _, e = net.InterfaceByName(receipt.Name); e == nil {
			return errors.New("reverse Disconnect left actual standard TUN")
		}
	}
	settled, err := linuxHostTUNJournal(ctx, journal, host.transaction)
	if err != nil || settled.Record.Committed.Target != nil || settled.Record.ReverseTransfer == nil || *settled.Record.ReverseTransfer != *result.Intent {
		return errors.Join(err, errors.New("reverse final joined journal lost its immutable intent"))
	}
	result.Journal = &settled
	if err = parent.parent.Close(ctx); err != nil {
		return err
	}
	controller.close()
	result.Stage = "retired"
	return json.NewEncoder(os.Stdout).Encode(result)
}

func readLinuxHostTUNReverse(t *testing.T, process *linuxHostTUNController, scenario, stage string) linuxHostTUNReverseResult {
	t.Helper()
	if err := process.output.SetReadDeadline(time.Now().Add(70 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer process.output.SetReadDeadline(time.Time{})
	raw, err := process.reader.ReadSlice('\n')
	var out linuxHostTUNReverseResult
	if err != nil || len(raw) > 64<<10 || decodeRelayControlJSON(raw, &out) != nil || out.Scenario != scenario || out.Stage != stage || !desktopMTURequestPattern.MatchString(out.NodeSession) {
		t.Fatal("reverse original controller lost exact stage", stage, err, string(raw), process.diagnostic.String())
	}
	return out
}

func TestDesktopLinuxGuardianKernelNodeStandardServiceReverse(t *testing.T) {
	linuxHostTUNNamespace(t)
	for _, scenario := range linuxHostTUNReverseCases {
		t.Run(scenario, func(t *testing.T) {
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			linuxHostTUNInstallBundle(t)
			peer := linuxHostTUNStartPeer(t, scenario)
			linuxHostTUNDirectHealth(t, peer)
			linuxHostTUNInstallProfile(t, peer, scenario)
			linuxHostTUNTransferService(t, installed, peer)
			process := linuxHostTUNStartController(t, installed, scenario)
			if _, err := process.gate.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			initial := readLinuxHostTUNReverse(t, process, scenario, "node-ready")
			before := peer.observe(t, "stats")
			if initial.NodeReady == nil || initial.NodeReady.MTU != 1376 || initial.NodeReady.DNSMilliseconds <= 0 || before.RouterQueries != 1 || before.DNSQueries < 2 || !linuxHostTUNEncryptedTCP(peer, linuxHostTUNPeerReply{}, before) {
				t.Fatal("reverse source lacked actual encrypted Node proof", initial, before)
			}
			if _, err := process.gate.Write([]byte{2}); err != nil {
				t.Fatal(err)
			}
			resolved := readLinuxHostTUNReverse(t, process, scenario, "transfer-resolved")
			after := peer.observe(t, "stats")
			if !resolved.Prepared || resolved.Source == nil || resolved.Destination == nil || resolved.Intent == nil || resolved.Source.Validate() != nil || resolved.Destination.Validate() != nil || resolved.Source.Capture.SessionID != initial.NodeSession || resolved.Intent.DestinationSession != resolved.Destination.Capture.SessionID || after.DirectQueries != before.DirectQueries {
				t.Fatal("reverse handoff lost actual guards or used direct LAN proof", resolved, before, after)
			}
			if scenario == "node-standard-original" {
				if resolved.Startup == nil || !resolved.SourceRemoved || !resolved.PrivateProof || resolved.Aborted || after.DNSQueries <= before.DNSQueries || after.RouterQueries != before.RouterQueries+1 || !linuxHostTUNEncryptedTCP(peer, before, after) {
					t.Fatal("reverse standard child omitted actual DNS/TUN/encrypted traffic", resolved, before, after)
				}
				if _, err := standardengine.DecodeReady(resolved.Startup.Ready, standardengine.SHA256(resolved.Startup.Capture)); err != nil {
					t.Fatal(err)
				}
			} else if !resolved.Faulted || (resolved.Startup != nil) != (scenario == "node-standard-lost-start-reply") || resolved.PrivateProof || resolved.Aborted != linuxHostTUNReverseAbortCase(scenario) {
				t.Fatal("reverse reply loss fabricated child or native outcome", resolved)
			}
			if _, err := process.gate.Write([]byte{3}); err != nil {
				t.Fatal(err)
			}
			final := readLinuxHostTUNReverse(t, process, scenario, "retired")
			if final.AlwaysReleased != linuxHostTUNReverseAlwaysCase(scenario) {
				t.Fatal("reverse Always retirement omitted explicit saved Off", final)
			}
			if final.Journal == nil || final.Journal.Incomplete || final.Journal.Record.Validate() != nil || final.Journal.Record.Committed.Target != nil || final.Journal.Record.ReverseTransfer == nil || *final.Journal.Record.ReverseTransfer != *resolved.Intent {
				t.Fatal("reverse teardown lost original durable settlement", final)
			}
			select {
			case <-process.done:
			case <-time.After(5 * time.Second):
				t.Fatal("reverse original controller did not join", process.diagnostic.String())
			}
			if process.waitErr != nil {
				t.Fatal(process.waitErr, process.diagnostic.String())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
				t.Fatal("reverse teardown retained native guard", err)
			}
			t.Log("verified installed Node to standard service original creators, DNS, private encrypted proof and joined retirement:", scenario)
		})
	}
}
