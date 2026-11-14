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

var linuxHostTUNCases = []string{"service-transfer", "service-transfer-lost-reply", "service-transfer-longer-deadline", "on-connect", "home-lan", "wrong-node", "resolver-failure", "wrong-key", "stale-ready", "cancelled-proof",
	"replaced-host", "request-ended", "shutdown", "always", "active-request-ended", "cancel-adoption", "active-profile-change",
	"active-network-change", "active-command-change", "mtu-rollback", "mtu-commit", "mtu-stale-profile", "mtu-stale-network", "mtu-hold", "mtu-retire-undrained", "restore-sealed", "public-connect",
	"cover-connect", "cover-replies-lost", "cover-wrong-node", "cover-no-replies", "cover-restore", "public-off", "public-off-save-retry",
	"layer-aes-connect", "layer-whitening-connect", "layer-whitening-wrong-key", "layer-whitening-resolver-failure", "layer-aes-restore", "layer-whitening-cover-restore"}

func init() {
	linuxHostTUNCases = append(linuxHostTUNCases, linuxImportedHostCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxNodeChainHostCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxNodeChainSOCKSHostCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNWireGuardCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNHysteria2Cases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNAmneziaCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNHysteria2LayerCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNWireGuardLayerCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNAmneziaLayerCases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNSIP003Cases...)
	linuxHostTUNCases = append(linuxHostTUNCases, linuxHostTUNExternalCases...)
}

func linuxHostTUNCoverCase(scenario string) bool {
	scenario = linuxHostTUNAction(scenario)
	return scenario == "cover-connect" || scenario == "cover-replies-lost" || scenario == "cover-wrong-node" || scenario == "cover-no-replies" || scenario == "cover-restore" || scenario == "layer-whitening-cover-restore"
}

func linuxHostTUNRestoreCase(scenario string) bool {
	scenario = linuxHostTUNAction(scenario)
	return scenario == "restore-sealed" || scenario == "cover-restore" || scenario == "layer-aes-restore" || scenario == "layer-whitening-cover-restore"
}

func linuxHostTUNPublicCase(scenario string) bool {
	scenario = linuxHostTUNAction(scenario)
	return linuxHostTUNBootTransferCase(scenario) || linuxHostTUNReverseCase(scenario) || linuxHostTUNTransferCase(scenario) || scenario == "public-connect" || scenario == "cover-connect" || scenario == "cover-replies-lost" || linuxHostTUNOffCase(scenario) ||
		scenario == "layer-aes-connect" || scenario == "layer-whitening-connect"
}

func linuxHostTUNOffCase(scenario string) bool {
	scenario = linuxHostTUNAction(scenario)
	return linuxHostTUNBootTransferCase(scenario) || scenario == "public-off" || scenario == "public-off-save-retry" || linuxHostTUNReverseAlwaysCase(scenario)
}

func linuxHostTUNFailedReadyCase(scenario string) bool {
	// Credential classifiers require the complete protocol-specific case name.
	// Stripping hy2- first loses the selected TLS and Salamander negatives.
	if linuxHostTUNWrongKeyCase(scenario) || linuxHostTUNResolverFailureCase(scenario) {
		return true
	}
	scenario = linuxHostTUNAction(scenario)
	return scenario == "cover-wrong-node" || scenario == "cover-no-replies"
}

func linuxHostTUNAssertReadinessClassification(t *testing.T) {
	t.Helper()
	negative := map[string]bool{}
	for _, scenario := range []string{
		"wrong-key", "resolver-failure", "cover-wrong-node", "cover-no-replies",
		"layer-whitening-wrong-key", "layer-whitening-resolver-failure",
		"wg-wrong-key", "wg-resolver-failure",
		"hy2-wrong-key", "hy2-wrong-trust", "hy2-wrong-salamander", "hy2-resolver-failure",
		"awg2-fast-wrong-key", "awg2-fast-wrong-header", "awg2-fast-wrong-padding", "awg2-fast-resolver-failure",
		"awg2-strong-wrong-key", "awg2-strong-wrong-header", "awg2-strong-wrong-padding", "awg2-strong-resolver-failure",
		"hy2-aes-wrong-key",
		"hy2-aes-wrong-trust",
		"hy2-aes-wrong-salamander",
		"hy2-aes-wrong-layer-key",
		"hy2-aes-resolver-failure",
		"hy2-whitening-wrong-key",
		"hy2-whitening-wrong-trust",
		"hy2-whitening-wrong-salamander",
		"hy2-whitening-wrong-layer-key",
		"hy2-whitening-resolver-failure",
		"hy2-whitening-wrong-whitening",
		"wg-aes-wrong-key",
		"wg-aes-wrong-psk",
		"wg-aes-wrong-layer-key",
		"wg-aes-resolver-failure",
		"wg-whitening-wrong-key",
		"wg-whitening-wrong-psk",
		"wg-whitening-wrong-layer-key",
		"wg-whitening-resolver-failure",
		"wg-whitening-wrong-whitening",
		"awg2-fast-aes-wrong-key",
		"awg2-fast-aes-wrong-psk",
		"awg2-fast-aes-wrong-layer-key",
		"awg2-fast-aes-wrong-header",
		"awg2-fast-aes-wrong-padding",
		"awg2-fast-aes-resolver-failure",
		"awg2-fast-whitening-wrong-key",
		"awg2-fast-whitening-wrong-psk",
		"awg2-fast-whitening-wrong-layer-key",
		"awg2-fast-whitening-wrong-header",
		"awg2-fast-whitening-wrong-padding",
		"awg2-fast-whitening-resolver-failure",
		"awg2-strong-aes-wrong-key",
		"awg2-strong-aes-wrong-psk",
		"awg2-strong-aes-wrong-layer-key",
		"awg2-strong-aes-wrong-header",
		"awg2-strong-aes-wrong-padding",
		"awg2-strong-aes-resolver-failure",
		"awg2-strong-whitening-wrong-key",
		"awg2-strong-whitening-wrong-psk",
		"awg2-strong-whitening-wrong-layer-key",
		"awg2-strong-whitening-wrong-header",
		"awg2-strong-whitening-wrong-padding",
		"awg2-strong-whitening-resolver-failure",
		"awg2-fast-whitening-wrong-whitening",
		"awg2-strong-whitening-wrong-whitening",
		"ss-v2ray-off-udp-key",
		"ss-v2ray-off-udp-trust",
		"ss-v2ray-off-udp-salamander",
		"ss-v2ray-off-resolver-failure",
		"ss-v2ray-off-cover-wrong-node",
		"ss-v2ray-off-cover-no-replies",
		"ss-v2ray-aes-udp-key",
		"ss-v2ray-aes-udp-trust",
		"ss-v2ray-aes-udp-salamander",
		"ss-v2ray-aes-resolver-failure",
		"ss-v2ray-aes-cover-wrong-node",
		"ss-v2ray-aes-cover-no-replies",
		"ss-v2ray-whitening-udp-key",
		"ss-v2ray-whitening-udp-trust",
		"ss-v2ray-whitening-udp-salamander",
		"ss-v2ray-whitening-resolver-failure",
		"ss-v2ray-whitening-cover-wrong-node",
		"ss-v2ray-whitening-cover-no-replies",
		"ss-v2ray-aes-wrong-layer-key",
		"ss-v2ray-whitening-wrong-layer-key",
		"ss-v2ray-whitening-wrong-whitening",
	} {
		negative[scenario] = true
	}
	seen := make(map[string]bool, len(linuxHostTUNCases))
	for _, scenario := range linuxHostTUNCases {
		if seen[scenario] || linuxHostTUNFailedReadyCase(scenario) != negative[scenario] {
			t.Fatal("installed host changed its exact negative-readiness classification", scenario)
		}
		seen[scenario] = true
	}
	for scenario := range negative {
		if !seen[scenario] {
			t.Fatal("installed host omitted an original negative-readiness case", scenario)
		}
	}
	t.Logf("verified installed host readiness classification: %d scenarios, %d expected rejections", len(seen), len(negative))
}

func TestDesktopLinuxInstalledHostNegativeReadinessClassification(t *testing.T) {
	linuxHostTUNAssertReadinessClassification(t)
}

func linuxHostTUNMTUCase(scenario string) bool {
	scenario = linuxHostTUNAction(scenario)
	return scenario == "mtu-rollback" || scenario == "mtu-commit" || scenario == "mtu-stale-profile" || scenario == "mtu-stale-network" || scenario == "mtu-hold" || scenario == "mtu-retire-undrained"
}

type linuxHostTUNResult struct {
	Transfer          bool                                   `json:"transfer,omitempty"`
	Stage             string                                 `json:"stage"`
	Scenario          string                                 `json:"scenario"`
	SessionID         string                                 `json:"session_id"`
	Outcome           string                                 `json:"outcome"`
	Ready             *mobilemultihop.DesktopNodeReadyRecord `json:"ready,omitempty"`
	Journal           *linuxprotection.JournalSelection      `json:"journal,omitempty"`
	ClosedTableSHA256 string                                 `json:"closed_table_sha256,omitempty"`
	Activation        string                                 `json:"activation,omitempty"`
	DNSProof          *dnsProofState                         `json:"dns_proof,omitempty"`
	MTU               *linuxHostTUNMTUResult                 `json:"mtu,omitempty"`
	MTUView           *linuxHostTUNMTUViewResult             `json:"mtu_view,omitempty"`
	Restore           *linuxHostTUNRestoreResult             `json:"restore,omitempty"`
	Public            bool                                   `json:"public,omitempty"`
	Cover             string                                 `json:"cover,omitempty"`
	ProtectionOff     *linuxHostTUNOffResult                 `json:"protection_off,omitempty"`
	StartLayer        string                                 `json:"start_layer,omitempty"`
	Physical          []mobilemultihop.PhysicalEgress        `json:"physical"`
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

// Exercise the actual app reporter after the original Connect request has
// finished. The receipt already contains the native query; this observer must
// not query the ambient resolver or label that prior exchange a fresh Retest.
func linuxHostTUNDNSObservation(ctx context.Context, a *app, host *desktopLinuxNodeHost) (dnsProofState, error) {
	observed := (&sessionTracker{a: a}).capture()
	calls := 0
	lookup := func(context.Context, string) ([]string, error) {
		calls++
		return []string{"203.0.113.17"}, nil
	}
	proof := proveSelectedDNSWithLookup(ctx, a, observed, host.launch.mode, lookup)
	if proof.Status != "passed" || host.ready == nil || proof.LatencyMs != host.ready.DNSMilliseconds || calls != 0 ||
		!strings.Contains(proof.Reason, "before connection") {
		return dnsProofState{}, errors.New("installed Linux DNS observation did not retain its original native receipt and owner")
	}
	for _, fault := range []string{"cancelled", "observation-node", "observation-key", "saved-dns", "presentation-starting", "duplicate-legacy"} {
		capture, query := observed, ctx
		if fault == "cancelled" {
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			query = cancelled
		}
		if fault == "observation-node" {
			capture.RouterID += "-replacement"
		}
		if fault == "observation-key" {
			capture.Profile.APIToken += "-replacement"
		}
		a.mu.Lock()
		original, phase := a.profiles.Profiles[0], a.state.Phase
		if fault == "saved-dns" {
			a.profiles.Profiles[0].AdGuardIPv4 = "192.168.50.134"
		}
		if fault == "presentation-starting" {
			a.state.Phase = "starting"
		}
		if fault == "duplicate-legacy" {
			desktopNodeOwners.Store(a, host.launch)
		}
		a.mu.Unlock()
		refused := proveSelectedDNSWithLookup(query, a, capture, host.launch.mode, lookup)
		a.mu.Lock()
		a.profiles.Profiles[0], a.state.Phase = original, phase
		if fault == "duplicate-legacy" {
			desktopNodeOwners.Delete(a)
		}
		a.mu.Unlock()
		if refused.Status != "failed" || refused.LatencyMs != 0 || calls != 0 {
			return dnsProofState{}, fmt.Errorf("installed Linux DNS observer accepted %s or used an unrelated resolver", fault)
		}
	}
	if err := host.Current(ctx); err != nil {
		return dnsProofState{}, errors.Join(err, errors.New("rejected DNS observation changed the original installed active owner"))
	}
	return proof, nil
}

// The actual protected installed controller owns every operation here. This
// fixture uses the ordinary completed bundle verifier and real generated
// executable, source, native channel, TUN, DNS, Router proof and journal.
// It changes no public capability predicate or verifier implementation.
func linuxNodeHostTUNFixture(controller *ownedDesktopController, scenario string) (failure error) {
	if strings.HasPrefix(scenario, "node-chain-") {
		return linuxHostTUNNodeChainFixture(controller, scenario)
	}
	if strings.HasPrefix(scenario, "imported-wg-ss-") {
		return linuxHostTUNImportedFixture(controller, scenario)
	}
	if linuxHostTUNExternalCase(scenario) {
		return linuxHostTUNExternalFixture(controller, scenario)
	}
	action, mode := linuxHostTUNAction(scenario), linuxHostTUNMode(scenario)
	found := linuxHostTUNReverseCase(scenario)
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
	mtuCase := linuxHostTUNMTUCase(scenario)
	restoreCase := linuxHostTUNRestoreCase(scenario)
	policyValid := linuxHostTUNProfilePolicyValid(profile, scenario)
	if profile.ID != "installed-linux-node" || ((mode == "shadowsocks" || mode == "hysteria2" || mode == "ss-v2ray") && profile.NodeProofID != linuxHostTUNNodeID || (mode == "wg" || linuxHostTUNIsAmnezia(mode)) && !nativeDigest(profile.NodeProofID)) || profile.RouterAPI != "http://10.77.0.1:8787" ||
		profile.DNSMode != "home" || profile.AdGuardIPv4 != "192.168.50.133" || profile.IPv6Mode != "on" || !policyValid || profile.EffectiveMTU != 9000 {
		return errors.New("installed-host fixture changed its captured node, selected DNS or fixed MTU")
	}
	a := &app{localController: controller, profiles: profiles, state: state{Mode: "off", Phase: "off", DAITA: linuxHostTUNCoverCase(scenario) && !linuxHostTUNPublicCase(scenario)},
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
	if linuxHostTUNReverseCase(scenario) {
		return linuxHostTUNReverseConnection(ctx, a, parent, controller, gate, scenario)
	}
	if linuxHostTUNPublicCase(scenario) {
		return linuxHostTUNPublicConnection(ctx, a, parent, controller, gate, scenario)
	}
	operation, finishOperation, err := a.beginConnectionTransaction()
	if err != nil {
		return err
	}
	var finished sync.Once
	finish := func() { finished.Do(finishOperation) }
	defer finish()
	var journal *desktopLinuxNodeJournal
	var retained *desktopLinuxNodeSession
	if action == "active-request-ended" || mtuCase || restoreCase {
		retained, err = captureDesktopLinuxNodeSession(ctx, a)
	} else {
		journal, err = createDesktopLinuxNodeJournal(ctx, parent)
		if journal != nil {
			defer journal.Close(context.Background())
		}
	}
	if err != nil {
		return err
	}
	runtimeProfile := cloneRouterProfile(profile)
	runtimeProfile.DAITAEnabled = a.state.DAITA
	host, err := prepareDesktopLinuxNodeHost(operation, a, runtimeProfile, mode, 0)
	if host != nil {
		defer host.Close(context.Background())
	}
	if err != nil {
		return fmt.Errorf("ordinary completed-bundle preparation: %w", err)
	}
	if linuxHostTUNCoverCase(scenario) && restoreCase && (!host.options[0] || host.savedOptions[0] || profile.DAITAEnabled) {
		return errors.New("native cover restoration did not capture independent runtime and saved options")
	}
	capture, err := host.policy.OriginalProfile().DesktopCapture()
	if err != nil || capture.MTUPolicy != profile.MTUPolicy || capture.ConfiguredMTU != 1376 && !mtuCase && !restoreCase ||
		(mtuCase || restoreCase) && capture.ConfiguredMTU != 1280 {
		return errors.Join(err, errors.New("installed host substituted historical MTU for the original configured policy"))
	}
	if err := host.Stage(ctx); err != nil {
		return err
	}
	workspace := host.launch.directory
	if retained != nil {
		err = retained.Start(ctx, host)
		journal = retained.journal
	} else {
		err = host.Start(ctx, journal, nil)
	}
	if err != nil {
		return fmt.Errorf("actual installed child and durable admission: %w", err)
	}
	if host.process == nil || host.transaction == nil || !host.transaction.admitted || !host.transaction.nativeCommitted ||
		host.process.command != a.cmd || a.state.Connected || a.state.Phase != "starting" {
		return errors.New("installed-host fixture bypassed original native admission or claimed Connected before proof")
	}
	result := linuxHostTUNResult{Scenario: scenario, SessionID: host.selection.SessionID}
	result.StartLayer, result.Physical, err = linuxHostTUNLayerSource(ctx, host, scenario)
	if err != nil {
		return err
	}
	ready, readyErr := host.WaitReady(ctx)
	failedReady := linuxHostTUNFailedReadyCase(scenario)
	var replacement *exec.Cmd
	var replacementState state
	if failedReady {
		if readyErr == nil || ready != (mobilemultihop.DesktopNodeReadyRecord{}) || host.ready != nil || host.proof != nil || a.state.Connected {
			return errors.New("installed host accepted a failed encrypted key or selected resolver as ready")
		}
		result.Outcome = "rejected-ready"
		if linuxHostTUNCoverCase(scenario) {
			result.Cover = "rejected-before-ready"
		}
	} else {
		if readyErr != nil || host.ready == nil || *host.ready != ready || ready.MTU != capture.ConfiguredMTU || ready.DNSMilliseconds <= 0 {
			return errors.Join(readyErr, errors.New("installed host did not prove its actual selected DNS and configured kernel MTU"))
		}
		result.Stage, result.Ready = "ready", &ready
		if linuxHostTUNCoverCase(scenario) {
			result.Cover = "native-active"
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if err := linuxHostTUNRendezvous(gate, 2); err != nil {
			return err
		}
		proofContext := ctx
		var activation *desktopLinuxNodeActivation
		if action == "stale-ready" {
			stale := ready
			stale.ProvedAt = host.started.UnixMilli() - 1
			body, err := json.Marshal(stale)
			if err != nil || os.WriteFile(filepath.Join(workspace, "node-ready.json"), body, 0600) != nil {
				return errors.Join(err, errors.New("installed-host stale receipt control could not be written"))
			}
		}
		if action == "cancelled-proof" {
			short, stop := context.WithCancel(ctx)
			stop()
			proofContext = short
		}
		if action == "replaced-host" {
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
		failedProof := action == "wrong-node" || action == "stale-ready" || action == "cancelled-proof" || action == "replaced-host" || linuxHostTUNSIP003TCPFault(scenario)
		if failedProof {
			if proofErr == nil || elapsed != 0 || host.proof != nil || action != "replaced-host" && a.state.Connected {
				return errors.New("installed host accepted a failed, stale, cancelled or replaced Router proof")
			}
			result.Outcome = "rejected-proof"
		} else {
			if proofErr != nil || elapsed <= 0 || host.proof == nil || host.proof.ready != ready || a.state.Connected {
				return errors.Join(proofErr, errors.New("installed host did not retain its actual routed private Router response"))
			}
			result.Outcome = "proved"
			if action == "cancel-adoption" {
				a.cancelConnectionOperation()
				if err := host.Activate(ctx); err == nil || a.state.Connected || host.activation != nil {
					return errors.New("cancelled original Connect adopted an installed native session")
				}
				result.Activation = "rejected-adoption"
			} else if strings.HasPrefix(action, "active-") || mtuCase || restoreCase {
				if host.Current(ctx) == nil || host.activation != nil {
					return errors.New("installed host inferred active ownership from readiness or proof alone")
				}
				if err := host.Activate(ctx); err != nil {
					return fmt.Errorf("activate original proved installed host: %w", err)
				}
				activation = host.activation
				finish()
				if !restoreCase {
					a.operationMu.Lock()
					defer a.operationMu.Unlock()
				}
				if operation.Err() == nil || a.connectionContext != nil || a.connectionCancel != nil ||
					!a.state.Connected || a.state.Phase != "connected" || a.cmd != host.process.command ||
					activation == nil || activation.operation != operation || activation.lifetime.Err() != nil {
					return errors.New("ordinary Connect completion discarded the original installed active owner")
				}
				if err := host.Current(ctx); err != nil {
					return fmt.Errorf("original active native readback after request completion: %w", err)
				}
				result.Activation = "retained-after-request"
				if restoreCase {
					fresh, restoration, err := linuxHostTUNSealedRestore(ctx, a, retained, host)
					if err != nil {
						return err
					}
					host, activation, workspace = fresh, fresh.activation, fresh.launch.directory
					result.SessionID, result.Ready, result.Restore = fresh.selection.SessionID, fresh.ready, &restoration
					result.StartLayer, result.Physical, err = linuxHostTUNLayerSource(ctx, fresh, scenario)
					if err != nil {
						return err
					}
					result.Activation = "restored-after-temporary"
					if linuxHostTUNCoverCase(scenario) {
						a.mu.Lock()
						savedCover := a.profiles.Profiles[0].DAITAEnabled
						a.mu.Unlock()
						if !fresh.options[0] || fresh.savedOptions[0] || savedCover {
							return errors.New("native restoration lost its frozen runtime cover selection")
						}
						result.Cover = "native-restored"
					}
					defer fresh.Close(context.Background())
					a.operationMu.Lock()
					defer a.operationMu.Unlock()
				}
				if action == "active-request-ended" || strings.HasPrefix(action, "mtu-") {
					view, err := linuxHostTUNMTUView(ctx, a, host)
					if err != nil {
						return err
					}
					result.MTUView = &view
				}
				if mtuCase {
					if retained == nil || retained.active != host || retained.journal != journal {
						return errors.New("installed MTU consumer lost its original retained session")
					}
					measurement, err := linuxHostTUNMTUConsumer(ctx, a, host, scenario)
					if err != nil {
						return err
					}
					result.MTU = &measurement
				}
				if action == "active-request-ended" {
					if retained == nil || retained.active != host || retained.journal != journal {
						return errors.New("installed DNS consumer lost its original retained session")
					}
					proof, err := linuxHostTUNDNSObservation(ctx, a, host)
					if err != nil {
						return err
					}
					result.DNSProof = &proof
				}
				switch action {
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
				if action != "active-request-ended" && !mtuCase && !restoreCase {
					if err := host.Current(ctx); err == nil {
						return errors.New("retained installed host accepted a replaced active profile, network or command")
					}
					result.Activation = "rejected-active"
				}
			} else if action == "request-ended" {
				finish()
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
				if operation.Err() == nil || a.connectionContext != nil || a.state.Connected || a.cmd != host.process.command {
					return errors.New("ordinary Connect completion changed the original unactivated host")
				}
			}
		}
		if action == "shutdown" {
			a.mu.Lock()
			a.closing = true
			a.mu.Unlock()
			if err := a.retireNativeNodeForShutdownContext(ctx); err != nil {
				return fmt.Errorf("ordered original installed controller shutdown: %w", err)
			}
		} else if action == "mtu-retire-undrained" {
			if retained == nil || retained.active != nil || host.mtu != nil {
				return errors.New("ordinary Stop retained its undrained original installed lease or active session")
			}
		} else {
			if err := host.Retire(ctx, true); err != nil {
				return fmt.Errorf("joined original installed host retirement: %w", err)
			}
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
	if action == "always" {
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
	if retained != nil {
		target := host
		if action == "mtu-retire-undrained" {
			target = nil // The ordinary application Stop already joined this exact host.
		}
		if err := retained.Retire(ctx, target, true); err != nil {
			return fmt.Errorf("joined original installed session retirement: %w", err)
		}
	}
	if err := host.Close(ctx); err != nil {
		return err
	}
	if _, err := os.Lstat(workspace); !errors.Is(err, os.ErrNotExist) {
		return errors.New("joined installed host retained its private launch workspace")
	}
	if retained == nil {
		if err := journal.Close(ctx); err != nil {
			return err
		}
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
	linuxHostTUNAssertReadinessClassification(t)
	linuxHostTUNNamespace(t)
	for _, scenario := range linuxHostTUNCases {
		t.Run(scenario, func(t *testing.T) {
			action := linuxHostTUNAction(scenario)
			installed := linuxControllerNamespaceInstall(t)
			if err := os.RemoveAll(filepath.Join("/opt", desktopLinuxNodeJournalDirectory)); err != nil {
				t.Fatal(err)
			}
			linuxHostTUNInstallBundle(t)
			if strings.HasPrefix(scenario, "node-chain-") {
				linuxHostTUNNodeChainParent(t, installed, scenario)
				return
			}
			if strings.HasPrefix(scenario, "imported-wg-ss-") {
				linuxHostTUNImportedParent(t, installed, scenario)
				return
			}
			if linuxHostTUNExternalCase(scenario) {
				linuxHostTUNExternalParent(t, installed, scenario)
				return
			}
			peer := linuxHostTUNStartPeer(t, scenario)
			linuxHostTUNDirectHealth(t, peer)
			linuxHostTUNInstallProfile(t, peer, scenario)
			if linuxHostTUNBootHostnameCase(scenario) {
				linuxHostTUNBootHostnameFixture(t, peer, scenario)
			}
			if linuxHostTUNBootTransferCase(scenario) {
				linuxHostTUNBootTransferService(t, installed, peer)
			} else if linuxHostTUNTransferCase(scenario) {
				linuxHostTUNTransferService(t, installed, peer)
			}
			if linuxHostTUNResolverFailureCase(scenario) {
				peer.observe(t, "fail-dns")
			}
			if action == "wrong-node" || action == "cover-wrong-node" {
				peer.observe(t, "wrong-node")
			}
			if action == "cover-no-replies" {
				peer.observe(t, "drop-cover")
			}
			process := linuxHostTUNStartController(t, installed, scenario)
			if _, err := process.gate.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			result := process.read(t, scenario)
			physical := []mobilemultihop.PhysicalEgress{
				{Host: peer.address.Addr().String(), Port: int(peer.address.Port()), Network: "tcp"},
				{Host: peer.address.Addr().String(), Port: int(peer.address.Port()), Network: "udp"},
			}
			if peer.mode == "wg" || linuxHostTUNIsAmnezia(peer.mode) || peer.mode == "hysteria2" {
				physical = physical[1:]
			}
			if peer.mode == "ss-v2ray" && peer.layer == "" {
				physical[1].Port = int(peer.udpBranchAddress.Port())
			}
			if result.StartLayer != peer.layer || !reflect.DeepEqual(result.Physical, physical) {
				t.Fatal("installed layer borrowed an inner AES, DNS or proof physical exception", result.Physical, physical)
			}
			failedReady := linuxHostTUNFailedReadyCase(scenario)
			var before linuxHostTUNPeerReply
			var dropped linuxHostTUNPeerReply
			if !failedReady {
				expectedMTU := 1376
				if linuxHostTUNMTUCase(scenario) || linuxHostTUNRestoreCase(scenario) {
					expectedMTU = 1280
				}
				if result.Stage != "ready" || result.Ready == nil || result.Ready.MTU != expectedMTU || result.Ready.DNSMilliseconds <= 0 {
					t.Fatal("installed host did not report its actual selected DNS and TUN")
				}
				if action == "home-lan" {
					// This direct same-node response is demonstrably available
					// after the TUN starts. Prove must still use the captured TUN.
					linuxHostTUNDirectHealth(t, peer)
				}
				before = peer.observe(t, "stats")
				expectedProofs := uint32(0)
				if linuxHostTUNPublicCase(scenario) {
					expectedProofs = 1 // The actual handler has already completed its routed proof.
				}
				if linuxHostTUNCoverCase(scenario) {
					expectedProofs++ // The actual native cover worker proves the same private Router independently.
					if result.Ready.CoverServices != 1 || !nativeDigest(result.Ready.CoverSHA256) || before.CoverPackets == 0 ||
						before.CoverReplies == 0 || before.CoverBytes < 128 || before.CoverReplyBytes < 128 || before.CoverMaximum < 128 || before.CoverMaximum > 400 {
						t.Fatal("native cover readiness omitted its actual bounded encrypted private packets", result, before)
					}
				}
				wrongProofs := before.RouterQueries != expectedProofs
				if linuxHostTUNCoverCase(scenario) {
					wrongProofs = before.RouterQueries < expectedProofs // Periodic same-worker reproof remains live.
				}
				dnsTraffic := before.RawUDP > 0 && before.PlainUDP > 0 && (!linuxHostTUNFinalProtocolCounters(peer) || before.ProtocolRawUDP > 0 && before.ProtocolUDP > 0)
				if peer.mode == "ss-v2ray" {
					dnsTraffic = linuxHostTUNSIP003DNS(peer, before)
				}
				if before.DNSQueries < 2 || !dnsTraffic || wrongProofs ||
					linuxHostTUNPublicCase(scenario) && !linuxHostTUNEncryptedTCP(peer, linuxHostTUNPeerReply{}, before) {
					t.Fatal("installed readiness bypassed the selected encrypted DNS path", before)
				}
				if action == "cover-replies-lost" {
					dropped = peer.observe(t, "drop-cover")
				}
				if _, err := process.gate.Write([]byte{2}); err != nil {
					t.Fatal(err)
				}
				result = process.read(t, scenario)
			}
			if result.StartLayer != peer.layer || !reflect.DeepEqual(result.Physical, physical) {
				t.Fatal("installed layer replaced its original outer transport during connection or restoration")
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
			if linuxHostTUNPrivateNegativeCase(scenario) {
				receipt := installedPrivateNegativeReceipt + scenario
				if strings.Count(process.diagnostic.String(), receipt) != 1 {
					t.Fatal("installed private negative omitted original authenticated RPC receipt", process.diagnostic.String())
				}
				t.Log(receipt)
			}
			if err := linuxHostTUNTUNAbsent(result.Ready); err != nil {
				t.Fatal(err)
			}
			after := peer.observe(t, "stats")
			if linuxHostTUNCoverCase(scenario) {
				expected := "native-active"
				if failedReady {
					expected = "rejected-before-ready"
				} else if action == "cover-replies-lost" {
					expected = "retired-after-reply-loss"
				} else if linuxHostTUNRestoreCase(scenario) {
					expected = "native-restored"
				}
				if result.Cover != expected || after.CoverMaximum > 400 || after.CoverReplyBytes > after.CoverBytes || after.CoverReplies > after.CoverPackets ||
					action == "cover-wrong-node" && (after.CoverPackets != 0 || after.CoverReplies != 0) ||
					action == "cover-no-replies" && (after.CoverPackets != 1 || after.CoverReplies != 0 || after.CoverBytes != 128) ||
					action == "cover-replies-lost" && (after.CoverPackets <= dropped.CoverPackets || after.CoverReplies != dropped.CoverReplies || after.CoverReplyBytes != dropped.CoverReplyBytes) ||
					linuxHostTUNRestoreCase(scenario) && (result.Ready == nil || result.Ready.CoverServices != 1 || !nativeDigest(result.Ready.CoverSHA256) || after.CoverReplies <= before.CoverReplies) {
					t.Fatal("installed native cover bypassed proof, amplified payload, lost restoration or survived reply failure", result, before, dropped, after)
				}
				// Joined native teardown must stop encrypted padding as well as
				// the TUN. Drain packets already received by the independent peer,
				// then require its exact counters to remain unchanged.
				time.Sleep(100 * time.Millisecond)
				joined := peer.observe(t, "stats")
				time.Sleep(150 * time.Millisecond)
				settled := peer.observe(t, "stats")
				if settled.CoverPackets != joined.CoverPackets || settled.CoverBytes != joined.CoverBytes || settled.CoverReplies != joined.CoverReplies || settled.CoverReplyBytes != joined.CoverReplyBytes {
					t.Fatal("private native padding outlived its original joined Box", joined, settled)
				}
				t.Log("verified installed host native cover:", scenario)
			} else if result.Cover != "" || after.CoverPackets != 0 || after.CoverReplies != 0 || result.Ready != nil && (result.Ready.CoverServices != 0 || result.Ready.CoverSHA256 != "") {
				t.Fatal("unrequested native cover appeared on an ordinary path", result, after)
			}
			if failedReady {
				expectedProofs := uint32(0)
				if linuxHostTUNCoverCase(scenario) {
					expectedProofs = 1
				}
				wrongCredential := linuxHostTUNWrongKeyCase(scenario) && (after.RawUDP == 0 || !linuxHostTUNFinalProtocolCounters(peer) && after.PlainUDP != 0 || linuxHostTUNFinalProtocolCounters(peer) && (after.ProtocolTCP != 0 || after.ProtocolUDP != 0 || after.DNSQueries != 0))
				if peer.mode == "ss-v2ray" {
					wrongCredential = linuxHostTUNWrongKeyCase(scenario) && !linuxHostTUNSIP003Rejected(scenario, after)
				}
				if result.Outcome != "rejected-ready" || result.Ready != nil || after.RouterQueries != expectedProofs ||
					linuxHostTUNResolverFailureCase(scenario) && after.DNSQueries == 0 || wrongCredential {
					t.Fatal("failed key/resolver fabricated readiness or a Router response", result, after)
				}
			} else {
				http := action != "stale-ready" && action != "cancelled-proof" && action != "replaced-host" && !linuxHostTUNPublicCase(scenario) && !linuxHostTUNSIP003TCPFault(scenario)
				expectedHTTP := before.RouterQueries
				if http {
					expectedHTTP++
				}
				if linuxHostTUNRestoreCase(scenario) {
					expectedHTTP++ // Fresh restoration must prove the private Router again.
					if linuxHostTUNCoverCase(scenario) {
						expectedHTTP++ // Fresh native cover cannot reuse the retired worker's proof.
					}
				}
				wrongProofs := after.RouterQueries != expectedHTTP
				if linuxHostTUNCoverCase(scenario) {
					wrongProofs = after.RouterQueries < expectedHTTP
				}
				expectedDirect := before.DirectQueries
				if linuxHostTUNOffCase(scenario) {
					expectedDirect++ // The same controller proves ordinary traffic only after explicit Off.
				}
				if wrongProofs || after.DirectQueries != expectedDirect || http && !linuxHostTUNEncryptedTCP(peer, before, after) {
					t.Fatal("installed Router proof used the direct LAN response or bypassed its exact encrypted graph", before, after)
				}
			}
			if linuxHostTUNSIP003TCPFault(scenario) {
				linuxHostTUNSIP003AssertTCPRejected(t, peer, scenario, result, before, after)
			}
			if action == "always" {
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
			if linuxHostTUNMTUCase(scenario) || linuxHostTUNPublicCase(scenario) {
				activation = "retained-after-request"
			}
			if linuxHostTUNRestoreCase(scenario) {
				activation = "restored-after-temporary"
			}
			switch action {
			case "active-request-ended", "public-connect", "cover-connect", "cover-replies-lost", "public-off", "public-off-save-retry":
				activation = "retained-after-request"
			case "cancel-adoption":
				activation = "rejected-adoption"
			case "active-profile-change", "active-network-change", "active-command-change":
				activation = "rejected-active"
			case "restore-sealed", "cover-restore":
				activation = "restored-after-temporary"
			}
			if result.Activation != activation {
				t.Fatal("installed host omitted its actual captured activation and lifetime result", result.Activation, activation)
			}
			if action == "active-request-ended" || linuxHostTUNPublicCase(scenario) {
				if result.DNSProof == nil || result.DNSProof.Status != "passed" || result.Ready == nil ||
					result.DNSProof.LatencyMs != result.Ready.DNSMilliseconds || after.DNSQueries != before.DNSQueries ||
					!strings.Contains(result.DNSProof.Reason, "before connection") {
					t.Fatal("installed DNS consumer substituted the original native query or called it a fresh Retest", result, before, after)
				}
				t.Log("verified installed host retained DNS observation:", scenario)
			} else if result.DNSProof != nil {
				t.Fatal("installed DNS result belongs to another original session scenario")
			}
			if activation != "" {
				t.Log("verified installed host active lifetime:", scenario)
			}
			if result.Public != linuxHostTUNPublicCase(scenario) {
				t.Fatal("installed public handler evidence belongs to another scenario")
			}
			if result.Transfer != (linuxHostTUNTransferCase(scenario) || linuxHostTUNBootTransferCase(scenario)) {
				t.Fatal("installed transfer evidence belongs to another scenario")
			}
			if linuxHostTUNBootTransferCase(scenario) {
				t.Log("verified installed host original boot service transfer:", scenario)
			} else if result.Transfer {
				t.Log("verified installed host original service transfer:", scenario)
			}
			if result.Public {
				t.Log("verified installed host public Connect and Disconnect:", scenario)
			}
			if linuxHostTUNOffCase(scenario) {
				off := result.ProtectionOff
				if off == nil || !off.RetainedAlways || !off.NetworkReleased || !off.ProfileSaved || !off.JournalSettled ||
					!off.ReplacementRejected || !off.ReplayRejected || off.SaveRetried != (action == "public-off-save-retry") {
					t.Fatal("installed Off omitted exact Always retention, private persistence, retry or original native release", off)
				}
				t.Log("verified installed host saved Linux protection Off:", scenario)
			} else if result.ProtectionOff != nil {
				t.Fatal("installed Off result belongs to another original scenario")
			}
			if linuxHostTUNRestoreCase(scenario) {
				restored := result.Restore
				if restored == nil || restored.PreviousSession == "" || restored.PreviousSession == restored.FreshSession ||
					restored.FreshSession != result.SessionID || restored.Execution != "local" || !restored.Cleared ||
					restored.SourceSHA256 != result.Ready.SourceSHA256 || restored.RestoredMTU != 1300 || result.Ready.MTU != 1300 ||
					after.DNSQueries <= before.DNSQueries {
					t.Fatal("installed restoration omitted its frozen graph, fresh DNS/Router proof or live MTU", result, before, after)
				}
				t.Log("verified installed host sealed temporary restoration:", scenario)
			} else if result.Restore != nil {
				t.Fatal("installed restoration belongs to another original scenario")
			}
			if linuxHostTUNMTUCase(scenario) {
				mtu := result.MTU
				if mtu == nil || mtu.OriginalMTU != 1280 || mtu.CandidateMTU != 1300 || mtu.InitialIndex < 1 ||
					mtu.InitialReader != 1 || mtu.StopHeld != (action == "mtu-hold") {
					t.Fatal("installed MTU consumer omitted its original interface, reader or Stop barrier", mtu)
				}
				if action == "mtu-retire-undrained" {
					if mtu.Outcome != "retired-original" || mtu.FinalMTU != 0 || mtu.FinalIndex != 0 || mtu.FinalReader != 0 {
						t.Fatal("retired installed MTU lease fabricated live readback or restored MTU", mtu)
					}
				} else if mtu.FinalIndex < 1 || mtu.FinalReader <= mtu.InitialReader {
					t.Fatal("installed MTU consumer omitted its actual replacement reader", mtu)
				} else if action == "mtu-commit" {
					if mtu.Outcome != "committed-candidate" || mtu.FinalMTU != 1300 {
						t.Fatal("installed MTU consumer did not commit its actual candidate", mtu)
					}
				} else if mtu.Outcome != "restored-original" || mtu.FinalMTU != 1280 {
					t.Fatal("installed MTU consumer did not roll back its actual original interface", mtu)
				}
				t.Log("verified installed host original MTU lease:", scenario)
			} else if result.MTU != nil {
				t.Fatal("installed MTU result belongs to another original scenario")
			}
			if action == "active-request-ended" || linuxHostTUNPublicCase(scenario) || strings.HasPrefix(action, "mtu-") {
				if result.MTUView == nil || result.Ready == nil || result.MTUView.Source != "live-captured-interface" ||
					result.MTUView.EffectiveMTU != result.Ready.MTU || result.MTUView.Automatic != strings.HasPrefix(action, "mtu-") {
					t.Fatal("installed MTU view omitted its original live Fixed/Auto readback", result.MTUView, result.Ready)
				}
				t.Log("verified installed host live MTU status:", scenario)
			} else if result.MTUView != nil {
				t.Fatal("installed MTU view belongs to another original native scenario")
			}
			if peer.mode == "wg" {
				if peer.layer == "" {
					t.Log("verified installed host plain WireGuard:", scenario)
				} else {
					t.Log("verified installed host layered WireGuard:", scenario)
				}
			}
			if linuxHostTUNIsAmnezia(peer.mode) {
				if peer.layer == "" {
					t.Log("verified installed host captured AWG2:", scenario)
				} else {
					t.Log("verified installed host layered AWG2:", scenario)
				}
			}
			if peer.mode == "hysteria2" {
				if peer.layer == "" {
					t.Log("verified installed host plain Hysteria2:", scenario)
				} else {
					t.Log("verified installed host layered Hysteria2:", scenario)
				}
			}
			if peer.mode == "ss-v2ray" {
				t.Log("verified installed host captured SIP003 lanes:", scenario)
			}
			t.Log("verified installed host native lifecycle:", scenario)
			if peer.layer != "" {
				t.Log("verified installed host captured Start Layer:", scenario)
			}
		})
	}
}
