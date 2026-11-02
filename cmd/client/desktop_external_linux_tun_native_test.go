//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/nativeopenvpn"
)

func linuxHostTUNExternalFixture(controller *ownedDesktopController, scenario string) (failure error) {
	if !linuxHostTUNExternalCase(scenario) {
		return errors.New("installed external fixture has no captured scenario")
	}
	raw, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "routers.json"), 64<<10)
	var profiles common.RouterProfileStore
	if err != nil || decodeRelayControlJSON(raw, &profiles) != nil || len(profiles.Profiles) != 2 || profiles.SelectedID != "installed-linux-node" ||
		profiles.Profiles[0].ID != "installed-linux-node" || profiles.Profiles[1].ID != "installed-linux-external" || profiles.Profiles[1].External == nil ||
		profiles.Profiles[1].External.Protocol != linuxHostTUNExternalProtocol(scenario) {
		return errors.Join(err, errors.New("installed external fixture lost its two original private node identities"))
	}
	a := &app{localController: controller, profiles: profiles, state: state{Mode: "off", Phase: "off"},
		cfg: common.ClientConfig{AutoTestSeconds: 10, ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
			ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"),
			StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 20 {
		return errors.Join(err, errors.New("installed external fixture lost the shipping runtime catalog"))
	}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "installed-external-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 1); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	response := httptest.NewRecorder()
	a.connect(response, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"shadowsocks"}`)).WithContext(ctx))
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"ok":true}` {
		return fmt.Errorf("external succession original public Connect failed: %d: %s", response.Code, response.Body.String())
	}
	a.mu.Lock()
	command := a.cmd
	a.mu.Unlock()
	path, handled, err := captureDesktopLinuxNodePath(ctx, a, command)
	if err != nil || !handled || path == nil || path.host == nil || path.sessionParent.parent != parent.parent {
		return errors.Join(err, errors.New("external succession lost its original installed Router owner"))
	}
	original, session, journal := path.host, path.session, path.journal
	last := original
	defer func() {
		if failure != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			failure = errors.Join(failure, retireDesktopLinuxNodeRestore(cleanup, session, last))
		}
	}()
	a.operationMu.Lock()
	measurement, err := linuxHostTUNMTUConsumer(ctx, a, original, "mtu-commit")
	a.operationMu.Unlock()
	if err != nil || measurement.FinalMTU != 1300 || measurement.Outcome != "committed-candidate" {
		return errors.Join(err, errors.New("external succession lost the actually observed original Router MTU"))
	}
	result := linuxExternalTUNResult{Stage: "router", Scenario: scenario, OriginalSession: original.selection.SessionID,
		Protocol: linuxHostTUNExternalProtocol(scenario), MTU: measurement.FinalMTU}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 2); err != nil {
		return err
	}
	if linuxHostTUNExternalAction(scenario) == "source" {
		if err := linuxHostTUNExternalRefuseSource(ctx, a, session, original); err != nil {
			return err
		}
		result.Stage, result.SourcePreserved = "source-refused", true
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if err := linuxHostTUNRendezvous(gate, 3); err != nil {
			return err
		}
	} else if linuxHostTUNExternalAction(scenario) == "public" {
		last, err = linuxHostTUNExternalPublic(ctx, a, session, original, gate, &result)
		if err != nil {
			return err
		}
	} else {
		last, err = linuxHostTUNExternalTemporary(ctx, a, session, original, gate, &result)
		if err != nil {
			return err
		}
	}
	result.FinalSession = last.selection.SessionID
	if !result.ReplacementKept {
		stop := httptest.NewRecorder()
		a.disconnect(stop, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil).WithContext(ctx))
		if stop.Code != http.StatusOK || strings.TrimSpace(stop.Body.String()) != `{"ok":true}` {
			return fmt.Errorf("external succession public Disconnect failed: %d: %s", stop.Code, stop.Body.String())
		}
	}
	if err := linuxHostTUNTUNAbsent(nil); err != nil {
		return err
	}
	settled, err := linuxHostTUNJournal(ctx, journal, last.transaction)
	if err != nil {
		return err
	}
	result.Journal = &settled
	if strings.HasSuffix(scenario, "-always") {
		if settled.Record.Committed.Target == nil || last.transaction.baselineReleased || last.transaction.baseline.ObserveClosed(ctx) != nil {
			return errors.New("external succession released the original closed Always protection")
		}
		closed, err := linuxShutdownTable(ctx, result.FinalSession)
		if err != nil || len(closed) == 0 {
			return errors.Join(err, errors.New("external succession lost its exact closed native table"))
		}
		digest := sha256.Sum256(closed)
		result.ClosedTableSHA256 = hex.EncodeToString(digest[:])
		a.mu.Lock()
		a.closing = true
		a.mu.Unlock()
		if err := a.retireNativeNodeForShutdownContext(ctx); err != nil {
			return err
		}
		after, err := linuxShutdownTable(ctx, result.FinalSession)
		if err != nil || !bytes.Equal(closed, after) || !last.transaction.closed || !last.transaction.released || last.transaction.baselineReleased {
			return errors.Join(err, errors.New("external terminal shutdown replaced or released Always protection"))
		}
		retained, err := linuxHostTUNJournal(ctx, journal, last.transaction)
		if err != nil || !reflect.DeepEqual(retained, settled) {
			return errors.Join(err, errors.New("external terminal shutdown changed its settled original journal"))
		}
	} else if settled.Record.Committed.Target != nil || mobiletor.ReadDesktopLinuxNodeAbsence(ctx, result.FinalSession) != nil {
		return errors.New("external succession did not release its exact joined On-connect protection")
	}
	if _, duplicate := desktopNodeOwners.Load(a); duplicate {
		return errors.New("external succession left a competing legacy process owner")
	}
	if _, exists := desktopExternalRetainedLaunches.Load(a); exists {
		return errors.New("external succession retained a retired observation handle")
	}
	if err := parent.parent.Close(ctx); err != nil {
		return err
	}
	controller.close()
	result.Stage = "retired"
	return json.NewEncoder(os.Stdout).Encode(result)
}

// Change the actual saved source after the ordinary native preparation. The
// real public Connect preflight must refuse before stopping the proved Router.
func linuxHostTUNExternalRefuseSource(ctx context.Context, a *app, session *desktopLinuxNodeSession, original *desktopLinuxNodeHost) error {
	a.mu.Lock()
	saved := cloneRouterProfile(a.profiles.Profiles[1])
	a.mu.Unlock()
	calls := 0
	var candidate *desktopLinuxExternalConnection
	driver := externalConnectRuntime{retained: func(owner *app, launch *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
		retained, err := prepareDesktopRetainedExternal(owner, launch)
		if err != nil {
			return retained, err
		}
		var ok bool
		candidate, ok = retained.(*desktopLinuxExternalConnection)
		if !ok || candidate == nil || candidate.session != session || candidate.host == nil || candidate.host.policy != nil || candidate.host.external == nil {
			return retained, errors.New("public external source refusal did not prepare the typed original native host")
		}
		calls++
		owner.mu.Lock()
		owner.profiles.Profiles[1] = cloneRouterProfile(saved)
		if owner.profiles.Profiles[1].External.SOCKS5 != nil {
			owner.profiles.Profiles[1].External.SOCKS5.Password = "changed-after-captured-native-preparation"
		} else {
			owner.profiles.Profiles[1].External.Shadowsocks.Password = "changed-after-captured-native-preparation"
		}
		owner.mu.Unlock()
		return retained, nil
	}}
	response := httptest.NewRecorder()
	a.externalProfileConnectWithRuntime(response, httptest.NewRequest(http.MethodPost, "/api/external-profile/connect",
		strings.NewReader(`{"profile_id":"installed-linux-external","direct":true,"execution":"local"}`)).WithContext(ctx), driver)
	a.mu.Lock()
	a.profiles.Profiles[1] = saved
	a.mu.Unlock()
	if calls != 1 || candidate == nil || response.Code != http.StatusConflict || candidate.host.process != nil || candidate.host.transaction != nil ||
		!candidate.host.closed || !candidate.host.released || original.Current(ctx) != nil {
		return fmt.Errorf("public external changed-source refusal consumed its original Router: %d: %s", response.Code, response.Body.String())
	}
	return linuxHostTUNRestoreCheck(ctx, session, original, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if session.active != original || a.cmd != original.launch.command || !a.state.Connected || original.process.command.ProcessState != nil ||
			original.policy == nil || original.activation == nil || original.activation.lifetime.Err() != nil {
			return errors.New("refused external source stopped or replaced its proved original Router")
		}
		return nil
	})
}

func linuxHostTUNExternalActive(ctx context.Context, a *app, session *desktopLinuxNodeSession, native *desktopNodeLaunch) (*desktopLinuxNodeHost, desktopExternalProof, error) {
	if native == nil || native.external == nil {
		return nil, desktopExternalProof{}, errors.New("external fixture lost its actual prepared native launch")
	}
	owner, ok := native.external.retained.(*desktopLinuxExternalConnection)
	if !ok || owner == nil || owner.session != session || owner.host == nil {
		return nil, desktopExternalProof{}, errors.New("external fixture lost its retained native session")
	}
	host := owner.host
	proof, err := a.readDesktopExternalProof(native)
	if err != nil || host.Current(ctx) != nil {
		return host, proof, errors.Join(err, errors.New("external fixture has no currently proved retained native host"))
	}
	if err := linuxHostTUNRestoreCheck(ctx, session, host, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if session.active != host || session.journal != host.transaction.journal || host.external == nil || host.policy != nil || host.ready != nil || host.proof != nil ||
			host.externalProof == nil || host.activation == nil || host.activation.external != host.external || host.activation.externalProof != host.externalProof ||
			host.process == nil || !host.transaction.admitted || !host.transaction.nativeCommitted || host.process.command != a.cmd || !a.state.Connected ||
			host.monitor == nil || host.monitor.Load() == nil || owner.ProcessDone() != host.process.joined || native.external.waitDone != nil {
			return errors.New("external fixture fabricated Router proof or bypassed its sole retained native process owner")
		}
		if _, duplicate := desktopNodeOwners.Load(a); duplicate {
			return errors.New("external fixture introduced a competing legacy process owner")
		}
		return nil
	}); err != nil {
		return host, proof, err
	}
	physical := host.external.Metadata()
	if physical.Protocol == "socks5" {
		capture, err := host.external.Capture()
		if err != nil || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 ||
			!capture.PhysicalRoots[0].DynamicSOCKSUDP || capture.PhysicalRoots[0].SOCKSVersion != "5" ||
			capture.PhysicalRoots[0].SOCKSControl == nil || capture.PhysicalRoots[0].SOCKSControl.Network != "tcp" ||
			capture.PhysicalRoots[0].Destinations[0].Network != "tcp" || capture.PhysicalRoots[0].Destinations[0].Host != "11.77.0.2" ||
			capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Physical || capture.SelectedDNS.Host != "203.0.113.53" || capture.SelectedDNS.Port != 5353 {
			return host, proof, errors.Join(err, errors.New("installed SOCKS host lost its original control or borrowed a fixed UDP port"))
		}
	}
	if physical.Protocol == "hysteria2" || physical.Protocol == "wireguard" {
		capture, err := host.external.Capture()
		if err != nil || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 ||
			!reflect.DeepEqual(capture.PhysicalRoots[0].Networks, []string{"udp"}) || capture.PhysicalRoots[0].Destinations[0].Network != "udp" ||
			capture.PhysicalRoots[0].Destinations[0].Host != "11.77.0.2" || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Physical ||
			capture.SelectedDNS.Host != "203.0.113.53" || capture.SelectedDNS.Port != 5353 {
			return host, proof, errors.Join(err, errors.New("external UDP transport acquired an extra physical root or bypassed selected DNS"))
		}
	}
	if physical.Protocol == "openvpn" {
		capture, err := host.external.Capture()
		profile := native.external.profile.External
		if err != nil || profile == nil || profile.OpenVPN == nil || profile.OpenVPNResponseProbes != nil || profile.ResponseProbe != nil ||
			len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Family != "endpoints" || capture.PhysicalRoots[0].Type != "openvpn-client" ||
			capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Physical || capture.SelectedDNS.Host != "203.0.113.53" || capture.SelectedDNS.Port != 5353 {
			return host, proof, errors.Join(err, errors.New("installed provider lost its direct import or selected DNS authority"))
		}
		endpoint, err := nativeopenvpn.CompileProfile(*profile.OpenVPN, mobilemultihop.ExternalFinalTag, "")
		if err != nil {
			return host, proof, err
		}
		remotes, err := nativeopenvpn.Remotes(endpoint)
		if err != nil || len(remotes) < 1 || len(remotes) > 2 || len(capture.PhysicalRoots[0].Destinations) != len(remotes) {
			return host, proof, errors.New("installed provider lost ordered remote count")
		}
		wanted := make(map[mobilemultihop.PhysicalEgress]bool)
		for _, remote := range remotes {
			if remote.Host != "11.77.0.2" {
				return host, proof, errors.New("installed provider replaced its actual peer address")
			}
			wanted[mobilemultihop.PhysicalEgress{Host: remote.Host, Port: remote.Port, Network: remote.Network}] = true
		}
		for _, destination := range capture.PhysicalRoots[0].Destinations {
			if !wanted[destination] {
				return host, proof, errors.New("installed provider multiplied physical network/port permissions")
			}
		}
		for _, raw := range []string{host.external.OriginalPolicy().Config(), host.external.Config()} {
			var graph map[string]any
			if json.Unmarshal([]byte(raw), &graph) != nil {
				return host, proof, errors.New("installed provider graph is malformed")
			}
			endpoints, ok := graph["endpoints"].([]any)
			if !ok || len(endpoints) != 1 {
				return host, proof, errors.New("installed provider endpoint owner changed")
			}
			selected, ok := endpoints[0].(map[string]any)
			if !ok {
				return host, proof, errors.New("installed provider endpoint is malformed")
			}
			actual, err := nativeopenvpn.Remotes(selected)
			if err != nil || !reflect.DeepEqual(actual, remotes) {
				return host, proof, errors.New("installed provider reordered or flattened its original fallback")
			}
		}
	}
	network, err := desktopnetwork.ParseDesktopNetworkReceipt(proof.NetworkReceipt)
	if err != nil || network.TargetOS != "linux" || network.MTU != 1376 || proof.EntryID != "" || proof.EntryNodeID != "" || proof.EntryProven ||
		!proof.DNSProven || !proof.Healthy || proof.Execution != "local" || proof.IP != "203.0.113.88" || proof.ExitID != "installed-linux-external" ||
		proof.SessionID != host.selection.SessionID || proof.SourceSHA256 != physical.OriginalSourceSHA256 || proof.ConfigSHA256 != physical.OriginalConfigSHA256 ||
		proof.Physical == nil || *proof.Physical != physical || physical.SourceSHA256 != host.selection.SourceSHA256 || physical.ConfigSHA256 != host.selection.ConfigSHA256 {
		return host, proof, errors.Join(err, errors.New("external fixture changed the independently proved DNS, exit or original source"))
	}
	actual, err := net.InterfaceByName(network.Name)
	if err != nil || actual.Index != int(network.Index) || actual.MTU != network.MTU {
		return host, proof, errors.Join(err, errors.New("external fixture omitted actual native TUN MTU readback"))
	}
	return host, proof, nil
}

func linuxHostTUNExternalPublic(ctx context.Context, a *app, session *desktopLinuxNodeSession, original *desktopLinuxNodeHost,
	gate *os.File, result *linuxExternalTUNResult) (*desktopLinuxNodeHost, error) {
	response := httptest.NewRecorder()
	a.externalProfileConnect(response, httptest.NewRequest(http.MethodPost, "/api/external-profile/connect",
		strings.NewReader(`{"profile_id":"installed-linux-external","direct":true,"execution":"local"}`)).WithContext(ctx))
	var replied struct {
		OK              bool   `json:"ok"`
		ProfileID       string `json:"profile_id"`
		ActualExitProof string `json:"actual_exit_proof"`
		Execution       string `json:"execution"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &replied) != nil || !replied.OK ||
		replied.ProfileID != "installed-linux-external" || replied.ActualExitProof != "expected-public-ip-passed" || replied.Execution != "local" {
		return original, fmt.Errorf("public external Connect failed its actual handler: %d: %s", response.Code, response.Body.String())
	}
	value, found := desktopExternalRetainedLaunches.Load(a)
	native, ok := value.(*desktopNodeLaunch)
	if !found || !ok {
		return original, errors.New("public external Connect lost its retained observation handle")
	}
	host, proof, err := linuxHostTUNExternalActive(ctx, a, session, native)
	if err != nil {
		return host, err
	}
	observed := (&sessionTracker{a: a}).capture()
	ambientCalls := 0
	lookup := func(context.Context, string) ([]string, error) {
		ambientCalls++
		return nil, errors.New("installed external DNS observation cannot use an ambient resolver")
	}
	dns := proveSelectedDNSWithLookup(ctx, a, observed, host.launch.mode, lookup)
	if dns.Status != "passed" || dns.LatencyMs != 0 || ambientCalls != 0 || !strings.Contains(dns.Reason, "before public-exit activation") {
		return host, errors.New("public external DNS observation lost its original proof or fabricated a fresh measurement")
	}
	foreign := observed
	foreign.Profile = cloneRouterProfile(observed.Profile)
	if foreign.Profile.External.AmneziaWG != nil {
		// A valid imported S4 from another profile cannot inherit this source's
		// previously proved DNS, even though the active peer remains healthy.
		foreign.Profile.External.AmneziaWG.Parameters["s4"] = "16"
	} else if foreign.Profile.External.WireGuard != nil {
		key, err := base64.StdEncoding.Strict().DecodeString(foreign.Profile.External.WireGuard.PresharedKey)
		if err != nil || len(key) != 32 {
			return host, errors.New("captured WireGuard observer lost its PSK")
		}
		key[0] ^= 255
		foreign.Profile.External.WireGuard.PresharedKey = base64.StdEncoding.EncodeToString(key)
		clear(key)
	} else if foreign.Profile.External.OpenVPN != nil {
		original := foreign.Profile.External.OpenVPN.Config
		foreign.Profile.External.OpenVPN.Config = strings.ReplaceAll(original, strings.Repeat("a", 32), strings.Repeat("b", 32))
		if original == foreign.Profile.External.OpenVPN.Config {
			return host, errors.New("captured provider observer lost its real original control key")
		}
	} else if foreign.Profile.External.Hysteria2 != nil {
		foreign.Profile.External.Hysteria2.Password += "-different-observed-source"
	} else if foreign.Profile.External.SOCKS5 != nil {
		foreign.Profile.External.SOCKS5.Password += "-different-observed-source"
	} else {
		foreign.Profile.External.Shadowsocks.Password += "-different-observed-source"
	}
	refused := proveSelectedDNSWithLookup(ctx, a, foreign, host.launch.mode, lookup)
	if refused.Status != "failed" || refused.LatencyMs != 0 || ambientCalls != 0 || host.Current(ctx) != nil {
		return host, errors.New("public external DNS observation accepted a different captured credential or changed its original owner")
	}
	foreign = observed
	foreign.Base += "-different-observed-base"
	refused = proveSelectedDNSWithLookup(ctx, a, foreign, host.launch.mode, lookup)
	if refused.Status != "failed" || refused.LatencyMs != 0 || ambientCalls != 0 || host.Current(ctx) != nil {
		return host, errors.New("public external DNS observation accepted a stale presentation after native proof")
	}
	if err := linuxHostTUNRestoreCheck(ctx, session, host, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		profile, exists := a.profileByIDLocked("installed-linux-external")
		if !exists || profile.UseCount != 1 || profile.LastUsedAt == "" || profile.PublicIP != "203.0.113.88" ||
			desktopOwnedNodeProfileToken(profile) != host.externalPersistedRevision || host.revision == host.externalPersistedRevision ||
			a.connectionContext != nil || a.connectionCancel != nil || host.activation.operation.Err() == nil || host.activation.lifetime.Err() != nil ||
			original.process.command.ProcessState == nil || original.source != nil || original.policy != nil || session.journal != host.transaction.journal {
			return errors.New("public external Connect lost real persistence or request-independent active ownership")
		}
		return nil
	}); err != nil {
		return host, err
	}
	raw, err := readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	var persisted common.RouterProfileStore
	if err != nil || decodeRelayControlJSON(raw, &persisted) != nil || len(persisted.Profiles) != 2 {
		return host, errors.Join(err, errors.New("public external Connect failed its original private saved store"))
	}
	profile, exists := profileByID(persisted.Profiles, "installed-linux-external")
	if !exists || profile.UseCount != 1 || profile.PublicIP != "203.0.113.88" || desktopOwnedNodeProfileToken(profile) != host.externalPersistedRevision {
		return host, errors.New("public external Connect reported persistence without writing the captured profile")
	}
	result.Stage, result.ExternalSession, result.Proof, result.MTU, result.PublicPersisted = "external", host.selection.SessionID, &proof, 1376, true
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return host, err
	}
	if err := linuxHostTUNRendezvous(gate, 3); err != nil {
		return host, err
	}
	if err := host.Current(ctx); err != nil {
		return host, errors.Join(err, errors.New("completed public external request discarded its original active monitor"))
	}
	return host, nil
}

func linuxHostTUNExternalTemporary(ctx context.Context, a *app, session *desktopLinuxNodeSession, original *desktopLinuxNodeHost,
	gate *os.File, result *linuxExternalTUNResult) (last *desktopLinuxNodeHost, failure error) {
	last = original
	tracker := sessionTrackerFor(a)
	tracker.observe(tracker.capture())
	_, snapshot, finish, err := a.beginSpeedLabTemporaryOperation()
	if err != nil {
		return last, err
	}
	defer finish()
	saved := snapshot.Plan.linux
	if saved == nil || saved.session != session || saved.journal != session.journal || saved.parent != session.parent || saved.mtu != 1300 ||
		snapshot.Plan.request.Mode != "shadowsocks" || snapshot.Plan.request.Execution != "local" {
		return last, errors.New("external Speed Lab lost the frozen Router source, execution or observed MTU")
	}
	sealed, copyToClear := append([]byte(nil), saved.source...), saved.source
	defer clear(sealed)
	originalSource, journal := original.selection.SourceSHA256, session.journal
	if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "generated", snapshot.Plan.profile.ID, "shadowsocks", "sing-box.json"),
		[]byte("not the captured private Router graph\n"), 0600); err != nil {
		return last, err
	}
	if err := a.speedLabSuspendPrevious(snapshot, false); err != nil {
		return last, err
	}
	if err := linuxHostTUNRestoreCheck(ctx, session, original, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if session.active != nil || original.policy != nil || original.source != nil || original.activation.lifetime.Err() == nil ||
			original.process.command.ProcessState == nil || a.cmd != nil || a.state.Connected || session.journal != journal {
			return errors.New("external temporary test failed to join exactly its original Router")
		}
		return nil
	}); err != nil {
		return last, err
	}
	if _, err := os.Lstat(original.launch.directory); !errors.Is(err, os.ErrNotExist) {
		return last, errors.New("external test retained the joined Router's private workspace")
	}
	query := speedLabRequest{Scope: "temporary", Topology: "external", NodeID: "installed-linux-external", Execution: "local"}
	prepared, err := a.prepareSpeedLabExternalPath(query, nil)
	if err != nil || prepared == nil || prepared.native == nil {
		return last, errors.Join(err, errors.New("external test failed actual native graph preparation"))
	}
	query.preparedExternal = prepared
	var external *desktopLinuxNodeHost
	if linuxHostTUNExternalAction(result.Scenario) == "cancelled" {
		done := make(chan error, 1)
		joined := false
		go func() { _, err := a.startSpeedLabExternalPath(query); done <- err }()
		defer func() {
			if !joined {
				snapshot.Owner.cancelTest()
				select {
				case <-done:
				case <-time.After(30 * time.Second):
					failure = errors.Join(failure, errors.New("cancelled fixture did not join its exact external start operation"))
				}
			}
		}()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for external == nil {
			if err := session.enter(ctx); err != nil {
				return last, err
			}
			candidate := session.active
			if candidate != nil && candidate != original {
				external = candidate
			}
			session.gate <- struct{}{}
			if external != nil {
				break
			}
			select {
			case err := <-done:
				joined = true
				return last, errors.Join(err, errors.New("external cancellation never reached native admission"))
			case <-ctx.Done():
				return last, ctx.Err()
			case <-ticker.C:
			}
		}
		last = external
		result.Stage, result.ExternalSession = "external-pending", external.selection.SessionID
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return last, err
		}
		if err := linuxHostTUNRendezvous(gate, 3); err != nil {
			return last, err
		}
		snapshot.Owner.cancelTest()
		select {
		case err := <-done:
			joined = true
			if err == nil {
				return last, errors.New("cancelled external HTTPS proof reported success")
			}
		case <-ctx.Done():
			return last, ctx.Err()
		}
		result.FailedProof = true
	} else {
		_, startErr := a.startSpeedLabExternalPath(query)
		owner, ok := prepared.native.external.retained.(*desktopLinuxExternalConnection)
		if !ok || owner == nil || owner.host == nil || owner.session != session {
			return last, errors.Join(startErr, errors.New("external test did not retain its actual new host"))
		}
		external, last = owner.host, owner.host
		result.ExternalSession = external.selection.SessionID
		if linuxHostTUNExternalFailedProof(result.Scenario) {
			if startErr == nil || external.activation != nil || external.externalProof != nil {
				return last, errors.New("failed external authentication, TLS or selected DNS reported a connected proof")
			}
			result.Stage, result.FailedProof = "proof-refused", true
		} else {
			if startErr != nil {
				return last, startErr
			}
			proved, proof, err := linuxHostTUNExternalActive(ctx, a, session, prepared.native)
			if err != nil || proved != external || external.selection.SessionID == result.OriginalSession || external.selection.SourceSHA256 == originalSource {
				return last, errors.Join(err, errors.New("external succession reused original Router proof authority"))
			}
			result.Stage, result.Proof, result.MTU = "external", &proof, 1376
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return last, err
		}
		if err := linuxHostTUNRendezvous(gate, 3); err != nil {
			return last, err
		}
	}
	if linuxHostTUNExternalAction(result.Scenario) == "replacement" {
		replacement := exec.Command("/bin/sleep", "60")
		if err := replacement.Start(); err != nil {
			return last, err
		}
		defer func() { _ = replacement.Process.Kill(); _ = replacement.Wait() }()
		replacementState := state{Connected: true, RouterID: "replacement", Mode: "replacement", RuntimeMode: "replacement", Phase: "connected"}
		a.mu.Lock()
		a.cmd, a.state = replacement, replacementState
		a.mu.Unlock()
		if err := a.speedLabRestoreTemporary(snapshot); err == nil {
			return last, errors.New("old external test restored over its actual replacement process")
		}
		if err := retireDesktopLinuxNodeRestore(ctx, session, external); err != nil {
			return last, err
		}
		a.mu.Lock()
		kept := a.cmd == replacement && reflect.DeepEqual(a.state, replacementState) && replacement.Process.Signal(syscall.Signal(0)) == nil
		if kept {
			a.cmd, a.state = nil, state{Mode: "off", Phase: "off"}
		}
		a.mu.Unlock()
		if !kept {
			return last, errors.New("old external retirement changed or killed a replacement owner")
		}
		finish()
		if err := session.Retire(ctx, nil, true); err != nil {
			return last, err
		}
		result.ReplacementKept = true
		return last, nil
	}
	if result.FailedProof {
		a.mu.Lock()
		connected := a.state.Connected
		a.mu.Unlock()
		if connected || external.activation != nil || external.externalProof != nil || a.speedLabCheckLaunchedRuntime() != nil {
			return last, errors.New("failed external proof retained Connected or borrowed a replacement runtime")
		}
	}
	snapshot.Owner.cancelTest()
	if err := a.speedLabRestoreTemporary(snapshot); err != nil {
		return last, err
	}
	fresh := saved.restored
	if fresh == nil {
		return last, errors.New("external restoration returned no newly proved Router owner")
	}
	last = fresh
	if err := currentDesktopLinuxRestoredHost(ctx, a, session, journal, fresh); err != nil {
		return last, err
	}
	if err := linuxHostTUNRestoreCheck(ctx, session, fresh, func() error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if fresh == original || fresh == external || fresh.policy == nil || fresh.external != nil || fresh.ready == nil || fresh.proof == nil ||
			fresh.process == original.process || fresh.process == external.process || fresh.activation == nil || fresh.activation == original.activation ||
			fresh.selection.SessionID == result.OriginalSession || fresh.selection.SessionID == result.ExternalSession || fresh.selection.SourceSHA256 != originalSource ||
			fresh.ready.MTU != 1300 || fresh.policy.Metadata().RestoredMTU != 1300 || !bytes.Equal(fresh.source, sealed) || session.journal != journal ||
			!reflect.DeepEqual(a.profiles, snapshot.Profiles) || a.cmd != fresh.launch.command || !a.state.Connected ||
			external.process.command.ProcessState == nil || external.source != nil || external.external != nil {
			return errors.New("external restore substituted private source, observed MTU, proof authority or original session")
		}
		return nil
	}); err != nil {
		return last, err
	}
	if _, err := os.Lstat(external.launch.directory); !errors.Is(err, os.ErrNotExist) {
		return last, errors.New("external restoration retained the retired candidate's private workspace")
	}
	finish()
	if !saved.cleared || saved.source != nil || !bytes.Equal(copyToClear, make([]byte, len(copyToClear))) ||
		a.restartCapturedDesktopLinuxNode(snapshot.Plan, "speed-lab:restore") == nil || currentDesktopLinuxRestoredHost(ctx, a, session, journal, fresh) != nil {
		return last, errors.New("external restore retained copied credentials, allowed replay or erased the fresh owner")
	}
	result.Restore = &linuxHostTUNRestoreResult{PreviousSession: result.OriginalSession, SourceSHA256: originalSource, RestoredMTU: 1300,
		FreshSession: fresh.selection.SessionID, Execution: "local", Cleared: true}
	return last, nil
}
