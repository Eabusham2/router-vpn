//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/nativeopenvpn"
)

const macOSExternalNativeMarker = "fixture-external-host"

// This separate test-only role serves the actual application handlers inside
// the installed supervisor's authenticated original controller. The regular
// installer/controller fixture retains its existing no-PF-mutation lifecycle.
func macOSExternalNativeController(owned *ownedDesktopController) (bool, error) {
	raw, err := readPrivateRegular(filepath.Join(macOSOwnedControllerRoot, macOSExternalNativeMarker), 128)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || string(raw) != "explicit disposable macOS external PF and TUN fixture\n" {
		return true, errors.Join(err, errors.New("native external fixture has no fixed disposable authority"))
	}
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{
		AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress,
		ProfilesFile: filepath.Join(macOSOwnedControllerRoot, "routers.json"),
		ModesFile:    filepath.Join(macOSOwnedControllerRoot, "modes.json"),
		ScriptsDir:   filepath.Join(macOSOwnedControllerRoot, "modes"),
		StateFile:    filepath.Join(macOSOwnedControllerRoot, "state.json"),
	}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || len(a.profiles.Profiles) != 1 || a.profiles.SelectedID != "installed-macos-external" || a.profiles.Profiles[0].ID != a.profiles.SelectedID {
		return true, errors.Join(err, errors.New("native external fixture lost its saved private profile"))
	}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	// The shipping catalog contains twenty raw runtimes plus SMART AUTO and CUSTOM.
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 22 {
		return true, errors.Join(err, errors.New("native external fixture lost its shipping mode catalog"))
	}
	captured, err := captureDesktopMacOSSession(context.Background(), a)
	if err != nil {
		return true, err
	}
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return true, err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original controller unavailable", http.StatusConflict)
			return
		}
		a.mu.Lock()
		value := a.state
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(value)
	})
	var observationMu sync.Mutex
	var original *desktopMacOSExternalHost
	// Forward the actual shipping preparation unchanged, retaining only its
	// returned pointer for failed-start cleanup observations after registry removal.
	mux.HandleFunc("/api/external-profile/connect", func(w http.ResponseWriter, r *http.Request) {
		a.externalProfileConnectWithRuntime(w, r, externalConnectRuntime{retained: func(owner *app, launch *desktopNodeLaunch) (desktopExternalRetainedRuntime, error) {
			retained, err := prepareDesktopRetainedExternalForLaunch(owner, launch)
			if retained != nil {
				host, ok := retained.(*desktopMacOSExternalHost)
				observationMu.Lock()
				defer observationMu.Unlock()
				if !ok || host == nil || host.parent.parent != captured.parent || host.parent.session != captured.session || original != nil && original != host {
					return retained, errors.New("native test observation received a replaced host")
				}
				original = host
			}
			return retained, err
		}})
	})
	mux.HandleFunc("/api/disconnect", a.disconnect)
	mux.HandleFunc("/api/mtu/retest", a.retestMTU)
	mux.HandleFunc("/api/mtu/status", a.desktopMTUStatus)
	mux.HandleFunc("/api/mtu/cancel", a.cancelDesktopMTURoute)
	mux.HandleFunc("/api/speed-lab/external-latency", a.desktopLatencyMeasurement)
	mux.HandleFunc("/api/speed-lab/external-latency/cancel", a.cancelDesktopLatencyMeasurement)
	mux.HandleFunc("/api/native-external-observation", func(w http.ResponseWriter, r *http.Request) {
		observationMu.Lock()
		defer observationMu.Unlock()
		if value, found := desktopExternalRetainedLaunches.Load(a); found {
			launch, ok := value.(*desktopNodeLaunch)
			if !ok || launch.external == nil {
				http.Error(w, "untyped native launch", http.StatusConflict)
				return
			}
			host, ok := launch.external.retained.(*desktopMacOSExternalHost)
			if !ok || host == nil || host.parent.parent != captured.parent || host.parent.session != captured.session || original != nil && original != host {
				http.Error(w, "replaced native host", http.StatusConflict)
				return
			}
			original = host
		}
		if original == nil {
			http.Error(w, "missing native host", http.StatusConflict)
			return
		}
		result, err := macOSExternalNativeObservation(r.Context(), original)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	return true, serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type macOSExternalNativeResult struct {
	OpenVPNRemotes                                                                                                          []nativeopenvpn.Remote
	PhysicalDestinations                                                                                                    []mobilemultihop.PhysicalEgress
	IPv6, DNSProtocol, DNSHost                                                                                              string
	DNSPort                                                                                                                 int
	HomeLAN                                                                                                                 bool
	Session, Source, Config, Protocol                                                                                       string
	Layer, LayerType, LayerHost, LayerDetour, OuterTag, OuterType, PhysicalNetwork, PhysicalAddress, InnerHost, InnerDetour string
	LayerPort                                                                                                               int
	ProcessID                                                                                                               int
	Connected, Closed, NativeJoined, WorkspaceRetired                                                                       bool
	Network                                                                                                                 desktopnetwork.DesktopNetworkReceipt
	Baseline                                                                                                                *desktopMacOSExternalReceipt
	Proof                                                                                                                   desktopExternalProof
}

func macOSExternalNativeObservation(ctx context.Context, h *desktopMacOSExternalHost) (macOSExternalNativeResult, error) {
	var result macOSExternalNativeResult
	if err := h.enter(ctx); err != nil {
		return result, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.policy == nil || h.policy.Validate() != nil {
		return result, errors.New("native observation lost its sealed policy")
	}
	capture, err := h.policy.Capture()
	if err != nil || len(capture.PhysicalRoots) != 1 {
		return result, errors.New("native observation lost its one original outer tuple")
	}
	result.IPv6, result.HomeLAN = capture.IPv6Mode, capture.HomeLANAccess
	result.DNSProtocol, result.DNSHost, result.DNSPort = capture.SelectedDNS.Type, capture.SelectedDNS.Host, capture.SelectedDNS.Port
	if capture.Protocol == "openvpn" {
		if err := macOSExternalNativeOpenVPNObservation(h, &result); err != nil {
			return result, err
		}
	}
	root := capture.PhysicalRoots[0]
	result.Layer, result.OuterTag, result.OuterType = capture.StartLayer, root.Tag, root.Type
	if capture.EntryID != "" && (root.Type == "shadowsocks" || root.Type == "routervpn-aes-xor" && capture.EntryStartLayer == common.StartLayerAES256GCMXOR) && (capture.Protocol == "shadowsocks" || capture.Protocol == "hysteria2") {
		if len(root.Destinations) != 2 {
			return result, errors.New("SS entry lost exact TCP/UDP physical tuples")
		}
		seen := map[string]bool{}
		for _, destination := range root.Destinations {
			address := net.JoinHostPort(destination.Host, strconv.Itoa(destination.Port))
			if destination.Network != "tcp" && destination.Network != "udp" || seen[destination.Network] || result.PhysicalAddress != "" && result.PhysicalAddress != address {
				return result, errors.New("SS entry acquired another physical destination")
			}
			result.PhysicalAddress, seen[destination.Network] = address, true
		}
		result.PhysicalNetwork = "tcp+udp"
		result.PhysicalDestinations = append([]mobilemultihop.PhysicalEgress(nil), root.Destinations...)
	} else if capture.EntryID != "" || capture.StartLayer != "" || capture.Protocol == "wireguard" || capture.Protocol == "amneziawg" || capture.Protocol == "socks5" {
		if len(root.Destinations) != 1 {
			return result, errors.New("layer observation lost its one original physical tuple")
		}
		destination := root.Destinations[0]
		result.PhysicalNetwork, result.PhysicalAddress = destination.Network, net.JoinHostPort(destination.Host, strconv.Itoa(destination.Port))
		if capture.EntryID != "" && root.Type == "shadowsocks" {
			result.PhysicalDestinations = append([]mobilemultihop.PhysicalEgress(nil), root.Destinations...)
		}
	}
	var graph struct {
		Endpoints []struct {
			Tag, Type, Detour string
			Peers             []struct {
				Address string
				Port    int
			}
		}
		Outbounds []struct {
			Tag, Type, Server, Detour string
			Port                      int `json:"server_port"`
		}
	}
	if json.Unmarshal([]byte(h.policy.Config()), &graph) != nil {
		return result, errors.New("native observation lost its original graph")
	}
	for _, outbound := range graph.Outbounds {
		if outbound.Tag == "routervpn-exit-start-layer" {
			result.LayerType, result.LayerHost, result.LayerDetour, result.LayerPort = outbound.Type, outbound.Server, outbound.Detour, outbound.Port
		}
		if outbound.Tag == mobilemultihop.ExternalFinalTag {
			result.InnerHost, result.InnerDetour = outbound.Server, outbound.Detour
		}
	}
	if capture.EntryID != "" && (capture.Protocol == "wireguard" || capture.Protocol == "amneziawg") {
		found := false
		for _, endpoint := range graph.Endpoints {
			if endpoint.Tag != mobilemultihop.ExternalFinalTag {
				continue
			}
			kind := "wireguard"
			if capture.Protocol == "amneziawg" {
				kind = mobilemultihop.AmneziaType
			}
			if found || endpoint.Type != kind || len(endpoint.Peers) != 1 || endpoint.Peers[0].Port == 0 || endpoint.Detour != capture.EntryTag {
				return result, errors.New("packet final observation lost its exact endpoint")
			}
			found = true
			result.InnerHost, result.InnerDetour = endpoint.Peers[0].Address, endpoint.Detour
		}
		if !found {
			return result, errors.New("packet final observation omitted its endpoint")
		}
	}
	result.Session, result.Source, result.Config, result.Protocol = h.selection.Session, h.selection.Source, h.selection.Config, h.selection.Protocol
	result.Closed, result.NativeJoined, result.WorkspaceRetired = h.closed, h.nativeRetired, h.workspaceRetired
	if h.baseline != nil {
		value := *h.baseline
		result.Baseline = &value
	}
	if h.process == nil || h.process.command == nil || h.process.command.Process == nil {
		return result, errors.New("native observation lacks its created runtime")
	}
	result.ProcessID = h.process.command.Process.Pid
	if h.closed {
		if err := h.process.NativeCleanup(ctx); err != nil {
			return result, err
		}
		if _, err := os.Lstat(h.launch.directory); !errors.Is(err, os.ErrNotExist) {
			return result, errors.New("native retirement retained or replaced its private workspace")
		}
		return result, nil
	}
	if err := h.current(ctx, true); err != nil {
		return result, err
	}
	proof, err := h.parent.app.readDesktopExternalProofRecord(h.launch)
	if err != nil {
		return result, err
	}
	if err = h.proofCurrent(ctx, proof); err != nil {
		return result, err
	}
	result.Proof = proof
	result.Network, err = desktopnetwork.ParseDesktopNetworkReceipt(proof.NetworkReceipt)
	if err != nil {
		return result, err
	}
	h.parent.app.mu.Lock()
	result.Connected = h.parent.app.state.Connected
	h.parent.app.mu.Unlock()
	if !result.Connected || !h.activated || h.proof == nil || h.monitorDone == nil {
		return result, errors.New("native application published incomplete active ownership")
	}
	select {
	case <-h.monitorDone:
		return result, errors.New("native monitor already retired")
	default:
	}
	return result, nil
}

// Keep error details bounded to fixture observations, never imported keys.
func macOSExternalNativeHTTP(ctx context.Context, client *http.Client, method, path, body string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://"+linuxOwnedControllerAddress+path, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if len(raw) > 256<<10 {
		return 0, nil, errors.New("native external response exceeded its bounded receipt")
	}
	return response.StatusCode, raw, err
}

func TestMacOSRetainedExternalNativeSealedProtocols(t *testing.T) {
	for _, protocol := range append(append(append(append([]string{"shadowsocks", "http-connect", "https-connect", "hysteria2",
		"hysteria2-aes", "hysteria2-aes-xor", "hysteria2-aes-wrong-layer-key", "hysteria2-aes-wrong-inner-key",
		"hysteria2-aes-xor-wrong-layer-key", "hysteria2-aes-xor-wrong-inner-key", "hysteria2-aes-xor-wrong-whitening", "wireguard", "wireguard-always", "wireguard-auto", "wireguard-wrong-client-key", "wireguard-wrong-psk", "wireguard-wrong-dns", "wireguard-wrong-trust", "wireguard-wrong-exit", "socks5", "socks5-always", "socks5-wrong-password", "socks5-auth-downgrade", "socks5-relay-domain", "socks5-control-eof", "socks5-wrong-dns", "socks5-wrong-trust", "socks5-wrong-exit", "amneziawg-fast", "amneziawg-fast-always", "amneziawg-strong", "amneziawg-strong-always", "amneziawg-fast-wrong-client-key", "amneziawg-strong-wrong-psk", "amneziawg-fast-wrong-parameters", "amneziawg-strong-wrong-parameters", "amneziawg-strong-wrong-dns", "amneziawg-strong-wrong-trust", "amneziawg-strong-wrong-exit", "openvpn-tcp", "openvpn-tcp-always", "openvpn-udp", "openvpn-udp-always", "openvpn-tcp-fallback", "openvpn-tcp-fallback-always", "openvpn-mixed-fallback", "openvpn-mixed-fallback-always", "openvpn-tcp-wrong-control", "openvpn-udp-wrong-control", "openvpn-tcp-wrong-provider-trust", "openvpn-udp-wrong-password", "openvpn-tcp-wrong-username", "openvpn-udp-wrong-dns", "openvpn-tcp-wrong-trust", "openvpn-udp-wrong-exit", "wg-entry-ss", "wg-entry-ss-always", "wg-entry-ss-wrong-entry-key", "wg-entry-ss-wrong-entry-public", "wg-entry-ss-wrong-exit-key", "wg-entry-ss-wrong-dns", "wg-entry-ss-wrong-trust", "wg-entry-ss-wrong-exit", "awg-entry-ss-fast", "awg-entry-ss-fast-always", "awg-entry-ss-strong", "awg-entry-ss-strong-always", "awg-entry-ss-fast-wrong-entry-key", "awg-entry-ss-strong-wrong-entry-psk", "awg-entry-ss-fast-wrong-entry-parameters", "awg-entry-ss-strong-wrong-entry-parameters", "awg-entry-ss-strong-wrong-entry-public", "awg-entry-ss-strong-wrong-exit-key", "awg-entry-ss-strong-wrong-dns", "awg-entry-ss-strong-wrong-trust", "awg-entry-ss-strong-wrong-exit"}, macOSExternalConnectEntryCases...), macOSExternalHysteriaEntryCases...), macOSExternalSOCKSEntryCases...), append(append(macOSExternalHysteriaLayerEntryCases, macOSExternalWireGuardFinalCases...), append(append(macOSExternalAmneziaFinalCases, macOSExternalOpenVPNFinalCases...), append(append(append(macOSExternalSSEntryCases, macOSExternalSSLayerCases...), macOSExternalSSCONNECTCases...), macOSExternalSSHysteriaCases...)...)...)...) {
		t.Run(protocol, func(t *testing.T) { macOSExternalNativeCase(t, protocol) })
	}
}

func macOSExternalNativeCase(t *testing.T, scenario string) {
	t.Helper()
	fixture := macOSControllerNativeInstall(t)
	macOSExternalNativeBundle(t)
	peer := macOSExternalNativePeerStart(t, scenario)
	protocol := peer.protocol
	configuredMTU := 1376
	if _, _, _, found := macOSExternalOpenVPNFinalScenario(scenario); found {
		configuredMTU = 1280
	}
	if _, _, found := macOSExternalWireGuardFinalScenario(scenario); found {
		configuredMTU = 1360
	}
	if _, _, _, found := macOSExternalAmneziaFinalScenario(scenario); found {
		configuredMTU = 1328
	}
	if scenario == "wireguard-auto" {
		configuredMTU = 1280
	}
	if peer.fault != "wrong-trust" {
		macOSExternalNativeTrust(t, peer)
	}
	if peer.fault == "wrong-dns" {
		if _, err := io.WriteString(peer.input, "fail-dns\n"); err != nil {
			t.Fatal(err)
		}
		peer.read(t)
	}
	macOSExternalNativeInstallProfile(t, peer)
	fixture.start()
	connection := fixture.connection(fixture.uid)
	if _, err := connection.Write(macOSControllerNativeFrame()); err != nil {
		t.Fatal(err)
	}
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	client := macOSControllerNativeHTTP(t)
	client.Timeout = 65 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	joined := false
	// This cleanup is registered last: native child/controller joins precede
	// GUI-peer cleanup, certificate removal, independent peer and install removal.
	t.Cleanup(func() {
		if !joined {
			cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
			defer stop()
			_, _, _ = macOSExternalNativeHTTP(cleanup, client, http.MethodPost, "/api/disconnect", "{}")
			if err := connection.CloseWrite(); err != nil {
				t.Error("native GUI lifetime did not half-close", err)
				return
			}
			receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
			if receipt.ExitCode != 0 {
				t.Error("native controller failed original cleanup", receipt.ExitCode)
			}
			joined = true
		}
	})
	macOSControllerNativeAwait(t, func() bool {
		probe, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		status, _, err := macOSExternalNativeHTTP(probe, client, http.MethodGet, "/api/status", "")
		return err == nil && status == http.StatusOK
	}, "actual external controller did not serve its authenticated original owner")
	beforeTunnels := macOSExternalNativeTunnels(t)
	connectRequest := `{"profile_id":"installed-macos-external","direct":true,"execution":"local"}`
	if peer.packetEntry || peer.ssEntry {
		connectRequest = `{"profile_id":"installed-macos-external","entry_id":"` + macOSExternalNativeEntryID(peer) + `","direct":false,"execution":"local"}`
	}
	status, raw, err := macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/external-profile/connect", connectRequest)
	if peer.fault != "" {
		if peer.ssEntry {
			if protocol == "shadowsocks" {
				macOSExternalNativeSSEntryRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
			} else if protocol == "hysteria2" {
				macOSExternalNativeSSHysteriaRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
			} else {
				macOSExternalNativeSSCONNECTRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
			}
		} else if peer.packetEntry {
			macOSExternalNativePacketEntryRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
		} else if protocol == "openvpn" {
			macOSExternalNativeOpenVPNRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
		} else if protocol == "amneziawg" {
			macOSExternalNativeAmneziaRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
		} else if protocol == "socks5" {
			macOSExternalNativeSOCKSRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
		} else if protocol == "wireguard" {
			macOSExternalNativeWireGuardRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
		} else {
			macOSExternalNativeLayerRefused(t, ctx, client, peer, status, raw, err, started.ProcessID, beforeTunnels)
		}
		if err := connection.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
		joined = true
		if receipt.ExitCode != 0 {
			t.Fatal("rejected layer controller did not join original cleanup", receipt.ExitCode)
		}
		if peer.ssEntry {
			if protocol == "shadowsocks" || protocol == "hysteria2" {
				t.Logf("actual sealed Darwin SS entry refused %s: original encrypted entry reached, expected entry or final boundary rejected, original TCP UDP PF and utun retired, controller joined", scenario)
			} else {
				t.Logf("actual sealed Darwin SS CONNECT entry refused %s: original encrypted entry reached, expected entry or final boundary rejected, original TCP PF and utun retired, controller joined", scenario)
			}
		} else if peer.packetEntry {
			t.Logf("actual sealed Darwin packet entry refused %s: first encrypted peer reached, expected entry or final proof boundary rejected, original physical UDP PF and utun retired, controller joined", scenario)
		} else if protocol == "openvpn" {
			t.Logf("actual sealed Darwin OpenVPN refused %s: actual native encrypted provider reached, expected authentication or proof boundary rejected, original ordered PF tuples and utun retired, controller joined", scenario)
		} else if protocol == "amneziawg" {
			t.Logf("actual sealed Darwin AmneziaWG refused %s: actual encrypted peer and eleven-parameter readback reached, expected proof boundary rejected, original UDP PF and utun retired, controller joined", scenario)
		} else if protocol == "socks5" {
			t.Logf("actual sealed Darwin SOCKS refused %s: actual peer reached, expected association or proof boundary rejected, original control UDP PF and utun retired, controller joined", scenario)
		} else if protocol == "wireguard" {
			t.Logf("actual sealed Darwin WireGuard refused %s: encrypted peer reached, expected proof boundary rejected, native PF reference and utun retired, original controller joined", scenario)
		} else {
			t.Logf("actual sealed Darwin layer refused %s: encrypted peer reached, no DNS or exit proof, native PF reference and utun retired, original controller joined", scenario)
		}
		return
	}
	if scenario == "wireguard-auto" {
		macOSExternalNativeAwaitAutomaticMTU(t, ctx, client, peer)
	}
	var connected struct {
		OK              bool   `json:"ok"`
		ProfileID       string `json:"profile_id"`
		ActualExitProof string `json:"actual_exit_proof"`
		Execution       string `json:"execution"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(raw, &connected) != nil || !connected.OK || connected.ProfileID != "installed-macos-external" || connected.ActualExitProof != "expected-public-ip-passed" || connected.Execution != "local" {
		t.Fatalf("actual sealed Darwin %s public Connect failed: status=%d error=%v response=%s", protocol, status, err, raw)
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var live macOSExternalNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &live) != nil || !live.Connected || live.Closed || live.ProcessID <= 0 || live.ProcessID == started.ProcessID || live.Protocol != protocol ||
		!live.Proof.Healthy || !live.Proof.DNSProven || live.Proof.EntryProven != (peer.packetEntry || peer.ssEntry) || live.Network.TargetOS != "darwin" || !strings.HasPrefix(live.Network.Name, "utun") || (scenario != "wireguard-auto" && live.Network.MTU != configuredMTU || scenario == "wireguard-auto" && (live.Network.MTU < 1280 || live.Network.MTU > 1420)) ||
		live.Baseline == nil || live.Baseline.Phase != "active" || !live.Baseline.Baseline.Present || live.Baseline.Capture.Session != live.Session {
		t.Fatalf("actual Darwin external ownership/readiness receipt failed: status=%d error=%v response=%s", status, err, raw)
	}
	macOSExternalNativeLayerAuthority(t, peer, live)
	if (protocol == "wireguard" || protocol == "amneziawg") && !peer.packetEntry {
		expectedIPv6 := "off"
		if peer.policy == "always" {
			expectedIPv6 = "on"
		}
		if live.IPv6 != expectedIPv6 || live.HomeLAN != (peer.policy == "always") || live.DNSProtocol != "udp" || live.DNSHost != "203.0.113.53" || live.DNSPort != 5353 || live.PhysicalNetwork != "udp" || live.PhysicalAddress != peer.address.String() {
			t.Fatal("WireGuard changed selected DNS, IPv6, LAN or physical peer", live)
		}
	}
	observed := peer.stats(t)
	if peer.ssEntry {
		if protocol == "shadowsocks" {
			macOSExternalNativeSSEntryProved(t, peer, live, observed)
		} else if protocol == "hysteria2" {
			macOSExternalNativeSSHysteriaProved(t, peer, live, observed)
		} else {
			macOSExternalNativeSSCONNECTProved(t, peer, live, observed)
		}
	}
	if peer.packetEntry {
		macOSExternalNativePacketEntryProved(t, peer, live, observed)
	}
	if protocol == "openvpn" {
		macOSExternalNativeOpenVPNProved(t, peer, live, observed)
	}
	if protocol == "socks5" && !peer.packetEntry {
		macOSExternalNativeSOCKSProved(t, peer, live, observed)
	}
	if observed.DNSQueries < 1 || observed.PublicAttempts < 1 || observed.PublicReplies < 1 || observed.Streams < 1 || observed.AuthFailures != 0 || (protocol == "hysteria2" || protocol == "wireguard" || protocol == "amneziawg") && (observed.PhysicalUDP < 1 || observed.Packets < 1) || protocol != "hysteria2" && protocol != "wireguard" && protocol != "amneziawg" && protocol != "openvpn" && observed.Connections < 1 {
		t.Fatal("independent peer did not observe the selected native transport, DNS and actual exit proof", observed)
	}
	if peer.layer != "" && (observed.Layer == nil || observed.Layer.Authenticated < 1 || observed.Layer.Forwarded < 1 || observed.Layer.Rejected != 0) {
		t.Fatal("Darwin layer did not decrypt and forward the captured HY2 inner transport", observed)
	}
	// The HTTP Connect request has ended. Its original monitor and private
	// child must remain current, with a live native PF reference and TUN.
	time.Sleep(600 * time.Millisecond)
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retained macOSExternalNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retained) != nil || retained.Session != live.Session || retained.ProcessID != live.ProcessID || !retained.Connected || retained.Baseline == nil || retained.Baseline.Token != live.Baseline.Token {
		t.Fatal("completed public request lost its original retained native owner", status, err, string(raw))
	}
	macOSExternalNativeLatency(t, ctx, client, peer, live)
	if scenario == "wireguard-auto" {
		macOSExternalNativeWireGuardMTU(t, ctx, client, peer, live)
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodPost, "/api/disconnect", "{}")
	if err != nil || status != http.StatusOK || strings.TrimSpace(string(raw)) != `{"ok":true}` {
		t.Fatal("actual Darwin public Disconnect failed", status, err, string(raw))
	}
	status, raw, err = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if err != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || !retired.NativeJoined || !retired.WorkspaceRetired || retired.Session != live.Session || retired.ProcessID != live.ProcessID ||
		retired.Baseline == nil || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present != (peer.policy == "always") || retired.Baseline.Token != live.Baseline.Token {
		t.Fatal("actual Darwin Disconnect did not join native cleanup and retire its exact PF reference", status, err, string(raw))
	}
	if link, err := net.InterfaceByIndex(int(live.Network.Index)); err == nil && link.Name == live.Network.Name {
		t.Fatal("actual native utun survived joined Disconnect")
	}
	if peer.policy == "always" {
		macOSExternalNativeAlwaysKernel(t, ctx, retired.Baseline, beforeTunnels)
	} else {
		macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, beforeTunnels)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	receipt := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
	joined = true
	if receipt.ExitCode != 0 {
		t.Fatal("original installed controller failed joined shutdown", receipt.ExitCode)
	}
	if peer.policy == "always" {
		macOSExternalNativeReleaseAlways(t, ctx, retired.Baseline, beforeTunnels)
	}
	t.Logf("actual sealed Darwin ordinary host accepted %s: native child, selected DNS, exit proof, MTU%d, original PF retirement and controller join", scenario, configuredMTU)
}

func macOSExternalNativeLayerAuthority(t *testing.T, peer *macOSExternalNativePeer, value macOSExternalNativeResult) {
	t.Helper()
	if peer.layer == "" {
		if value.Layer != "" {
			t.Fatal("ordinary host acquired a layer")
		}
		return
	}
	kind := "shadowsocks"
	if peer.layer == common.StartLayerAES256GCMXOR {
		kind = "routervpn-aes-xor"
	}
	if peer.packetEntry {
		macOSExternalNativePacketEntryLayerAuthority(t, peer, value, kind)
		return
	}
	if value.Layer != peer.layer || value.OuterTag != "routervpn-exit-start-layer" || value.OuterType != kind ||
		value.PhysicalNetwork != "udp" || value.PhysicalAddress != peer.address.String() ||
		value.InnerHost != "10.93.0.1" || value.InnerDetour != value.OuterTag {
		t.Fatal("Darwin layer promoted the inner transport or lost its captured outer authority", value)
	}
	if remote, err := netip.ParseAddrPort(value.PhysicalAddress); err != nil || remote == peer.inner {
		t.Fatal("Darwin layer used the inner physical socket", err)
	}
}

func macOSExternalNativeLayerRefused(t *testing.T, ctx context.Context, client *http.Client, peer *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, beforeTunnels map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || (status != http.StatusConflict && status != http.StatusBadGateway) {
		t.Fatal("layer negative did not complete the actual native Connect refusal", status, failure, string(raw))
	}
	observed := peer.stats(t)
	layer := observed.Layer
	if layer == nil || layer.Raw < 1 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 || observed.Streams != 0 || observed.Packets != 0 {
		t.Fatal("layer negative missed encrypted traffic or admitted upper proof", observed)
	}
	if peer.fault == "wrong-inner-key" {
		if layer.Authenticated < 1 || layer.Forwarded < 1 || layer.Rejected != 0 {
			t.Fatal("inner credential negative failed before authenticated outer transport", observed)
		}
	} else if layer.Authenticated != 0 || layer.Forwarded != 0 || layer.Rejected < 1 {
		t.Fatal("outer authentication negative reached private HY2", observed)
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired ||
		retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Capture.Session != retired.Session ||
		retired.Baseline.Capture.Source != retired.Source || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present {
		t.Fatal("failed encrypted Connect did not join its exact native child and protective baseline transition", status, failure, string(raw))
	}
	macOSExternalNativeLayerAuthority(t, peer, retired)
	// Failed public Connect calls stopOwnedConnectionRuntime -> stopMode(false),
	// so On-connect protection must already be retired. Do not repair state by
	// issuing another Stop or accept a cached held baseline as absence proof.
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, beforeTunnels)
}

type macOSExternalTunnelIdentity struct {
	Name string
	MTU  int
}

func macOSExternalNativeTunnels(t *testing.T) map[int]macOSExternalTunnelIdentity {
	t.Helper()
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal("native utun inventory failed", err)
	}
	result := make(map[int]macOSExternalTunnelIdentity)
	for _, link := range links {
		if strings.HasPrefix(link.Name, "utun") {
			result[link.Index] = macOSExternalTunnelIdentity{link.Name, link.MTU}
		}
	}
	return result
}

// Inspect the exact original kernel reference and native namespace without
// applying any transition. An error or unknown state is never an absence.
func macOSExternalNativeRetiredKernel(t *testing.T, parent context.Context, token string, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	request, err := mobiletor.EncodeDesktopDarwinPFReferenceRequest(mobiletor.DesktopDarwinPFReferenceRequest{Schema: 1, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mobiletor.RunDesktopDarwinPFReference(ctx, request)
	var reference mobiletor.DesktopDarwinPFReferenceResult
	if err != nil || decodeRelayControlJSON(raw, &reference) != nil || reference.Schema != 1 || reference.Token != token || reference.Present {
		t.Fatal("original native PF reference survived joined retirement or became unreadable", err, string(raw))
	}
	request, err = mobiletor.EncodeDesktopDarwinPFBaselineRequest(mobiletor.DesktopDarwinPFBaselineRequest{Schema: 1, Action: "clear", Expected: []mobiletor.DesktopDarwinPFBaselineProof{{}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = mobiletor.RunDesktopDarwinPFBaseline(ctx, request, false)
	var baseline mobiletor.DesktopDarwinPFBaselineResult
	if err != nil || decodeRelayControlJSON(raw, &baseline) != nil || baseline.Schema != 1 || baseline.Applied || baseline.Previous.Present || baseline.Target.Present {
		t.Fatal("read-only native PF inspection did not prove original namespace absence", err, string(raw))
	}
	if _, err := os.Lstat(filepath.Join(macOSOwnedControllerRoot, "run", "kill-switch.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original On-connect journal survived native retirement", err)
	}
	if after := macOSExternalNativeTunnels(t); !maps.Equal(before, after) {
		t.Fatal("native retirement left a new utun or changed an existing interface", before, after)
	}
}
