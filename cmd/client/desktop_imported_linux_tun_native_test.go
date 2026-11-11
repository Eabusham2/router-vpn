//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mtuprobe"
)

var linuxImportedHostCases = []string{"imported-wg-ss-public", "imported-wg-ss-wrong-public", "imported-wg-ss-wrong-node", "imported-wg-ss-dns-failure", "imported-wg-ss-mtu-cancel", "imported-wg-ss-restore", "imported-wg-ss-cover-lost", "imported-wg-ss-temporary"}

type linuxImportedPeerReply struct {
	Schema             int    `json:"schema"`
	Address            string `json:"address"`
	PublicCA           string `json:"public_ca"`
	EntryPublicIP      string `json:"entry_public_ip"`
	FinalPublicIP      string `json:"final_public_ip"`
	EntryRawUDP        int64  `json:"entry_raw_udp"`
	EntryTCP           int64  `json:"entry_tcp"`
	EntryUDP           int64  `json:"entry_udp"`
	FinalRawTCP        int64  `json:"final_raw_tcp"`
	FinalRawUDP        int64  `json:"final_raw_udp"`
	FinalTCP           int64  `json:"final_tcp"`
	FinalUDP           int64  `json:"final_udp"`
	EntryPublicQueries uint64 `json:"entry_public_queries"`
	FinalPublicQueries uint64 `json:"final_public_queries"`
	RouterQueries      uint64 `json:"router_queries"`
	DirectQueries      uint32 `json:"direct_router_queries"`
	DNSQueries         uint64 `json:"dns_queries"`
	MTUQueries         uint64 `json:"mtu_queries"`
	MTUReplies         uint64 `json:"mtu_replies"`
	CoverPackets       uint64 `json:"cover_packets"`
	CoverReplies       uint64 `json:"cover_replies"`
	CoverMaximum       uint32 `json:"cover_maximum"`
	DownloadBytes      uint64 `json:"download_bytes"`
	UploadBytes        uint64 `json:"upload_bytes"`
}

type linuxImportedPeer struct {
	input                 *os.File
	output                *os.File
	reader                *bufio.Reader
	command               *exec.Cmd
	done                  chan struct{}
	diagnostic            linuxHostTUNOutput
	client, server, final *ecdh.PrivateKey
	psk, password         string
	reply                 linuxImportedPeerReply
}

func (peer *linuxImportedPeer) read(t *testing.T) linuxImportedPeerReply {
	t.Helper()
	if err := peer.output.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := peer.reader.ReadSlice('\n')
	var result linuxImportedPeerReply
	if err != nil || len(raw) > 32768 || decodeRelayControlJSON(raw, &result) != nil || result.Schema != 1 {
		t.Fatal("independent imported peer lost its exact bounded reply", err, peer.diagnostic.String())
	}
	address, err := netip.ParseAddrPort(result.Address)
	if err != nil || address.Addr() != netip.MustParseAddr("192.168.210.2") || address.Port() == 0 || result.PublicCA == "" || result.EntryPublicIP != "203.0.113.88" || result.FinalPublicIP != "203.0.113.89" {
		t.Fatal("independent imported peer changed its endpoints or CA")
	}
	if peer.reply.Address != "" && (peer.reply.Address != result.Address || peer.reply.PublicCA != result.PublicCA) {
		t.Fatal("independent imported peer replaced its original identity")
	}
	peer.reply = result
	return result
}

func (peer *linuxImportedPeer) observe(t *testing.T, action string) linuxImportedPeerReply {
	t.Helper()
	if _, err := io.WriteString(peer.input, action+"\n"); err != nil {
		t.Fatal(err)
	}
	return peer.read(t)
}

func startLinuxImportedPeer(t *testing.T, cover bool) *linuxImportedPeer {
	t.Helper()
	directory, err := os.MkdirTemp("/opt", "routervpn-imported-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	image := filepath.Join(directory, "peer.test")
	linuxHostTUNCopy(t, os.Getenv("ROUTERVPN_NODE_HOST_PEER_BINARY"), image, 512<<20, os.Getenv("ROUTERVPN_NODE_HOST_PEER_SHA256"), 0755)
	peer := &linuxImportedPeer{done: make(chan struct{})}
	for _, destination := range []**ecdh.PrivateKey{&peer.client, &peer.server, &peer.final} {
		*destination, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	peer.psk = base64.StdEncoding.EncodeToString(key)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	peer.password = base64.StdEncoding.EncodeToString(key)
	clear(key)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	peer.command = exec.CommandContext(ctx, "ip", "netns", "exec", "rvpn-peer", image, "-test.run=^TestRouterVPNDesktopImportedWGSSReferenceProcess$", "-test.count=1", "-test.timeout=115s")
	peer.command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_IMPORTED_WG_SS_REFERENCE_CHILD=1"}
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	peer.input, peer.output, peer.reader = inputWrite, outputRead, bufio.NewReaderSize(outputRead, 32768)
	peer.command.Stdin, peer.command.Stdout, peer.command.Stderr = inputRead, outputWrite, &peer.diagnostic
	if err := peer.command.Start(); err != nil {
		t.Fatal(err)
	}
	inputRead.Close()
	outputWrite.Close()
	go func() { _ = peer.command.Wait(); close(peer.done) }()
	t.Cleanup(func() { inputWrite.Close(); cancel(); <-peer.done; outputRead.Close() })
	finalPublic := base64.StdEncoding.EncodeToString(peer.final.PublicKey().Bytes())
	identity := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + finalPublic))
	request := map[string]any{"schema": 1, "address": "192.168.210.2", "client_address": "192.168.210.1", "private_key": base64.StdEncoding.EncodeToString(peer.server.Bytes()),
		"client_public_key": base64.StdEncoding.EncodeToString(peer.client.PublicKey().Bytes()), "pre_shared_key": peer.psk, "final_password": peer.password,
		"node_proof_id": hex.EncodeToString(identity[:]), "token": "installed-imported-final-token", "direct_router": true, "cover": cover}
	if err := json.NewEncoder(peer.input).Encode(request); err != nil {
		t.Fatal(err)
	}
	peer.read(t)
	return peer
}

func installLinuxImportedProfiles(t *testing.T, peer *linuxImportedPeer, cover bool) {
	t.Helper()
	entry := common.RouterProfile{ID: "installed-imported-entry", Name: "Original imported entry", NodeKind: "external", Endpoint: "192.168.210.2", StartLayer: "off",
		DNSMode: "rescue", IPv6Mode: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect",
		External: &common.ExternalNodeConfig{Protocol: "wireguard", ExpectedPublicIP: peer.reply.EntryPublicIP,
			WireGuard: &common.ExternalWireGuardConfig{PrivateKey: base64.StdEncoding.EncodeToString(peer.client.Bytes()), PeerPublicKey: base64.StdEncoding.EncodeToString(peer.server.PublicKey().Bytes()),
				PresharedKey: peer.psk, Endpoint: peer.reply.Address, Addresses: []string{"10.78.0.2/32", "fd78:78::2/128"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, MTU: 1500}}}
	finalPublic := base64.StdEncoding.EncodeToString(peer.final.PublicKey().Bytes())
	identity := sha256.Sum256([]byte("router-vpn-node-proof-v1\n" + finalPublic))
	final := common.RouterProfile{ID: "installed-imported-final", Name: "Independent paired final", NodeProofID: hex.EncodeToString(identity[:]),
		Endpoint: "10.77.0.1", RouterAPI: "http://10.77.0.1:8787", APIToken: "installed-imported-final-token", AdGuardIPv4: "192.168.50.133", DNSMode: "home",
		IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect", BaseTunnel: "wg",
		DAITAHost: "10.77.0.1", DAITAPort: 45999, DAITARateKbps: 64, DAITAEnabled: cover,
		MultihopEnabled: true, MultihopEntryID: entry.ID, MultihopExitID: "installed-imported-final", MultihopEntryMode: "wireguard", MultihopExecution: "local"}
	for _, profile := range []*common.RouterProfile{&entry, &final} {
		if err := common.NormalizeRouterProfile(profile); err != nil {
			t.Fatal(err)
		}
	}
	store, err := json.Marshal(common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion, SelectedID: final.ID, Profiles: []common.RouterProfile{entry, final}})
	if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), store, 0600) != nil {
		t.Fatal("imported fixture lost independently saved profiles", err)
	}
	if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "imported-peer-ca.pem"), []byte(peer.reply.PublicCA), 0600); err != nil {
		t.Fatal(err)
	}
	assets := map[string]map[string][]byte{"wg": {"wg.conf": []byte(fmt.Sprintf("[Interface]\nAddress=10.79.0.2/32\nPrivateKey=%s\nMTU=1500\n[Peer]\nPublicKey=%s\nEndpoint=10.77.0.1:51820\nAllowedIPs=0.0.0.0/0\n", base64.StdEncoding.EncodeToString(peer.client.Bytes()), finalPublic))}}
	graph, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "10.77.0.1", "server_port": 8388, "method": mobilemultihop.NativeStartLayerMethod, "password": peer.password}}, "route": map[string]any{"final": "proxy"}})
	if err != nil {
		t.Fatal(err)
	}
	assets["shadowsocks"] = map[string][]byte{"sing-box.json": graph}
	for mode, files := range assets {
		directory := filepath.Join(linuxOwnedControllerRoot, "generated", final.ID, mode)
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type linuxImportedHostResult struct {
	Scenario     string                                 `json:"scenario"`
	Stage        string                                 `json:"stage"`
	Session      string                                 `json:"session"`
	FreshSession string                                 `json:"fresh_session"`
	Ready        *mobilemultihop.DesktopNodeReadyRecord `json:"ready"`
	Rejected     bool                                   `json:"rejected"`
	MTU          int                                    `json:"mtu"`
	Retired      bool                                   `json:"retired"`
	Monitor      bool                                   `json:"monitor"`
}

func (process *linuxHostTUNController) readImported(t *testing.T, scenario string) linuxImportedHostResult {
	t.Helper()
	if err := process.output.SetReadDeadline(time.Now().Add(75 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := process.reader.ReadSlice('\n')
	var result linuxImportedHostResult
	if err != nil || len(raw) > 32768 || decodeRelayControlJSON(raw, &result) != nil || result.Scenario != scenario {
		t.Fatal("installed imported host omitted its bounded result", err, string(raw), process.diagnostic.String())
	}
	return result
}

func linuxHostTUNImportedParent(t *testing.T, installed, scenario string) {
	peer := startLinuxImportedPeer(t, strings.HasSuffix(scenario, "cover-lost"))
	installLinuxImportedProfiles(t, peer, strings.HasSuffix(scenario, "cover-lost"))
	action := strings.TrimPrefix(scenario, "imported-wg-ss-")
	negative := action == "wrong-public" || action == "wrong-node" || action == "dns-failure"
	if action == "wrong-public" || action == "wrong-node" {
		peer.observe(t, action)
	}
	if action == "dns-failure" {
		peer.observe(t, "fail-dns")
	}
	process := linuxHostTUNStartController(t, installed, scenario)
	if _, err := process.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	result := process.readImported(t, scenario)
	before := peer.observe(t, "stats")
	if negative {
		if !result.Rejected || !result.Retired || result.Ready != nil || result.Session == "" || before.DirectQueries != 0 ||
			before.EntryRawUDP == 0 || before.FinalRawUDP == 0 || before.FinalUDP == 0 || before.DNSQueries == 0 {
			t.Fatal("negative imported graph was not completely refused and retired", result)
		}
		if action == "wrong-public" && before.EntryPublicQueries == 0 || action == "wrong-node" && before.RouterQueries == 0 {
			t.Fatal("imported negative control failed before its intended independently counted proof", before)
		}
	} else {
		if result.Stage != "ready" || result.Ready == nil || result.Ready.DNSMilliseconds <= 0 || !result.Monitor ||
			before.EntryRawUDP == 0 || before.EntryTCP == 0 || before.FinalRawTCP == 0 || before.FinalTCP == 0 || before.FinalRawUDP == 0 || before.FinalUDP == 0 ||
			before.EntryPublicQueries == 0 || before.RouterQueries == 0 || before.DNSQueries < 2 || before.DirectQueries != 0 {
			t.Fatal("public imported Connect bypassed an independently encrypted owner or final DNS", result, before)
		}
		if action == "cover-lost" {
			if before.CoverPackets == 0 || before.CoverReplies == 0 || result.Ready.CoverServices != 1 {
				t.Fatal("imported final cover was not live", before)
			}
			peer.observe(t, "drop-cover")
		}
		if _, err := process.gate.Write([]byte{2}); err != nil {
			t.Fatal(err)
		}
		result = process.readImported(t, scenario)
		if !result.Retired || result.Stage != "retired" {
			t.Fatal("imported original source did not join retirement", result)
		}
		after := peer.observe(t, "stats")
		if after.DirectQueries != 0 {
			t.Fatal("imported proof used direct-router control", after)
		}
		if (action == "restore" || action == "temporary") && (result.FreshSession == "" || result.FreshSession == result.Session || result.MTU != 1300 || after.DNSQueries <= before.DNSQueries || after.MTUReplies == 0) {
			t.Fatal("imported restoration omitted live MTU or fresh source/proofs", result, before, after)
		}
		if action == "mtu-cancel" && (result.MTU != 1280 || after.MTUReplies == 0) {
			t.Fatal("imported MTU cancellation omitted authenticated native rollback", result, after)
		}
	}
	select {
	case <-process.done:
		if process.waitErr != nil {
			t.Fatal("installed imported controller failed", process.waitErr, process.diagnostic.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("installed imported controller did not join")
	}
	t.Log("verified installed host native lifecycle:", scenario)
	t.Log("verified installed host imported independent WG entry and paired SS final:", scenario)
}

func linuxHostTUNImportedFixture(controller *ownedDesktopController, scenario string) (failure error) {
	raw, err := readPrivateRegular(filepath.Join(linuxOwnedControllerRoot, "routers.json"), 64<<10)
	var profiles common.RouterProfileStore
	if err != nil || decodeRelayControlJSON(raw, &profiles) != nil || len(profiles.Profiles) != 2 || profiles.SelectedID != "installed-imported-final" {
		return errors.Join(err, errors.New("imported installed fixture lost its saved independent profiles"))
	}
	a := &app{localController: controller, profiles: profiles, state: state{Mode: "off", Phase: "off", DAITA: profiles.Profiles[1].DAITAEnabled}, cfg: common.ClientConfig{AutoTestSeconds: 10,
		ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	parent, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(parent.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "imported-host-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 1); err != nil {
		return err
	}
	if err := os.Setenv("SSL_CERT_FILE", filepath.Join(linuxOwnedControllerRoot, "imported-peer-ca.pem")); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	// The original MTU hold keeps automatic work out of these explicit,
	// authenticated low-level lease cases; ordinary Stop nests this same hold.
	releaseMTU, err := a.holdCapturedMTU(ctx)
	if err != nil {
		return err
	}
	defer releaseMTU()
	var constructed *desktopNodeLaunch
	driver := nativeMultihopConnectRuntime{capture: func(a *app, s multihopSelection, m []string) (multihopSelection, error) {
		return captureDesktopLinuxImportedForApp(a.connectionOperationContextOrBackground(), a, s, m)
	},
		preflight: func(a *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			var err error
			constructed, err = preflightOwnedNativeMultihopCommand(a, selection, descriptor)
			return constructed, err
		}, stage: stageOwnedNativeMultihopCommand, proof: (*app).proveNativeMultihop}
	connect := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		a.nativeMultihopConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", strings.NewReader(`{"entry_id":"installed-imported-entry","exit_id":"installed-imported-final","entry_mode":"wireguard","exit_mode":"shadowsocks","execution":"local"}`)).WithContext(ctx), driver)
		return response
	}
	response := connect()
	action := strings.TrimPrefix(scenario, "imported-wg-ss-")
	negative := action == "wrong-public" || action == "wrong-node" || action == "dns-failure"
	result := linuxImportedHostResult{Scenario: scenario}
	session, err := captureDesktopLinuxNodeSession(ctx, a)
	if err != nil {
		return err
	}
	defer func() {
		if failure != nil {
			cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			if session.active != nil {
				failure = errors.Join(failure, session.Retire(cleanup, session.active, false))
			}
		}
	}()
	if negative {
		if response.Code == http.StatusOK || a.state.Connected || a.cmd != nil {
			return fmt.Errorf("negative imported public path admitted or retained command: %d %s", response.Code, response.Body.String())
		}
		if constructed == nil {
			return errors.New("imported negative control failed before original native construction")
		}
		owner, ok := constructed.importedPlatform.(*desktopLinuxImportedConnection)
		if !ok || owner == nil || owner.host == nil || owner.host.process == nil || owner.host.process.command.ProcessState == nil ||
			!owner.host.closed || !owner.host.released || owner.host.imported != nil || len(owner.host.source) != 0 {
			return errors.New("imported negative control did not join and retire its actual original process/source")
		}
		select {
		case <-owner.host.process.joined:
		default:
			return errors.New("imported negative control returned before original Wait joined")
		}
		result.Session = owner.host.selection.SessionID
		result.Rejected = true
	} else {
		if response.Code != http.StatusOK {
			return fmt.Errorf("installed imported public Connect failed: %d %s", response.Code, response.Body.String())
		}
		h := session.active
		if h == nil || h.imported == nil || h.activation == nil || h.ready == nil || h.monitor == nil || h.monitor.Load() == nil || h.Current(ctx) != nil || !a.state.Connected {
			return errors.New("installed imported public Connect lost original activation and monitor")
		}
		if _, duplicate := desktopNodeOwners.Load(a); duplicate {
			return errors.New("installed imported path created another process owner")
		}
		graph, found := getActiveMultihopGraph(a)
		runtime, err := capturedNativeMultihopRuntimeContext(ctx, a, a.cmd, graph)
		if err != nil || !found || runtime.launch != h.launch {
			return errors.Join(err, errors.New("installed imported graph lost its original Linux session"))
		}
		tracker := sessionTrackerFor(a)
		tracker.observe(tracker.capture())
		identity, path, err := captureSpeedLabIdentityContext(ctx, a)
		if err != nil || identity.Imported != runtime || identity.Linux != nil || path.Topology != "multihop" {
			return errors.Join(err, errors.New("imported current Speed Lab did not retain its actual multihop owner"))
		}
		if err := validateSpeedLabIdentityContext(ctx, a, identity); err != nil {
			return err
		}
		result.Stage, result.Session, result.Ready, result.Monitor = "ready", h.selection.SessionID, h.ready, true
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if err := linuxHostTUNRendezvous(gate, 2); err != nil {
			return err
		}
		if action == "cover-lost" {
			deadline := time.NewTimer(12 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(25 * time.Millisecond)
			defer ticker.Stop()
			for {
				a.mu.Lock()
				connected := a.state.Connected
				a.mu.Unlock()
				if !connected {
					break
				}
				select {
				case <-deadline.C:
					return errors.New("lost imported final cover remained Connected")
				case <-ticker.C:
				}
			}
		} else if action == "restore" || action == "temporary" || action == "mtu-cancel" {
			result.MTU, err = linuxImportedHostMTU(ctx, a, runtime, action != "mtu-cancel")
			if err != nil {
				return err
			}
			if action == "restore" || action == "temporary" {
				fresh, err := linuxImportedHostSpeedLab(ctx, a, session, h, runtime, action == "temporary")
				if err != nil {
					return err
				}
				result.FreshSession = fresh.selection.SessionID
			}
		}
	}
	stop := httptest.NewRecorder()
	a.disconnect(stop, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil).WithContext(ctx))
	if stop.Code != http.StatusOK || a.cmd != nil || a.state.Connected || session.active != nil {
		return fmt.Errorf("imported public Disconnect did not join: %d %s", stop.Code, stop.Body.String())
	}
	if session.journal == nil {
		return errors.New("imported retirement omitted its original journal")
	}
	head, err := session.journal.Snapshot(ctx)
	if err != nil || head.Incomplete || head.Record.Phase != "settled" || head.Record.Committed.Engine != nil || head.Record.Committed.Target != nil {
		return errors.Join(err, errors.New("imported retirement did not settle original protection"))
	}
	if _, found := nativeMultihopOwners.Load(a); found {
		return errors.New("imported retirement retained graph authority after source join")
	}
	if err := linuxHostTUNTUNAbsent(result.Ready); err != nil {
		return err
	}
	result.Stage, result.Retired = "retired", true
	controller.close()
	return json.NewEncoder(os.Stdout).Encode(result)
}

func linuxImportedHostSpeedLab(ctx context.Context, a *app, session *desktopLinuxNodeSession, previous *desktopLinuxNodeHost, runtime *nativeMultihopRuntime, temporary bool) (*desktopLinuxNodeHost, error) {
	requireEncrypted := true
	q := speedLabRequest{Scope: "temporary", Topology: "multihop", EntryID: runtime.selection.Entry.ID, ExitID: runtime.selection.Exit.ID,
		EntryMode: "wireguard", ExitMode: "shadowsocks", Execution: "local", RequireEncrypted: &requireEncrypted}
	operation, snapshot, finish, err := a.beginSpeedLabTemporaryOperationExpectedContext(ctx, &q)
	if err != nil {
		return nil, err
	}
	defer finish()
	saved := snapshot.Plan.multihop
	if saved == nil || saved.Native != runtime.selection.Native || saved.restoreMTU != 1300 || snapshot.Plan.request.Execution != "local" ||
		snapshot.Plan.linux != nil || snapshot.Plan.native != nil {
		return nil, errors.New("imported Speed Lab replaced its independent source or live MTU with another restore owner")
	}
	if temporary {
		q.preparedMultihop, err = a.prepareSpeedLabImportedMultihopWithRuntime(operation, q, speedLabMultihopPreparationRuntime{
			capture: captureDesktopLinuxImportedForApp,
		})
		if err != nil {
			return nil, err
		}
		defer q.preparedMultihop.releaseUnused()
		if err := a.guardDesktopOwnedNodeTemporary(q, snapshot); err != nil {
			return nil, err
		}
	}
	// A successful restoration must use the already captured sealed source.
	// No newly compiled generated profile can pass after this replacement.
	if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "generated", saved.Exit.ID, "shadowsocks", "sing-box.json"), []byte("changed after exact restore capture\n"), 0600); err != nil {
		return nil, err
	}
	oldJournal, sealed := session.journal, append([]byte(nil), previous.source...)
	defer clear(sealed)
	if err := a.speedLabSuspendPrevious(snapshot, false); err != nil {
		return nil, err
	}
	if previous.imported != nil || len(previous.source) != 0 || previous.activation == nil || previous.activation.lifetime.Err() == nil {
		return nil, errors.New("imported suspension did not join and clear the original child")
	}
	if temporary {
		if _, err := a.startSpeedLabMultihopPath(q); err != nil {
			return nil, err
		}
		if err := session.enter(ctx); err != nil {
			return nil, err
		}
		tested := session.active
		session.gate <- struct{}{}
		if tested == nil || tested == previous || tested.launch != q.preparedMultihop.launch {
			return nil, errors.New("temporary imported path did not consume its original prepared launch")
		}
		if err := linuxHostTUNRestoreCheck(ctx, session, tested, func() error {
			if tested.activation == nil || tested.monitor == nil || tested.monitor.Load() == nil || tested.observeLocked(ctx) != nil {
				return errors.New("temporary Local proof failed to activate and monitor its original Linux host")
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if !a.profiles.Profiles[1].AutoRequireEncrypted || !a.state.Connected || q.preparedMultihop.owner.runtime != a.cmd {
				return errors.New("temporary imported projection was not exact and independently owned")
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	snapshot.Owner.cancelTest()
	if err := a.speedLabRestoreTemporary(snapshot); err != nil {
		return nil, err
	}
	if err := session.enter(ctx); err != nil {
		return nil, err
	}
	fresh := session.active
	session.gate <- struct{}{}
	if fresh == nil || fresh == previous {
		return nil, errors.New("imported restoration did not create a fresh original host")
	}
	if err := linuxHostTUNRestoreCheck(ctx, session, fresh, func() error {
		if fresh.imported == nil || fresh.ready == nil || fresh.ready.MTU != 1300 || fresh.imported.Metadata().RestoredMTU != 1300 ||
			fresh.activation == nil || fresh.process == previous.process || fresh.activation == previous.activation ||
			fresh.selection.SessionID == previous.selection.SessionID || session.journal != oldJournal || !bytes.Equal(fresh.source, sealed) ||
			fresh.monitor == nil || fresh.monitor.Load() == nil || fresh.observeLocked(ctx) != nil {
			return errors.New("imported restoration borrowed old authority or lost exact source, live MTU, proof or monitor")
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if !reflect.DeepEqual(a.profiles, snapshot.Profiles) || !a.state.Connected || a.cmd != fresh.launch.command {
			return errors.New("imported restoration replaced the independently saved profiles")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	finish()
	return fresh, fresh.Current(ctx)
}

func linuxImportedHostMTU(ctx context.Context, a *app, runtime *nativeMultihopRuntime, commit bool) (int, error) {
	_, policy, err := readDesktopImportedMTUPolicyContext(ctx, runtime.selection)
	if err != nil {
		return 0, err
	}
	owner, err := newDesktopImportedMTUOwner(ctx, a, runtime, policy)
	if err != nil {
		return 0, err
	}
	work, finish, err := mobilemtu.WithOperationContext(ctx, 10*time.Second, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer finish()
	initial, err := owner.CaptureContext(work)
	if err != nil {
		return 0, err
	}
	if err := owner.prepare(work, strings.Repeat("c", 32)); err != nil {
		return 0, err
	}
	changed, err := owner.ChangeMTU(work, initial, 1300)
	if err != nil {
		return 0, err
	}
	connection, err := owner.DialThroughTunnel(work, changed, "udp4", "10.77.0.1:45999")
	if err != nil {
		return 0, err
	}
	request, err := mtuprobe.Request(1252, policy.Token, policy.Proof, time.Now())
	if err != nil {
		connection.Close()
		return 0, err
	}
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = connection.Write(request)
	reply := make([]byte, 2048)
	count, readErr := connection.Read(reply)
	connection.Close()
	if err != nil || readErr != nil || mtuprobe.ValidateReply(request, reply[:count], policy.Token, policy.Proof, time.Now()) != nil {
		return 0, errors.Join(err, readErr, errors.New("imported MTU probe did not traverse authenticated final"))
	}
	if commit {
		if err := owner.finish(work, true); err != nil {
			return 0, err
		}
	}
	cleanup, err := mobilemtu.OperationCleanupContext(work)
	if err != nil {
		return 0, err
	}
	owner.mu.Lock()
	err = owner.closeLocked(cleanup)
	owner.mu.Unlock()
	if err != nil {
		return 0, err
	}
	live, err := owner.CaptureContext(cleanup)
	if err != nil {
		return 0, err
	}
	if commit && live.MTU != 1300 || !commit && live.MTU != initial.MTU {
		return 0, errors.New("imported MTU native final readback did not match original transaction")
	}
	return live.MTU, nil
}
