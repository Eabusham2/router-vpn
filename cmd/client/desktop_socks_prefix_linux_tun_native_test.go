//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
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
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type linuxSOCKSPrefixExecutionCase struct {
	Prefixes                 int
	Modes                    []string
	Requested, Winner, Fault string
}

var linuxSOCKSPrefixExecutionCases = []string{
	"socks-p2-server",
	"socks-p2-auto-local",
	"socks-p2-auto-server",
	"socks-p3-server",
	"socks-p3-auto-local",
	"socks-p3-auto-server",
	"socks-p4-server",
	"socks-p4-auto-local",
	"socks-p4-auto-server",
	"socks-p5-server",
	"socks-p5-auto-local",
	"socks-p5-auto-server",
	"socks-p6-server",
	"socks-p6-auto-local",
	"socks-p6-auto-server",
	"socks-p6-wrong-first-key",
	"socks-p6-wrong-later-key",
	"socks-p6-wrong-auth",
	"socks-p6-auth-downgrade",
	"socks-p6-relay-domain",
	"socks-p6-relay-route",
	"socks-p6-control-eof",
	"socks-p6-wrong-public",
	"socks-p6-wrong-final-key",
	"socks-p6-failed-dns",
	"socks-p6-replaced-source",
	"socks-p6-carrier-change",
	"socks-p6-held-cleanup",
}
var linuxSOCKSPrefixExecutionScenarios = func() map[string]linuxSOCKSPrefixExecutionCase {
	out := map[string]linuxSOCKSPrefixExecutionCase{}
	modes := []string{"wg", "awg2-fast", "awg2-strong"}
	for n := 2; n <= 6; n++ {
		for arm, choice := range []string{"server", "auto-local", "auto-server"} {
			item := linuxSOCKSPrefixExecutionCase{Prefixes: n, Requested: "server", Winner: "server"}
			if arm > 0 {
				item.Requested = "auto"
			}
			if arm == 1 {
				item.Winner = "local"
			}
			for i := 0; i < n; i++ {
				item.Modes = append(item.Modes, modes[(i+n+arm-1)%3])
			}
			out[fmt.Sprintf("socks-p%d-%s", n, choice)] = item
		}
	}
	for _, fault := range []string{"wrong-first-key", "wrong-later-key", "wrong-auth", "auth-downgrade", "relay-domain", "relay-route", "control-eof", "wrong-public", "wrong-final-key", "failed-dns", "replaced-source", "carrier-change", "held-cleanup"} {
		out["socks-p6-"+fault] = linuxSOCKSPrefixExecutionCase{Prefixes: 6, Modes: []string{"wg", "awg2-fast", "awg2-strong", "wg", "awg2-fast", "awg2-strong"}, Requested: "server", Winner: "server", Fault: fault}
	}
	return out
}()

type linuxSOCKSPrefixExecutionObservation = linuxSOCKSExecutionObservation

// Reuse the original typed SOCKS observation without copying or weakening its
// live controller/physical/source/proof/DNS/process/journal ownership checks.
func linuxSOCKSPrefixExecutionObserve(ctx context.Context, a *app) (linuxSOCKSPrefixExecutionObservation, error) {
	return linuxSOCKSExecutionObserve(ctx, a)
}

func linuxSOCKSPrefixExecutionController(owned *ownedDesktopController, scenario string) error {
	item, found := linuxSOCKSPrefixExecutionScenarios[scenario]
	if !found {
		return errors.New("uncaptured installed imported execution case")
	}
	requested, fault := item.Requested, item.Fault
	var err error
	var raw []byte
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress, ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || len(a.profiles.Profiles) != item.Prefixes+2 {
		return errors.New("original complete imported catalog absent")
	}
	raw, err = readPrivateRegular(a.cfg.ModesFile, 256<<10)
	if err != nil || json.Unmarshal(raw, &a.modes) != nil || len(a.modes) != 22 {
		return errors.New("original mode catalog absent")
	}
	captured, err := captureDesktopLinuxNodeParent(a)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(captured.record); err != nil {
		return err
	}
	gate := os.NewFile(3, "socks-prefix-execution-rendezvous")
	defer gate.Close()
	if err := linuxprocess.SetCloseOnExec(gate); err != nil {
		return err
	}
	if err := linuxHostTUNRendezvous(gate, 1); err != nil {
		return err
	}
	if err := os.Setenv("SSL_CERT_FILE", filepath.Join(linuxOwnedControllerRoot, "node-chain-peer-ca.pem")); err != nil {
		return err
	}
	release, err := a.holdCapturedMTU(context.Background())
	if err != nil {
		return err
	}
	defer release()
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	var public, restored atomic.Bool
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if captured.Current(r.Context()) != nil {
			http.Error(w, "original controller lost", 409)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(a.state)
	})
	mux.HandleFunc("/api/native-socks-prefix-execution-source", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		profiles := cloneRouterProfileStore(a.profiles)
		a.mu.Unlock()
		if !found {
			http.Error(w, "original control absent", 409)
			return
		}
		selection, err := resolveDesktopNodeChainSelection(control, profiles.Profiles, control.MultihopNodes, "local")
		if err == nil {
			selection, err = captureNativeMultihopSelection(r.Context(), linuxOwnedControllerRoot, selection, []string{"socks5"}, nil)
		}
		if err != nil || selection.Native == nil || selection.Native.chain == nil {
			http.Error(w, fmt.Sprint(err), 409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"local_source": selection.Native.chain.input})
	})
	mux.HandleFunc("/api/native-ordered-request", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		tokens, err := a.connectionProfileTokensLocked(control)
		if !found || err != nil {
			http.Error(w, "source changed", 409)
			return
		}
		selected := a.profiles.SelectedID
		_ = json.NewEncoder(w).Encode(multihopConnectRequest{Nodes: append([]common.MultihopNodeSelection(nil), control.MultihopNodes...), Execution: requested, desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: tokens}})
	})
	mux.HandleFunc("/api/multihop/connect", func(w http.ResponseWriter, r *http.Request) {
		public.Store(true)
		a.nativeMultihopConnect(w, r)
	})
	mux.HandleFunc("/api/multihop/status", a.nativeMultihopStatus)
	mux.HandleFunc("/api/disconnect", a.disconnect)
	mux.HandleFunc("/api/native-socks-prefix-execution-observation", func(w http.ResponseWriter, r *http.Request) {
		value, err := linuxSOCKSPrefixExecutionObserve(r.Context(), a)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		value.PublicConnect = public.Load()
		value.Restored = restored.Load()
		_ = json.NewEncoder(w).Encode(value)
	})
	// The trigger is test-only. Capture, retained Stop, successor launch and
	// restoration use the real Speed Lab coordinator and its original intent.
	mux.HandleFunc("/api/native-socks-prefix-execution-restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "" {
			http.Error(w, "uncaptured restore", 409)
			return
		}
		_, snapshot, finish, err := a.beginSpeedLabTemporaryOperationExpectedContext(r.Context(), nil)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		defer finish()
		if err = a.speedLabSuspendPrevious(snapshot, false); err == nil {
			err = a.speedLabRestoreTemporary(snapshot)
		}
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		restored.Store(true)
		_ = json.NewEncoder(w).Encode(map[string]bool{"restored": true})
	})
	mux.HandleFunc("/api/native-socks-prefix-execution-cleanup-retry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "held-cleanup" {
			http.Error(w, "uncaptured cleanup retry", 409)
			return
		}
		owner, err := a.desktopOrderedExecutionOwner()
		if err != nil || owner == nil || owner.session.Current(r.Context()) != nil {
			http.Error(w, "original live owner absent", 409)
			return
		}
		original := owner.session.launch.chain.platform.host
		if original == nil || original.launch.chain.execution != owner.session.execution || original.transaction == nil || original.transaction.execution != owner.session.execution || original.enter(r.Context()) != nil {
			http.Error(w, "original native gate absent", 409)
			return
		}
		released := false
		releaseGate := func() {
			if !released {
				original.gate <- struct{}{}
				released = true
			}
		}
		defer releaseGate()
		// Hold the actual original host gate, not a replacement cleanup method.
		// The bounded public request must refuse without forgetting this live child.
		call, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		request := httptest.NewRequest(http.MethodPost, "/api/disconnect", strings.NewReader("{}")).WithContext(call)
		result := httptest.NewRecorder()
		a.disconnect(result, request)
		cancel()
		releaseGate()
		if result.Code == http.StatusOK || !strings.Contains(result.Body.String(), context.DeadlineExceeded.Error()) {
			http.Error(w, "held original native cleanup was not bounded", 500)
			return
		}
		retained, err := a.desktopOrderedExecutionOwner()
		if err != nil || retained != owner || retained.session.launch.chain.platform.host != original || retained.session.Current(r.Context()) != nil {
			http.Error(w, "failed cleanup replaced original native owner", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"refused": true, "same_owner": true, "joined": false})
	})
	mux.HandleFunc("/api/native-socks-prefix-execution-replace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "replaced-source" {
			http.Error(w, "uncaptured replacement", 409)
			return
		}
		a.mu.Lock()
		external := a.profiles.Profiles[item.Prefixes].External
		external.SOCKS5.Password += "changed"
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"changed": true})
	})
	return serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type linuxSOCKSPrefixExecutionPeer struct {
	peer                                           *linuxNodeChainPeer
	item                                           linuxSOCKSPrefixExecutionCase
	serverPrivateKeys                              []string
	started, joined, quitAttempted, namespaceOwned bool
	retirementRead, outputClosed                   bool
	retirementError                                error
}

func (p *linuxSOCKSPrefixExecutionPeer) exchange(t *testing.T, value any) map[string]json.RawMessage {
	t.Helper()
	if err := p.peer.output.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer p.peer.output.SetReadDeadline(time.Time{})
	if json.NewEncoder(p.peer.input).Encode(value) != nil {
		t.Fatal("original peer input closed")
	}
	line, err := p.peer.reader.ReadBytes('\n')
	if err != nil || len(line) > 32768 {
		t.Fatal("original peer output missing", err)
	}
	var reply map[string]json.RawMessage
	if json.Unmarshal(line, &reply) != nil {
		t.Fatal("original peer output changed")
	}
	return reply
}
func (p *linuxSOCKSPrefixExecutionPeer) close(ctx context.Context) error {
	if p == nil || p.joined {
		return nil
	}
	if !p.started {
		return p.closeNamespace(ctx)
	}
	if !p.quitAttempted {
		p.quitAttempted = true
		// A partial startup may already have closed its input. Still wait for
		// this exact process; retry must never send a second shutdown command.
		_ = json.NewEncoder(p.peer.input).Encode(map[string]string{"command": "quit"})
		_ = p.peer.input.Close()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.peer.done:
	}
	if p.peer.waitErr != nil {
		return p.peer.waitErr
	}
	if !p.retirementRead {
		raw, err := io.ReadAll(io.LimitReader(p.peer.reader, 4097))
		p.retirementRead = true
		lines := strings.Split(string(raw), "\n")
		var receipt struct {
			Joined   bool   `json:"joined"`
			Launches uint64 `json:"launches"`
		}
		// One JSON receipt and one terminal Go PASS; diagnostics cannot borrow
		// an earlier joined flag or a later successful terminal.
		if err != nil || len(raw) > 4096 || len(lines) != 3 || lines[1] != "PASS" || lines[2] != "" {
			p.retirementError = errors.Join(errors.New("original SOCKS worker retirement transcript changed"), err)
		} else if decodeRelayControlJSON([]byte(lines[0]), &receipt) != nil || !receipt.Joined || receipt.Launches == 0 {
			p.retirementError = errors.New("original SOCKS worker retirement receipt changed")
		}
	}
	if p.retirementError != nil {
		return p.retirementError
	}
	if !p.outputClosed {
		if err := p.peer.output.Close(); err != nil {
			return err
		}
		p.outputClosed = true
	}
	if err := p.closeNamespace(ctx); err != nil {
		return err
	}
	p.joined = true
	return nil
}
func (p *linuxSOCKSPrefixExecutionPeer) closeNamespace(ctx context.Context) error {
	if !p.namespaceOwned {
		return nil
	}
	if err := exec.CommandContext(ctx, "ip", "netns", "delete", "rvpn-cp-worker").Run(); err != nil {
		return err
	}
	p.namespaceOwned = false
	return nil
}

func linuxSOCKSPrefixExecutionStartController(t *testing.T, installed, scenario string, retained **linuxHostTUNController) *linuxHostTUNController {
	// A complete SOCKS proof/Compare/Restore retains its existing finite
	// installed SOCKS controller/process budget.
	return linuxSOCKSExecutionStartController(t, installed, scenario, retained)
}

func linuxSOCKSPrefixExecutionNamespace(t *testing.T, p *linuxSOCKSPrefixExecutionPeer) {
	t.Helper()
	linuxHostTUNNamespace(t)
	linuxHostTUNCommand(t, "ip", "netns", "add", "rvpn-cp-worker")
	p.namespaceOwned = true
	commands := [][]string{
		{"link", "add", "rvpn-cp-net", "type", "veth", "peer", "name", "rvpn-cp-peer"},
		{"link", "set", "rvpn-cp-net", "mtu", "9000"}, {"link", "set", "rvpn-cp-peer", "mtu", "9000"},
		{"link", "set", "rvpn-cp-net", "netns", "rvpn-cp-worker"}, {"link", "set", "rvpn-cp-peer", "netns", "rvpn-peer"},
		{"netns", "exec", "rvpn-cp-worker", "ip", "link", "set", "lo", "up"},
		{"netns", "exec", "rvpn-cp-worker", "ip", "addr", "add", "192.168.211.1/30", "dev", "rvpn-cp-net"},
		{"netns", "exec", "rvpn-cp-worker", "ip", "link", "set", "rvpn-cp-net", "up"},
		{"netns", "exec", "rvpn-peer", "ip", "addr", "add", "192.168.211.2/30", "dev", "rvpn-cp-peer"},
		{"netns", "exec", "rvpn-peer", "ip", "link", "set", "rvpn-cp-peer", "up"},
	}
	for _, command := range commands {
		linuxHostTUNCommand(t, append([]string{"ip"}, command...)...)
	}
	api, client := "10.80.0.1", "10.80.0.2"
	if p.item.Prefixes == 1 {
		api, client = "10.78.0.1", "10.78.0.2"
	}
	for _, command := range [][]string{
		{"netns", "exec", "rvpn-cp-worker", "ip", "addr", "add", api + "/32", "dev", "lo"},
		{"netns", "exec", "rvpn-peer", "ip", "addr", "add", client + "/32", "dev", "lo"},
		{"netns", "exec", "rvpn-cp-worker", "ip", "route", "add", client + "/32", "via", "192.168.211.2", "dev", "rvpn-cp-net"},
		{"netns", "exec", "rvpn-peer", "ip", "route", "add", api + "/32", "via", "192.168.211.1", "dev", "rvpn-cp-peer"},
	} {
		linuxHostTUNCommand(t, append([]string{"ip"}, command...)...)
	}
	destination := "198.51.100.102"
	if p.item.Prefixes == 1 {
		destination = "10.79.0.1"
	}
	linuxHostTUNCommand(t, "ip", "netns", "exec", "rvpn-peer", "ip", "addr", "add", destination+"/32", "dev", "rvpn-cp-peer")
	linuxHostTUNCommand(t, "ip", "netns", "exec", "rvpn-cp-worker", "ip", "route", "add", destination+"/32", "via", "192.168.211.2", "dev", "rvpn-cp-net")
}
func linuxSOCKSPrefixExecutionReadback(t *testing.T, p *linuxSOCKSPrefixExecutionPeer, value linuxSOCKSExecutionReply) {
	t.Helper()
	peer := p.peer
	if !peer.middleSOCKS || peer.middleCONNECT != "" || value.SOCKSAssociations < 0 || value.SOCKSJoinFailed || value.CONNECTProtocol != "" || value.CONNECTCA != "" || value.CONNECTServerName != "" || value.OpenCONNECTStreams != nil || value.FinalUOTVersion != 0 {
		t.Fatal("original SOCKS prefix acquired foreign transport or lost association ownership")
	}
	for _, raw := range value.SOCKSRelays {
		relay, err := netip.ParseAddrPort(raw)
		if err != nil || relay.Addr() != netip.MustParseAddr("10.79.0.1") || relay.Port() == 0 || relay.Port() == 1080 {
			t.Fatal("SOCKS prefix replaced original negotiated relay tuple")
		}
	}
	address, err := netip.ParseAddrPort(value.Address)
	if err != nil || address.Addr() != netip.MustParseAddr("192.168.210.2") || address.Port() == 0 || value.Schema != 1 || len(value.Prefixes) != p.item.Prefixes || value.PublicCA == "" || value.Middle == nil || value.Middle.Method != "socks5" || value.Final.FinalPublicIP != "203.0.113.89" {
		t.Fatal("original native imported peer receipt changed")
	}
	if peer.reply.Address != "" && (value.Address != peer.reply.Address || value.PublicCA != peer.reply.PublicCA) {
		t.Fatal("original native imported transport or TLS identity replaced")
	}
	for i, prefix := range value.Prefixes {
		expected := ""
		request := peer.requests[i]
		if request.Mode != "wg" {
			parameters, err := awgpolicy.ParametersUAPI(request.Parameters)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(parameters))
			expected = hex.EncodeToString(sum[:])
		}
		if prefix.Mode != request.Mode || prefix.ParametersSHA256 != expected {
			t.Fatal("original packet mode or parameters changed")
		}
	}
}
func startLinuxSOCKSPrefixExecutionPeer(t *testing.T, p *linuxSOCKSPrefixExecutionPeer) {
	t.Helper()
	p.peer = linuxNodeChainPeerForModes(t, []string{"wg", "socks5"})
	peer := p.peer
	for len(peer.requests) < p.item.Prefixes {
		extra := linuxNodeChainPeerKeys(t, 3)
		peer.requests = append(peer.requests, extra.requests[0])
		peer.clients = append(peer.clients, extra.clients[0])
	}
	for i := range peer.requests {
		peer.requests[i].APIToken = fmt.Sprintf("installed-socks-prefix-%d-%s", i, peer.requests[i].NodeProofID)
	}
	linuxNodeChainSetModes(t, peer, p.item.Modes)
	peer.middleMethod = "2022-blake3-aes-256-gcm"
	size := 32
	if peer.middleMethod == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	peer.middlePassword = base64.StdEncoding.EncodeToString(secret)
	clear(secret)
	p.serverPrivateKeys = make([]string, p.item.Prefixes+2)
	for i := range p.serverPrivateKeys {
		if i == 0 || i == p.item.Prefixes {
			continue
		}
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.serverPrivateKeys[i] = base64.StdEncoding.EncodeToString(key.Bytes())
	}
	linuxSOCKSPrefixExecutionNamespace(t, p)
	directory, err := os.MkdirTemp("/opt", "routervpn-socks-prefix-execution-peer-")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(directory, "peer.test")
	linuxHostTUNCopy(t, os.Getenv("ROUTERVPN_NODE_HOST_PEER_BINARY"), image, 512<<20, os.Getenv("ROUTERVPN_NODE_HOST_PEER_SHA256"), 0755)
	worker := filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName())
	raw, err := os.ReadFile(worker)
	if err != nil {
		t.Fatal("original native worker missing")
	}
	workerHash := sha256.Sum256(raw)
	parentNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parentMount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	peer.command = exec.Command("ip", "netns", "exec", "rvpn-cp-worker", image, "-test.run=^TestRouterVPNDesktopNativeSOCKSPrefixExecutionProcess$", "-test.count=1", "-test.timeout=240s")
	peer.command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_NATIVE_IMPORTED_ROLE=worker", "ROUTERVPN_LINUX_GUARDIAN_TEST_NS=1", "ROUTERVPN_NATIVE_IMPORTED_PARENT_NETNS=" + parentNamespace, "ROUTERVPN_NATIVE_SOCKS_PARENT_MOUNT_NS=" + parentMount}
	peer.command.Stderr = os.Stderr
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		inputRead.Close()
		inputWrite.Close()
		t.Fatal(err)
	}
	peer.input, peer.output = inputWrite, outputRead
	peer.reader = bufio.NewReaderSize(outputRead, 32768)
	peer.command.Stdin, peer.command.Stdout = inputRead, outputWrite
	if err = peer.command.Start(); err != nil {
		inputRead.Close()
		inputWrite.Close()
		outputRead.Close()
		outputWrite.Close()
		t.Fatal(err)
	}
	p.started = true
	inputRead.Close()
	outputWrite.Close()
	go func() { peer.waitErr = peer.command.Wait(); close(peer.done) }()
	paired := map[string]any{"schema": 1, "address": "192.168.210.2", "client_address": "192.168.210.1", "prefixes": peer.requests, "final_password": peer.password, "final_node_proof_id": linuxNodeChainProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token", "benchmark_port": 45998}
	wire := map[string]any{"schema": 1, "peer": map[string]any{"schema": 2, "paired": paired, "middle_method": peer.middleMethod, "middle_password": peer.middlePassword}, "server_private_keys": p.serverPrivateKeys, "image": worker, "image_sha256": hex.EncodeToString(workerHash[:]), "fault": p.item.Fault, "username": "captured-native-user", "password": peer.middlePassword}
	reply := p.exchange(t, wire)
	var observed linuxSOCKSExecutionReply
	var endpoint string
	if decodeRelayControlJSON(reply["peer"], &observed) != nil || json.Unmarshal(reply["middle_address"], &endpoint) != nil || endpoint != "10.79.0.1:1080" {
		t.Fatal("original global imported peer endpoint missing")
	}
	linuxSOCKSPrefixExecutionReadback(t, p, observed)
	peer.reply = observed.linuxNodeChainPeerReply
}
func TestDesktopLinuxGuardianKernelSOCKSPrefixExecution(t *testing.T) {
	linuxHostTUNNamespace(t)
	if os.Getenv("HOMEVPN_MTU_BENCH_FAKE") != "" {
		t.Fatal("native execution forbids modeled MTU")
	}
	for _, scenario := range linuxSOCKSPrefixExecutionCases {
		t.Run(scenario, func(t *testing.T) { linuxSOCKSPrefixExecutionNativeCase(t, scenario) })
	}
}
func linuxSOCKSPrefixExecutionNativeCase(t *testing.T, scenario string) {
	item, found := linuxSOCKSPrefixExecutionScenarios[scenario]
	if !found {
		t.Fatal("uncaptured installed imported execution case")
	}
	requested, winner, fault := item.Requested, item.Winner, item.Fault
	var err error
	installed := linuxControllerNamespaceInstall(t)
	linuxHostTUNInstallBundle(t)
	peer := &linuxSOCKSPrefixExecutionPeer{item: item}
	controllerJoined := true
	var process *linuxHostTUNController
	t.Cleanup(func() {
		if !controllerJoined {
			if process == nil || process.command.Process == nil {
				controllerJoined = true
			} else {
				select {
				case <-process.done:
					if process.waitErr != nil {
						t.Error("failed original controller retirement", process.waitErr)
						return
					}
					controllerJoined = true
				default:
					t.Error("original Linux controller not joined before peer retirement")
					return
				}
			}
		}
		ctx, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if err := peer.close(ctx); err != nil {
			t.Error(err)
		}
	})
	startLinuxSOCKSPrefixExecutionPeer(t, peer)
	installLinuxNodeChainProfiles(t, peer.peer, "")
	raw, err := os.ReadFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"))
	var store common.RouterProfileStore
	if err != nil || json.Unmarshal(raw, &store) != nil || len(store.Profiles) != item.Prefixes+2 {
		t.Fatal("original complete imported catalog absent", err)
	}
	middle := &store.Profiles[item.Prefixes]
	proxy := middle.External.SOCKS5
	if proxy == nil || proxy.Host != "10.79.0.1" {
		t.Fatal("original SOCKS source missing")
	}
	proxy.Port = 1080
	store.Profiles[len(store.Profiles)-1].MultihopExecution = requested
	raw, _ = json.Marshal(store)
	if err = os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	repositorySource := os.Getenv("ROUTERVPN_SOCKS_PREFIX_EXECUTION_SOURCE")
	raw, err = os.ReadFile(filepath.Join(repositorySource, "configs/client/modes.json"))
	if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "modes.json"), raw, 0600) != nil {
		t.Fatal("original mode catalog missing", err)
	}
	controllerJoined = false
	linuxSOCKSPrefixExecutionStartController(t, installed, scenario, &process)
	if _, err := process.gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 150 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Second)
	defer cancel()
	t.Cleanup(func() {
		if controllerJoined {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_, _, _ = linuxSOCKSExecutionHTTP(cleanup, client, http.MethodPost, "/api/disconnect", "{}")
		_ = process.input.Close()
		select {
		case <-process.done:
			if process.waitErr != nil {
				t.Error(process.waitErr)
				return
			}
			controllerJoined = true
		case <-cleanup.Done():
			t.Error(cleanup.Err())
		}
	})
	deadline := time.Now().Add(8 * time.Second)
	for {
		call, stop := context.WithTimeout(ctx, time.Second)
		status, _, err := linuxSOCKSExecutionHTTP(call, client, http.MethodGet, "/api/status", "")
		stop()
		if err == nil && status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original Linux controller did not start", err, process.diagnostic.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	status, raw, err := linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-socks-prefix-execution-source", "")
	var source map[string]string
	if err != nil || status != 200 || json.Unmarshal(raw, &source) != nil || source["local_source"] == "" {
		t.Fatal("original complete source capture failed", status, err, string(raw))
	}
	configured := peer.exchange(t, map[string]string{"local_source": source["local_source"], "winner": winner})
	if string(configured["ready"]) != "true" || string(configured["carrier_required"]) != strconv.FormatBool(item.Prefixes > 1) || string(configured["positions"]) != strconv.Itoa(item.Prefixes+1) {
		t.Fatal("registered original suffix unavailable")
	}
	commands := map[string]string{"wrong-public": "wrong-middle-public", "failed-dns": "fail-dns"}
	if command := commands[fault]; command != "" {
		peer.exchange(t, map[string]string{"command": command})
	}
	status, request, err := linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-ordered-request", "")
	if err != nil || status != 200 {
		t.Fatal("original execution request unavailable")
	}
	status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/multihop/connect", string(request))
	negative := commands[fault] != "" || fault == "wrong-first-key" || fault == "wrong-later-key" || fault == "wrong-auth" || fault == "auth-downgrade" || fault == "relay-domain" || fault == "relay-route" || fault == "control-eof" || fault == "wrong-final-key"
	if err != nil || negative && status == 200 || !negative && status != 200 {
		t.Fatal("actual Linux public execution verdict", status, err, string(raw))
	}
	read := func() linuxSOCKSPrefixExecutionObservation {
		status, raw, err := linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-socks-prefix-execution-observation", "")
		var value linuxSOCKSPrefixExecutionObservation
		if err != nil || status != 200 || json.Unmarshal(raw, &value) != nil {
			t.Fatal("original execution observation missing", status, err, string(raw))
		}
		return value
	}
	var restoreLaunches uint64
	var comparisonTrials int
	if !negative {
		before := read()
		linuxSOCKSExecutionRequireMeasurements(t, before.Ready.Progress.Comparison, winner, requested == "auto")
		comparisonTrials = len(before.Ready.Progress.Comparison.Measurements)
		if !before.Connected || !before.PublicConnect || before.Requested != requested || before.Winner != winner || before.PID == 0 {
			t.Fatal("public execution replaced original chosen graph")
		}
		if fault == "carrier-change" {
			peer.exchange(t, map[string]string{"command": "carrier-change"})
			status, _, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-socks-prefix-execution-observation", "")
			if err != nil || status == 200 {
				t.Fatal("changed original native carrier remained current")
			}
		} else if fault == "replaced-source" {
			status, _, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/native-socks-prefix-execution-replace", "{}")
			if err != nil || status != 200 {
				t.Fatal(err)
			}
			status, _, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-socks-prefix-execution-observation", "")
			if err != nil || status == 200 {
				t.Fatal("foreign source remained current")
			}
		} else if fault == "" {
			beforeStats := peer.exchange(t, map[string]string{"command": "stats"})
			var beforeLaunches uint64
			if json.Unmarshal(beforeStats["launches"], &beforeLaunches) != nil {
				t.Fatal("original worker launch count absent")
			}
			status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/native-socks-prefix-execution-restore", "{}")
			if err != nil || status != 200 {
				t.Fatal("actual retained-choice restoration failed", status, err, string(raw))
			}
			after := read()
			linuxSOCKSExecutionRequireMeasurements(t, after.Ready.Progress.Comparison, winner, false)
			if !after.Restored || after.PID == before.PID || after.Ready.Identity == before.Ready.Identity || after.Winner != before.Winner || after.Ready.Progress.Comparison.Target != before.Ready.Progress.Comparison.Target || !reflect.DeepEqual(after.Ready.Progress.Comparison.Winner, before.Ready.Progress.Comparison.Winner) {
				t.Fatal("restoration replaced retained choice or reused original native reader")
			}
			afterStats := peer.exchange(t, map[string]string{"command": "stats"})
			var afterLaunches uint64
			if json.Unmarshal(afterStats["launches"], &afterLaunches) != nil || afterLaunches < beforeLaunches {
				t.Fatal("original worker launch count regressed")
			}
			restoreLaunches = afterLaunches - beforeLaunches
			expectedLaunches := uint64(0)
			if winner == "server" {
				expectedLaunches = 1
			}
			if restoreLaunches != expectedLaunches {
				t.Fatal("Last restoration reran discovery or replaced original worker")
			}
		}
	}
	if fault == "held-cleanup" {
		status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/native-socks-prefix-execution-cleanup-retry", "{}")
		var refusal struct {
			Refused bool `json:"refused"`
			Same    bool `json:"same_owner"`
			Joined  bool `json:"joined"`
		}
		if err != nil || status != 200 || json.Unmarshal(raw, &refusal) != nil || !refusal.Refused || !refusal.Same || refusal.Joined {
			t.Fatal("original held cleanup did not retain retry authority", status, err, string(raw))
		}
	}
	status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/disconnect", "{}")
	if err != nil || status != 200 {
		t.Fatal("actual public Disconnect did not join", status, err, string(raw))
	}
	stats := peer.exchange(t, map[string]string{"command": "retired"})
	var observed linuxSOCKSExecutionReply
	var launches uint64
	if string(stats["workers_joined"]) != "true" || decodeRelayControlJSON(stats["peer"], &observed) != nil || json.Unmarshal(stats["launches"], &launches) != nil {
		t.Fatal("original relay worker survived public Disconnect or lost its counters")
	}
	linuxSOCKSPrefixExecutionReadback(t, peer, observed)
	var serverPrefixes []linuxSOCKSPrefixExecutionPrefixCounter
	var entryProofs, carrierPackets, carrierTCP, delayed uint64
	if json.Unmarshal(stats["server_prefixes"], &serverPrefixes) != nil || len(serverPrefixes) != item.Prefixes-1 || json.Unmarshal(stats["entry_proofs"], &entryProofs) != nil || json.Unmarshal(stats["carrier_packets"], &carrierPackets) != nil || json.Unmarshal(stats["carrier_tcp"], &carrierTCP) != nil || json.Unmarshal(stats["local_delayed_packets"], &delayed) != nil {
		t.Fatal("original complete native traffic inventory absent")
	}
	localPrefixes := make([]linuxSOCKSPrefixExecutionPrefixCounter, len(observed.Prefixes))
	for i, row := range observed.Prefixes {
		localPrefixes[i] = linuxSOCKSPrefixExecutionPrefixCounter{Position: i, Mode: row.Mode, ParametersSHA256: row.ParametersSHA256, RawUDP: row.RawUDP, TCP: row.TCP, UDP: row.UDP, ProofQueries: row.ProofQueries, AuthRefusals: row.AuthRefusals}
	}
	for i := range serverPrefixes {
		serverPrefixes[i].Position = i + 1
		expected := localPrefixes[i+1]
		if serverPrefixes[i].Mode != expected.Mode || serverPrefixes[i].ParametersSHA256 != expected.ParametersSHA256 {
			t.Fatal("Server traffic inventory replaced an original packet position")
		}
	}
	if launches == 0 || entryProofs == 0 || localPrefixes[0].RawUDP == 0 || localPrefixes[0].TCP == 0 || observed.Final.DirectQueries != 0 || observed.Final.EntryPublicQueries != 0 || item.Prefixes > 1 && (carrierPackets == 0 || carrierTCP != 0) || item.Prefixes == 1 && carrierTCP == 0 {
		t.Fatal("native execution omitted actual original entry/carrier or acquired a direct bypass")
	}
	linuxSOCKSPrefixExecutionRequireCounters(t, item, localPrefixes, serverPrefixes, observed)
	if negative {
		status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/status", "")
		var current state
		if err != nil || status != 200 || json.Unmarshal(raw, &current) != nil || current.Connected {
			t.Fatal("refused execution published Connected")
		}
	}
	{
		middle := observed.Middle
		final := observed.Final
		counters, err := json.Marshal(map[string]any{"case": scenario, "prefixes": item.Prefixes, "requested": requested, "winner": winner, "carrier_required": item.Prefixes > 1, "launches": launches, "restore_launches": restoreLaunches, "comparison_trials": comparisonTrials, "entry_proofs": entryProofs, "local_prefixes": localPrefixes, "server_prefixes": serverPrefixes, "carrier_packets": carrierPackets, "carrier_tcp": carrierTCP, "local_delayed_packets": delayed,
			"middle": map[string]any{"method": middle.Method, "auth_refusals": observed.SOCKSAuthRefusals, "rejected_replies": observed.SOCKSRejectedReplies, "negotiated_relays": len(observed.SOCKSRelays), "open_associations": observed.SOCKSAssociations, "join_failed": observed.SOCKSJoinFailed, "raw_tcp": middle.RawTCP, "raw_udp": middle.RawUDP, "tcp": middle.TCP, "udp": middle.UDP, "public_queries": middle.PublicQueries},
			"final":  map[string]any{"raw_tcp": final.FinalRawTCP, "raw_udp": final.FinalRawUDP, "tcp": final.FinalTCP, "udp": final.FinalUDP, "proof_queries": final.RouterQueries, "dns_queries": final.DNSQueries, "public_queries": final.FinalPublicQueries, "direct_queries": final.DirectQueries, "entry_public_queries": final.EntryPublicQueries}})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("LINUX_SOCKS_PREFIX_EXECUTION_COUNTERS %s", counters)
	}

	if err = process.input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.done:
		if process.waitErr != nil {
			t.Fatal("original Linux controller did not join", process.waitErr, process.diagnostic.String())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	controllerJoined = true
	if err = peer.close(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("LINUX_SOCKS_PREFIX_EXECUTION_RECEIPT case=%s prefixes=%d requested=%s winner=%s negative=%t restored=%t cleanup_retry=%t carrier_required=%t native_joined=true relay_joined=true namespace_owned=true", scenario, item.Prefixes, requested, winner, negative, !negative && fault == "", fault == "held-cleanup", item.Prefixes > 1)
}

type linuxSOCKSPrefixExecutionPrefixCounter struct {
	Position         int    `json:"position"`
	Mode             string `json:"mode"`
	ParametersSHA256 string `json:"parameters_sha256"`
	RawUDP           int64  `json:"raw_udp"`
	TCP              int64  `json:"tcp"`
	UDP              int64  `json:"udp"`
	ProofQueries     uint64 `json:"proof_queries"`
	AuthRefusals     uint64 `json:"auth_refusals"`
}

func linuxSOCKSPrefixExecutionRequireCounters(t *testing.T, item linuxSOCKSPrefixExecutionCase, local, server []linuxSOCKSPrefixExecutionPrefixCounter, reply linuxSOCKSExecutionReply) {
	t.Helper()
	fault := item.Fault
	positive := func(p linuxSOCKSPrefixExecutionPrefixCounter) {
		if p.RawUDP <= 0 || p.TCP <= 0 || p.ProofQueries == 0 || p.AuthRefusals != 0 {
			t.Fatal("original encrypted packet/private proof absent", p.Position)
		}
	}
	for i, p := range local {
		if p.AuthRefusals != 0 {
			t.Fatal("original Local private token refused")
		}
		if i > 0 && item.Requested == "auto" {
			positive(p)
		}
	}
	for i, p := range server {
		if fault == "wrong-first-key" || fault == "wrong-later-key" && i == len(server)-1 {
			if i == 0 || fault == "wrong-later-key" {
				if p.RawUDP <= 0 {
					t.Fatal("wrong packet key never reached original encrypted provider")
				}
			} else if p.RawUDP != 0 {
				t.Fatal("wrong first key bypassed its original packet owner")
			}
			if p.TCP != 0 || p.UDP != 0 || p.ProofQueries != 0 {
				t.Fatal("wrong packet key acquired plaintext authority")
			}
			continue
		}
		positive(p)
	}
	m, f := reply.Middle, reply.Final
	if reply.SOCKSAssociations != 0 || reply.SOCKSJoinFailed || reply.OpenCONNECTStreams != nil || reply.FinalUOTVersion != 0 || m == nil || m.Method != "socks5" {
		t.Fatal("SOCKS prefix retained original association or borrowed another transport")
	}
	if fault != "wrong-auth" && reply.SOCKSAuthRefusals != 0 {
		t.Fatal("SOCKS prefix acquired foreign authentication")
	}
	switch fault {
	case "wrong-first-key", "wrong-later-key":
		if m.RawTCP != 0 || m.RawUDP != 0 || m.TCP != 0 || m.UDP != 0 || m.PublicQueries != 0 || f.FinalRawTCP != 0 || f.FinalRawUDP != 0 || f.RouterQueries != 0 || f.DNSQueries != 0 || len(reply.SOCKSRelays) != 0 || reply.SOCKSRejectedReplies != 0 {
			t.Fatal("failed packet prefix reached SOCKS or final")
		}
	case "wrong-auth", "auth-downgrade", "relay-domain", "relay-route", "control-eof", "wrong-public":
		linuxSOCKSExecutionNegativeCounters(t, reply, fault)
	case "wrong-final-key":
		linuxSOCKSExecutionNegativeCounters(t, reply, "wrong-final")
	default:
		linuxSOCKSExecutionPositiveCounters(t, reply)
		if f.FinalTCP == 0 || f.RouterQueries == 0 || f.DNSQueries == 0 {
			t.Fatal("original selected final private/public/DNS proof absent")
		}
	}
}
