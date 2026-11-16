//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/routechoice"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type linuxSOCKSExecutionCase struct{ Mode, Protocol, Requested, Winner, Fault string }

var linuxSOCKSExecutionCases = []string{
	"socks-wg-server",
	"socks-awg-fast-auto-local",
	"socks-awg-strong-auto-server",
	"socks-awg-strong-server",
	"socks-wg-auto-local",
	"socks-awg-fast-auto-server",
	"socks-wrong-auth",
	"socks-auth-downgrade",
	"socks-relay-domain",
	"socks-relay-route",
	"socks-control-eof",
	"socks-wrong-public",
	"socks-wrong-final",
	"socks-failed-dns",
	"socks-replaced-source",
	"socks-held-cleanup",
}
var linuxSOCKSExecutionScenarios = map[string]linuxSOCKSExecutionCase{
	"socks-wg-server":              {"wg", "socks5", "server", "server", ""},
	"socks-awg-fast-auto-local":    {"awg2-fast", "socks5", "auto", "local", ""},
	"socks-awg-strong-auto-server": {"awg2-strong", "socks5", "auto", "server", ""},
	"socks-awg-strong-server":      {"awg2-strong", "socks5", "server", "server", ""},
	"socks-wg-auto-local":          {"wg", "socks5", "auto", "local", ""},
	"socks-awg-fast-auto-server":   {"awg2-fast", "socks5", "auto", "server", ""},
	"socks-wrong-auth":             {"wg", "socks5", "server", "server", "wrong-auth"},
	"socks-auth-downgrade":         {"wg", "socks5", "server", "server", "auth-downgrade"},
	"socks-relay-domain":           {"wg", "socks5", "server", "server", "relay-domain"},
	"socks-relay-route":            {"wg", "socks5", "server", "server", "relay-route"},
	"socks-control-eof":            {"wg", "socks5", "server", "server", "control-eof"},
	"socks-wrong-public":           {"wg", "socks5", "server", "server", "wrong-public"},
	"socks-wrong-final":            {"wg", "socks5", "server", "server", "wrong-final"},
	"socks-failed-dns":             {"wg", "socks5", "server", "server", "failed-dns"},
	"socks-replaced-source":        {"wg", "socks5", "server", "server", "replaced-source"},
	"socks-held-cleanup":           {"wg", "socks5", "server", "server", "held-cleanup"},
}

func linuxSOCKSExecutionScenario(value string) (mode, protocol, requested, winner, fault string, err error) {
	x, found := linuxSOCKSExecutionScenarios[value]
	if !found {
		err = errors.New("uncaptured SOCKS execution case")
		return
	}
	return x.Mode, x.Protocol, x.Requested, x.Winner, x.Fault, nil
}
func linuxSOCKSExecutionEntryLayer(scenario string) string {
	switch scenario {
	case "socks-awg-fast-auto-local", "socks-awg-strong-server":
		return "aes-256-gcm"
	case "socks-awg-strong-auto-server", "socks-wg-auto-local":
		return "aes-256-gcm+xor-whitening"
	default:
		return "off"
	}
}

type linuxSOCKSExecutionObservation struct {
	Connected, PublicConnect, Joined, Restored bool
	Requested, Winner, Source, Transfer        string
	PID                                        int
	Ready                                      mobilemultihop.DesktopNodeChainExecutionReadyRecord
	Journal                                    string
	Comparison                                 json.RawMessage
}

func linuxSOCKSExecutionObserve(ctx context.Context, a *app) (linuxSOCKSExecutionObservation, error) {
	var result linuxSOCKSExecutionObservation
	owner, err := a.desktopOrderedExecutionOwner()
	if err != nil || owner == nil {
		return result, errors.Join(err, errors.New("original execution owner absent"))
	}
	s := owner.session
	if err = s.Current(ctx); err != nil {
		return result, err
	}
	h := s.launch.chain.platform.host
	if s.execution.socksPhysical == nil {
		return result, errors.New("missing original typed physical source")
	}
	original, physicalErr := s.execution.socksPhysical.OriginalDesktopSOCKSPolicy()
	if physicalErr != nil {
		return result, physicalErr
	}
	if h == nil || h.launch != s.launch || h.launch.chain.execution != s.execution || h.socksChain != original || h.transaction == nil || h.transaction.execution != s.execution || h.transaction.baseline == nil || h.activation == nil {
		return result, errors.New("original Linux execution/TUN/protection owner changed")
	}
	if err = h.enter(ctx); err != nil {
		return result, err
	}
	defer func() { h.gate <- struct{}{} }()
	if _, _, err = h.readReadyLocked(ctx, false); err != nil {
		return result, err
	}
	s.execution.mu.Lock()
	if s.execution.ready == nil {
		s.execution.mu.Unlock()
		return result, errors.New("original selected proof missing")
	}
	result.Ready = *s.execution.ready
	s.execution.mu.Unlock()
	_, meta, capture, err := s.execution.readPolicy()
	if err != nil || meta.TargetOS != "linux" || len(capture.PhysicalRoots) != 1 || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.SelectedDNS.Type != "udp" || capture.SelectedDNS.Host != "192.168.50.133" {
		return result, errors.Join(err, errors.New("original physical and selected DNS source changed"))
	}
	if h.process == nil || h.process.command == nil || h.process.command.Process == nil || h.transaction.head.SHA256 == "" {
		return result, errors.New("original process and protection journal absent")
	}
	result.PID = h.process.command.Process.Pid
	result.Source = meta.SourceSHA256
	result.Transfer = result.Ready.TransferSHA256
	result.Journal = h.transaction.head.SHA256
	result.Winner = result.Ready.Progress.Execution
	result.Requested = s.execution.preparation.Execution()
	result.Comparison, _ = json.Marshal(result.Ready.Progress.Comparison)
	a.mu.Lock()
	result.Connected = a.state.Connected && a.cmd == s.launch.command
	a.mu.Unlock()
	if !result.Connected || result.Transfer == "" || result.Ready.Kind != "routervpn-node-chain-socks-execution-ready-v1" || result.Ready.InterfaceIndex == 0 || result.Ready.InterfaceName == "" || !result.Ready.Progress.DNSProven {
		return result, errors.New("original selected Linux TUN/DNS proof absent")
	}
	return result, nil
}
func linuxSOCKSExecutionRequireMeasurements(t *testing.T, result routechoice.Result, winner string, compare bool) {
	t.Helper()
	valid := func(m routechoice.Measurement) bool {
		positive := func(v float64) bool { return v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }
		return m.Candidate.Valid() && m.Eligible && m.Failure == "" && positive(m.LastNodeMS) && positive(m.ExternalMS) && m.ScoreMS != nil && positive(*m.ScoreMS) && math.Abs(*m.ScoreMS-(m.LastNodeMS/2+m.ExternalMS/2)) <= 0.000001
	}
	target := false
	for _, original := range mobilemultihop.Targets {
		target = target || result.Target == original
	}
	if !target || result.Winner == nil || string(result.Winner.Execution) != winner || result.Final == nil || result.Final.Candidate != *result.Winner || !valid(*result.Final) {
		t.Fatal("original chosen path lost its routed final measurement")
	}
	if !compare {
		if len(result.Measurements) != 0 {
			t.Fatal("retained choice reran candidate comparison")
		}
		return
	}
	if len(result.Measurements) != 2 {
		t.Fatal("original Compare omitted a candidate")
	}
	seen := map[routechoice.Execution]bool{}
	for _, m := range result.Measurements {
		if seen[m.Candidate.Execution] || !valid(m) || m.Candidate.Transport != result.Winner.Transport || m.Candidate.EntryID != result.Winner.EntryID || m.Candidate.ExitID != result.Winner.ExitID {
			t.Fatal("original Compare lost a routed candidate or score")
		}
		seen[m.Candidate.Execution] = true
	}
	if !seen[routechoice.Local] || !seen[routechoice.Server] {
		t.Fatal("original Compare replaced a candidate")
	}
}

func linuxSOCKSExecutionController(owned *ownedDesktopController, scenario string) error {
	_, protocol, requested, _, fault, err := linuxSOCKSExecutionScenario(scenario)
	if err != nil {
		return err
	}
	var raw []byte
	a := &app{localController: owned, state: state{Mode: "off", Phase: "off"}, cfg: common.ClientConfig{AutoTestSeconds: 10, Listen: linuxOwnedControllerAddress, ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"), ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")}}
	raw, err = readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	if err != nil || decodeRelayControlJSON(raw, &a.profiles) != nil || len(a.profiles.Profiles) != 3 {
		return errors.New("original imported trio catalog absent")
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
	gate := os.NewFile(3, "socks-execution-rendezvous")
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
	mux.HandleFunc("/api/native-socks-execution-source", func(w http.ResponseWriter, r *http.Request) {
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
			selection, err = captureNativeMultihopSelection(r.Context(), linuxOwnedControllerRoot, selection, []string{protocol}, nil)
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
	mux.HandleFunc("/api/native-socks-execution-observation", func(w http.ResponseWriter, r *http.Request) {
		value, err := linuxSOCKSExecutionObserve(r.Context(), a)
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
	mux.HandleFunc("/api/native-socks-execution-restore", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/native-socks-execution-cleanup-retry", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/api/native-socks-execution-replace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || fault != "replaced-source" {
			http.Error(w, "uncaptured replacement", 409)
			return
		}
		a.mu.Lock()
		a.profiles.Profiles[1].External.SOCKS5.Password += "changed"
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"changed": true})
	})
	return serveClientHTTP(closing, listener, mux, make(chan os.Signal))
}

type linuxSOCKSExecutionLayerCase struct{ Entry, Final string }
type linuxSOCKSExecutionLayerTransport struct {
	Method        string `json:"method"`
	Address       string `json:"address"`
	PhysicalTCP   int64  `json:"physical_tcp"`
	PhysicalUDP   int64  `json:"physical_udp"`
	Streams       int64  `json:"streams"`
	Packets       int64  `json:"packets"`
	PublicReplies uint32 `json:"public_replies"`
	AuthTCP       uint32 `json:"auth_tcp"`
	AuthUDP       uint32 `json:"auth_udp"`
}
type linuxSOCKSExecutionLayerObservation struct {
	Entry          string                             `json:"entry"`
	Final          string                             `json:"final"`
	EntryTransport *linuxSOCKSExecutionLayerTransport `json:"entry_transport,omitempty"`
	FinalTransport *linuxSOCKSExecutionLayerTransport `json:"final_transport"`
}
type linuxSOCKSExecutionPeer struct {
	peer                                   *linuxNodeChainPeer
	protocol, fault, middle, entryPassword string
	layers                                 *linuxSOCKSExecutionLayerCase
	layerObservation                       linuxSOCKSExecutionLayerObservation
	started, joined, quitAttempted         bool
}

func (p *linuxSOCKSExecutionPeer) exchange(t *testing.T, value any) map[string]json.RawMessage {
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
func (p *linuxSOCKSExecutionPeer) close(ctx context.Context) error {
	if p == nil || !p.started || p.joined {
		return nil
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
	raw, err := io.ReadAll(io.LimitReader(p.peer.reader, 4097))
	lines := strings.Split(string(raw), "\n")
	var receipt struct {
		Joined       bool   `json:"joined"`
		Launches     uint64 `json:"launches"`
		Associations int    `json:"associations"`
	}
	if err != nil || len(raw) > 4096 || len(lines) != 3 || lines[1] != "PASS" || lines[2] != "" || decodeRelayControlJSON([]byte(lines[0]), &receipt) != nil || !receipt.Joined || receipt.Associations != 0 {
		return errors.New("original peer omitted exact Manager/worker/association joined receipt")
	}
	p.joined = true
	return p.peer.output.Close()
}
func linuxSOCKSExecutionInstallLayers(t *testing.T, p *linuxSOCKSExecutionPeer, store *common.RouterProfileStore) {
	t.Helper()
	if p.layers == nil {
		return
	}
	if len(store.Profiles) != 3 || p.layerObservation.Entry != p.layers.Entry || p.layerObservation.Final != p.layers.Final || p.layerObservation.FinalTransport == nil {
		t.Fatal("original independent layer source missing")
	}
	store.Profiles[0].StartLayer, store.Profiles[2].StartLayer = p.layers.Entry, p.layers.Final
	if p.layers.Entry == "off" {
		if p.layerObservation.EntryTransport != nil {
			t.Fatal("Off entry borrowed layer ownership")
		}
		return
	}
	outer := p.layerObservation.EntryTransport
	if outer == nil || outer.Method != "2022-blake3-aes-256-gcm" {
		t.Fatal("original packet layer missing")
	}
	address, err := netip.ParseAddrPort(outer.Address)
	if err != nil || address.Addr() != netip.MustParseAddr("192.168.210.2") || address.Port() == 0 || p.layers.Entry == "aes-256-gcm+xor-whitening" && address.Port() != 8389 {
		t.Fatal("packet layer changed captured physical endpoint", err)
	}
	directory := filepath.Join(linuxOwnedControllerRoot, "generated", store.Profiles[0].ID, "shadowsocks")
	if err = os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	graph, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": netip.MustParseAddr("192.168.210.2").String(), "server_port": int(address.Port()), "method": "2022-blake3-aes-256-gcm", "password": p.entryPassword}}, "route": map[string]any{"final": "proxy"}})
	if err != nil || os.WriteFile(filepath.Join(directory, "sing-box.json"), graph, 0600) != nil {
		t.Fatal("original independent entry AES source not captured", err)
	}
}

type linuxSOCKSExecutionReply struct {
	linuxNodeChainPeerReply
	SOCKSRelays          []string `json:"socks_relays"`
	SOCKSAssociations    int      `json:"socks_associations"`
	SOCKSAuthRefusals    uint32   `json:"socks_auth_refusals"`
	SOCKSRejectedReplies uint32   `json:"socks_rejected_replies"`
	SOCKSJoinFailed      bool     `json:"socks_join_failed"`
}

func linuxSOCKSExecutionReadback(t *testing.T, peer *linuxNodeChainPeer, reply linuxSOCKSExecutionReply) {
	t.Helper()
	if !peer.middleSOCKS || peer.middleCONNECT != "" || reply.Schema != 1 || len(reply.Prefixes) != len(peer.requests) || reply.Middle == nil || reply.Middle.Method != "socks5" || reply.SOCKSAssociations < 0 || reply.SOCKSJoinFailed || reply.CONNECTProtocol != "" || reply.CONNECTCA != "" || reply.CONNECTServerName != "" || reply.OpenCONNECTStreams != nil || reply.FinalUOTVersion != 0 {
		t.Fatal("original SOCKS peer acquired another transport or lost association ownership")
	}
	address, err := netip.ParseAddrPort(reply.Address)
	if err != nil || address.Addr() != netip.MustParseAddr("192.168.210.2") || address.Port() == 0 || reply.PublicCA == "" || reply.Final.FinalPublicIP != "203.0.113.89" {
		t.Fatal("original SOCKS peer replaced physical or final identity")
	}
	if peer.reply.Address != "" && (peer.reply.Address != reply.Address || peer.reply.PublicCA != reply.PublicCA) {
		t.Fatal("original SOCKS peer replaced captured identity")
	}
	for i, prefix := range peer.requests {
		expected := ""
		if awgpolicy.IsMode(prefix.Mode) {
			parameters, err := awgpolicy.ParametersUAPI(prefix.Parameters)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(parameters))
			expected = hex.EncodeToString(digest[:])
		} else if prefix.Mode != "wg" || len(prefix.Parameters) != 0 {
			t.Fatal("unowned SOCKS packet cipher")
		}
		if reply.Prefixes[i].Mode != prefix.Mode || reply.Prefixes[i].ParametersSHA256 != expected {
			t.Fatal("original SOCKS packet parameters changed")
		}
	}
	for _, raw := range reply.SOCKSRelays {
		relay, err := netip.ParseAddrPort(raw)
		if err != nil || relay.Addr() != netip.MustParseAddr("192.168.210.2") || relay.Port() == 0 {
			t.Fatal("SOCKS returned a foreign actual bound relay")
		}
	}
	peer.reply = reply.linuxNodeChainPeerReply
}
func linuxSOCKSExecutionPositiveCounters(t *testing.T, reply linuxSOCKSExecutionReply) {
	t.Helper()
	middle := reply.Middle
	if middle == nil || middle.RawTCP == 0 || middle.TCP == 0 || middle.RawUDP == 0 || middle.UDP == 0 || middle.PublicQueries == 0 || reply.Final.FinalRawTCP == 0 || reply.Final.FinalRawUDP == 0 || reply.Final.FinalUDP == 0 || reply.SOCKSAuthRefusals != 0 || reply.SOCKSRejectedReplies != 0 || len(reply.SOCKSRelays) == 0 {
		t.Fatal("installed SOCKS omitted authenticated TCP and original negotiated UDP", reply)
	}
}
func linuxSOCKSExecutionNegativeCounters(t *testing.T, reply linuxSOCKSExecutionReply, fault string) {
	t.Helper()
	middle := reply.Middle
	if middle == nil || middle.RawTCP == 0 {
		t.Fatal("SOCKS refusal missed its actual original control", reply)
	}
	switch fault {
	case "wrong-auth":
		if reply.SOCKSAuthRefusals == 0 || middle.TCP != 0 || middle.PublicQueries != 0 || reply.Final.RouterQueries != 0 || middle.RawUDP != 0 {
			t.Fatal("SOCKS credential refusal missed original authentication", reply)
		}
	case "auth-downgrade", "relay-domain":
		if reply.SOCKSRejectedReplies == 0 || reply.SOCKSAuthRefusals != 0 || middle.RawUDP != 0 || reply.Final.DNSQueries != 0 {
			t.Fatal("SOCKS reply refusal missed original negotiated authority", reply)
		}
	case "relay-route":
		if len(reply.SOCKSRelays) == 0 || middle.RawUDP != 0 || reply.Final.DNSQueries != 0 {
			t.Fatal("foreign advertised SOCKS route acquired UDP authority", reply)
		}
	case "control-eof":
		if len(reply.SOCKSRelays) == 0 || middle.RawUDP == 0 || reply.Final.DNSQueries != 0 {
			t.Fatal("SOCKS control EOF did not revoke actual UDP relay", reply)
		}
	case "wrong-public":
		if middle.TCP == 0 || middle.PublicQueries == 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong SOCKS public identity missed original public response", reply)
		}
	case "wrong-final":
		if middle.TCP == 0 || middle.PublicQueries == 0 || reply.Final.FinalRawTCP == 0 || reply.Final.FinalTCP != 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong paired final key escaped original encrypted final", reply)
		}
	default:
		t.Fatal("unknown SOCKS refusal boundary", fault)
	}
}

func startLinuxSOCKSExecutionPeer(t *testing.T, p *linuxSOCKSExecutionPeer, mode, protocol, fault string) {
	t.Helper()
	p.peer = linuxNodeChainPeerForModes(t, []string{mode, protocol})
	peer := p.peer
	physical := netip.MustParseAddr("192.168.210.2")
	// Retain the peer image in the existing private /opt mount using the same
	// nofollow descriptor/hash/ownership copy as the original installed gates.
	// The private namespace keeps this inode until every owned process joins.
	directory, err := os.MkdirTemp("/opt", "routervpn-socks-execution-peer-")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(directory, "peer.test")
	linuxHostTUNCopy(t, os.Getenv("ROUTERVPN_NODE_HOST_PEER_BINARY"), image, 512<<20, os.Getenv("ROUTERVPN_NODE_HOST_PEER_SHA256"), 0755)
	raw, err := os.ReadFile(image)
	sum := sha256.Sum256(raw)
	if err != nil || !filepath.IsAbs(image) || hex.EncodeToString(sum[:]) != os.Getenv("ROUTERVPN_NODE_HOST_PEER_SHA256") {
		t.Fatal("original peer image changed")
	}
	worker := filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName())
	workerRaw, err := os.ReadFile(worker)
	workerHash := sha256.Sum256(workerRaw)
	if err != nil {
		t.Fatal("shipping native SOCKS worker missing", err)
	}
	for _, address := range []string{"10.78.0.1/32", "10.78.0.2/32"} {
		linuxHostTUNCommand(t, "ip", "netns", "exec", "rvpn-peer", "ip", "addr", "add", address, "dev", "lo")
	}
	peer.command = exec.Command("ip", "netns", "exec", "rvpn-peer", image, "-test.run=^TestRouterVPNDesktopSOCKSExecutionReferenceProcess$", "-test.count=1", "-test.timeout=240s")
	parentNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	peer.command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_SOCKS_EXECUTION_REFERENCE=1", "ROUTERVPN_LINUX_GUARDIAN_TEST_NS=1", "ROUTERVPN_SOCKS_EXECUTION_PARENT_NETNS=" + parentNamespace}
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
	paired := map[string]any{"schema": 1, "address": physical.String(), "client_address": "192.168.210.1", "prefixes": peer.requests, "final_password": peer.password, "final_node_proof_id": linuxNodeChainProofID(peer.finalServer), "final_api_token": "installed-ordered-final-token", "benchmark_port": 45998}
	wire := map[string]any{"schema": 1, "peer": map[string]any{"schema": 1, "paired": paired, "middle_method": peer.middleMethod, "middle_password": peer.middlePassword}, "image": worker, "image_sha256": hex.EncodeToString(workerHash[:])}
	wire["username"], wire["password"], wire["fault"] = "captured-native-user", peer.middlePassword, fault
	wire["layers"] = map[string]string{"entry": p.layers.Entry, "final": "off", "entry_password": p.entryPassword}
	reply := p.exchange(t, wire)
	var observed linuxSOCKSExecutionReply
	if decodeRelayControlJSON(reply["peer"], &observed) != nil || json.Unmarshal(reply["middle_address"], &p.middle) != nil || p.middle == "" || observed.PublicCA == "" {
		t.Fatal("original imported peer identity missing")
	}
	if json.Unmarshal(reply["layers"], &p.layerObservation) != nil {
		t.Fatal("original entry layer capture missing")
	}
	linuxSOCKSExecutionReadback(t, peer, observed)
}

func linuxSOCKSExecutionStartController(t *testing.T, installed, scenario string, retained **linuxHostTUNController) *linuxHostTUNController {
	t.Helper()
	reader, writer := linuxControllerUserPipe(t, installed)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 230*time.Second)
	base := linuxControllerBootstrapCommand(installed, reader)
	command := exec.CommandContext(ctx, installed, base.Args[1:]...)
	command.Stdin, command.Env, command.ExtraFiles = reader, append(base.Env, "ROUTERVPN_CONTROLLER_NODE_PARENT_CASE=host-tun/"+scenario), []*os.File{gateRead}
	process := &linuxHostTUNController{command: command, input: writer, gate: gateWrite, done: make(chan struct{}), cancel: cancel}
	if retained == nil || *retained != nil {
		t.Fatal("controller already has another start owner")
	}
	*retained = process
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
	t.Cleanup(func() {
		_ = writer.Close()
		_ = gateWrite.Close()
		cancel()
		if command.Process != nil {
			select {
			case <-process.done:
			case <-time.After(15 * time.Second):
				t.Error("original controller failed bounded startup join")
			}
		}
		_ = process.output.Close()
	})
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

func linuxSOCKSExecutionHTTP(ctx context.Context, client *http.Client, method, path, body string) (int, []byte, error) {
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

func TestDesktopLinuxGuardianKernelSOCKSExecution(t *testing.T) {
	linuxHostTUNNamespace(t)
	if os.Getenv("HOMEVPN_MTU_BENCH_FAKE") != "" {
		t.Fatal("native execution forbids modeled MTU")
	}
	for _, scenario := range linuxSOCKSExecutionCases {
		t.Run(scenario, func(t *testing.T) { linuxSOCKSExecutionNativeCase(t, scenario) })
	}
}
func linuxSOCKSExecutionNativeCase(t *testing.T, scenario string) {
	mode, protocol, requested, winner, fault, err := linuxSOCKSExecutionScenario(scenario)
	if err != nil {
		t.Fatal(err)
	}
	installed := linuxControllerNamespaceInstall(t)
	linuxHostTUNInstallBundle(t)
	peer := &linuxSOCKSExecutionPeer{protocol: protocol, fault: fault, layers: &linuxSOCKSExecutionLayerCase{Entry: linuxSOCKSExecutionEntryLayer(scenario), Final: "off"}}
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
	if peer.layers.Entry != "off" {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		peer.entryPassword = base64.StdEncoding.EncodeToString(key[:])
		clear(key[:])
	}
	startLinuxSOCKSExecutionPeer(t, peer, mode, protocol, fault)
	installLinuxNodeChainProfiles(t, peer.peer, "")
	raw, err := os.ReadFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"))
	var store common.RouterProfileStore
	if err != nil || json.Unmarshal(raw, &store) != nil || len(store.Profiles) != 3 {
		t.Fatal("original private catalog absent", err)
	}
	linuxSOCKSExecutionInstallLayers(t, peer, &store)
	host, port, err := net.SplitHostPort(peer.middle)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || host != "192.168.210.2" {
		t.Fatal("captured imported literal changed")
	}
	store.Profiles[1].Endpoint = host
	proxy := store.Profiles[1].External.SOCKS5
	if proxy == nil {
		t.Fatal("original imported proxy absent")
	}
	proxy.Host, proxy.Port = host, n
	store.Profiles[2].MultihopExecution = requested
	raw, _ = json.Marshal(store)
	if err = os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	repositorySource := os.Getenv("ROUTERVPN_SOCKS_EXECUTION_SOURCE")
	raw, err = os.ReadFile(filepath.Join(repositorySource, "configs/client/modes.json"))
	if err != nil || os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "modes.json"), raw, 0600) != nil {
		t.Fatal("original mode catalog missing", err)
	}
	controllerJoined = false
	linuxSOCKSExecutionStartController(t, installed, scenario, &process)
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
	status, raw, err := linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-socks-execution-source", "")
	var source map[string]string
	if err != nil || status != 200 || json.Unmarshal(raw, &source) != nil || source["local_source"] == "" {
		t.Fatal("original complete source capture failed", status, err, string(raw))
	}
	configured := peer.exchange(t, map[string]string{"local_source": source["local_source"], "winner": winner})
	if string(configured["ready"]) != "true" {
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
	negative := commands[fault] != "" || fault == "wrong-auth" || fault == "auth-downgrade" || fault == "relay-domain" || fault == "relay-route" || fault == "control-eof" || fault == "wrong-final"
	if err != nil || negative && status == 200 || !negative && status != 200 {
		t.Fatal("actual Linux public execution verdict", status, err, string(raw))
	}
	read := func() linuxSOCKSExecutionObservation {
		status, raw, err := linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-socks-execution-observation", "")
		var value linuxSOCKSExecutionObservation
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
		if fault == "replaced-source" {
			status, _, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/native-socks-execution-replace", "{}")
			if err != nil || status != 200 {
				t.Fatal(err)
			}
			status, _, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/native-socks-execution-observation", "")
			if err != nil || status == 200 {
				t.Fatal("foreign source remained current")
			}
		} else if fault == "" {
			beforeStats := peer.exchange(t, map[string]string{"command": "stats"})
			var beforeLaunches uint64
			if json.Unmarshal(beforeStats["launches"], &beforeLaunches) != nil {
				t.Fatal("original worker launch count absent")
			}
			status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/native-socks-execution-restore", "{}")
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
		status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodPost, "/api/native-socks-execution-cleanup-retry", "{}")
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
	stats := peer.exchange(t, map[string]string{"command": "stats"})
	var observed linuxSOCKSExecutionReply
	var launches uint64
	if string(stats["workers_joined"]) != "true" || decodeRelayControlJSON(stats["peer"], &observed) != nil || json.Unmarshal(stats["launches"], &launches) != nil {
		t.Fatal("original relay worker survived public Disconnect or lost its counters")
	}
	var layers linuxSOCKSExecutionLayerObservation
	if json.Unmarshal(stats["layers"], &layers) != nil || layers.Entry != peer.layers.Entry || layers.Final != "off" || layers.FinalTransport == nil || layers.FinalTransport.Address != peer.layerObservation.FinalTransport.Address {
		t.Fatal("original entry/final layer ownership changed")
	}
	var layerPackets, layerCiphertext int64
	var layerAuth uint32
	if layers.Entry == "off" {
		if layers.EntryTransport != nil {
			t.Fatal("Off borrowed a layer owner")
		}
	} else {
		transport := layers.EntryTransport
		if transport == nil || peer.layerObservation.EntryTransport == nil || transport.Address != peer.layerObservation.EntryTransport.Address || transport.Method != "2022-blake3-aes-256-gcm" || transport.PhysicalUDP == 0 || transport.Packets == 0 || transport.AuthUDP != 0 {
			t.Fatal("original entry layer did not carry and decrypt captured packets")
		}
		layerPackets, layerCiphertext, layerAuth = transport.Packets, transport.PhysicalUDP, transport.AuthUDP
	}
	linuxSOCKSExecutionReadback(t, peer.peer, observed)
	if observed.SOCKSAssociations != 0 || observed.SOCKSJoinFailed {
		t.Fatal("original SOCKS associations survived Disconnect")
	}
	if launches == 0 || len(observed.Prefixes) != 1 || observed.Prefixes[0].Mode != mode || observed.Prefixes[0].RawUDP == 0 || observed.Prefixes[0].TCP == 0 || observed.Prefixes[0].ProofQueries == 0 {
		t.Fatal("execution refused before original encrypted prefix and worker")
	}
	switch fault {
	case "wrong-auth", "auth-downgrade", "relay-domain", "relay-route", "control-eof", "wrong-public", "wrong-final":
		linuxSOCKSExecutionNegativeCounters(t, observed, fault)
	default:
		linuxSOCKSExecutionPositiveCounters(t, observed)
		if observed.Final.RouterQueries == 0 || observed.Final.DNSQueries == 0 {
			t.Fatal("omitted original final proof or selected DNS")
		}
	}
	if negative {
		status, raw, err = linuxSOCKSExecutionHTTP(ctx, client, http.MethodGet, "/api/status", "")
		var current state
		if err != nil || status != 200 || json.Unmarshal(raw, &current) != nil || current.Connected {
			t.Fatal("refused execution published Connected")
		}
	}
	{
		counters, err := json.Marshal(map[string]any{"case": scenario, "launches": launches, "restore_launches": restoreLaunches, "comparison_trials": comparisonTrials, "entry_raw_udp": observed.Prefixes[0].RawUDP, "entry_tcp": observed.Prefixes[0].TCP, "entry_proofs": observed.Prefixes[0].ProofQueries, "middle_raw_tcp": observed.Middle.RawTCP, "middle_tcp": observed.Middle.TCP, "middle_public": observed.Middle.PublicQueries, "final_raw_tcp": observed.Final.FinalRawTCP, "final_tcp": observed.Final.FinalTCP, "final_proofs": observed.Final.RouterQueries, "dns": observed.Final.DNSQueries, "middle_raw_udp": observed.Middle.RawUDP, "final_raw_udp": observed.Final.FinalRawUDP, "auth_refusals": observed.SOCKSAuthRefusals, "rejected_replies": observed.SOCKSRejectedReplies, "negotiated_relays": len(observed.SOCKSRelays), "open_associations": observed.SOCKSAssociations, "middle_udp": observed.Middle.UDP, "final_udp": observed.Final.FinalUDP, "entry_layer": layers.Entry, "entry_layer_packets": layerPackets, "entry_layer_ciphertext": layerCiphertext, "entry_layer_auth": layerAuth})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("LINUX_SOCKS_EXECUTION_COUNTERS %s", counters)
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
	t.Logf("LINUX_SOCKS_EXECUTION_RECEIPT case=%s requested=%s winner=%s negative=%t restored=%t cleanup_retry=%t native_joined=true relay_joined=true namespace_owned=true", scenario, requested, winner, negative, !negative && fault == "", fault == "held-cleanup")
}
