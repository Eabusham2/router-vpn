//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

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
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/windowscontroller"
	"strings"
	"sync"
	"testing"
	"time"
)

type windowsCONNECTExecutionLayerTransport struct {
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
type windowsCONNECTExecutionLayers struct {
	Entry          string                                 `json:"entry"`
	Final          string                                 `json:"final"`
	EntryTransport *windowsCONNECTExecutionLayerTransport `json:"entry_transport,omitempty"`
	FinalTransport *windowsCONNECTExecutionLayerTransport `json:"final_transport"`
}
type windowsCONNECTExecutionPeer struct {
	peer                                                *windowsPrefixPeer
	protocol, password, middle, physical, entryPassword string
	first                                               windowsCONNECTPeerReply
	layers                                              windowsCONNECTExecutionLayers
	aliases                                             *windowsCONNECTExecutionAliases
	command                                             *exec.Cmd
	image                                               *windowscontroller.Image
	process                                             *windowscontroller.Process
	input                                               io.WriteCloser
	output                                              *os.File
	reader                                              *bufio.Reader
	diagnostic                                          *windowsPrefixOutput
	done                                                chan struct{}
	waitErr, terminal                                   error
	mu                                                  sync.Mutex
	started, quit, joined, closed                       bool
}

// Cancellation closes the original pipes and joins the reader; no orphan may
// consume a later response or adopt a successor protocol stream.
func (p *windowsCONNECTExecutionPeer) exchange(ctx context.Context, value any) (map[string]json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx == nil || !p.started || p.joined {
		return nil, errors.New("original peer exchange absent")
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		if value != nil {
			if err := json.NewEncoder(p.input).Encode(value); err != nil {
				done <- result{err: err}
				return
			}
		}
		raw, err := p.reader.ReadBytes('\n')
		done <- result{raw, err}
	}()
	var valueRead result
	select {
	case valueRead = <-done:
	case <-call.Done():
		p.input.Close()
		p.output.Close()
		<-done
		return nil, call.Err()
	}
	if valueRead.err != nil || len(valueRead.raw) > 32768 {
		return nil, errors.Join(valueRead.err, errors.New("original peer omitted bounded frame"))
	}
	var reply map[string]json.RawMessage
	if json.Unmarshal(valueRead.raw, &reply) != nil {
		return nil, errors.New("original peer returned malformed frame")
	}
	return reply, nil
}
func (p *windowsCONNECTExecutionPeer) close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.terminal
	}
	if ctx == nil {
		return errors.New("peer retirement requires original context")
	}
	if p.started {
		if !p.quit {
			p.quit = true
			if p.process == nil {
				p.terminal = errors.Join(p.terminal, errors.New("original peer process capture absent"))
			} else if err := p.process.VerifyImage(p.image); err != nil {
				p.terminal = errors.Join(p.terminal, err)
			}
			if p.input != nil {
				_ = json.NewEncoder(p.input).Encode(map[string]string{"command": "quit"})
				_ = p.input.Close()
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
		}
		if p.waitErr != nil {
			p.terminal = errors.Join(p.terminal, p.waitErr, errors.New(p.diagnostic.String()))
		} else {
			raw, err := io.ReadAll(io.LimitReader(p.reader, 4097))
			if err != nil || len(raw) > 4096 || strings.Count(string(raw), `"joined":true`) != 1 || !strings.HasSuffix(string(raw), "PASS\n") || strings.Contains(string(raw), "FAIL") || strings.Contains(string(raw), "SKIP") {
				p.terminal = errors.Join(p.terminal, err, errors.New("original peer omitted joined Manager/worker result"))
			}
		}
	}
	// Even a partially started provider retains and joins its original command.
	// Release only acquired resources; a failed proof remains a failed retry.
	if p.input != nil {
		_ = p.input.Close()
		p.input = nil
	}
	if p.output != nil {
		p.terminal = errors.Join(p.terminal, p.output.Close())
		p.output = nil
	}
	if p.process != nil {
		p.terminal = errors.Join(p.terminal, p.process.Close())
		p.process = nil
	}
	if p.image != nil {
		p.terminal = errors.Join(p.terminal, p.image.Close())
		p.image = nil
	}
	p.closed = true
	p.joined = p.started && p.terminal == nil
	return p.terminal
}
func windowsCONNECTExecutionStartPeer(t *testing.T, ctx context.Context, scenario string, retained **windowsCONNECTExecutionPeer) *windowsCONNECTExecutionPeer {
	t.Helper()
	mode, protocol, _, _, fault, err := windowsCONNECTExecutionScenario(scenario)
	if err != nil {
		t.Fatal(err)
	}
	keys := windowsPrefixPeerKeys(t, 3)
	password := keys.requests[1].PreSharedKey
	keys.requests, keys.clients = keys.requests[:1], keys.clients[:1]
	windowsPrefixSetModes(t, keys, []string{mode})
	p := &windowsCONNECTExecutionPeer{peer: keys, protocol: protocol, password: password, done: make(chan struct{}), diagnostic: new(windowsPrefixOutput)}
	*retained = p
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	p.entryPassword = base64.StdEncoding.EncodeToString(key)
	image := os.Getenv("ROUTERVPN_WINDOWS_PREFIX_PEER")
	worker := os.Getenv("ROUTERVPN_WINDOWS_CONNECT_EXECUTION_WORKER")
	if !filepath.IsAbs(image) || !filepath.IsAbs(worker) {
		t.Fatal("original peer/worker image paths absent")
	}
	p.image, err = windowscontroller.PinImage(image)
	if err != nil {
		t.Fatal(err)
	}
	p.command = exec.Command(p.image.Path(), "-test.run=^TestRouterVPNDesktopWindowsCONNECTExecutionReferenceProcess$", "-test.count=1", "-test.timeout=240s")
	p.command.Env = append(os.Environ(), "ROUTERVPN_WINDOWS_PREFIX_REFERENCE=1", "ROUTERVPN_CONNECT_EXECUTION_REFERENCE=1")
	p.input, err = p.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var writer *os.File
	p.output, writer, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p.reader = bufio.NewReaderSize(p.output, 32769)
	p.command.Stdout, p.command.Stderr = writer, p.diagnostic
	if err = p.command.Start(); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	p.started = true
	writer.Close()
	go func() { p.waitErr = p.command.Wait(); close(p.done) }()
	p.process, err = windowscontroller.OpenProcess(uint32(p.command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if err = p.process.VerifyImage(p.image); err != nil {
		t.Fatal(err)
	}
	banner, err := p.exchange(ctx, nil)
	if err != nil || string(banner["schema"]) != "1" || json.Unmarshal(banner["physical_address"], &p.physical) != nil {
		t.Fatal("original physical peer absent", err)
	}
	physical, err := netip.ParseAddr(p.physical)
	if err != nil {
		t.Fatal(err)
	}
	p.aliases, err = windowsCONNECTExecutionOwnAliases(ctx, physical)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(worker)
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if err != nil || digest != os.Getenv("ROUTERVPN_WINDOWS_CONNECT_EXECUTION_WORKER_SHA256") {
		t.Fatal("original separately captured worker changed", err)
	}
	paired := map[string]any{"schema": 1, "address": p.physical, "client_address": p.physical, "prefixes": keys.requests, "final_password": keys.password, "final_node_proof_id": windowsPrefixProofID(keys.finalServer), "final_api_token": "installed-ordered-final-token", "benchmark_port": 45998}
	wire := map[string]any{"schema": 1, "peer": map[string]any{"schema": 1, "paired": paired, "middle_method": mobilemultihop.NativeStartLayerMethod, "middle_password": password}, "protocol": protocol, "username": "captured-native-user", "password": password, "fault": fault, "image": worker, "image_sha256": digest, "layers": map[string]string{"entry": windowsCONNECTExecutionEntryLayer(scenario), "final": "off", "entry_password": p.entryPassword}}
	reply, err := p.exchange(ctx, wire)
	if err != nil || json.Unmarshal(reply["peer"], &p.first) != nil || json.Unmarshal(reply["middle_address"], &p.middle) != nil || json.Unmarshal(reply["layers"], &p.layers) != nil {
		t.Fatal("original execution provider omitted source", err)
	}
	keys.reply = p.first.windowsPrefixPeerReply
	endpoint, err := netip.ParseAddrPort(keys.reply.Address)
	middle, middleErr := netip.ParseAddrPort(p.middle)
	if err != nil || middleErr != nil || endpoint.String() != keys.reply.Address || endpoint.Addr() != physical || endpoint.Port() == 0 || middle.Addr() != physical || middle.Port() == 0 || p.first.Schema != 1 || len(p.first.Prefixes) != 1 || p.first.Protocol != protocol || p.first.Middle.Method != protocol || p.first.OpenStreams == nil || p.first.FinalUOTVersion != 2 || p.first.PublicCA == "" {
		t.Fatal("original peer physical/identity inventory changed")
	}
	if protocol == "https-connect" && (p.first.ConnectCA == "" || p.first.ConnectCA == p.first.PublicCA || p.first.ServerName != "speed.cloudflare.com") || protocol == "http-connect" && (p.first.ConnectCA != "" || p.first.ServerName != "") {
		t.Fatal("original independent TLS authority changed")
	}
	if p.layers.Entry != windowsCONNECTExecutionEntryLayer(scenario) || p.layers.Final != "off" || p.layers.FinalTransport == nil {
		t.Fatal("original independent layers absent")
	}
	return p
}
func (p *windowsCONNECTExecutionPeer) stats(t *testing.T, ctx context.Context, action string) (windowsCONNECTPeerReply, uint64, bool, windowsCONNECTExecutionLayers) {
	t.Helper()
	reply, err := p.exchange(ctx, map[string]string{"command": action})
	var value windowsCONNECTPeerReply
	var launches uint64
	var joined bool
	var layers windowsCONNECTExecutionLayers
	if err != nil || json.Unmarshal(reply["peer"], &value) != nil || json.Unmarshal(reply["launches"], &launches) != nil || json.Unmarshal(reply["workers_joined"], &joined) != nil || json.Unmarshal(reply["layers"], &layers) != nil {
		t.Fatal("original peer counters absent", err)
	}
	if value.Address != p.first.Address || value.PublicCA != p.first.PublicCA || value.Protocol != p.first.Protocol || value.ConnectCA != p.first.ConnectCA || value.ServerName != p.first.ServerName || value.OpenStreams == nil || value.FinalUOTVersion != 2 || len(value.Prefixes) != 1 || value.Prefixes[0].Mode != p.first.Prefixes[0].Mode || value.Prefixes[0].ParametersSHA256 != p.first.Prefixes[0].ParametersSHA256 || value.Final.Address != p.first.Final.Address || value.Final.PublicCA != p.first.Final.PublicCA || layers.Entry != p.layers.Entry || layers.Final != "off" || layers.FinalTransport == nil || layers.FinalTransport.Address != p.layers.FinalTransport.Address {
		t.Fatal("original peer source/identity replaced")
	}
	return value, launches, joined, layers
}
func windowsCONNECTExecutionSources(t *testing.T, scenario string, p *windowsCONNECTExecutionPeer) (common.RouterProfileStore, map[string]map[string]map[string][]byte) {
	t.Helper()
	_, _, requested, _, fault, _ := windowsCONNECTExecutionScenario(scenario)
	profiles, assets := windowsCONNECTInstalledSources(t, p.peer, p.protocol, p.password, p.first.ServerName, fault)
	middle := &profiles.Profiles[1]
	address, _ := netip.ParseAddrPort(p.middle)
	middle.Endpoint = address.Addr().String()
	proxy := middle.External.HTTPConnect
	if p.protocol == "https-connect" {
		proxy = middle.External.HTTPSConnect
	}
	proxy.Host = address.Addr().String()
	proxy.Port = int(address.Port())
	profiles.Profiles[0].StartLayer = p.layers.Entry
	profiles.Profiles[2].StartLayer = "off"
	profiles.Profiles[2].MultihopExecution = requested
	if p.layers.Entry != "off" {
		outer := p.layers.EntryTransport
		if outer == nil || outer.Method != mobilemultihop.NativeStartLayerMethod {
			t.Fatal("original entry layer absent")
		}
		address, err := netip.ParseAddrPort(outer.Address)
		if err != nil || address.Addr().String() != p.physical || address.Port() == 0 || p.layers.Entry == "aes-256-gcm+xor-whitening" && address.Port() != 8389 {
			t.Fatal("original entry layer physical endpoint changed")
		}
		raw, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}}, "outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": p.physical, "server_port": int(address.Port()), "method": mobilemultihop.NativeStartLayerMethod, "password": p.entryPassword}}, "route": map[string]any{"final": "proxy"}})
		if err != nil {
			t.Fatal(err)
		}
		assets[profiles.Profiles[0].ID]["shadowsocks"] = map[string][]byte{"sing-box.json": raw}
	} else if p.layers.EntryTransport != nil {
		t.Fatal("Off borrowed layer ownership")
	}
	for i := range profiles.Profiles {
		if err := common.NormalizeRouterProfile(&profiles.Profiles[i]); err != nil {
			t.Fatal(err)
		}
	}
	return profiles, assets
}
