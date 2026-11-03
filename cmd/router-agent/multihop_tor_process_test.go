package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/multihoprelay"
)

func torPipeCapture(t *testing.T) multihoprelay.TorCapture {
	t.Helper()
	node := strings.Repeat("1", 64)
	source := multihoprelay.TorExitSource{ID: "operator-tor", Mode: "tor", SourceSHA256: strings.Repeat("2", 64), DNSPolicySHA256: strings.Repeat("3", 64)}
	raw, _ := json.Marshal(struct {
		NodeID string                      `json:"node_id"`
		Source multihoprelay.TorExitSource `json:"source"`
	}{node, source})
	digest := sha256.Sum256(raw)
	request := multihoprelay.TorRequest{SessionID: strings.Repeat("a", 32), EntryNodeID: node, ExitID: source.ID, ExitMode: source.Mode, SourceSHA256: source.SourceSHA256, DNSPolicySHA256: source.DNSPolicySHA256, Epoch: strings.Repeat("4", 64), Peer: "10.77.0.2", AcquireExpiresAt: time.Now().Add(time.Minute).Unix()}
	capture := multihoprelay.TorCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: hex.EncodeToString(digest[:]), OwnerID: strings.Repeat("5", 64), Peer: request.Peer, Host: "10.77.0.1", Port: 26240, Username: strings.Repeat("6", 48), Password: strings.Repeat("7", 48), BootstrapDeadline: time.Now().Add(time.Minute)}
	if err := capture.Validate(); err != nil {
		t.Fatal(err)
	}
	return capture
}
func TestServerTorIPCChild(t *testing.T) {
	mode := os.Getenv("ROUTER_VPN_TOR_IPC_FIXTURE")
	if mode == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(os.Getenv("ROUTER_VPN_TOR_IPC_DIRECTORY"), "capture.json"))
	if err != nil {
		os.Exit(90)
	}
	var c multihoprelay.TorCapture
	if json.Unmarshal(raw, &c) != nil || c.Validate() != nil {
		os.Exit(91)
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	ready := false
	var sequence uint64
	for scanner.Scan() {
		var q multihoprelay.TorIPCRequest
		if json.Unmarshal(scanner.Bytes(), &q) != nil || !q.Valid() {
			os.Exit(92)
		}
		response := multihoprelay.TorIPCResponse{Schema: 1, Operation: q.Operation, Nonce: q.Nonce, OK: true}
		switch q.Operation {
		case "snapshot":
			sequence++
			r := multihoprelay.TorReceipt{Schema: 1, SessionID: c.Request.SessionID, OwnerID: c.OwnerID, Peer: c.Peer, SourceSHA256: c.Source.SourceSHA256, RegistrySHA256: c.RegistrySHA256, DNSPolicySHA256: c.Source.DNSPolicySHA256, FrontSHA256: c.FrontSHA256(), Nonce: q.Nonce, Sequence: sequence, HeartbeatAt: time.Now().UnixMilli(), Phase: multihoprelay.TorPending, FrontReady: true}
			if ready {
				r.Phase = multihoprelay.TorReady
				r.Bootstrap = 100
				r.TrafficAllowed = true
				r.ExitIP = "203.0.113.9"
				r.IsTor = true
				r.DNSProven = true
				// This synthetic proof and heartbeat are one observation. A
				// second clock read could put the proof after its own heartbeat.
				r.ProofAt = r.HeartbeatAt
			}
			switch mode {
			case "wrong-source":
				r.SourceSHA256 = strings.Repeat("f", 64)
			case "replay":
				r.Sequence = 1
			case "wrong-front":
				r.FrontSHA256 = strings.Repeat("f", 64)
			case "missing-dns":
				if ready {
					r.DNSProven = false
				}
			case "proof-after-heartbeat":
				if ready {
					r.ProofAt = r.HeartbeatAt + 1
				}
			case "nonce":
				r.Nonce = strings.Repeat("f", 64)
			}
			response.Receipt = r
		case "bootstrap":
			ready = true
		case "stop":
			if mode == "no-cleanup" {
				os.Exit(0)
			}
			_ = encoder.Encode(response)
			terminal := multihoprelay.TorIPCResponse{Schema: 1, Operation: "closed", Nonce: c.OwnerID, OK: true}
			if mode == "wrong-cleanup-owner" {
				terminal.Nonce = strings.Repeat("f", 64)
			}
			_ = encoder.Encode(terminal)
			if mode == "duplicate-cleanup" {
				_ = encoder.Encode(terminal)
			}
			if mode == "closed-then-malformed" {
				_, _ = io.WriteString(os.Stdout, "not-json\n")
			}
			os.Exit(0)
		}
		if encoder.Encode(response) != nil {
			os.Exit(93)
		}
	}
	os.Exit(0)
}
func torPipeProcess(t *testing.T, mode string) (*relayTorProcess, string) {
	t.Helper()
	return torPipeProcessReader(t, mode, nil)
}
func torPipeProcessReader(t *testing.T, mode string, wrap func(io.ReadCloser) io.ReadCloser) (*relayTorProcess, string) {
	t.Helper()
	c := torPipeCapture(t)
	dir := filepath.Join(t.TempDir(), "owned")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("mkdir")
	}
	raw, _ := json.Marshal(c)
	if os.WriteFile(filepath.Join(dir, "capture.json"), raw, 0600) != nil {
		t.Fatal("capture")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerTorIPCChild$")
	cmd.Env = append(os.Environ(), "ROUTER_VPN_TOR_IPC_FIXTURE="+mode, "ROUTER_VPN_TOR_IPC_DIRECTORY="+dir)
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if configureRelayProcess(cmd) != nil {
		t.Skip("requires Linux server process")
	}
	process, output, err := startOwnedRelayTorProcess(cmd, dir)
	if err != nil {
		t.Fatal(err)
	}
	process.root, err = os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	var reader io.ReadCloser = output
	if wrap != nil {
		reader = wrap(reader)
	}
	p := newRelayTorProcess(process, c, input, reader)
	t.Cleanup(func() {
		_ = input.Close()
		if process.Alive() {
			_ = cmd.Process.Kill()
		}
		<-process.done
		<-p.readerDone
		if process.root != nil {
			_ = process.root.Close()
		}
	})
	return p, dir
}
func TestServerTorIPCRealChildNonceProofAndConfirmedCleanup(t *testing.T) {
	p, dir := torPipeProcess(t, "normal")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	nonce, _ := torIPCNonce()
	r, err := p.Snapshot(ctx, nonce)
	if err != nil || r.Phase != multihoprelay.TorPending || r.TrafficAllowed {
		t.Fatal("fresh real child lost its gated pending state", err, r.Phase)
	}
	if err := p.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	nonce, _ = torIPCNonce()
	r, err = p.Snapshot(ctx, nonce)
	if err != nil || r.Phase != multihoprelay.TorReady || !r.DNSProven {
		t.Fatal("fresh challenged proof missing", err)
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.process.done:
	default:
		t.Fatal("cleanup returned before actual Wait")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("joined private workspace retained", err)
	}
	if _, err := p.Snapshot(ctx, nonce); err == nil {
		t.Fatal("closed child served a snapshot")
	}
}
func TestServerTorIPCRejectsWrongOwnerReplayAndUnprovedDNS(t *testing.T) {
	for _, mode := range []string{"wrong-source", "wrong-front", "nonce", "replay", "missing-dns", "proof-after-heartbeat"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := torPipeProcess(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			nonce, _ := torIPCNonce()
			_, err := p.Snapshot(ctx, nonce)
			if mode == "replay" {
				if err != nil {
					t.Fatal(err)
				}
				nonce, _ = torIPCNonce()
				_, err = p.Snapshot(ctx, nonce)
			}
			if mode == "missing-dns" || mode == "proof-after-heartbeat" {
				if err != nil {
					t.Fatal(err)
				}
				err = p.Bootstrap(ctx)
			}
			if err == nil {
				t.Fatal("foreign/replayed/unproved child receipt was accepted")
			}
			stop, cancelStop := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelStop()
			if err := p.Stop(stop); err != nil {
				t.Fatal("rejected child was not joined", err)
			}
		})
	}
}
func TestServerTorIPCCancelAndUnacknowledgedExitRetainOwnership(t *testing.T) {
	p, dir := torPipeProcess(t, "no-cleanup")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if p.Stop(canceled) == nil {
		t.Fatal("canceled stop claimed cleanup")
	}
	if !p.process.Alive() {
		t.Fatal("canceled operation destroyed the retained child")
	}
	ctx, finish := context.WithTimeout(t.Context(), 3*time.Second)
	defer finish()
	if p.Stop(ctx) == nil {
		t.Fatal("unacknowledged native exit claimed complete teardown")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("unconfirmed ownership workspace was deleted", err)
	}
}
func TestServerTorRunnerReadsOnlyExactPrivateOperatorSource(t *testing.T) {
	node := strings.Repeat("1", 64)
	raw := `{"schema":1,"id":"operator-tor","entry_node_id":"` + node + `","mode":"tor","dns":{"mode":"home"},"adguard_ipv4":"192.168.50.133"}`
	policy, err := mobiletor.NewServerTorPolicy(raw, node)
	if err != nil {
		t.Fatal(err)
	}
	source := multihoprelay.TorExitSource{ID: policy.ID(), Mode: policy.Mode(), SourceSHA256: policy.SourceSHA256(), DNSPolicySHA256: policy.DNSPolicySHA256()}
	r := &relayTorExecRunner{sources: t.TempDir()}
	name := filepath.Join(r.sources, source.SourceSHA256+".json")
	if os.WriteFile(name, []byte(policy.Source()), 0600) != nil {
		t.Fatal("source write")
	}
	if _, err := r.source(source, node); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "dns", "node", "symlink", "mode"} {
		t.Run(field, func(t *testing.T) {
			bad := source
			identity := node
			switch field {
			case "id":
				bad.ID = "other"
			case "dns":
				bad.DNSPolicySHA256 = strings.Repeat("f", 64)
			case "node":
				identity = strings.Repeat("f", 64)
			case "mode":
				bad.Mode = "tor-bridge"
			case "symlink":
				backup := name + ".saved"
				if os.Rename(name, backup) != nil || os.Symlink(backup, name) != nil {
					t.Fatal("fixture symlink")
				}
				defer func() { _ = os.Remove(name); _ = os.Rename(backup, name) }()
			}
			if _, err := r.source(bad, identity); err == nil {
				t.Fatal("source borrowed another private identity")
			}
		})
	}
}

// Delay only the parent's first read. The actual child writes its captured
// acknowledgements and exits before the parent can drain the OS pipe.
type torIPCReadGate struct {
	io.ReadCloser
	release <-chan struct{}
}

func (r *torIPCReadGate) Read(body []byte) (int, error) {
	<-r.release
	return r.ReadCloser.Read(body)
}
func TestServerTorIPCExitBeforeReadDrainsConfirmedCleanup(t *testing.T) {
	for _, mode := range []string{"normal", "no-cleanup", "wrong-cleanup-owner", "duplicate-cleanup", "closed-then-malformed"} {
		t.Run(mode, func(t *testing.T) { torIPCExitBeforeRead(t, mode, false) })
	}
}

type torIPCWriteObserver struct {
	io.WriteCloser
	written chan struct{}
}

func (w *torIPCWriteObserver) Write(body []byte) (int, error) {
	n, err := w.WriteCloser.Write(body)
	select {
	case w.written <- struct{}{}:
	default:
	}
	return n, err
}
func TestServerTorIPCCancelledReplyCannotObstructConfirmedCleanup(t *testing.T) {
	torIPCExitBeforeRead(t, "normal", true)
}
func torIPCExitBeforeRead(t *testing.T, mode string, cancelSnapshot bool) {
	t.Helper()
	release := make(chan struct{})
	p, dir := torPipeProcessReader(t, mode, func(reader io.ReadCloser) io.ReadCloser {
		return &torIPCReadGate{ReadCloser: reader, release: release}
	})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if cancelSnapshot {
		original := p.input
		observer := &torIPCWriteObserver{WriteCloser: original, written: make(chan struct{}, 1)}
		p.input = observer
		operation, cancelOperation := context.WithCancel(ctx)
		nonce, err := torIPCNonce()
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := p.Snapshot(operation, nonce); result <- err }()
		select {
		case <-observer.written:
		case <-ctx.Done():
			t.Fatal("snapshot was not sent")
		}
		cancelOperation()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("unread cancelled snapshot acquired proof")
			}
		case <-ctx.Done():
			t.Fatal("cancelled snapshot did not return")
		}
		p.input = original
		if !p.process.Alive() {
			t.Fatal("cancelled snapshot destroyed retained child")
		}
	}
	result := make(chan error, 1)
	go func() { result <- p.Stop(ctx) }()
	select {
	case <-p.process.done:
	case <-ctx.Done():
		t.Fatal("actual child did not exit before its stdout was drained")
	}
	unblock()
	select {
	case err := <-result:
		if mode == "normal" && err != nil {
			t.Fatal("exited child lost its buffered nonce and cleanup receipt", err)
		}
		if mode != "normal" && err == nil {
			t.Fatal("invalid terminal stream claimed confirmed cleanup", mode)
		}
	case <-ctx.Done():
		t.Fatal("confirmed child exit did not join its original reader")
	}
	if mode == "normal" {
		if p.bad.Load() || !p.closed.Load() {
			t.Fatal("joined cleanup did not retain exact terminal receipt")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("confirmed workspace was not retired", err)
		}
	} else if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatal("unconfirmed original workspace was removed", mode, err)
	}
}
