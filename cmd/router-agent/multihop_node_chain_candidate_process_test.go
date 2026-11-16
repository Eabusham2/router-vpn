package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func candidateProcessCapture(t *testing.T) multihoprelay.NodeChainCandidateCapture {
	t.Helper()
	c := chainPipeCapture(t)
	public := func(seed byte) string {
		key, e := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
		if e != nil {
			t.Fatal(e)
		}
		return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	c.Source.Members[0].Position = 2
	c.Source.Members = append([]multihoprelay.NodeChainMember{{Position: 1, ProfileID: "packet-middle", NodeID: strings.Repeat("a", 64), Mode: "wg", StartLayer: "off", ClientPublicKey: public(51), ServerPublicKey: public(61)}}, c.Source.Members...)
	c.Request.LocalPacketPublicKeys = append(c.Request.LocalPacketPublicKeys, public(91))
	c.Request.Users[0].Position = 2
	c.Request.Users = append([]multihoprelay.NodeChainUser{{Position: 1, Username: strings.Repeat("b", 48), Password: strings.Repeat("c", 48)}}, c.Request.Users...)
	digest, err := c.Source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	c.Request.DescriptorSHA256 = digest
	c.RegistrySHA256 = digest
	if err = c.Validate(); err != nil {
		t.Fatal("invalid real packet fixture", err)
	}
	digest, _ = c.Digest()
	q := multihoprelay.NodeChainCandidateRequest{Schema: 1, Lease: c.Request.Clone(), OwnerID: c.OwnerID, CaptureSHA256: digest, Operation: strings.Repeat("a", 64), ExecutionSHA256: strings.Repeat("b", 64), Trial: strings.Repeat("c", 32), SelectionEpoch: 1, InventorySHA256: strings.Repeat("d", 64), Position: 1, CandidateID: "candidate", CandidateSourceSHA256: strings.Repeat("e", 64), Address: "192.168.1.9:443", DeadlineAt: time.Now().Add(time.Minute).UnixMilli(), Password: strings.Repeat("f", 64)}
	out, err := multihoprelay.NewNodeChainCandidateCapture(c, q, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Only the native receipt endpoint is doubled. The actual process executable,
// inherited pipes, single Wait, response parser and original cleanup run here.
func TestServerNodeChainCandidateIPCChild(t *testing.T) {
	mode := os.Getenv("ROUTER_VPN_CANDIDATE_IPC_FIXTURE")
	if mode == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(os.Getenv("ROUTER_VPN_CHAIN_IPC_DIRECTORY"), "candidate.json"))
	if err != nil {
		os.Exit(90)
	}
	var capture multihoprelay.NodeChainCandidateCapture
	if json.Unmarshal(raw, &capture) != nil || capture.Validate() != nil {
		os.Exit(91)
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), multihoprelay.NodeChainCandidateIPCMaximumBytes+1)
	encoder := json.NewEncoder(os.Stdout)
	closes := 0
	for scanner.Scan() {
		var hint struct {
			Operation string `json:"operation"`
		}
		if json.Unmarshal(scanner.Bytes(), &hint) != nil {
			os.Exit(92)
		}
		if hint.Operation == "stop" {
			q, err := multihoprelay.DecodeNodeChainIPCRequest(scanner.Bytes())
			if err != nil {
				os.Exit(93)
			}
			digest, _ := capture.Lease.Digest()
			_ = encoder.Encode(multihoprelay.NodeChainIPCResponse{Schema: 1, Operation: "stop", Nonce: q.Nonce, CaptureSHA256: digest, OK: true})
			if mode == "terminal-missing" {
				os.Exit(0)
			}
			terminal := multihoprelay.NodeChainIPCResponse{Schema: 1, Operation: "closed", Nonce: capture.Lease.OwnerID, CaptureSHA256: digest, OK: true}
			if mode == "terminal-wrong" {
				terminal.Nonce = strings.Repeat("0", 64)
			}
			_ = encoder.Encode(terminal)
			if mode == "terminal-duplicate" {
				_ = encoder.Encode(terminal)
			}
			if mode == "terminal-nonzero" {
				os.Exit(17)
			}
			os.Exit(0)
		}
		q, err := multihoprelay.DecodeNodeChainCandidateIPCRequest(scanner.Bytes())
		if err != nil {
			os.Exit(94)
		}
		digest, _ := q.Capture.Digest()
		r := multihoprelay.NodeChainCandidateIPCResponse{Schema: 1, Operation: q.Operation, Nonce: q.Nonce, CaptureSHA256: digest, OK: true}
		if q.Operation != "candidate-close" {
			r.Receipt = &multihoprelay.NodeChainCandidateReceipt{Schema: 1, Operation: q.Capture.Request.Operation, OperationOwnerID: q.Capture.OperationOwnerID, CaptureSHA256: digest, DeadlineAt: q.Capture.Request.DeadlineAt, Prepared: true}
		}
		if q.Operation == "candidate-close" {
			closes++
			if mode == "retry-close" && closes == 1 {
				r.OK = false
			}
		}
		if q.Operation == "candidate-prepare" {
			switch mode {
			case "wrong-operation":
				r.Operation = "candidate-status"
			case "wrong-capture":
				r.CaptureSHA256 = strings.Repeat("0", 64)
			case "wrong-owner":
				r.Receipt.OperationOwnerID = strings.Repeat("0", 64)
			case "wrong-deadline":
				r.Receipt.DeadlineAt++
			case "not-ok":
				r.OK = false
				r.Receipt = nil
			case "wrong-nonce":
				r.Nonce = strings.Repeat("0", 64)
			case "duplicate":
				_ = encoder.Encode(r)
			}
		}
		if encoder.Encode(r) != nil {
			os.Exit(95)
		}
	}
	os.Exit(0)
}
func candidatePipeProcess(t *testing.T, mode string) (*relayNodeChainProcess, multihoprelay.NodeChainCandidateCapture) {
	t.Helper()
	c := candidateProcessCapture(t)
	dir := filepath.Join(t.TempDir(), "owned")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(filepath.Join(dir, "candidate.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(dir)
	p := newRelayNodeChainProcess(c.Lease, dir, info)
	p.root, _ = os.OpenRoot(dir)
	command := exec.Command(os.Args[0], "-test.run=^TestServerNodeChainCandidateIPCChild$")
	command.Env = append(os.Environ(), "ROUTER_VPN_CANDIDATE_IPC_FIXTURE="+mode, "ROUTER_VPN_CHAIN_IPC_DIRECTORY="+dir)
	command.Stderr = io.Discard
	if err := p.start(command); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.input.Close()
		if p.running() {
			_ = command.Process.Kill()
		}
		<-p.done
		<-p.readerDone
		if p.root != nil {
			_ = p.root.Close()
		}
	})
	return p, c
}
func TestServerNodeChainCandidateProcessOriginalLifecycle(t *testing.T) {
	p, c := candidatePipeProcess(t, "original")
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	raw, err := p.NewCandidateOperation(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.NewCandidateOperation(ctx, c); err == nil {
		t.Fatal("duplicate allocation replaced original candidate")
	}
	receipt, err := raw.Prepare(ctx)
	if err != nil || receipt.Validate(c) != nil || !receipt.Prepared {
		t.Fatal("original candidate preparation failed", err)
	}
	if _, err = raw.Prepare(ctx); err == nil {
		t.Fatal("candidate Prepare was not one-shot")
	}
	if _, err = raw.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = raw.Close(ctx); err != nil {
		t.Fatal(err)
	}
	replacement := c.Clone()
	replacement.Request.Operation = strings.Repeat("1", 64)
	replacement.OperationOwnerID = strings.Repeat("2", 64)
	next, err := p.NewCandidateOperation(ctx, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err = raw.Close(ctx); err != nil {
		t.Fatal("joined idempotent close failed", err)
	}
	if p.candidate != next {
		t.Fatal("stale close retired replacement")
	}
	if err = next.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err = p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestServerNodeChainCandidateProcessRefusals(t *testing.T) {
	for _, mode := range []string{"wrong-operation", "wrong-capture", "wrong-owner", "wrong-deadline", "not-ok", "wrong-nonce", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			p, c := candidatePipeProcess(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()
			handle, err := p.NewCandidateOperation(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			_, err = handle.Prepare(ctx)
			if mode == "duplicate" { // Sole reader must join before the sticky duplicate verdict is inspected.
				_ = p.input.Close()
				<-p.done
				<-p.readerDone
				if !p.bad.Load() {
					t.Fatal("duplicate candidate response retained authority")
				}
			} else if err == nil {
				t.Fatal("foreign candidate response gained authority")
			}
		})
	}
}
func TestServerNodeChainCandidateProcessCloseRetainsOriginal(t *testing.T) {
	for _, mode := range []string{"retry-close", "held-prepare", "copied-owner"} {
		t.Run(mode, func(t *testing.T) {
			p, c := candidatePipeProcess(t, "retry-close")
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			raw, err := p.NewCandidateOperation(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			op := raw.(*relayNodeChainCandidateOperation)
			if mode == "copied-owner" {
				forged := &relayNodeChainCandidateOperation{self: op, process: p, capture: c, ctx: op.ctx, cancel: op.cancel}
				if forged.Close(ctx) == nil || p.candidate != op {
					t.Fatal("copied candidate retired original")
				}
				return
			}
			if mode == "held-prepare" {
				entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
				p.current = func() bool { close(entered); <-release; return true }
				go func() { defer close(finished); _, _ = op.Prepare(ctx) }()
				<-entered
				short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
				err = op.Close(short)
				stop()
				if err == nil || p.candidate != op {
					t.Fatal("unjoined candidate preparation released original slot")
				}
				close(release)
				<-finished
				p.current = nil
				return
			}
			if _, err = op.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			if err = op.Close(ctx); err == nil || p.candidate != op {
				t.Fatal("failed native candidate close released original slot")
			}
			if err = op.Close(ctx); err != nil || p.candidate != nil {
				t.Fatal("original close retry failed", err)
			}
		})
	}
}
func TestServerNodeChainCandidateProcessTerminalCleanup(t *testing.T) {
	for _, mode := range []string{"terminal-original", "terminal-missing", "terminal-wrong", "terminal-duplicate", "terminal-nonzero"} {
		t.Run(mode, func(t *testing.T) {
			p, c := candidatePipeProcess(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			raw, err := p.NewCandidateOperation(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = raw.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			nonce, _ := torIPCNonce()
			if err = p.lock(ctx); err != nil {
				t.Fatal(err)
			}
			_, _ = p.request(ctx, "stop", nonce)
			<-p.gate
			<-p.done
			<-p.readerDone
			err = raw.Close(ctx)
			if mode == "terminal-original" {
				if err != nil || p.candidate != nil {
					t.Fatal("joined exact terminal cleanup failed", err)
				}
			} else {
				if err == nil || p.candidate == nil {
					t.Fatal("unproved terminal exit discarded candidate owner")
				}
				if p.Stop(ctx) == nil {
					t.Fatal("unproved terminal exit removed workspace")
				}
			}
		})
	}
}
