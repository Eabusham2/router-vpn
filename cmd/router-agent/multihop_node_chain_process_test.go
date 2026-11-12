package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

func chainPipeCapture(t *testing.T) multihoprelay.NodeChainCapture {
	t.Helper()
	source := multihoprelay.NodeChainDescriptor{Schema: 1, EntryID: "original-entry", EntryNodeID: strings.Repeat("1", 64), EntryMode: "wg", SourceSHA256: strings.Repeat("2", 64), DNSPolicySHA256: strings.Repeat("3", 64), Members: []multihoprelay.NodeChainMember{{Position: 1, ProfileID: "final", NodeID: strings.Repeat("4", 64), Mode: "shadowsocks", StartLayer: "off"}}}
	digest, err := source.Digest()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	request := multihoprelay.NodeChainRequest{Schema: 1, SessionID: strings.Repeat("5", 32), EntryNodeID: source.EntryNodeID, SourceSHA256: source.SourceSHA256, DescriptorSHA256: digest, DNSPolicySHA256: source.DNSPolicySHA256, Epoch: strings.Repeat("6", 64), Peer: "10.77.0.2", AcquireExpiresAt: time.Now().Add(time.Minute).Unix(), LocalPacketPublicKeys: []string{base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}, Port: 26240, Users: []multihoprelay.NodeChainUser{{Position: 1, Username: strings.Repeat("7", 48), Password: strings.Repeat("8", 48)}}}
	capture := multihoprelay.NodeChainCapture{Schema: 1, Request: request, Source: source, RegistrySHA256: digest, OwnerID: strings.Repeat("9", 64), Peer: request.Peer, Host: "10.77.0.1", BootstrapDeadline: time.Now().Add(time.Minute).UTC()}
	if capture.Validate() != nil {
		t.Fatal("invalid complete fixture")
	}
	return capture
}

// The child is an explicit native-receipt boundary double. Pipes, executable
// launch, nonce correlation, sole Wait and workspace retirement are actual.
func TestServerNodeChainIPCChild(t *testing.T) {
	mode := os.Getenv("ROUTER_VPN_CHAIN_IPC_FIXTURE")
	if mode == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(os.Getenv("ROUTER_VPN_CHAIN_IPC_DIRECTORY"), "capture.json"))
	if err != nil {
		os.Exit(90)
	}
	capture, err := multihoprelay.DecodeNodeChainCapture(raw)
	if err != nil {
		os.Exit(91)
	}
	digest, _ := capture.Digest()
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	ready := false
	sequence := uint64(0)
	proofAt := int64(0)
	stops := 0
	for scanner.Scan() {
		q, err := multihoprelay.DecodeNodeChainIPCRequest(scanner.Bytes())
		if err != nil || q.CaptureSHA256 != digest {
			os.Exit(92)
		}
		r := multihoprelay.NodeChainIPCResponse{Schema: 1, Operation: q.Operation, Nonce: q.Nonce, CaptureSHA256: digest, OK: true}
		switch q.Operation {
		case "snapshot":
			sequence++
			receipt := multihoprelay.NodeChainReceipt{Schema: 1, SessionID: capture.Request.SessionID, OwnerID: capture.OwnerID, Peer: capture.Peer, SourceSHA256: capture.Source.SourceSHA256, RegistrySHA256: capture.RegistrySHA256, DNSPolicySHA256: capture.Source.DNSPolicySHA256, CaptureSHA256: digest, Nonce: q.Nonce, Sequence: sequence, HeartbeatAt: time.Now().UnixMilli(), Phase: multihoprelay.NodeChainPending, FrontReady: true}
			if ready {
				receipt.Phase = multihoprelay.NodeChainReady
				receipt.TrafficAllowed = true
				receipt.DNSProven = true
				receipt.PublicProven = true
				receipt.ProofAt = proofAt
				for _, member := range capture.Source.Members {
					receipt.Prefixes = append(receipt.Prefixes, multihoprelay.NodeChainPrefixReceipt{Position: member.Position, ProfileID: member.ProfileID, NodeID: member.NodeID, Mode: member.Mode, Proven: true, ResponseMS: 1.25})
				}
			}
			switch mode {
			case "wrong-source":
				receipt.SourceSHA256 = strings.Repeat("f", 64)
			case "wrong-capture":
				r.CaptureSHA256 = strings.Repeat("f", 64)
			case "wrong-nonce":
				receipt.Nonce = strings.Repeat("f", 64)
			case "replay":
				receipt.Sequence = 1
			case "pending-traffic":
				receipt.TrafficAllowed = true
			case "missing-dns":
				if ready {
					receipt.DNSProven = false
				}
			case "missing-member":
				if ready {
					receipt.Prefixes = nil
				}
			case "foreign-member":
				if ready {
					receipt.Prefixes[0].NodeID = capture.Request.EntryNodeID
				}
			case "future-proof":
				if ready {
					receipt.ProofAt = receipt.HeartbeatAt + 1
				}
			}
			r.Receipt = &receipt
		case "bootstrap":
			ready = true
			proofAt = time.Now().UnixMilli()
		case "stop":
			stops++
			if mode == "no-cleanup" {
				os.Exit(0)
			}
			if mode == "retry-cleanup" && stops == 1 {
				r.OK = false
				_ = encoder.Encode(r)
				continue
			}
			_ = encoder.Encode(r)
			terminal := multihoprelay.NodeChainIPCResponse{Schema: 1, Operation: "closed", Nonce: capture.OwnerID, CaptureSHA256: digest, OK: true}
			if mode == "wrong-cleanup-owner" {
				terminal.Nonce = strings.Repeat("f", 64)
			}
			if mode == "wrong-cleanup-capture" {
				terminal.CaptureSHA256 = strings.Repeat("f", 64)
			}
			_ = encoder.Encode(terminal)
			if mode == "duplicate-cleanup" {
				_ = encoder.Encode(terminal)
			}
			if mode == "trailing-malformed" {
				_, _ = io.WriteString(os.Stdout, "not-json\n")
			}
			if mode == "exit-error" {
				os.Exit(19)
			}
			os.Exit(0)
		}
		if mode == "duplicate-schema" && q.Operation == "snapshot" {
			raw, _ := json.Marshal(r)
			_, _ = fmt.Fprintln(os.Stdout, strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1))
			continue
		}
		if mode == "missing-native-field" && q.Operation == "snapshot" {
			raw, _ := json.Marshal(r)
			_, _ = fmt.Fprintln(os.Stdout, strings.Replace(string(raw), `"front_ready":true,`, "", 1))
			continue
		}
		if encoder.Encode(r) != nil {
			os.Exit(93)
		}
	}
	os.Exit(0)
}
func chainPipeProcess(t *testing.T, mode string) (*relayNodeChainProcess, string) {
	t.Helper()
	capture := chainPipeCapture(t)
	dir := filepath.Join(t.TempDir(), "original")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(capture)
	if err := os.WriteFile(filepath.Join(dir, "capture.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := newRelayNodeChainProcess(capture, dir, info)
	p.root, err = os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestServerNodeChainIPCChild$")
	command.Env = append(os.Environ(), "ROUTER_VPN_CHAIN_IPC_FIXTURE="+mode, "ROUTER_VPN_CHAIN_IPC_DIRECTORY="+dir)
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
	return p, dir
}
func TestServerNodeChainIPCRealProcessJoinedReceipt(t *testing.T) {
	p, dir := chainPipeProcess(t, "normal")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	nonce, _ := torIPCNonce()
	r, err := p.Snapshot(ctx, nonce)
	if err != nil || r.Phase != multihoprelay.NodeChainPending || r.TrafficAllowed {
		t.Fatal("pending child lost its closed front receipt", err)
	}
	if err := p.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	nonce, _ = torIPCNonce()
	r, err = p.Snapshot(ctx, nonce)
	if err != nil || r.Phase != multihoprelay.NodeChainReady || !r.DNSProven || len(r.Prefixes) != 1 {
		t.Fatal("fresh challenged complete proof missing", err)
	}
	proofAt := r.ProofAt
	nonce, _ = torIPCNonce()
	r, err = p.Snapshot(ctx, nonce)
	if err != nil || r.ProofAt != proofAt {
		t.Fatal("status refreshed original proof time", err)
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
	default:
		t.Fatal("stop preceded sole Wait")
	}
	select {
	case <-p.readerDone:
	default:
		t.Fatal("stop preceded terminal pipe drain")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("original workspace remained after joined stop", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte("new owner"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "replacement")); err != nil {
		t.Fatal("idempotent old cleanup removed replacement", err)
	}
}
func TestServerNodeChainIPCRejectsFalseProofAuthority(t *testing.T) {
	for _, mode := range []string{"wrong-source", "wrong-capture", "wrong-nonce", "replay", "pending-traffic", "missing-dns", "missing-member", "foreign-member", "future-proof", "duplicate-schema", "missing-native-field"} {
		t.Run(mode, func(t *testing.T) {
			p, dir := chainPipeProcess(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			nonce, _ := torIPCNonce()
			_, err := p.Snapshot(ctx, nonce)
			switch mode {
			case "replay":
				if err != nil {
					t.Fatal("baseline failed", err)
				}
				nonce, _ = torIPCNonce()
				_, err = p.Snapshot(ctx, nonce)
			case "missing-dns", "missing-member", "foreign-member", "future-proof":
				if err != nil {
					t.Fatal("pending baseline failed", err)
				}
				err = p.Bootstrap(ctx)
			}
			if err == nil {
				t.Fatal("false original native proof was accepted")
			}
			if _, err := os.Stat(dir); err != nil {
				t.Fatal("proof refusal discarded original cleanup authority", err)
			}
		})
	}
}
func TestServerNodeChainIPCRetainsUnconfirmedOriginalCleanup(t *testing.T) {
	for _, mode := range []string{"no-cleanup", "wrong-cleanup-owner", "wrong-cleanup-capture", "duplicate-cleanup", "trailing-malformed", "exit-error"} {
		t.Run(mode, func(t *testing.T) {
			p, dir := chainPipeProcess(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if err := p.Stop(ctx); err == nil {
				t.Fatal("unconfirmed cleanup released original lease")
			}
			if p.cleaned {
				t.Fatal("failed cleanup was marked completed")
			}
			if _, err := os.Stat(dir); err != nil {
				t.Fatal("unconfirmed original workspace was removed", err)
			}
		})
	}
}
func TestServerNodeChainIPCFailedCloseRetriesExactOwner(t *testing.T) {
	p, dir := chainPipeProcess(t, "retry-cleanup")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := p.Stop(ctx); err == nil {
		t.Fatal("first failed native close was acknowledged")
	}
	if !p.running() || p.cleaned {
		t.Fatal("failed close lost original live owner")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal("same original close could not retry", err)
	}
	if !p.cleaned {
		t.Fatal("confirmed retry retained ownership")
	}
}
func TestServerNodeChainIPCReplacementWorkspaceCannotBeAdopted(t *testing.T) {
	p, dir := chainPipeProcess(t, "normal")
	initial, finish := context.WithTimeout(t.Context(), 3*time.Second)
	nonce, _ := torIPCNonce()
	if _, err := p.Snapshot(initial, nonce); err != nil {
		finish()
		t.Fatal("original child baseline failed", err)
	}
	finish()
	retired := dir + "-retained"
	if err := os.Rename(dir, retired); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "replacement")
	if err := os.WriteFile(marker, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := p.Stop(ctx); err == nil {
		t.Fatal("replacement workspace accepted as original cleanup")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("replacement workspace was touched", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(retired, dir); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal("retained original workspace could not finish cleanup", err)
	}
}

func TestServerNodeChainIPCCallerCancelAtOriginalReadback(t *testing.T) {
	p, _ := chainPipeProcess(t, "normal")
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	reads := 0
	p.current = func() bool {
		reads++
		if reads == 2 {
			cancel()
		}
		return true
	}
	nonce, _ := torIPCNonce()
	if _, err := p.Snapshot(ctx, nonce); err == nil {
		t.Fatal("expired caller adopted a late native receipt")
	}
	if reads != 2 || p.sequence != 0 || !p.Alive() {
		t.Fatal("caller cancellation changed original native lifetime")
	}
}
