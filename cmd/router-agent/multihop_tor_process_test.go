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
				r.ProofAt = time.Now().UnixMilli()
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
			_ = encoder.Encode(multihoprelay.TorIPCResponse{Schema: 1, Operation: "closed", Nonce: c.OwnerID, OK: true})
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
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if configureRelayProcess(cmd) != nil {
		t.Skip("requires Linux server process")
	}
	process, err := startOwnedRelayProcess(cmd, dir)
	if err != nil {
		t.Fatal(err)
	}
	process.root, err = os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := newRelayTorProcess(process, c, input, output)
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
	for _, mode := range []string{"wrong-source", "wrong-front", "nonce", "replay", "missing-dns"} {
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
			if mode == "missing-dns" {
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
