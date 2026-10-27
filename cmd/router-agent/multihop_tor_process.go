package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/multihoprelay"
)

const serverTorSourcesDirectory = "/etc/router-vpn/tor-sources"

// Only this admitted production wrapper advertises the native Tor contract.
// A bare relayExecRunner, missing package, or unprovisioned source cannot do so.
type relayTorExecRunner struct {
	relayExecRunner
	sources  string
	runtime  string
	core     string
	coreInfo os.FileInfo
	binary   *mobiletor.ServerTorBinary
}

func installedRelayRunner(cfg multihoprelay.Config, node string) (multihoprelay.Runner, error) {
	if len(cfg.TorExits) == 0 {
		return relayExecRunner{}, nil
	}
	binary, err := mobiletor.VerifyServerTorPackage("/usr/local")
	if err != nil {
		return nil, errors.New("installed native Tor relay package is unavailable")
	}
	core := "/usr/local/bin/sing-box"
	info, err := os.Lstat(core)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("installed native Tor relay core is unavailable")
	}
	runner := &relayTorExecRunner{sources: serverTorSourcesDirectory, runtime: "/run/router-vpn-relays", core: core, coreInfo: info, binary: binary}
	for _, source := range cfg.TorExits {
		if _, err := runner.source(source, node); err != nil {
			return nil, err
		}
	}
	return runner, nil
}

func (r *relayTorExecRunner) source(source multihoprelay.TorExitSource, node string) (*mobiletor.ServerTorPolicy, error) {
	bad := errors.New("private server Tor source is unavailable or changed")
	if !relayExternalDigest.MatchString(source.SourceSHA256) {
		return nil, bad
	}
	raw, err := readPrivilegedState(filepath.Join(r.sources, source.SourceSHA256+".json"), 64<<10)
	if err != nil {
		return nil, bad
	}
	defer clear(raw)
	policy, err := mobiletor.NewServerTorPolicy(string(raw), node)
	if err != nil || policy.ID() != source.ID || policy.Mode() != source.Mode || policy.SourceSHA256() != source.SourceSHA256 || policy.DNSPolicySHA256() != source.DNSPolicySHA256 {
		return nil, bad
	}
	return policy, nil
}
func (r *relayTorExecRunner) current() bool {
	if r == nil || r.binary == nil || !r.binary.Current() {
		return false
	}
	info, err := os.Lstat(r.core)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 && os.SameFile(info, r.coreInfo) && info.Size() == r.coreInfo.Size() && info.ModTime().Equal(r.coreInfo.ModTime())
}

type relayTorProcess struct {
	process    *relayProcess
	capture    multihoprelay.TorCapture
	started    time.Time
	input      io.WriteCloser
	responses  chan multihoprelay.TorIPCResponse
	readerDone chan struct{}
	gate       chan struct{}
	closed     atomic.Bool
	bad        atomic.Bool
	sequence   uint64 // protected by gate
}

func (r *relayTorExecRunner) StartTor(ctx context.Context, capture multihoprelay.TorCapture) (multihoprelay.TorProcess, error) {
	bad := errors.New("owned native Tor relay could not start")
	if ctx == nil || ctx.Err() != nil || capture.Validate() != nil || !r.current() {
		return nil, bad
	}
	policy, err := r.source(capture.Source, capture.Request.EntryNodeID)
	if err != nil {
		return nil, bad
	}
	if err := validatePrivilegedStateParent(filepath.Join(r.runtime, "lease")); err != nil {
		return nil, bad
	}
	info, err := os.Lstat(r.runtime)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, bad
	}
	dir, err := os.MkdirTemp(r.runtime, "tor-")
	if err != nil {
		return nil, bad
	}
	adopted := false
	defer func() {
		if !adopted {
			_ = os.RemoveAll(dir)
		}
	}()
	raw, err := json.Marshal(capture)
	if err != nil || atomicWritePrivilegedState(filepath.Join(dir, "tor-capture.json"), raw) != nil || atomicWritePrivilegedState(filepath.Join(dir, "tor-source.json"), []byte(policy.Source())) != nil {
		return nil, bad
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, bad
	}
	defer func() {
		if !adopted {
			_ = root.Close()
		}
	}()
	command := exec.Command(r.core, "routervpn-tor-relay", "--runtime-dir", dir)
	command.Dir = dir
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}
	command.Stderr = io.Discard
	input, err := command.StdinPipe()
	if err != nil {
		return nil, bad
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, bad
	}
	if configureRelayProcess(command) != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, bad
	}
	process, err := startOwnedRelayProcess(command, dir)
	if err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, bad
	}
	process.root = root
	adopted = true
	p := newRelayTorProcess(process, capture, input, output)
	if !r.current() {
		return p, bad
	}
	request, err := torIPCNonce()
	if err != nil {
		return p, bad
	}
	receipt, err := p.Snapshot(ctx, request)
	if err != nil || receipt.Phase != multihoprelay.TorPending {
		return p, bad
	}
	return p, nil
}
func newRelayTorProcess(process *relayProcess, capture multihoprelay.TorCapture, input io.WriteCloser, output io.ReadCloser) *relayTorProcess {
	p := &relayTorProcess{process: process, capture: capture, started: time.Now(), input: input, responses: make(chan multihoprelay.TorIPCResponse, 1), readerDone: make(chan struct{}), gate: make(chan struct{}, 1)}
	go func() {
		defer close(p.readerDone)
		defer output.Close()
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 8192), 16384)
		for scanner.Scan() {
			var response multihoprelay.TorIPCResponse
			decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || response.Schema != 1 {
				p.bad.Store(true)
				return
			}
			if response.Operation == "closed" {
				if response.OK && response.Nonce == capture.OwnerID {
					p.closed.Store(true)
				} else {
					p.bad.Store(true)
				}
				continue
			}
			select {
			case p.responses <- response:
			case <-process.done:
				p.bad.Store(true)
				return
			}
		}
		if scanner.Err() != nil {
			p.bad.Store(true)
		}
	}()
	return p
}
func (p *relayTorProcess) Alive() bool { return p != nil && !p.bad.Load() && p.process.Alive() }
func torIPCNonce() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
func (p *relayTorProcess) lock(ctx context.Context) error {
	select {
	case p.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *relayTorProcess) request(ctx context.Context, operation, nonce string) (multihoprelay.TorIPCResponse, error) {
	bad := errors.New("owned Tor process channel did not answer")
	request := multihoprelay.TorIPCRequest{Schema: 1, Operation: operation, Nonce: nonce}
	if ctx == nil || ctx.Err() != nil || !request.Valid() || !p.process.Alive() {
		return multihoprelay.TorIPCResponse{}, bad
	}
	if file, ok := p.input.(*os.File); ok {
		deadline := time.Now().Add(time.Second)
		if end, exists := ctx.Deadline(); exists && end.Before(deadline) {
			deadline = end
		}
		if file.SetWriteDeadline(deadline) != nil {
			return multihoprelay.TorIPCResponse{}, bad
		}
		defer file.SetWriteDeadline(time.Time{})
	}
	if json.NewEncoder(p.input).Encode(request) != nil {
		return multihoprelay.TorIPCResponse{}, bad
	}
	for {
		select {
		case response := <-p.responses:
			if response.Nonce != nonce {
				continue
			} // an expired operation cannot satisfy this fresh request
			if response.Operation != operation || !response.OK || p.bad.Load() {
				return multihoprelay.TorIPCResponse{}, bad
			}
			return response, nil
		case <-p.readerDone:
			return multihoprelay.TorIPCResponse{}, bad
		case <-ctx.Done():
			return multihoprelay.TorIPCResponse{}, bad
		}
	}
}
func (p *relayTorProcess) Snapshot(ctx context.Context, nonce string) (multihoprelay.TorReceipt, error) {
	if ctx == nil {
		return multihoprelay.TorReceipt{}, errors.New("Tor snapshot requires context")
	}
	if err := p.lock(ctx); err != nil {
		return multihoprelay.TorReceipt{}, err
	}
	defer func() { <-p.gate }()
	response, err := p.request(ctx, "snapshot", nonce)
	if err != nil || !p.Alive() || response.Receipt.Sequence <= p.sequence || multihoprelay.ValidateTorReceipt(response.Receipt, p.capture, nonce, p.started, time.Now()) != nil {
		return multihoprelay.TorReceipt{}, errors.New("owned native Tor snapshot is invalid")
	}
	p.sequence = response.Receipt.Sequence
	return response.Receipt, nil
}
func (p *relayTorProcess) Bootstrap(ctx context.Context) error {
	nonce, err := torIPCNonce()
	if err != nil {
		return err
	}
	if err := p.lock(ctx); err != nil {
		return err
	}
	_, err = p.request(ctx, "bootstrap", nonce)
	<-p.gate
	if err != nil {
		return err
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		nonce, err := torIPCNonce()
		if err != nil {
			return err
		}
		receipt, err := p.Snapshot(ctx, nonce)
		if err != nil {
			return err
		}
		if receipt.Phase == multihoprelay.TorReady {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (p *relayTorProcess) Stop(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Tor stop requires context")
	}
	if err := p.lock(ctx); err != nil {
		return err
	}
	defer func() { <-p.gate }()
	if p.process.Alive() && !p.closed.Load() {
		nonce, err := torIPCNonce()
		if err != nil {
			return err
		}
		if _, err = p.request(ctx, "stop", nonce); err != nil && !p.closed.Load() {
			return err
		}
	}
	select {
	case <-p.process.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-p.readerDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if !p.closed.Load() {
		return errors.New("native Tor worker exited without its complete cleanup acknowledgement")
	}
	_ = p.input.Close()
	return p.process.Stop(ctx)
}
