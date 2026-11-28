package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

const serverNodeChainPrefixSourcesDirectory = "/etc/router-vpn/node-chain-prefix-sources"

func (r *relayNodeChainExecRunner) capturePrefixSource(source multihoprelay.NodeChainPrefixDescriptor, node string) (*mobilemultihop.NodeChainServerPrefixPolicy, func() bool, error) {
	bad := errors.New("private ordered prefix source is unavailable or changed")
	if r == nil || source.Validate() != nil || source.EntryNodeID != node {
		return nil, nil, bad
	}
	path := filepath.Join(r.prefixSources, source.SourceSHA256+".json")
	raw, original, err := readNodeChainRegistration(path, nil)
	if err != nil {
		return nil, nil, bad
	}
	defer clear(raw)
	policy, err := mobilemultihop.NewNodeChainServerPrefixPolicy(string(raw))
	if err != nil {
		return nil, nil, bad
	}
	descriptor, err := policy.Descriptor()
	if err != nil {
		return nil, nil, bad
	}
	actual, err := descriptor.Digest()
	expected, other := source.Digest()
	if err != nil || other != nil || actual != expected {
		return nil, nil, bad
	}
	fingerprint := sha256.Sum256(raw)
	current := func() bool {
		raw, _, err := readNodeChainRegistration(path, original)
		defer clear(raw)
		if err != nil || sha256.Sum256(raw) != fingerprint {
			return false
		}
		descriptor, err := policy.Descriptor()
		if err != nil {
			return false
		}
		digest, err := descriptor.Digest()
		return err == nil && digest == expected
	}
	return policy, current, nil
}
func (r *relayNodeChainExecRunner) StartPrefix(ctx context.Context, capture multihoprelay.NodeChainPrefixCapture) (multihoprelay.NodeChainPrefixProcess, error) {
	bad := errors.New("owned ordered prefix relay could not start")
	if r == nil || ctx == nil || ctx.Err() != nil || capture.Validate() != nil {
		return nil, bad
	}
	policy, currentSource, err := r.capturePrefixSource(capture.Source, capture.Request.EntryNodeID)
	if err != nil {
		return nil, bad
	}
	image, info, digest, err := captureRelayNodeChainImage(r.core)
	if err != nil {
		return nil, bad
	}
	defer image.Close()
	if !os.SameFile(info, r.coreInfo) || digest != r.coreSHA || validatePrivilegedStateParent(filepath.Join(r.runtime, "lease")) != nil {
		return nil, bad
	}
	runtimeInfo, err := os.Lstat(r.runtime)
	if err != nil || !runtimeInfo.IsDir() || runtimeInfo.Mode().Perm() != 0700 {
		return nil, bad
	}
	dir, err := os.MkdirTemp(r.runtime, "prefix-")
	if err != nil {
		return nil, bad
	}
	p := newRelayNodeChainPrefixProcess(capture, dir)
	original, err := os.Lstat(dir)
	if err != nil {
		return p, bad
	}
	p.original = original
	p.packetKeys = &r.packetKeys
	keys, err := policy.PacketRuntimeKeys()
	if err != nil {
		return p, bad
	}
	keys = append(keys, capture.Request.LocalPacketPublicKeys...)
	p.packetBase, err = r.packetKeys.reservePrefix(p, keys)
	if err != nil {
		return p, bad
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return p, bad
	}
	p.root = root
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(original, actual) {
		return p, bad
	}
	raw, err := multihoprelay.MarshalNodeChainPrefixWorkerCapture(capture)
	if err != nil {
		return p, bad
	}
	defer clear(raw)
	if atomicWritePrivilegedState(filepath.Join(dir, "node-chain-prefix-capture.json"), raw) != nil || atomicWritePrivilegedState(filepath.Join(dir, "node-chain-prefix-source.json"), []byte(policy.Source())) != nil {
		return p, bad
	}
	p.current = func() bool {
		if !currentSource() {
			return false
		}
		now, err := os.Lstat(r.core)
		return err == nil && os.SameFile(now, r.coreInfo) && now.Size() == r.coreInfo.Size() && now.ModTime().Equal(r.coreInfo.ModTime())
	}
	command := exec.Command("/proc/self/fd/3", "routervpn-node-chain-prefix-relay", "--runtime-dir", dir)
	command.ExtraFiles = []*os.File{image}
	command.Dir = dir
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}
	command.Stderr = io.Discard
	if configureRelayProcess(command) != nil || !p.current() {
		return p, bad
	}
	if err = p.start(command); err != nil {
		return p, bad
	}
	nonce, err := torIPCNonce()
	if err != nil {
		return p, bad
	}
	receipt, err := p.SnapshotPrefix(ctx, nonce)
	if err != nil || receipt.Phase != multihoprelay.NodeChainPrefixPending {
		return p, bad
	}
	return p, nil
}

type relayNodeChainPrefixProcess struct {
	self             *relayNodeChainPrefixProcess
	packetKeys       *relayNodeChainPacketKeyLedger
	packetBase       *relayNodeChainPacketKeyReservation
	capture          multihoprelay.NodeChainPrefixCapture
	digest           string
	started          time.Time
	command          *exec.Cmd
	done             chan struct{}
	waitError        error
	input            io.WriteCloser
	responses        chan multihoprelay.NodeChainPrefixIPCResponse
	readerDone       chan struct{}
	gate             chan struct{}
	closed, bad      atomic.Bool
	responseMu       sync.Mutex
	pendingNonce     string
	responded        bool
	sequence         uint64
	dir              string
	original         os.FileInfo
	root             *os.Root
	removed, cleaned bool
	current          func() bool
	candidateMu      sync.Mutex
	candidate        *relayNodeChainPrefixCandidateOperation
}

func newRelayNodeChainPrefixProcess(c multihoprelay.NodeChainPrefixCapture, dir string) *relayNodeChainPrefixProcess {
	digest, _ := c.Digest()
	p := &relayNodeChainPrefixProcess{capture: c.Clone(), digest: digest, dir: dir, started: time.Now(), gate: make(chan struct{}, 1), responses: make(chan multihoprelay.NodeChainPrefixIPCResponse, 1)}
	p.self = p
	return p
}

func (p *relayNodeChainPrefixProcess) start(command *exec.Cmd) error {
	input, err := command.StdinPipe()
	if err != nil {
		return err
	}
	output, writer, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return err
	}
	command.Stdout = writer
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		_ = writer.Close()
		return err
	}
	p.command, p.input, p.done, p.readerDone = command, input, make(chan struct{}), make(chan struct{})
	_ = writer.Close()
	go func() { p.waitError = command.Wait(); close(p.done) }()
	go p.read(output)
	return nil
}
func (p *relayNodeChainPrefixProcess) read(output io.ReadCloser) {
	defer close(p.readerDone)
	defer output.Close()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 1024), multihoprelay.NodeChainPrefixIPCMaximumBytes+1)
	for scanner.Scan() {
		if p.closed.Load() {
			p.bad.Store(true)
			return
		}
		r, err := multihoprelay.DecodeNodeChainPrefixIPCResponse(scanner.Bytes())
		if err != nil || r.CaptureSHA256 != p.digest || p.closed.Load() {
			p.bad.Store(true)
			return
		}
		if r.Operation == "closed" {
			if r.Nonce != p.capture.OwnerID || !r.OK {
				p.bad.Store(true)
				return
			}
			p.closed.Store(true)
			continue
		}
		p.responseMu.Lock()
		if r.Nonce == p.pendingNonce && p.pendingNonce != "" {
			if p.responded {
				p.bad.Store(true)
			} else {
				p.responded = true
				select {
				case p.responses <- r:
				default:
					p.bad.Store(true)
				}
			}
		}
		p.responseMu.Unlock()
	}
	if scanner.Err() != nil {
		p.bad.Store(true)
	}
}
func (p *relayNodeChainPrefixProcess) running() bool {
	if p == nil || p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}
func (p *relayNodeChainPrefixProcess) Alive() bool {
	return p != nil && !p.bad.Load() && !p.closed.Load() && p.running()
}
func (p *relayNodeChainPrefixProcess) lock(ctx context.Context) error {
	if ctx == nil {
		return errors.New("ordered worker requires a bounded caller")
	}
	select {
	case p.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *relayNodeChainPrefixProcess) request(ctx context.Context, operation, nonce string, candidate *multihoprelay.NodeChainPrefixCandidateCapture) (multihoprelay.NodeChainPrefixIPCResponse, error) {
	bad := errors.New("original ordered process did not answer")
	q := multihoprelay.NodeChainPrefixIPCRequest{Schema: 1, Operation: operation, Nonce: nonce, CaptureSHA256: p.digest, Candidate: candidate}
	if ctx == nil || ctx.Err() != nil || !q.Valid() || !p.running() || p.bad.Load() {
		return multihoprelay.NodeChainPrefixIPCResponse{}, bad
	}
	p.responseMu.Lock()
	select {
	case <-p.responses:
	default:
	}
	p.pendingNonce, p.responded = nonce, false
	p.responseMu.Unlock()
	defer func() { p.responseMu.Lock(); p.pendingNonce = ""; p.responseMu.Unlock() }()
	if file, ok := p.input.(*os.File); ok {
		deadline := time.Now().Add(time.Second)
		if limit, exists := ctx.Deadline(); exists && limit.Before(deadline) {
			deadline = limit
		}
		if file.SetWriteDeadline(deadline) != nil {
			return multihoprelay.NodeChainPrefixIPCResponse{}, bad
		}
		defer file.SetWriteDeadline(time.Time{})
	}
	raw, err := json.Marshal(q)
	if err != nil || ctx.Err() != nil {
		return multihoprelay.NodeChainPrefixIPCResponse{}, bad
	}
	raw = append(raw, '\n')
	if operation == "candidate-prepare" {
		if err := p.beginCandidatePreparePublication(candidate); err != nil {
			return multihoprelay.NodeChainPrefixIPCResponse{}, err
		}
	}
	if written, err := p.input.Write(raw); err != nil || written != len(raw) {
		return multihoprelay.NodeChainPrefixIPCResponse{}, bad
	}
	valid := func(r multihoprelay.NodeChainPrefixIPCResponse) bool {
		return ctx.Err() == nil && r.Nonce == nonce && r.Operation == operation && r.CaptureSHA256 == p.digest && r.OK && !p.bad.Load()
	}
	select {
	case r := <-p.responses:
		if valid(r) {
			return r, nil
		}
	case <-p.readerDone:
		select {
		case r := <-p.responses:
			if valid(r) {
				return r, nil
			}
		default:
		}
	case <-ctx.Done():
	}
	return multihoprelay.NodeChainPrefixIPCResponse{}, bad
}
func (p *relayNodeChainPrefixProcess) SnapshotPrefix(ctx context.Context, nonce string) (multihoprelay.NodeChainPrefixExecutionReceipt, error) {
	if err := p.lock(ctx); err != nil {
		return multihoprelay.NodeChainPrefixExecutionReceipt{}, err
	}
	defer func() { <-p.gate }()
	began := time.Now()
	if p.current != nil && !p.current() {
		return multihoprelay.NodeChainPrefixExecutionReceipt{}, errors.New("original ordered source changed")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	r, err := p.request(bounded, "snapshot", nonce, nil)
	if err != nil || ctx.Err() != nil || r.Receipt == nil || !p.Alive() || r.Receipt.Sequence <= p.sequence || time.Since(began) > time.Second || multihoprelay.ValidateNodeChainPrefixExecutionReceipt(*r.Receipt, p.capture, nonce, p.started, time.Now()) != nil || p.current != nil && !p.current() || ctx.Err() != nil {
		return multihoprelay.NodeChainPrefixExecutionReceipt{}, errors.New("original ordered receipt is invalid")
	}
	p.sequence = r.Receipt.Sequence
	return r.Receipt.Clone(), nil
}
func (p *relayNodeChainPrefixProcess) PreparePrefix(ctx context.Context) error {
	nonce, err := torIPCNonce()
	if err != nil {
		return err
	}
	if err := p.lock(ctx); err != nil {
		return err
	}
	if p.current != nil && !p.current() {
		<-p.gate
		return errors.New("original ordered source changed before bootstrap")
	}
	_, err = p.request(ctx, "prepare", nonce, nil)
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
		r, err := p.SnapshotPrefix(ctx, nonce)
		if err != nil {
			return err
		}
		if r.Phase == multihoprelay.NodeChainPrefixPrepared {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (p *relayNodeChainPrefixProcess) Stop(ctx context.Context) error {
	if err := p.lock(ctx); err != nil {
		return err
	}
	defer func() { <-p.gate }()
	if p.cleaned {
		return nil
	}
	if p.command != nil {
		if p.running() && !p.closed.Load() {
			nonce, err := torIPCNonce()
			if err != nil {
				return err
			}
			if _, err = p.request(ctx, "stop", nonce, nil); err != nil && !p.closed.Load() {
				return err
			}
		}
		if err := p.joinedCleanupProof(ctx); err != nil {
			return err
		}
		_ = p.input.Close()
	}
	return p.cleanup()
}
func (p *relayNodeChainPrefixProcess) cleanup() error {
	bad := errors.New("original ordered workspace cleanup is pending")
	if p.cleaned {
		return nil
	}
	if p.original == nil {
		return bad
	}
	if !p.removed {
		current, err := os.Lstat(p.dir)
		if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(current, p.original) {
			return bad
		}
		if p.root == nil {
			p.root, err = os.OpenRoot(p.dir)
			if err != nil {
				return bad
			}
		}
		actual, err := p.root.Stat(".")
		if err != nil || !os.SameFile(actual, p.original) {
			return bad
		}
		if removeRelayRootContents(p.root) != nil {
			return bad
		}
		current, err = os.Lstat(p.dir)
		if err != nil || !os.SameFile(current, p.original) || os.Remove(p.dir) != nil {
			return bad
		}
		p.removed = true
	}
	if p.root != nil {
		if p.root.Close() != nil {
			return bad
		}
		p.root = nil
	}
	if p.packetBase != nil {
		if p.packetKeys == nil || p.packetKeys.releasePrefix(p.packetBase, p) != nil {
			return bad
		}
		p.packetBase = nil
	}
	p.cleaned = true
	return nil
}

// joinedCleanupProof is only called while the original process gate is held.
// The authenticated terminal receipt and both original joins are required even
// after process death; a bad or absent receipt remains quarantined for retry.
func (p *relayNodeChainPrefixProcess) joinedCleanupProof(ctx context.Context) error {
	if p == nil || ctx == nil || p.command == nil || p.done == nil || p.readerDone == nil {
		return errors.New("ordered worker has no original cleanup proof")
	}
	select {
	case <-p.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-p.readerDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if !p.closed.Load() || p.bad.Load() || p.waitError != nil {
		return errors.New("ordered worker exited without joined original cleanup")
	}
	return ctx.Err()
}
