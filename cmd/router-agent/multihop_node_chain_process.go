package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const serverNodeChainSourcesDirectory = "/etc/router-vpn/node-chain-sources"

// This wrapper advertises the ordered contract only after every original
// private source and the installed core are admitted. Ordinary/Tor dispatch
// remains with its original runner, not an ordered fallback.
type relayNodeChainExecRunner struct {
	multihoprelay.Runner
	sources, runtime, core string
	coreInfo               os.FileInfo
	coreSHA                string
}

func installedRelayRunner(cfg multihoprelay.Config, node string) (multihoprelay.Runner, error) {
	base, err := installedTorRelayRunner(cfg, node)
	if err != nil {
		return nil, err
	}
	if len(cfg.NodeChains) == 0 {
		return base, nil
	}
	r := &relayNodeChainExecRunner{Runner: base, sources: serverNodeChainSourcesDirectory, runtime: "/run/router-vpn-relays", core: "/usr/local/bin/sing-box"}
	file, info, digest, err := captureRelayNodeChainImage(r.core)
	if err != nil {
		return nil, errors.New("installed ordered relay core is unavailable")
	}
	_ = file.Close()
	r.coreInfo, r.coreSHA = info, digest
	for _, source := range cfg.NodeChains {
		if _, err := r.source(source, node); err != nil {
			return nil, err
		}
	}
	return r, nil
}
func (r *relayNodeChainExecRunner) StartTor(ctx context.Context, capture multihoprelay.TorCapture) (multihoprelay.TorProcess, error) {
	original, ok := r.Runner.(multihoprelay.TorRunner)
	if !ok {
		return nil, multihoprelay.ErrUnavailable
	}
	return original.StartTor(ctx, capture)
}
func captureRelayNodeChainImage(path string) (*os.File, os.FileInfo, string, error) {
	bad := errors.New("ordered relay executable changed")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0 || before.Size() <= 0 || before.Size() > 256<<20 {
		return nil, nil, "", bad
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, "", bad
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return nil, nil, "", bad
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, 256<<20+1))
	after, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || size != before.Size() || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, nil, "", bad
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, "", bad
	}
	ok = true
	return file, before, hex.EncodeToString(hash.Sum(nil)), nil
}
func (r *relayNodeChainExecRunner) source(source multihoprelay.NodeChainDescriptor, node string) (*mobilemultihop.NodeChainServerPolicy, error) {
	bad := errors.New("private ordered server source is unavailable or changed")
	if r == nil || source.Validate() != nil || source.EntryNodeID != node {
		return nil, bad
	}
	raw, err := readPrivilegedState(filepath.Join(r.sources, source.SourceSHA256+".json"), mobilemultihop.NodeChainInputLimit)
	if err != nil {
		return nil, bad
	}
	defer clear(raw)
	policy, err := mobilemultihop.NewNodeChainServerPolicy(string(raw))
	if err != nil {
		return nil, bad
	}
	actual, err := policy.Descriptor().Digest()
	expected, _ := source.Digest()
	if err != nil || actual != expected {
		return nil, bad
	}
	return policy, nil
}
func (r *relayNodeChainExecRunner) StartChain(ctx context.Context, capture multihoprelay.NodeChainCapture) (multihoprelay.NodeChainProcess, error) {
	bad := errors.New("owned ordered relay could not start")
	if ctx == nil || ctx.Err() != nil || capture.Validate() != nil {
		return nil, bad
	}
	policy, err := r.source(capture.Source, capture.Request.EntryNodeID)
	if err != nil {
		return nil, bad
	}
	image, info, digest, err := captureRelayNodeChainImage(r.core)
	if err != nil {
		return nil, bad
	}
	defer image.Close()
	if !os.SameFile(info, r.coreInfo) || digest != r.coreSHA {
		return nil, bad
	}
	if validatePrivilegedStateParent(filepath.Join(r.runtime, "lease")) != nil {
		return nil, bad
	}
	runtimeInfo, err := os.Lstat(r.runtime)
	if err != nil || !runtimeInfo.IsDir() || runtimeInfo.Mode().Perm() != 0700 {
		return nil, bad
	}
	dir, err := os.MkdirTemp(r.runtime, "chain-")
	if err != nil {
		return nil, bad
	}
	p := newRelayNodeChainProcess(capture, dir, nil)
	original, err := os.Lstat(dir)
	if err != nil {
		return p, bad
	}
	p.original = original
	root, err := os.OpenRoot(dir)
	if err != nil {
		return p, bad
	}
	p.root = root
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(original, current) {
		return p, bad
	}
	raw, err := json.Marshal(capture)
	if err != nil {
		return p, bad
	}
	defer clear(raw)
	if atomicWritePrivilegedState(filepath.Join(dir, "node-chain-capture.json"), raw) != nil || atomicWritePrivilegedState(filepath.Join(dir, "node-chain-source.json"), []byte(policy.Source())) != nil {
		return p, bad
	}
	// The child executes the exact verified open image. A pathname replacement
	// between preflight and exec cannot select another executable.
	command := exec.Command("/proc/self/fd/3", "routervpn-node-chain-relay", "--runtime-dir", dir)
	command.ExtraFiles = []*os.File{image}
	command.Dir = dir
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}
	command.Stderr = io.Discard
	if configureRelayProcess(command) != nil {
		return p, bad
	}
	if err := p.start(command); err != nil {
		return p, bad
	}
	p.current = func() bool {
		actual, err := r.source(capture.Source, capture.Request.EntryNodeID)
		if err != nil || actual.Source() != policy.Source() {
			return false
		}
		current, err := os.Lstat(r.core)
		return err == nil && os.SameFile(current, r.coreInfo) && current.Size() == r.coreInfo.Size() && current.ModTime().Equal(r.coreInfo.ModTime())
	}
	nonce, err := torIPCNonce()
	if err != nil {
		return p, bad
	}
	receipt, err := p.Snapshot(ctx, nonce)
	if err != nil || receipt.Phase != multihoprelay.NodeChainPending {
		return p, bad
	}
	return p, nil
}

type relayNodeChainProcess struct {
	capture          multihoprelay.NodeChainCapture
	digest           string
	started          time.Time
	command          *exec.Cmd
	done             chan struct{}
	waitError        error // written before sole waiter closes done
	input            io.WriteCloser
	responses        chan multihoprelay.NodeChainIPCResponse
	readerDone       chan struct{}
	gate             chan struct{}
	closed, bad      atomic.Bool
	responseMu       sync.Mutex
	pendingNonce     string
	responded        bool
	sequence         uint64 // gate
	dir              string
	original         os.FileInfo
	root             *os.Root // gate after start
	removed, cleaned bool     // exact original directory only
	current          func() bool
}

func newRelayNodeChainProcess(capture multihoprelay.NodeChainCapture, dir string, original os.FileInfo) *relayNodeChainProcess {
	digest, _ := capture.Digest()
	return &relayNodeChainProcess{capture: capture.Clone(), digest: digest, dir: dir, original: original, started: time.Now(), gate: make(chan struct{}, 1), responses: make(chan multihoprelay.NodeChainIPCResponse, 1)}
}
func (p *relayNodeChainProcess) start(command *exec.Cmd) error {
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
	_ = writer.Close()
	p.command, p.input, p.done, p.readerDone = command, input, make(chan struct{}), make(chan struct{})
	go func() { p.waitError = command.Wait(); close(p.done) }()
	go p.read(output)
	return nil
}
func (p *relayNodeChainProcess) read(output io.ReadCloser) {
	defer close(p.readerDone)
	defer output.Close()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 1024), multihoprelay.NodeChainIPCMaximumBytes+1)
	for scanner.Scan() {
		r, err := multihoprelay.DecodeNodeChainIPCResponse(scanner.Bytes())
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
func (p *relayNodeChainProcess) running() bool {
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
func (p *relayNodeChainProcess) Alive() bool {
	return p != nil && !p.bad.Load() && !p.closed.Load() && p.running()
}
func (p *relayNodeChainProcess) lock(ctx context.Context) error {
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
func (p *relayNodeChainProcess) request(ctx context.Context, operation, nonce string) (multihoprelay.NodeChainIPCResponse, error) {
	bad := errors.New("original ordered process did not answer")
	q := multihoprelay.NodeChainIPCRequest{Schema: 1, Operation: operation, Nonce: nonce, CaptureSHA256: p.digest}
	if ctx == nil || ctx.Err() != nil || !q.Valid() || !p.running() || p.bad.Load() {
		return multihoprelay.NodeChainIPCResponse{}, bad
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
			return multihoprelay.NodeChainIPCResponse{}, bad
		}
		defer file.SetWriteDeadline(time.Time{})
	}
	if json.NewEncoder(p.input).Encode(q) != nil {
		return multihoprelay.NodeChainIPCResponse{}, bad
	}
	valid := func(r multihoprelay.NodeChainIPCResponse) bool {
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
	return multihoprelay.NodeChainIPCResponse{}, bad
}
func (p *relayNodeChainProcess) Snapshot(ctx context.Context, nonce string) (multihoprelay.NodeChainReceipt, error) {
	if err := p.lock(ctx); err != nil {
		return multihoprelay.NodeChainReceipt{}, err
	}
	defer func() { <-p.gate }()
	began := time.Now()
	if p.current != nil && !p.current() {
		return multihoprelay.NodeChainReceipt{}, errors.New("original ordered source changed")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	r, err := p.request(bounded, "snapshot", nonce)
	if err != nil || ctx.Err() != nil || r.Receipt == nil || !p.Alive() || r.Receipt.Sequence <= p.sequence || time.Since(began) > time.Second || multihoprelay.ValidateNodeChainReceipt(*r.Receipt, p.capture, nonce, p.started, time.Now()) != nil || p.current != nil && !p.current() || ctx.Err() != nil {
		return multihoprelay.NodeChainReceipt{}, errors.New("original ordered receipt is invalid")
	}
	p.sequence = r.Receipt.Sequence
	return r.Receipt.Clone(), nil
}
func (p *relayNodeChainProcess) Bootstrap(ctx context.Context) error {
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
		r, err := p.Snapshot(ctx, nonce)
		if err != nil {
			return err
		}
		if r.Phase == multihoprelay.NodeChainReady {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (p *relayNodeChainProcess) Stop(ctx context.Context) error {
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
			if _, err = p.request(ctx, "stop", nonce); err != nil && !p.closed.Load() {
				return err
			}
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
		_ = p.input.Close()
	}
	return p.cleanup()
}
func (p *relayNodeChainProcess) cleanup() error {
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
	p.cleaned = true
	return nil
}
