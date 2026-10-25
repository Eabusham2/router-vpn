package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type relayExecRunner struct{}
type relayProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	dir     string
	rootMu  sync.Mutex
	root    *os.Root
	capture multihoprelay.NativeOpenVPNCapture
}

func (p *relayProcess) Alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}
func (p *relayProcess) Stop(ctx context.Context) error {
	if p.Alive() {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
		p.rootMu.Lock()
		defer p.rootMu.Unlock()
		if p.root != nil {
			// Delete only the directory whose descriptor was captured before
			// launch. A replacement at the old path is never our workspace.
			actual, err := p.root.Stat(".")
			current, pathErr := os.Lstat(p.dir)
			if err != nil || pathErr != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(actual, current) {
				return errors.New("owned relay directory identity changed")
			}
			directory, err := p.root.Open(".")
			if err != nil {
				return errors.New("owned relay directory cleanup failed")
			}
			entries, readErr := directory.ReadDir(-1)
			closeErr := directory.Close()
			if readErr != nil || closeErr != nil {
				return errors.New("owned relay directory cleanup failed")
			}
			for _, entry := range entries {
				if err := p.root.RemoveAll(entry.Name()); err != nil {
					return errors.New("owned relay directory cleanup failed")
				}
			}
			current, pathErr = os.Lstat(p.dir)
			if pathErr != nil || !os.SameFile(actual, current) || os.Remove(p.dir) != nil {
				return errors.New("owned relay directory cleanup failed")
			}
			if err := p.root.Close(); err != nil {
				return errors.New("owned relay directory close failed")
			}
			p.root = nil
			return nil
		}
		if p.capture.Validate() == nil {
			return nil
		}
		return os.RemoveAll(p.dir)
	case <-ctx.Done():
		return errors.New("owned relay process has not exited")
	}
}

// OpenVPNRemote reads only the exact child-owned receipt. Listener readiness,
// a persisted file from an earlier session, and a live PID are insufficient.
func (p *relayProcess) OpenVPNRemote(ctx context.Context) (nativeopenvpn.RemoteReceipt, error) {
	bad := errors.New("owned native OpenVPN remote is unavailable")
	if ctx.Err() != nil || !p.Alive() {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	p.rootMu.Lock()
	defer p.rootMu.Unlock()
	if p.root == nil || p.capture.Validate() != nil {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	query := multihoprelay.NativeOpenVPNQuery{Capture: p.capture, RequestID: hex.EncodeToString(nonce)}
	raw, err := json.Marshal(query)
	if err != nil {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	temporary := ".openvpn-query-" + query.RequestID
	file, err := p.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	defer p.root.Remove(temporary)
	written, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || written != len(raw) || closeErr != nil || p.root.Rename(temporary, "openvpn-query.json") != nil {
		return nativeopenvpn.RemoteReceipt{}, bad
	}
	defer p.root.Remove("openvpn-query.json")
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		receipt, err := p.readOpenVPNReceiptLocked()
		if err == nil && receipt.RequestID == query.RequestID && receipt.Validate(p.capture, time.Now()) == nil && ctx.Err() == nil && p.Alive() {
			return receipt.Remote, nil
		}
		select {
		case <-ctx.Done():
			return nativeopenvpn.RemoteReceipt{}, bad
		case <-p.done:
			return nativeopenvpn.RemoteReceipt{}, bad
		case <-deadline.C:
			return nativeopenvpn.RemoteReceipt{}, bad
		case <-ticker.C:
		}
	}
}

func (p *relayProcess) readOpenVPNReceiptLocked() (multihoprelay.NativeOpenVPNReceipt, error) {
	bad := errors.New("owned native OpenVPN receipt is unavailable")
	info, err := p.root.Lstat("openvpn-remote.json")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > 8192 {
		return multihoprelay.NativeOpenVPNReceipt{}, bad
	}
	file, err := p.root.Open("openvpn-remote.json")
	if err != nil {
		return multihoprelay.NativeOpenVPNReceipt{}, bad
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return multihoprelay.NativeOpenVPNReceipt{}, bad
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	var receipt multihoprelay.NativeOpenVPNReceipt
	if err != nil || int64(len(raw)) != info.Size() || json.Unmarshal(raw, &receipt) != nil {
		return multihoprelay.NativeOpenVPNReceipt{}, bad
	}
	return receipt, nil
}
func (relayExecRunner) Start(ctx context.Context, config []byte, lease multihoprelay.Lease) (multihoprelay.Process, error) {
	root := "/run/router-vpn-relays"
	if err := validatePrivilegedStateParent(filepath.Join(root, "lease")); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != 0700 {
		return nil, errors.New("relay runtime directory must be private")
	}
	dir, err := os.MkdirTemp(root, "lease-")
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			_ = os.RemoveAll(dir)
		}
	}()
	path := filepath.Join(dir, "sing-box.json")
	if err := atomicWritePrivilegedState(path, config); err != nil {
		return nil, err
	}
	var capture multihoprelay.NativeOpenVPNCapture
	var ownedRoot *os.Root
	if lease.OpenVPNRemote {
		sum := sha256.Sum256(config)
		capture = multihoprelay.NativeOpenVPNCapture{Schema: 1, SessionID: lease.SessionID, ConfigSHA256: hex.EncodeToString(sum[:]), ExternalFingerprint: lease.ExternalFingerprint, ExternalAttempt: lease.ExternalAttempt}
		if capture.Validate() != nil {
			return nil, errors.New("invalid captured OpenVPN relay owner")
		}
		raw, err := json.Marshal(capture)
		if err != nil || atomicWritePrivilegedState(filepath.Join(dir, "native-capture.json"), raw) != nil {
			return nil, errors.New("native OpenVPN relay capture could not be written")
		}
		ownedRoot, err = os.OpenRoot(dir)
		if err != nil {
			return nil, errors.New("native OpenVPN relay directory could not be captured")
		}
		defer func() {
			if !adopted {
				_ = ownedRoot.Close()
			}
		}()
	}
	check := exec.CommandContext(ctx, "/usr/local/bin/sing-box", "check", "-c", path)
	check.Dir = dir
	check.Stdout = io.Discard
	check.Stderr = io.Discard
	if err := check.Run(); err != nil {
		return nil, errors.New("pinned server core rejected the relay configuration")
	}
	cmd := exec.Command("/usr/local/bin/sing-box", "run", "-c", path)
	if lease.OpenVPNRemote {
		cmd = exec.Command("/usr/local/bin/sing-box", "routervpn-relay", "--runtime-dir", dir, "--session", lease.SessionID)
	}
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := configureRelayProcess(cmd); err != nil {
		return nil, err
	}
	p, err := startOwnedRelayProcess(cmd, dir)
	if err != nil {
		return nil, err
	}
	p.root, p.capture = ownedRoot, capture
	adopted = true
	// Authenticate the exact fresh credentials. A listener already occupying the
	// port must not be mistaken for the engine just launched.
	for p.Alive() {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		attempt, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		err := probeRelayAuthentication(attempt, lease)
		cancel()
		if err == nil && p.Alive() {
			return p, nil
		}
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-time.After(30 * time.Millisecond):
		}
	}
	return p, errors.New("relay exited before authenticated readiness")
}
func probeRelayAuthentication(ctx context.Context, l multihoprelay.Lease) error {
	if len(l.Username) < 1 || len(l.Username) > 255 || len(l.Password) < 1 || len(l.Password) > 255 {
		return errors.New("invalid relay credentials")
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(l.Host, strconv.Itoa(l.Port)))
	if err != nil {
		return err
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if _, err = c.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return errors.New("relay must require SOCKS username/password authentication")
	}
	auth := append([]byte{1, byte(len(l.Username))}, []byte(l.Username)...)
	auth = append(auth, byte(len(l.Password)))
	auth = append(auth, []byte(l.Password)...)
	if _, err = c.Write(auth); err != nil {
		return err
	}
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{1, 0} {
		return errors.New("relay credential verification failed")
	}
	return nil
}

// Linux parent-death signals follow the creating OS thread, not merely the Go
// process. Keep that thread alive until Wait confirms this exact child exited.
func startOwnedRelayProcess(cmd *exec.Cmd, dir string) (*relayProcess, error) {
	p := &relayProcess{cmd: cmd, done: make(chan struct{}), dir: dir}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(p.done)
		err := cmd.Start()
		started <- err
		if err == nil {
			_ = cmd.Wait()
		}
	}()
	if err := <-started; err != nil {
		<-p.done
		return nil, errors.New("relay engine could not start")
	}
	return p, nil
}
