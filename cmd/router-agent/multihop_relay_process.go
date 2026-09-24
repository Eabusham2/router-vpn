package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/multihoprelay"
	"runtime"
	"strconv"
	"time"
)

type relayExecRunner struct{}
type relayProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	dir  string
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
		return os.RemoveAll(p.dir)
	case <-ctx.Done():
		return errors.New("owned relay process has not exited")
	}
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
	check := exec.CommandContext(ctx, "/usr/local/bin/sing-box", "check", "-c", path)
	check.Dir = dir
	check.Stdout = io.Discard
	check.Stderr = io.Discard
	if err := check.Run(); err != nil {
		return nil, errors.New("pinned server core rejected the relay configuration")
	}
	cmd := exec.Command("/usr/local/bin/sing-box", "run", "-c", path)
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
