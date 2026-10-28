package mobiletor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerTorChild owns one foreground standalone Tor and its authenticated
// control session. Closing is a real process/control barrier, never a PID poll.
// The surrounding native worker separately drains its front, PTs and Box.
type ServerTorChild struct {
	root      *os.Root
	directory string
	identity  os.FileInfo
	binary    *ServerTorBinary
	command   *exec.Cmd
	done      chan struct{}
	control   *DesktopControl
	session   *ServerTorSession
	mu        sync.Mutex
	retired   bool
}

func StartServerTorChild(ctx context.Context, directory string, binary *ServerTorBinary, policy *ServerTorPolicy, socksPort int) (child *ServerTorChild, failure error) {
	bad := errors.New("captured server Tor child could not start")
	stage := "input admission"
	defer func() {
		if failure == bad {
			failure = errors.New("captured server Tor child " + stage + " failed")
		}
	}()
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || binary == nil || !binary.Current() || policy == nil {
		return nil, bad
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return nil, bad
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, bad
	}
	child = &ServerTorChild{root: root, directory: directory, identity: info, binary: binary, done: make(chan struct{})}
	stage = "private data creation"
	// Return the partial owner on every subsequent failure. The caller must
	// keep it until Close has joined its actual process and controller.
	if root.Mkdir("tor-data", 0700) != nil {
		return child, bad
	}
	torrc := strings.Join([]string{"ClientOnly 1", "AvoidDiskWrites 1", "SafeLogging 1", "RunAsDaemon 0",
		"DisableNetwork 1", "__ReloadTorrcOnSIGHUP 0", "SocksPort 0", "UseBridges 0",
		// This pinned standalone build disables relay support. Even explicit
		// zero ORPort/DirPort entries are rejected by that upstream build;
		// keep them unset and verify its actual empty listener inventories.
		"DNSPort 0", "TransPort 0", "HTTPTunnelPort 0", "MetricsPort 0",
		"ControlPort 127.0.0.1:auto", "CookieAuthentication 1", "CookieAuthFileGroupReadable 0", "DataDirectoryGroupReadable 0",
		"DataDirectory " + torQuote(filepath.Join(directory, "tor-data")), "CookieAuthFile " + torQuote(filepath.Join(directory, "tor-control.cookie")),
		"ControlPortWriteToFile " + torQuote(filepath.Join(directory, "tor-control.port")), "Log notice stdout"}, "\n") + "\n"
	for name, body := range map[string]string{"torrc": torrc, "tor-defaults": "\n"} {
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return child, bad
		}
		_, writeErr := io.WriteString(f, body)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return child, bad
		}
	}
	command := exec.Command(binary.path, "--defaults-torrc", filepath.Join(directory, "tor-defaults"), "-f", filepath.Join(directory, "torrc"), "--__OwningControllerProcess", strconv.Itoa(os.Getpid()))
	command.Dir = directory
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	stage = "process launch"
	if err := startServerTorChild(command, child.done); err != nil {
		return child, bad
	}
	child.command = command
	stage = "post-launch identity"
	if !child.currentFiles() || !binary.Current() {
		return child, bad
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		stage = "private control publication"
		if ctx.Err() != nil || !child.Alive() || !child.currentFiles() {
			return child, bad
		}
		port, _, portErr := serverTorRead(root, "tor-control.port", 128, true)
		cookie, _, cookieErr := serverTorRead(root, "tor-control.cookie", 32, true)
		if portErr == nil && cookieErr == nil {
			stage = "control endpoint readback"
			text := strings.TrimSuffix(strings.TrimSuffix(string(port), "\n"), "\r")
			address, err := netip.ParseAddrPort(strings.TrimPrefix(text, "PORT="))
			if err != nil || !strings.HasPrefix(text, "PORT=") || address.Addr() != netip.MustParseAddr("127.0.0.1") || address.Port() < 1024 || len(cookie) != 32 || text != "PORT="+address.String() {
				clear(cookie)
				return child, bad
			}
			stage = "control connection"
			connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address.String())
			if err != nil {
				clear(cookie)
				return child, bad
			}
			stage = "SAFECOOKIE authentication"
			child.control, err = NewDesktopControl(ctx, connection, cookie, command.Process.Pid)
			clear(cookie)
			if err != nil {
				return child, err
			}
			stage = "session capture"
			child.session, err = NewServerTorSession(child.control, policy, socksPort)
			if err != nil || ctx.Err() != nil || !child.Alive() || !child.currentFiles() {
				return child, bad
			}
			return child, nil
		}
		clear(cookie)
		if portErr != nil && !os.IsNotExist(portErr) || cookieErr != nil && !os.IsNotExist(cookieErr) {
			return child, bad
		}
		select {
		case <-ctx.Done():
			return child, bad
		case <-child.done:
			return child, bad
		case <-ticker.C:
		}
	}
}

func (p *ServerTorChild) currentFiles() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.root == nil || !p.binary.Current() {
		return false
	}
	actual, err := p.root.Stat(".")
	current, pathErr := os.Lstat(p.directory)
	return err == nil && pathErr == nil && current.IsDir() && current.Mode().Perm() == 0700 && current.Mode()&os.ModeSymlink == 0 && os.SameFile(actual, p.identity) && os.SameFile(actual, current)
}
func (p *ServerTorChild) Alive() bool {
	if p == nil || p.command == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// Joined is an independent witness for ambiguous measurement-control cleanup.
// The signal closes only after this exact foreground child's Cmd.Wait returns;
// a closed front, lost control socket or merely expired lease is insufficient.
func (p *ServerTorChild) Joined() bool {
	if p == nil || p.command == nil || p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return p.command.Process != nil && p.command.Process.Pid > 0 && p.command.ProcessState != nil &&
			p.command.ProcessState.Pid() == p.command.Process.Pid
	default:
		return false
	}
}
func (p *ServerTorChild) Session() *ServerTorSession { return p.session }
func (p *ServerTorChild) Verify(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || !p.Alive() || !p.currentFiles() || p.control == nil {
		return errors.New("server Tor process owner changed")
	}
	return p.control.VerifyProcess(ctx)
}
func (p *ServerTorChild) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("server Tor child close requires a live context")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retired = true
	if p.command != nil {
		if p.session != nil {
			_ = p.session.Quiesce(ctx)
		}
		if p.control != nil {
			_ = p.control.Close()
		}
		if p.Alive() {
			if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
		}
		select {
		case <-p.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if p.root != nil {
		if err := p.root.Close(); err != nil {
			return err
		}
		p.root = nil
	}
	return nil
}
