//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
)

type desktopLinuxNodePin struct {
	file *os.File
	info os.FileInfo
	name string // Relative to the retained installed root.
}

// This owner retains the original installed controller and the child created
// from its pinned runtime image. It supplies process/channel ownership only;
// its Close does not attest firewall retirement or settle a protection journal.
type desktopLinuxNodeProcess struct {
	parent                                    *desktopLinuxNodeParentCapture
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	gate                                      chan struct{}
	root                                      *os.Root
	pins                                      []*desktopLinuxNodePin
	image, workspace                          *desktopLinuxNodePin
	channel                                   *linuxprocess.Channel
	childChannel, parentDirectory, clonePIDFD *os.File
	bootstrap                                 *linuxprocess.Bootstrap
	command                                   *exec.Cmd
	started                                   atomic.Bool
	retiring                                  atomic.Bool
	joined                                    chan struct{}
	waitErr                                   error // Read only after joined closes.
	waitCode                                  uint32
	closed, released                          bool
	closeErr                                  error
}

func startDesktopLinuxNodeProcess(ctx context.Context, parent *desktopLinuxNodeParentCapture, arguments, environment []string,
	directory, captureSHA256 string) (*desktopLinuxNodeProcess, error) {
	return startDesktopLinuxNodeProcessWithVerifier(ctx, parent, arguments, environment, directory, captureSHA256, verifyBundledNativeContext)
}

// The private verifier seam models only package build-metadata verification in
// the native process fixture. Shipping always retains the full verifier above.
// Native controller, files, clone, channel and process checks have no override.
func startDesktopLinuxNodeProcessWithVerifier(ctx context.Context, parent *desktopLinuxNodeParentCapture, arguments, environment []string,
	directory, captureSHA256 string, verify func(context.Context, string) (string, error)) (*desktopLinuxNodeProcess, error) {
	if ctx == nil || ctx.Err() != nil || parent == nil || parent.parent == nil || verify == nil {
		return nil, errors.New("Linux Node launch requires its live captured controller operation")
	}
	arguments, err := validateDesktopNodeProcessArguments(arguments, directory)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for i := 1; i < len(arguments); i += 2 {
		values[arguments[i]] = arguments[i+1]
	}
	wanted, err := linuxprotection.NodeCommandCaptureSHA256(values["--session"], values["--physical-source-sha256"], values["--config-sha256"])
	if err != nil || wanted != captureSHA256 {
		return nil, errors.Join(err, errors.New("Linux Node launch changed its captured native command digest"))
	}
	if err := parent.Current(ctx); err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(linuxOwnedControllerRoot, directory)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("Linux Node workspace belongs to another installed controller")
	}
	lifetime, cancel := context.WithCancel(parent.lifetime)
	p := &desktopLinuxNodeProcess{parent: parent, ctx: lifetime, cancel: cancel, gate: make(chan struct{}, 1), joined: make(chan struct{})}
	// Register before opening any native owner. Parent Close joins this same
	// partial construction and never drops its borrowed process witness first.
	controller := parent.parent
	select {
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case <-lifetime.Done():
		cancel()
		return nil, lifetime.Err()
	case <-controller.gate:
	}
	if err := controller.currentLocked(true); err != nil {
		controller.gate <- struct{}{}
		cancel()
		return nil, err
	}
	if controller.dependents == nil {
		controller.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	controller.dependents[p] = struct{}{}
	p.root, err = controller.root.OpenRoot(".")
	controller.gate <- struct{}{}
	defer func() { p.gate <- struct{}{} }()
	if err != nil {
		return p, err
	}
	launch, stop := context.WithTimeout(ctx, 30*time.Second)
	stopLifetime := context.AfterFunc(lifetime, stop)
	defer func() { stopLifetime(); stop() }()
	if err := p.parent.Current(launch); err != nil {
		return p, err
	}
	p.workspace, err = p.pin(relative, true)
	if err != nil {
		return p, err
	}
	if p.workspace.info.Mode().Perm()&0077 != 0 {
		return p, errors.New("Linux Node workspace is not private to its original controller")
	}
	if err := p.captureRuntime(launch, verify); err != nil {
		return p, err
	}
	p.channel, p.childChannel, err = linuxprocess.ChannelPair()
	if err != nil {
		return p, err
	}
	p.parentDirectory, err = controller.processWitness.DuplicateDirectory(launch)
	if err != nil {
		return p, err
	}
	if err := p.currentFiles(launch); err != nil {
		return p, err
	}
	clone := -1
	args := append(arguments, "--linux-parent-channel", "3", "--linux-parent-directory", "4", "--linux-parent-capture", captureSHA256)
	// The child descriptor table supplies both the actual executable and cwd.
	// Replacing a pathname cannot select a different image between pin and exec.
	p.command = exec.Command("/proc/self/fd/5", args...)
	p.command.Args[0] = filepath.Join(linuxOwnedControllerRoot, p.image.name)
	// Go changes cwd before remapping ExtraFiles. Use this retained original
	// descriptor at that step; the kernel keeps the cwd after exec closes it.
	p.command.Dir = fmt.Sprintf("/proc/self/fd/%d", p.workspace.file.Fd())
	p.command.Env = nativeLibraryEnvironment(append([]string(nil), environment...), filepath.Join(linuxOwnedControllerRoot, "runtime", "native"))
	p.command.Stderr = os.Stderr
	p.command.ExtraFiles = []*os.File{p.childChannel, p.parentDirectory, p.image.file}
	p.command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: &clone}
	if err := p.command.Start(); err != nil {
		return p, err
	}
	p.started.Store(true)
	go func() {
		p.waitErr = p.command.Wait()
		if p.command.ProcessState != nil {
			p.waitCode = uint32(p.command.ProcessState.ExitCode())
		}
		close(p.joined)
	}()
	if clone >= 0 {
		p.clonePIDFD = os.NewFile(uintptr(clone), "linux-original-node-clone")
	}
	if err := p.closeInheritedCopies(); err != nil {
		return p, err
	}
	if p.clonePIDFD == nil {
		return p, errors.New("Linux Node launch omitted its clone-created pidfd")
	}
	image, err := desktopLinuxNodeObjectOf(p.image.info)
	if err != nil {
		return p, err
	}
	p.bootstrap, err = linuxprocess.BindCreatedChild(launch, p.channel, controller.processWitness, p.clonePIDFD, p.command.Process.Pid,
		linuxprocess.Object(image), captureSHA256)
	p.channel, p.clonePIDFD = nil, nil // BindCreatedChild consumes even partial native owners.
	if err != nil {
		return p, err
	}
	if err := p.currentFiles(launch); err != nil {
		return p, err
	}
	if err := p.bootstrap.Current(launch); err != nil {
		return p, err
	}
	return p, nil
}

func (p *desktopLinuxNodeProcess) pin(name string, directory bool) (*desktopLinuxNodePin, error) {
	if p.root == nil || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") {
		return nil, errors.New("Linux Node pin escaped its retained installed root")
	}
	for prefix := filepath.Dir(name); prefix != "."; prefix = filepath.Dir(prefix) {
		info, err := p.root.Lstat(prefix)
		if err != nil || !info.IsDir() || !ownedDesktopInfo(info) {
			return nil, errors.Join(err, errors.New("Linux Node pin has replaced or unprotected ancestry"))
		}
	}
	file, err := p.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	owned := &desktopLinuxNodePin{file: file, name: name}
	p.pins = append(p.pins, owned)
	owned.info, err = file.Stat()
	if err != nil || !ownedDesktopInfo(owned.info) || owned.info.IsDir() != directory || (!directory && !owned.info.Mode().IsRegular()) {
		return owned, errors.Join(err, errors.New("Linux Node pin lost its exact protected native object"))
	}
	if err := ownedPathACL(filepath.Join(linuxOwnedControllerRoot, name)); err != nil {
		return owned, err
	}
	return owned, p.checkPin(owned)
}

func (p *desktopLinuxNodeProcess) checkPin(pin *desktopLinuxNodePin) error {
	if p.root == nil || pin == nil || pin.file == nil || pin.info == nil {
		return errors.New("Linux Node lost a retained package pin")
	}
	actual, err := pin.file.Stat()
	entry, pathErr := p.root.Lstat(pin.name)
	if err != nil || pathErr != nil || !ownedDesktopInfo(actual) || !ownedDesktopInfo(entry) || !os.SameFile(pin.info, actual) || !os.SameFile(pin.info, entry) {
		return errors.Join(err, pathErr, errors.New("Linux Node pinned object was replaced"))
	}
	before, first := pin.info.Sys().(*syscall.Stat_t)
	after, second := actual.Sys().(*syscall.Stat_t)
	if !first || !second || before.Mode != after.Mode || (!pin.info.IsDir() && (pin.info.Size() != actual.Size() || before.Mtim != after.Mtim || before.Ctim != after.Ctim)) {
		return errors.New("Linux Node pinned payload changed after capture")
	}
	return ownedPathACL(filepath.Join(linuxOwnedControllerRoot, pin.name))
}

func (p *desktopLinuxNodeProcess) currentFiles(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.ctx.Err() != nil || p.retiring.Load() || p.closed {
		return errors.New("Linux Node process owner is retired")
	}
	if err := p.parent.Current(ctx); err != nil {
		p.cancel()
		return err
	}
	for _, pin := range p.pins {
		if err := p.checkPin(pin); err != nil {
			p.cancel()
			return err
		}
	}
	if err := p.parent.Current(ctx); err != nil {
		p.cancel()
		return err
	}
	return nil
}

func (p *desktopLinuxNodeProcess) captureRuntime(ctx context.Context, verify func(context.Context, string) (string, error)) error {
	receiptPin, err := p.pin("runtime/native/NATIVE-RUNTIME.json", false)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(receiptPin.file, 32769))
	if err != nil || len(raw) > 32768 {
		return errors.Join(err, errors.New("Linux Node runtime receipt exceeds its captured bound"))
	}
	receipt, err := validateNativeReceipt(raw)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(receipt.Files))
	for name := range receipt.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		pin, err := p.pin(filepath.Join("runtime", "native", name), false)
		if err != nil {
			return err
		}
		expected := receipt.Files[name]
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(pin.file, expected.Size+1))
		if err != nil || pin.info.Size() != expected.Size || n != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return errors.Join(err, errors.New("Linux Node pinned runtime differs from its exact receipt"))
		}
		if name == nativeBinaryName() {
			p.image = pin
		}
	}
	if p.image == nil || p.image.info.Mode().Perm()&0111 == 0 {
		return errors.New("Linux Node has no pinned executable")
	}
	if err := p.currentFiles(ctx); err != nil {
		return err
	}
	binary, err := verify(ctx, linuxOwnedControllerRoot)
	if err != nil || binary != filepath.Join(linuxOwnedControllerRoot, "runtime", "native", nativeBinaryName()) {
		return errors.Join(err, errors.New("Linux Node runtime verification selected a foreign package"))
	}
	return p.currentFiles(ctx)
}

func (p *desktopLinuxNodeProcess) enter(ctx context.Context) error {
	if p == nil || ctx == nil || p.gate == nil || ctx.Err() != nil {
		return errors.New("Linux Node process has no bounded owner operation")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
		return nil
	}
}

func (p *desktopLinuxNodeProcess) Started() bool { return p != nil && p.started.Load() }

func (p *desktopLinuxNodeProcess) Alive() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := p.Bootstrap(ctx)
	return err
}

// The returned capability remains owned by this process. Every Send, Receive
// or Observations operation independently rechecks its original live capture.
func (p *desktopLinuxNodeProcess) Bootstrap(ctx context.Context) (*linuxprocess.Bootstrap, error) {
	if err := p.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { p.gate <- struct{}{} }()
	if err := p.currentFiles(ctx); err != nil {
		return nil, err
	}
	if !p.started.Load() || p.bootstrap == nil {
		return nil, errors.New("Linux Node process has no authenticated created child")
	}
	if err := p.bootstrap.Current(ctx); err != nil {
		return nil, err
	}
	return p.bootstrap, nil
}

func (p *desktopLinuxNodeProcess) Wait(ctx context.Context) (uint32, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || !p.started.Load() {
		return 0, errors.New("Linux Node wait has no original started child")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-p.joined:
		return p.waitCode, p.waitErr
	}
}

func (p *desktopLinuxNodeProcess) closeInheritedCopies() error {
	for _, slot := range []**os.File{&p.childChannel, &p.parentDirectory} {
		if *slot != nil {
			if err := (*slot).Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				p.closeErr = errors.Join(p.closeErr, err)
				return p.closeErr
			}
			*slot = nil
		}
	}
	return p.closeErr
}

func (p *desktopLinuxNodeProcess) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.retiring.Store(true)
	if p.cancel != nil {
		p.cancel()
	}
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { p.gate <- struct{}{} }()
	if p.closed && p.released {
		return p.closeErr
	}
	if p.started.Load() {
		// os.Process retains the actual creation handle. Never signal a decoded
		// PID/process group or treat another process's disappearance as this exit.
		if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.joined:
		}
	}
	if p.bootstrap != nil {
		if err := p.bootstrap.Close(ctx); err != nil {
			return err
		}
		p.bootstrap = nil
	}
	if p.channel != nil {
		if err := p.channel.Close(ctx); err != nil {
			return err
		}
		p.channel = nil
	}
	if err := p.closeInheritedCopies(); err != nil {
		return err
	}
	if p.clonePIDFD != nil {
		if err := p.clonePIDFD.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			p.closeErr = errors.Join(p.closeErr, err)
			return p.closeErr
		}
		p.clonePIDFD = nil
	}
	for index := len(p.pins) - 1; index >= 0; index-- {
		if file := p.pins[index].file; file != nil {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				p.closeErr = errors.Join(p.closeErr, err)
				return p.closeErr
			}
			p.pins[index].file = nil
		}
	}
	if p.root != nil {
		if err := p.root.Close(); err != nil {
			p.closeErr = errors.Join(p.closeErr, err)
			return p.closeErr
		}
		p.root = nil
	}
	if p.closeErr != nil {
		return fmt.Errorf("Linux Node retains failed native retirement: %w", p.closeErr)
	}
	p.closed = true
	if !p.released {
		if err := p.parent.parent.releaseDependent(ctx, p); err != nil {
			return err
		}
		p.released = true
	}
	return nil
}
