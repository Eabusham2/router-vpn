//go:build windows

// Package windowsapp composes the installed and Portable desktop session from
// retained native owners. Public names are rendezvous hints, never authority.
package windowsapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowsbootstrap"
	"router-vpn/internal/windowscontroller"
	"router-vpn/internal/windowsuibridge"
)

type Session struct {
	mu                                     sync.Mutex
	runMu                                  sync.Mutex
	ctx                                    context.Context
	cancel                                 context.CancelCauseFunc
	self, controller                       *windowscontroller.Process
	selfImage, controllerImage, powershell *windowscontroller.Image
	controllerShell                        *windowscontroller.ProtectedShellImage
	directController                       *windowscontroller.GUIChild
	updater                                *windowscontroller.GUIChild
	updaterImage                           *windowscontroller.Image
	updateCache                            *capturedUpdateCache
	pipe                                   *windowscontroller.Pipe
	files                                  []*windowscontroller.CodeFile
	client                                 *controllertransport.Client
	packageRoot, dataRoot                  string
	temporary                              *portableTemporary
	portable                               bool
	environment                            []string
	desktop                                windowscontroller.TokenIdentity
	workers                                sync.WaitGroup
	guis                                   []*gui
	authenticated, receipt, joined, closed bool
}

type gui struct {
	child *windowscontroller.GUIChild
	pipe  *windowscontroller.Pipe
	done  chan error
	ready chan struct{}
}

// Start derives both roots from this actual retained launcher executable. The
// caller must retain a non-nil result even when err is non-nil, and call Close
// until its owned processes have joined; a failed join never releases owners.
func Start(ctx context.Context, portable bool) (_ *Session, failure error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("the Windows app needs its live launch operation")
	}
	s := &Session{portable: portable}
	s.ctx, s.cancel = context.WithCancelCause(ctx)
	defer func() {
		if failure != nil {
			s.cancel(failure)
		}
	}()
	var err error
	s.selfImage, err = windowscontroller.PinCurrentImage()
	if err != nil {
		return s, err
	}
	s.self, err = windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		return s, err
	}
	if err = s.self.VerifyImage(s.selfImage); err != nil {
		return s, err
	}
	s.desktop, err = s.self.Identity()
	if err != nil || !s.desktop.Primary || s.desktop.SID == "" || s.desktop.AuthenticationID == 0 {
		return s, errors.Join(err, errors.New("the Windows app has no captured original desktop identity"))
	}
	launcherName := filepath.Base(s.selfImage.Path())
	validLauncher := strings.EqualFold(launcherName, "RouterVPN.exe")
	s.packageRoot = filepath.Dir(s.selfImage.Path())
	s.dataRoot = s.packageRoot
	if portable {
		validLauncher = windowsbootstrap.IsPortableLauncherName(launcherName)
		s.dataRoot = filepath.Join(s.packageRoot, "Data")
		s.packageRoot = filepath.Join(s.packageRoot, "App", "RouterVPN")
	}
	if !validLauncher {
		return s, errors.New("the Windows app is not its exact installed or Portable launcher")
	}
	s.controllerImage, err = windowscontroller.PinImage(filepath.Join(s.packageRoot, "router-vpn-client.exe"))
	if err != nil {
		return s, err
	}
	s.powershell, err = windowscontroller.PinSystemPowerShell()
	if err != nil {
		return s, err
	}
	if err = s.pinUI(); err != nil {
		return s, err
	}
	if portable {
		if err = PreparePortableData(s.ctx, s.selfImage, s.self); err != nil {
			return s, err
		}
	}
	profile, err := s.self.UserDirectories()
	if err != nil {
		return s, err
	}
	system, err := windowscontroller.SystemDirectory()
	if err != nil {
		return s, err
	}
	appData, localAppData := profile.RoamingAppData, profile.LocalAppData
	temporary := filepath.Join(profile.LocalAppData, "Temp")
	if portable {
		appData, localAppData = s.dataRoot, s.dataRoot
		s.temporary, err = capturePortableTemporary(s.dataRoot, s.desktop.SID)
		if err != nil {
			return s, err
		}
		temporary = s.temporary.path
	}
	s.environment = []string{
		"SystemRoot=" + filepath.Dir(system), "windir=" + filepath.Dir(system),
		"PATH=" + system + ";" + filepath.Dir(system) + ";" + filepath.Join(system, "WindowsPowerShell", "v1.0"),
		"PATHEXT=.COM;.EXE;.BAT;.CMD", "USERPROFILE=" + profile.Profile,
		"PSModulePath=" + filepath.Join(system, "WindowsPowerShell", "v1.0", "Modules"),
		"COMSPEC=" + filepath.Join(system, "cmd.exe"), "OS=Windows_NT",
		"APPDATA=" + appData, "LOCALAPPDATA=" + localAppData,
		"TEMP=" + temporary, "TMP=" + temporary,
		"HOMEVPN_ROOT=" + s.dataRoot, "HOMEVPN_CLIENT_CONFIG=" + filepath.Join(s.dataRoot, "client.json"),
		"HOMEVPN_NATIVE_APP=windows-wpf-product",
	}
	if portable {
		s.environment = append(s.environment, "HOMEVPN_PORTABLE=1", "HOME="+s.dataRoot)
	}
	s.pipe, err = windowscontroller.NewPipe()
	if err != nil {
		return s, err
	}
	arguments, err := windowsbootstrap.Arguments(s.pipe.Name(), s.self.PID(), s.selfImage.Path())
	if err != nil {
		return s, err
	}
	// An already elevated desktop does not require a second UAC operation.
	// Exact image, creation-time Job, primary token and suspended readback still
	// precede execution. Ordinary desktops use the independently retained global
	// mapping for the pre-configuration Shell bootstrap. That operation does not
	// require opening an elevated thread from the original desktop token.
	if s.desktop.Elevated && s.desktop.Administrator {
		s.directController, err = windowscontroller.LaunchGUIChild(s.ctx, s.controllerImage,
			func(uint64) ([]string, error) { return arguments, nil }, s.environment, s.dataRoot)
		if err != nil {
			return s, err
		}
		s.controller, err = s.directController.RetainProcess()
	} else {
		// Assign each returned owner before checking its error. A failed capture
		// can retain native handles, and cancelled consent can still return the
		// exact newly created process. Close joins it before releasing this map.
		s.controllerShell, err = windowscontroller.PinProtectedShellImage(s.controllerImage)
		if err != nil {
			return s, err
		}
		s.controller, err = windowscontroller.LaunchProtectedBootstrapElevated(s.ctx, s.controllerShell, arguments)
	}
	if err != nil {
		return s, err
	}
	if s.controller == nil {
		return s, errors.New("Windows did not return this launch's retained controller")
	}
	bootstrap, stop := context.WithTimeout(s.ctx, 30*time.Second)
	defer stop()
	if err = s.pipe.Accept(bootstrap); err != nil {
		return s, fmt.Errorf("owned Windows controller pipe admission: %w", err)
	}
	frame, err := s.pipe.ReadFrame(bootstrap)
	if err != nil {
		return s, fmt.Errorf("owned Windows controller public hello: %w", err)
	}
	peer, err := s.pipe.VerifyPeer(s.controller, s.controllerImage)
	if err != nil {
		return s, err
	}
	elevated, identityErr := s.controller.Identity()
	writer := peer.Identity
	closeErr := peer.Process.Close()
	if identityErr != nil || closeErr != nil || !elevated.Primary || !elevated.Elevated || !elevated.Administrator ||
		elevated.SessionID != s.desktop.SessionID || writer.Primary ||
		writer.SID != elevated.SID || writer.AuthenticationID != elevated.AuthenticationID ||
		writer.SessionID != elevated.SessionID || writer.Elevated != elevated.Elevated || writer.Administrator != elevated.Administrator {
		return s, errors.Join(identityErr, closeErr, errors.New("the actual controller pipe did not prove its captured administrator consent"))
	}
	hello, err := windowsbootstrap.DecodeHello(frame, s.controller.PID())
	if err != nil {
		return s, err
	}
	credentials, err := windowsbootstrap.NewCredentials()
	if err != nil {
		return s, err
	}
	s.client, err = controllertransport.NewClient(s.controller, hello.TLSPin, credentials.AccessToken, credentials.OwnerToken)
	if err != nil {
		return s, err
	}
	private, err := windowsbootstrap.EncodeCredentials(credentials)
	if err != nil {
		return s, err
	}
	if err = s.pipe.WriteFrame(bootstrap, private); err != nil {
		return s, err
	}
	s.authenticated = true
	s.workers.Add(2)
	go func() {
		defer s.workers.Done()
		_, e := s.controller.Wait(s.ctx)
		if s.ctx.Err() == nil {
			s.cancel(errors.Join(e, errors.New("the captured controller exited")))
		}
	}()
	go func() {
		defer s.workers.Done()
		e := s.pipe.ObserveLifetime(s.ctx)
		if s.ctx.Err() == nil {
			s.cancel(errors.Join(e, errors.New("the captured controller lifetime channel closed")))
		}
	}()
	var proofErr error
	for {
		proofErr = s.client.VerifyIdentity(bootstrap)
		if proofErr == nil {
			break
		}
		select {
		case <-bootstrap.Done():
			return s, errors.Join(proofErr, context.Cause(bootstrap))
		case <-time.After(100 * time.Millisecond):
		}
	}
	return s, nil
}

func (s *Session) pinUI() error {
	count := 0
	root := filepath.Join(s.packageRoot, "client")
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, failure error) error {
		if failure != nil {
			return failure
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("the Windows UI code tree contains a link")
		}
		if entry.IsDir() && strings.EqualFold(path, filepath.Join(root, ".routervpn-state")) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		if count >= 10000 {
			return errors.New("the Windows UI code tree is unbounded")
		}
		file, err := windowscontroller.PinFile(path)
		if err != nil {
			return err
		}
		s.files = append(s.files, file)
		count++
		return nil
	}); err != nil {
		return err
	}
	for _, name := range []string{"RouterVPN-Windows-App.ps1", "RouterVPN-Windows-Tray.ps1", "RouterVPN-Windows-ControllerTransport.psm1", "RouterVPN-Windows-ControllerTransport.cs"} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil || !info.Mode().IsRegular() {
			return errors.Join(err, fmt.Errorf("the captured Windows UI is missing %s", name))
		}
	}
	return nil
}

func (s *Session) launchUI(tray, selfTest bool, uiPID uint32, uiTicks int64) (*gui, error) {
	name := "RouterVPN-Windows-App.ps1"
	if tray {
		name = "RouterVPN-Windows-Tray.ps1"
	}
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		return nil, err
	}
	g := &gui{pipe: pipe, done: make(chan error, 1), ready: make(chan struct{})}
	s.guis = append(s.guis, g)
	g.child, err = windowscontroller.LaunchGUIChild(s.ctx, s.powershell, func(parent uint64) ([]string, error) {
		arguments := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(s.packageRoot, "client", name),
			"-ControllerPipe", pipe.Name(), "-ControllerParentHandle", strconv.FormatUint(parent, 10)}
		if tray {
			arguments = append(arguments, "-UiPid", strconv.FormatUint(uint64(uiPID), 10), "-UiCreationTicks", strconv.FormatInt(uiTicks, 10))
		}
		if selfTest {
			arguments = append(arguments, "-SelfTest")
		}
		return arguments, nil
	}, s.environment, s.dataRoot)
	if err != nil {
		close(g.done)
		return g, err
	}
	go func() {
		g.done <- windowsuibridge.ServeReady(s.ctx, g.pipe, g.child, s.powershell, s.client, func() { close(g.ready) })
		close(g.done)
	}()
	return g, nil
}

// RunUI keeps the App and Tray in independent original-user Jobs/pipe owners.
// Each bridge uses the same retained TLS controller, without exposing its keys.
func (s *Session) RunUI(selfTest bool) error {
	if s == nil || s.client == nil || !s.authenticated {
		return errors.New("the Windows UI has no authenticated controller session")
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.ctx.Err() != nil {
		return context.Cause(s.ctx)
	}
	if selfTest {
		response, err := s.client.Request(s.ctx, http.MethodGet, "/api/logical-modes", nil, 1<<20)
		var modes []struct {
			ID string `json:"id"`
		}
		if err != nil || response.Status != http.StatusOK || json.Unmarshal(response.Body, &modes) != nil || len(modes) != 16 {
			return errors.Join(err, errors.New("the owned Windows controller did not return its sixteen logical modes"))
		}
		seen := make(map[string]bool, len(modes))
		for _, mode := range modes {
			if mode.ID == "" || seen[mode.ID] || strings.HasPrefix(mode.ID, "max-quic-") || strings.HasPrefix(mode.ID, "max-tls-") {
				return errors.New("the owned Windows catalog repeated or exposed a raw duplicate mode")
			}
			seen[mode.ID] = true
		}
	}
	app, err := s.launchUI(false, selfTest, 0, 0)
	if err != nil {
		return err
	}
	appOwner, err := app.child.RetainProcess()
	if err != nil {
		return err
	}
	created, captureErr := appOwner.StartTimeUTCTicks()
	err = errors.Join(captureErr, appOwner.Close())
	if err != nil {
		return err
	}
	tray, err := s.launchUI(true, selfTest, app.child.PID(), created)
	if err != nil {
		return err
	}
	type completion struct {
		code uint32
		err  error
	}
	appDone := make(chan completion, 1)
	waitCtx, stop := context.WithCancel(s.ctx)
	defer stop()
	go func() { code, err := app.child.Wait(waitCtx); appDone <- completion{code, err} }()
	var outcome completion
	trayDone := tray.done
	if selfTest {
		trayDone = nil
	}
	select {
	case outcome = <-appDone:
	case err = <-app.done:
		// The script joins its channel in finally before its process exits.
		// Allow that ordinary exit to complete, while a lost channel belonging
		// to a still-running window remains a bounded session failure.
		grace := time.NewTimer(3 * time.Second)
		select {
		case outcome = <-appDone:
			grace.Stop()
		case <-grace.C:
			stop()
			<-appDone
			return errors.Join(err, errors.New("the App lost its owned controller bridge before exiting"))
		case <-s.ctx.Done():
			grace.Stop()
			stop()
			<-appDone
			return context.Cause(s.ctx)
		}
	case err = <-trayDone:
		// The user's Tray Exit closes its channel before process exit. A clean
		// captured Tray exit retires this entire session; Close then joins only
		// the already retained App Job, even if the window was unresponsive.
		grace, cancel := context.WithTimeout(s.ctx, 3*time.Second)
		code, waitErr := tray.child.Wait(grace)
		cancel()
		stop()
		<-appDone
		if waitErr != nil || code != 0 {
			return errors.Join(err, waitErr, errors.New("the Tray lost its owned controller bridge"))
		}
		select {
		case <-tray.ready:
		default:
			return errors.New("the Tray exited without its authenticated native handoff")
		}
		return nil
	case <-s.ctx.Done():
		stop()
		<-appDone
		return context.Cause(s.ctx)
	}
	if outcome.err != nil || outcome.code != 0 {
		return errors.Join(outcome.err, fmt.Errorf("the native App exited with code %d", outcome.code))
	}
	select {
	case <-app.ready:
	default:
		return errors.New("the App exited without its authenticated native handoff")
	}
	if selfTest {
		code, err := tray.child.Wait(s.ctx)
		if err != nil || code != 0 {
			return errors.Join(err, fmt.Errorf("the native Tray self-test exited with code %d", code))
		}
		select {
		case <-tray.ready:
		default:
			return errors.New("the Tray exited without its authenticated native handoff")
		}
	}
	return nil
}

// Close revokes UI work first, requires the authenticated terminal controller
// receipt, independently joins its retained process, and only then releases
// executable/code pins. A failed checked drain remains an error with retained
// owners; it is never converted into success merely because a process died.
func (s *Session) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("Windows session cleanup requires a bounded operation")
	}
	s.cancel(errors.New("the Windows app is closing"))
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var failures []error
	if s.updater != nil {
		failures = append(failures, s.updater.Close(ctx))
	}
	for _, g := range s.guis {
		if g.child != nil {
			failures = append(failures, g.child.Close(ctx))
		}
		if g.pipe != nil {
			failures = append(failures, g.pipe.Close())
		}
		if g.done != nil {
			select {
			case <-g.done:
			case <-ctx.Done():
				failures = append(failures, ctx.Err())
			}
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	if err := s.updateCache.Close(); err != nil {
		return err
	}
	s.workers.Wait()
	if s.authenticated && !s.receipt {
		if err := s.client.Shutdown(ctx); err != nil {
			return fmt.Errorf("owned Windows controller cleanup is unproved: %w", err)
		}
		s.receipt = true
	}
	if s.pipe != nil {
		if err := s.pipe.Close(); err != nil {
			return err
		}
	}
	if s.controller != nil && !s.joined {
		if _, err := s.controller.Wait(ctx); err != nil {
			return fmt.Errorf("owned Windows controller has not joined: %w", err)
		}
		s.joined = true
	}
	if s.directController != nil {
		if err := s.directController.Close(ctx); err != nil {
			return err
		}
	}
	if err := s.temporary.Close(); err != nil {
		return err
	}
	if s.client != nil {
		failures = append(failures, s.client.Close())
	}
	if s.controller != nil {
		failures = append(failures, s.controller.Close())
	}
	if s.controllerShell != nil {
		failures = append(failures, s.controllerShell.Close())
	}
	for _, file := range s.files {
		failures = append(failures, file.Close())
	}
	for _, image := range []*windowscontroller.Image{s.updaterImage, s.powershell, s.controllerImage, s.selfImage} {
		if image != nil {
			failures = append(failures, image.Close())
		}
	}
	if s.self != nil {
		failures = append(failures, s.self.Close())
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	s.closed = true
	return nil
}
