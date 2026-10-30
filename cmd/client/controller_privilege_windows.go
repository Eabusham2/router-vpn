//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"router-vpn/internal/common"
	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowsbootstrap"
	"router-vpn/internal/windowscontroller"
)

var windowsOwnedCapture atomic.Pointer[windowsOwnedController]

type windowsOwnedController struct {
	parent, self           *windowscontroller.Process
	parentImage, selfImage *windowscontroller.Image
	powerShell             *windowscontroller.Image
	modeSource             []common.Mode
	pipe                   *windowscontroller.Pipe
	code                   []*windowscontroller.CodeFile
	directories            []*os.File
	desktop, elevated      windowscontroller.TokenIdentity
	profile                windowscontroller.UserDirectories
	privateOwner           *windowsRuntimeOriginalOwner
	packageRoot, dataRoot  string
	portable               bool
	ctx                    context.Context
	cancel                 context.CancelFunc
	done                   chan struct{}
	workers                sync.WaitGroup
	authenticated          atomic.Bool
	closeOnce              sync.Once
	closeErr               error
}

func prepareNativeOwnedController(arguments []string) (_ *ownedDesktopController, failure error) {
	for _, argument := range arguments {
		if argument == linuxOwnedControllerArgument || argument == macOSOwnedControllerArgument || argument == macOSControllerSupervisorArgument {
			return nil, errors.New("this native controller launch belongs to another platform")
		}
	}
	if !windowsbootstrap.Requested(arguments) {
		return nil, nil
	}
	rendezvous, err := windowsbootstrap.ParseArguments(arguments)
	if err != nil {
		return nil, err
	}
	capture := &windowsOwnedController{done: make(chan struct{})}
	capture.ctx, capture.cancel = context.WithCancel(context.Background())
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, capture.Close())
		}
	}()
	capture.elevated, err = windowscontroller.CurrentIdentity()
	if err != nil || !capture.elevated.Primary || !capture.elevated.Elevated || !capture.elevated.Administrator {
		return nil, errors.Join(err, errors.New("the Windows controller requires its actual administrator consent"))
	}
	capture.selfImage, err = windowscontroller.PinCurrentImage()
	if err != nil {
		return nil, err
	}
	capture.self, err = windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		return nil, err
	}
	if err = capture.self.VerifyImage(capture.selfImage); err != nil {
		return nil, err
	}
	capture.parentImage, err = windowscontroller.PinImage(rendezvous.ParentImage)
	if err != nil {
		return nil, err
	}
	if err = capture.captureLayout(); err != nil {
		return nil, err
	}
	capture.parent, err = windowscontroller.OpenProcess(rendezvous.ParentPID)
	if err != nil {
		return nil, err
	}
	bootstrap, stop := context.WithTimeout(capture.ctx, 30*time.Second)
	defer stop()
	capture.pipe, err = windowscontroller.DialPipe(bootstrap, rendezvous.PipeName)
	if err != nil {
		return nil, err
	}
	peer, err := capture.pipe.VerifyPeer(capture.parent, capture.parentImage)
	if err != nil {
		return nil, err
	}
	capture.desktop = peer.Identity
	err = peer.Process.Close()
	if err != nil || !capture.desktop.Primary || capture.desktop.SID == "" || capture.desktop.AuthenticationID == 0 || capture.desktop.SessionID != capture.elevated.SessionID {
		return nil, errors.Join(err, errors.New("the Windows controller did not capture its original desktop session"))
	}
	capture.profile, err = capture.parent.UserDirectories()
	if err != nil {
		return nil, err
	}
	actual, err := capture.parent.Identity()
	if err != nil || actual != capture.desktop {
		return nil, errors.Join(err, errors.New("the original desktop token changed during capture"))
	}
	if !windowsOwnedCapture.CompareAndSwap(nil, capture) {
		return nil, errors.New("this controller already has another native launch owner")
	}
	capture.privateOwner = &windowsRuntimeOriginalOwner{desktopSID: capture.desktop.SID, controllerSID: capture.elevated.SID}
	if !windowsRuntimeOriginalOwnerCapture.CompareAndSwap(nil, capture.privateOwner) {
		return nil, errors.New("private Windows state already belongs to another native launch")
	}
	if err = capture.pinPackage(); err != nil {
		return nil, err
	}
	if err = capture.captureCatalog(); err != nil {
		return nil, err
	}
	// Authenticate the package and data roots before reading any private config
	// or allowing ordinary startup to migrate it. Credentials never select paths.
	if err = capture.pinDataDirectory(); err != nil {
		return nil, err
	}
	raw, err := readPrivateRuntimeSnapshot(filepath.Join(capture.dataRoot, "client.json"), maxPrivateStoreBytes)
	if err != nil {
		return nil, err
	}
	var config common.ClientConfig
	if err = decodeRelayControlJSON(raw, &config); err != nil {
		return nil, err
	}
	if _, err = capture.CaptureConfiguration(config); err != nil {
		return nil, err
	}
	identity, err := controllertransport.NewIdentity()
	if err != nil {
		return nil, err
	}
	hello, err := windowsbootstrap.EncodeHello(uint32(os.Getpid()), identity.Pin())
	if err != nil {
		return nil, err
	}
	if err = capture.pipe.WriteFrame(bootstrap, hello); err != nil {
		return nil, err
	}
	private, err := capture.pipe.ReadFrame(bootstrap)
	if err != nil {
		return nil, err
	}
	credentials, err := windowsbootstrap.DecodeCredentials(private)
	if err != nil {
		return nil, err
	}
	if err = capture.parent.Alive(); err != nil {
		return nil, err
	}
	if err = windowscontroller.OwnProcessLifetime(); err != nil {
		return nil, err
	}
	if err = capture.applyEnvironment(identity.Pin()); err != nil {
		return nil, err
	}
	capture.authenticated.Store(true)
	capture.workers.Add(2)
	go func() { defer capture.workers.Done(); _ = capture.pipe.ObserveLifetime(capture.ctx); capture.cancel() }()
	go func() { defer capture.workers.Done(); _, _ = capture.parent.Wait(capture.ctx); capture.cancel() }()
	go func() { <-capture.ctx.Done(); close(capture.done) }()
	return &ownedDesktopController{processID: os.Getpid(), accessToken: credentials.AccessToken, ownerToken: credentials.OwnerToken,
		ownerDone: capture.done, pinnedTLS: identity, nativeOwner: capture}, nil
}

func (c *windowsOwnedController) captureLayout() error {
	self, parent := c.selfImage.Path(), c.parentImage.Path()
	if !strings.EqualFold(filepath.Base(self), "router-vpn-client.exe") {
		return errors.New("the Windows controller is not its fixed package executable")
	}
	c.packageRoot = filepath.Dir(self)
	switch {
	case strings.EqualFold(filepath.Base(parent), "RouterVPN.exe") && strings.EqualFold(filepath.Dir(parent), c.packageRoot):
		c.dataRoot = c.packageRoot
	case windowsbootstrap.IsPortableLauncherName(filepath.Base(parent)) && strings.EqualFold(filepath.Join(filepath.Dir(parent), "App", "RouterVPN"), c.packageRoot):
		c.portable = true
		c.dataRoot = filepath.Join(filepath.Dir(parent), "Data")
	default:
		return errors.New("the retained Windows launcher does not own this exact installed or Portable package")
	}
	return nil
}

func (c *windowsOwnedController) pinPackage() error {
	count := 0
	pin := func(path string, info fs.FileInfo) error {
		if count >= 10000 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("the owned Windows package contains unsupported or unbounded code")
		}
		code, err := windowscontroller.PinFile(path)
		if err != nil {
			return err
		}
		c.code = append(c.code, code)
		count++
		file, err := openPrivateRuntimeForRead(code.Path(), info)
		if err != nil {
			return err
		}
		security, err := windowsRuntimeInspectSecurity(file)
		if err == nil {
			err = windowsRuntimeValidateCodeSecurity(security, c.desktop.SID)
			security.close()
		}
		return errors.Join(err, file.Close())
	}
	// These are package code/catalog inputs. Generated node data and writable
	// settings are deliberately outside the read locks; the controller's checked
	// private-store transactions continue to own those files.
	roots := []string{filepath.Join(c.packageRoot, "client"), filepath.Join(c.packageRoot, "modes"), filepath.Join(c.packageRoot, "runtime")}
	// Portable runtime installation materializes its executables into Data.
	// Capture that actual runtime as well as the immutable bundled archives.
	for _, optional := range []string{filepath.Join(c.packageRoot, "bin"), filepath.Join(c.dataRoot, "runtime")} {
		if optional == filepath.Join(c.packageRoot, "runtime") {
			continue
		}
		if _, err := os.Lstat(optional); err == nil {
			roots = append(roots, optional)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, failure error) error {
			if failure != nil {
				return failure
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.IsDir() {
				if info.Mode()&os.ModeSymlink != 0 {
					return errors.New("owned Windows package directory is a link")
				}
				if strings.EqualFold(root, filepath.Join(c.packageRoot, "client")) && strings.EqualFold(entry.Name(), ".routervpn-state") {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.EqualFold(root, filepath.Join(c.packageRoot, "client")) && !ownedWindowsImmutableClientInput(root, path) {
				return nil
			}
			return pin(path, info)
		}); err != nil {
			return fmt.Errorf("capture package %s: %w", filepath.Base(root), err)
		}
	}
	entries, err := os.ReadDir(c.packageRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !(strings.EqualFold(filepath.Ext(name), ".exe") || name == "modes.json" || name == "logical-modes.json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if err := pin(filepath.Join(c.packageRoot, name), info); err != nil {
			return err
		}
	}
	return nil
}

func ownedWindowsImmutableClientInput(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ps1", ".psm1", ".psd1", ".cs", ".exe", ".dll", ".py", ".sh", ".cmd", ".bat", ".js", ".html", ".css", ".wasm", ".inc", ".swift", ".c", ".h", ".m", ".policy":
		return true
	case ".json":
		return strings.EqualFold(relative, "unified-control-center-v2.json") || strings.EqualFold(relative, filepath.Join("shared", "map", "routervpn-land-110m.json"))
	}
	return false
}

func (c *windowsOwnedController) pinDataDirectory() error {
	info, err := os.Lstat(c.dataRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("the owned Windows private data directory is invalid"))
	}
	name, err := syscall.UTF16PtrFromString(c.dataRoot)
	if err != nil {
		return err
	}
	// Attribute-only access does not enforce the no-delete share. Retain actual
	// directory-read access so this captured private root cannot be renamed.
	handle, err := syscall.CreateFile(name, windowsRuntimeReadControl|windowsRuntimeReadAttributes|syscall.FILE_LIST_DIRECTORY, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), c.dataRoot)
	c.directories = append(c.directories, file)
	return validatePrivateRuntimeOpenPermissions(file, info)
}

func (c *windowsOwnedController) captureCatalog() error {
	for _, path := range []string{filepath.Join(c.packageRoot, "modes.json"), filepath.Join(c.packageRoot, "client", "native-wireguard-windows.ps1"), filepath.Join(c.packageRoot, "client", "native-windows-mode.ps1")} {
		found := false
		for _, code := range c.code {
			if strings.EqualFold(code.Path(), path) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("the Windows mode catalog lost a retained package adapter")
		}
	}
	file, err := os.Open(filepath.Join(c.packageRoot, "modes.json"))
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxPrivateStoreBytes+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	if len(body) == 0 || len(body) > maxPrivateStoreBytes || json.Unmarshal(body, &c.modeSource) != nil {
		return errors.New("the retained Windows source mode catalog is invalid")
	}
	c.powerShell, err = windowscontroller.PinSystemPowerShell()
	if err != nil {
		return err
	}
	_, err = c.CaptureModes(c.modeSource)
	return err
}

func (c *windowsOwnedController) CaptureModes(selected []common.Mode) ([]common.Mode, error) {
	if c == nil || c.powerShell == nil {
		return nil, errors.New("the Windows controller has no retained system interpreter")
	}
	return captureOwnedWindowsModes(c.modeSource, selected, c.powerShell.Path(), filepath.Join(c.packageRoot, "client"), windowsOwnedSamePath)
}

func (c *windowsOwnedController) CaptureConfiguration(config common.ClientConfig) (common.ClientConfig, error) {
	if c == nil || c.dataRoot == "" || c.packageRoot == "" || config.Listen != "" && config.Listen != linuxOwnedControllerAddress {
		return common.ClientConfig{}, errors.New("the Windows controller requires its captured fixed listener and data layout")
	}
	config.Listen = linuxOwnedControllerAddress
	modes := []string{filepath.Join(c.packageRoot, "modes.json"), filepath.Join(c.dataRoot, "modes.windows.json")}
	for name, item := range map[string]struct {
		given   *string
		allowed []string
	}{
		"modes_file": {&config.ModesFile, modes}, "scripts_dir": {&config.ScriptsDir, []string{filepath.Join(c.packageRoot, "modes")}},
		"profiles_file": {&config.ProfilesFile, []string{filepath.Join(c.dataRoot, "routers.json")}}, "state_file": {&config.StateFile, []string{filepath.Join(c.dataRoot, "state.json")}},
	} {
		if *item.given == "" {
			*item.given = item.allowed[0]
			continue
		}
		value := *item.given
		if !filepath.IsAbs(value) {
			value = filepath.Join(c.dataRoot, value)
		}
		// Existing configurations may use a DOS spelling. Resolve the opened
		// file/directory identity against the captured canonical package target;
		// string equality alone cannot authorize a remapped drive.
		matched := false
		for _, expected := range item.allowed {
			if windowsOwnedSamePath(value, expected) {
				*item.given = expected
				matched = true
				break
			}
		}
		if !matched {
			return common.ClientConfig{}, fmt.Errorf("the Windows controller %s escaped its captured data/package layout", name)
		}
	}
	return config, nil
}

func windowsOwnedSamePath(value, expected string) bool {
	if strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if strings.EqualFold(filepath.Clean(value), expected) {
		return true
	}
	actual, err := os.Lstat(value)
	want, wantErr := os.Lstat(expected)
	if err == nil && wantErr == nil && actual.Mode()&os.ModeSymlink == 0 && want.Mode()&os.ModeSymlink == 0 && os.SameFile(actual, want) {
		return true
	}
	// A not-yet-created state/catalog file is authorized only by its already
	// existing parent identity and its exact fixed leaf, never another leaf.
	if os.IsNotExist(err) && os.IsNotExist(wantErr) && strings.EqualFold(filepath.Base(value), filepath.Base(expected)) {
		actual, err = os.Lstat(filepath.Dir(value))
		want, wantErr = os.Lstat(filepath.Dir(expected))
		return err == nil && wantErr == nil && actual.IsDir() && want.IsDir() && actual.Mode()&os.ModeSymlink == 0 && want.Mode()&os.ModeSymlink == 0 && os.SameFile(actual, want)
	}
	return false
}

func (c *windowsOwnedController) applyEnvironment(pin string) error {
	machine, err := windowscontroller.MachineDirectories()
	if err != nil {
		return err
	}
	system := machine.System
	temporary := filepath.Join(c.dataRoot, "run", "controller-temp")
	if err := ensurePrivateRuntimeDirectory(temporary); err != nil {
		return err
	}
	values := map[string]string{
		"SystemRoot": machine.Windows, "WINDIR": machine.Windows, "SystemDrive": machine.SystemDrive, "COMSPEC": filepath.Join(system, "cmd.exe"),
		"PATH":         strings.Join([]string{system, filepath.Join(system, "WindowsPowerShell", "v1.0"), c.packageRoot, filepath.Join(c.packageRoot, "bin")}, string(os.PathListSeparator)),
		"PSModulePath": filepath.Join(system, "WindowsPowerShell", "v1.0", "Modules"),
		"PATHEXT":      ".COM;.EXE;.BAT;.CMD", "TEMP": temporary, "TMP": temporary,
		"USERPROFILE": c.profile.Profile, "APPDATA": c.profile.RoamingAppData, "LOCALAPPDATA": c.profile.LocalAppData,
		"HOME": c.profile.Profile, "ProgramData": machine.ProgramData, "ProgramFiles": machine.ProgramFiles, "OS": "Windows_NT", "PROCESSOR_ARCHITECTURE": strings.ToUpper(runtime.GOARCH),
		"HOMEVPN_ROOT": c.dataRoot, "HOMEVPN_CLIENT_CONFIG": filepath.Join(c.dataRoot, "client.json"), "HOMEVPN_NATIVE_APP": "windows-owned-controller",
		"HOMEVPN_CONTROLLER_PID": strconv.Itoa(os.Getpid()), "HOMEVPN_CONTROLLER_TLS_PIN": pin, "HOMEVPN_CONTROLLER_TRANSPORT": "pinned-tls", "HOMEVPN_CONTROLLER_EXECUTABLE": c.selfImage.Path(),
	}
	if c.portable {
		values["HOMEVPN_PORTABLE"] = "1"
		values["HOMEVPN_MODES_DIR"] = filepath.Join(c.packageRoot, "modes")
		// Portable runtime/user caches remain under its captured Data folder;
		// no administrator profile or process environment selects private state.
		values["APPDATA"], values["LOCALAPPDATA"] = c.dataRoot, c.dataRoot
		values["HOME"] = c.dataRoot
	}
	os.Clearenv()
	for name, value := range values {
		if err := os.Setenv(name, value); err != nil {
			return err
		}
	}
	return os.Chdir(c.dataRoot)
}

func windowsOwnedSystemDirectory() (string, error) {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")
	buffer := make([]uint16, 32768)
	length, _, err := proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if length == 0 || length >= uintptr(len(buffer)) {
		return "", fmt.Errorf("read native Windows system directory: %w", err)
	}
	value := syscall.UTF16ToString(buffer[:length])
	if !filepath.IsAbs(value) {
		return "", errors.New("Windows returned no absolute system directory")
	}
	return value, nil
}

func (c *windowsOwnedController) Captured() bool { return c != nil && c.authenticated.Load() }
func (c *windowsOwnedController) Alive() error {
	if !c.Captured() {
		return windowscontroller.ErrClosed
	}
	select {
	case <-c.ctx.Done():
		return windowscontroller.ErrClosed
	default:
	}
	if err := c.parent.Alive(); err != nil {
		return err
	}
	return c.ctx.Err()
}
func (c *windowsOwnedController) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.authenticated.Store(false)
		if c.cancel != nil {
			c.cancel()
		}
		if c.pipe != nil {
			c.closeErr = errors.Join(c.closeErr, c.pipe.Close())
		}
		c.workers.Wait()
		for index := len(c.code) - 1; index >= 0; index-- {
			c.closeErr = errors.Join(c.closeErr, c.code[index].Close())
		}
		for index := len(c.directories) - 1; index >= 0; index-- {
			c.closeErr = errors.Join(c.closeErr, c.directories[index].Close())
		}
		for _, process := range []*windowscontroller.Process{c.parent, c.self} {
			if process != nil {
				c.closeErr = errors.Join(c.closeErr, process.Close())
			}
		}
		for _, image := range []*windowscontroller.Image{c.parentImage, c.selfImage, c.powerShell} {
			if image != nil {
				c.closeErr = errors.Join(c.closeErr, image.Close())
			}
		}
		windowsOwnedCapture.CompareAndSwap(c, nil)
		if c.privateOwner != nil {
			windowsRuntimeOriginalOwnerCapture.CompareAndSwap(c.privateOwner, nil)
		}
	})
	return c.closeErr
}

func validateNativeOwnedStartup(owned *ownedDesktopController) error {
	if owned == nil {
		return nil
	}
	capture, ok := owned.nativeOwner.(*windowsOwnedController)
	if !ok || capture != windowsOwnedCapture.Load() || owned.callerUID != 0 || owned.processID != os.Getpid() || owned.ownerDone != capture.done || owned.pinnedTLS == nil ||
		!validLocalControllerSecret(owned.accessToken) || !validControllerOwnerToken(owned.ownerToken) {
		return errors.New("the Windows controller lost its authenticated native launch")
	}
	return capture.Alive()
}
func validateNativeOwnedConfiguration(common.ClientConfig) error {
	return errors.New("Windows configuration requires its retained native layout")
}
func macOSControllerSupervisorUtility(arguments []string) (bool, error) {
	for _, argument := range arguments {
		if argument == macOSControllerSupervisorArgument {
			return true, errors.New("the macOS controller supervisor requires macOS")
		}
	}
	return false, nil
}
