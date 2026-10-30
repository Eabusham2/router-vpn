//go:build windows

package windowsuibridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-vpn/internal/windowscontroller"
)

// This gate launches an actual PowerShell host through the shipping Job/handle
// primitive. The adapter uses its public ConnectAsync constructor; no private
// Stream seam, bearer, TLS callback or substituted process identity is supplied.
func nativePowerShellHost(t *testing.T, wrongPin bool) (*nativeBridgeHost, string, windowscontroller.UserDirectories) {
	t.Helper()
	root := os.Getenv("ROUTERVPN_GUI_POWERSHELL_ROOT")
	shell := os.Getenv("ROUTERVPN_GUI_POWERSHELL")
	if !filepath.IsAbs(root) || !filepath.IsAbs(shell) {
		t.Fatal("actual PowerShell image and captured source root are required")
	}
	var image *windowscontroller.Image
	var err error
	switch os.Getenv("ROUTERVPN_GUI_POWERSHELL_KIND") {
	case "Desktop":
		image, err = windowscontroller.PinSystemPowerShell()
	case "Core":
		image, err = windowscontroller.PinImage(shell)
	default:
		t.Fatal("actual PowerShell runtime identity is required")
	}
	if err != nil {
		t.Fatal("actual PowerShell image was not pinned", err)
	}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	selected, selectedErr := os.Stat(shell)
	retained, retainedErr := os.Stat(image.Path())
	if selectedErr != nil || retainedErr != nil || !os.SameFile(selected, retained) {
		t.Fatal("selected PowerShell differs from its actual retained file identity", selectedErr, retainedErr)
	}
	for _, name := range []string{
		"client/RouterVPN-Windows-ControllerTransport.psm1", "client/RouterVPN-Windows-ControllerTransport.cs",
		"deploy/fixtures/windows-controller-transport/bridge_process.ps1",
	} {
		file, err := windowscontroller.PinFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal("actual PowerShell code input was not retained", name, err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	process, err := windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	directories, err := process.UserDirectories()
	closed := process.Close()
	if err != nil || closed != nil {
		t.Fatal("actual original-user directories were not captured", err, closed)
	}
	extra := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/ui/status":
			if r.Method != http.MethodGet {
				http.Error(w, "wrong method", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"owner": "captured"})
		case "/api/ui/body":
			body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			if r.Method != http.MethodPost || err != nil || !bytes.Equal(body, []byte("{\"name\":\"captured λ\"}")) {
				http.Error(w, "changed actual JSON bytes", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"exact": true})
		case "/api/profile/import":
			body, err := io.ReadAll(io.LimitReader(r.Body, 32770))
			if r.Method != http.MethodPost || err != nil || len(body) != 32769 {
				http.Error(w, "wrong actual import", 400)
				return
			}
			for index, value := range body {
				if value != byte((index*29+7)&255) {
					http.Error(w, "changed actual import bytes", 400)
					return
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"exact": true, "bytes": len(body)})
		default:
			http.Error(w, "another fixture target", 404)
		}
	})
	return nativeBridgeHostForImage(t, wrongPin, image, extra), root, directories
}

func nativePowerShellLaunch(t *testing.T, host *nativeBridgeHost, root string, directories windowscontroller.UserDirectories, mode string, invalidParent bool) *nativeBridgeGUI {
	t.Helper()
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	gui := &nativeBridgeGUI{pipe: pipe, report: filepath.Join(t.TempDir(), "result.txt")}
	t.Cleanup(func() {
		if gui.cancel != nil {
			gui.cancel()
		}
		ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if gui.child != nil {
			if err := gui.child.Close(ctx); err != nil {
				t.Error("actual PowerShell Job did not retire", err)
			}
		}
		if gui.pipe != nil {
			_ = gui.pipe.Close()
		}
		if gui.done != nil {
			select {
			case <-gui.done:
			case <-ctx.Done():
				t.Error("actual PowerShell forwarding did not join")
			}
		}
	})
	environment := []string{
		"SystemRoot=" + os.Getenv("SystemRoot"), "TEMP=" + filepath.Dir(gui.report), "TMP=" + filepath.Dir(gui.report),
		"USERPROFILE=" + directories.Profile, "APPDATA=" + directories.RoamingAppData, "LOCALAPPDATA=" + directories.LocalAppData,
		"PSModuleAnalysisCachePath=" + filepath.Join(filepath.Dir(gui.report), "module-cache"), "POWERSHELL_TELEMETRY_OPTOUT=1",
	}
	gui.child, err = windowscontroller.LaunchGUIChild(nativeBridgeContext(t, 50*time.Second), host.image, func(parent uint64) ([]string, error) {
		if invalidParent {
			parent = 1
		}
		return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
			filepath.Join(root, "deploy", "fixtures", "windows-controller-transport", "bridge_process.ps1"),
			"-Root", root, "-ControllerPipe", pipe.Name(), "-ControllerParentHandle", fmt.Sprint(parent), "-Mode", mode, "-Report", gui.report}, nil
	}, environment, filepath.Dir(gui.report))
	if err != nil {
		t.Fatal("actual PowerShell GUI did not start", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	gui.cancel, gui.done = cancel, make(chan struct{})
	go func() { defer close(gui.done); gui.serveErr = Serve(ctx, pipe, gui.child, host.image, host.client) }()
	return gui
}

func nativePowerShellFinished(t *testing.T, gui *nativeBridgeGUI, expected string) {
	t.Helper()
	code, err := gui.child.Wait(nativeBridgeContext(t, 40*time.Second))
	raw, readErr := os.ReadFile(gui.report)
	if err != nil || code != 0 || readErr != nil || string(raw) != expected {
		t.Fatal("actual PowerShell adapter missed its native boundary", expected, code, err, readErr, string(raw))
	}
	// The public constructor may reject an invalid inherited handle before it
	// connects. Retire the exact server after the child is conclusively joined.
	gui.cancel()
	select {
	case <-gui.done:
	case <-time.After(3 * time.Second):
		t.Fatal("actual PowerShell pipe did not join after its GUI exited")
	}
}

func TestWindowsUIBridgePowerShellActualRequests(t *testing.T) {
	host, root, directories := nativePowerShellHost(t, false)
	gui := nativePowerShellLaunch(t, host, root, directories, "roundtrip", false)
	nativePowerShellFinished(t, gui, "PASS ROUNDTRIP")
	if host.requests.Load() != 4 {
		t.Fatal("actual PowerShell requests bypassed captured TLS", host.requests.Load())
	}
}

func TestWindowsUIBridgePowerShellCancellation(t *testing.T) {
	host, root, directories := nativePowerShellHost(t, false)
	gui := nativePowerShellLaunch(t, host, root, directories, "cancel", false)
	nativePowerShellFinished(t, gui, "PASS CANCEL")
	select {
	case <-host.drained:
	default:
		t.Fatal("actual PowerShell cancellation left its controller request alive")
	}
	if host.requests.Load() != 4 {
		t.Fatal("actual PowerShell cancellation changed another owner", host.requests.Load())
	}
}

func TestWindowsUIBridgePowerShellWrongParent(t *testing.T) {
	host, root, directories := nativePowerShellHost(t, false)
	gui := nativePowerShellLaunch(t, host, root, directories, "reject-peer", true)
	nativePowerShellFinished(t, gui, "REJECTED PEER")
	if host.requests.Load() != 0 {
		t.Fatal("unproved parent admitted PowerShell controller traffic")
	}
}

func TestWindowsUIBridgePowerShellWrongPin(t *testing.T) {
	host, root, directories := nativePowerShellHost(t, true)
	gui := nativePowerShellLaunch(t, host, root, directories, "reject-request", false)
	nativePowerShellFinished(t, gui, "REJECTED REQUEST")
	if host.requests.Load() != 0 {
		t.Fatal("PowerShell used controller authority without its captured TLS pin")
	}
}
