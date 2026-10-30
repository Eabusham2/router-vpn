//go:build windows && routervpn_windows_app_native

package windowsapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/windowscontroller"
)

// The native runner copies this test executable into disposable real installed
// and Portable layouts. Start then captures that exact launcher, starts the
// separately built production cmd/client, and launches the actual packaged App
// and Tray. No production entry point accepts a fixture/environment override.
func TestWindowsAppComposedSession(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) != 2 {
		t.Fatal("the native Windows Session gate requires its owned layout and case")
	}
	root, scenario := arguments[0], arguments[1]
	portable := scenario == "portable-selftest"
	packageRoot, dataRoot := root, root
	if portable {
		packageRoot = filepath.Join(root, "App", "RouterVPN")
		dataRoot = filepath.Join(root, "Data")
		for _, name := range []string{"client.json", "routers.json"} {
			if _, err := os.Lstat(filepath.Join(dataRoot, name)); !os.IsNotExist(err) {
				t.Fatal("the actual Portable Session fixture preseeded private Data instead of testing first launch")
			}
		}
	}
	operation, stop := context.WithTimeout(context.Background(), 100*time.Second)
	defer stop()
	session, startErr := Start(operation, portable)
	if session != nil {
		// Even a failed partial Start retains its exact owners until checked
		// cleanup joins them. Never turn an early test failure into a leaked
		// controller, or use a PID/name sweep to clean up this fixture.
		t.Cleanup(func() {
			retire, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			if err := session.Close(retire); err != nil {
				t.Errorf("native Windows Session retained an unproved owner: %v", err)
			}
		})
	}
	if scenario == "foreign-launcher" || scenario == "code-hardlink" {
		if startErr == nil || session == nil || session.authenticated || session.controller != nil {
			t.Fatalf("unsafe Windows Session layout reached a controller launch: %v", startErr)
		}
		t.Log("the actual launch boundary rejected its foreign or multiply linked code input")
		return
	}
	if startErr != nil || session == nil {
		if session != nil && session.controller != nil {
			observation, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			code, waitErr := session.controller.Wait(observation)
			cancel()
			if waitErr == nil {
				t.Logf("actual retained controller exit after failed startup: %d", code)
			} else {
				t.Logf("actual retained controller exit remains unproved after failed startup: %v", waitErr)
			}
		}
		t.Fatalf("actual production Windows controller did not start: %v", startErr)
	}
	if !session.authenticated || !session.desktop.Primary || !session.desktop.Elevated || !session.desktop.Administrator || session.directController == nil {
		t.Fatal("native Session fixture did not capture its actual elevated test desktop")
	}
	assertSessionSameFile(t, session.packageRoot, packageRoot)
	assertSessionSameFile(t, session.dataRoot, dataRoot)
	assertSessionSameFile(t, session.controllerImage.Path(), filepath.Join(packageRoot, "router-vpn-client.exe"))
	if portable {
		assertSessionPortableData(t, session, packageRoot, dataRoot)
	}
	if !strings.HasPrefix(strings.ToLower(session.packageRoot), `\\?\volume{`) {
		t.Fatal("native Session lost the captured local-volume package identity")
	}
	controller, err := session.directController.RetainProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if controller.PID() != session.controller.PID() || controller.Alive() != nil {
		t.Fatal("native Session did not retain its exact running controller")
	}
	assertSessionCodePinned(t, filepath.Join(packageRoot, "client", "RouterVPN-Windows-ControllerTransport.cs"))
	assertSessionStatusOff(t, session)
	state := capturedSessionPreferences(t, packageRoot, dataRoot)
	var guis []*windowscontroller.Process
	if scenario == "retirement-retry" {
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if err := session.Close(cancelled); err == nil || session.closed || session.receipt || session.joined {
			t.Fatalf("cancelled Session retirement released or acknowledged its live controller: %v", err)
		}
		if controller.Alive() != nil {
			t.Fatal("cancelled Session retirement killed its unacknowledged controller")
		}
		assertSessionCodePinned(t, filepath.Join(packageRoot, "client", "RouterVPN-Windows-ControllerTransport.cs"))
		if err := session.RunUI(true); err == nil || len(session.guis) != 0 {
			t.Fatalf("retired Session accepted replacement GUI work: %v", err)
		}
	} else {
		if scenario != "installed-selftest" && scenario != "portable-selftest" {
			t.Fatal("unknown native Windows Session scenario")
		}
		runErr := session.RunUI(true)
		if len(session.guis) != 2 {
			t.Fatalf("actual App and Tray did not both launch: %v", runErr)
		}
		for _, gui := range session.guis {
			select {
			case <-gui.ready:
			default:
				t.Fatalf("native UI self-test omitted an authenticated channel: %v", runErr)
			}
			owner, err := gui.child.RetainProcess()
			if err != nil {
				t.Fatal(err)
			}
			guis = append(guis, owner)
			defer owner.Close()
		}
		if runErr != nil {
			t.Fatalf("actual packaged App/Tray self-test failed: %v", runErr)
		}
		// Each UI self-test sends /api/status through its owned pipe. Closing
		// either independent GUI channel must leave the shared controller live
		// until the launcher requests its authenticated terminal receipt.
		if controller.Alive() != nil {
			t.Fatal("one native UI channel retired the shared controller")
		}
		assertSessionStatusOff(t, session)
	}
	retire, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := session.Close(retire); err != nil {
		t.Fatalf("actual Windows Session could not complete its checked retirement: %v", err)
	}
	if !session.receipt || !session.joined || !session.closed {
		t.Fatal("Session released code without its authenticated receipt and independent process join")
	}
	code, err := controller.Wait(retire)
	if err != nil || code != 0 {
		t.Fatalf("the actual controller did not exit after checked cleanup: %d %v", code, err)
	}
	for _, gui := range guis {
		code, err := gui.Wait(retire)
		if err != nil || code != 0 {
			t.Fatalf("the actual native UI did not join after its successful self-test: %d %v", code, err)
		}
	}
	if err := session.RunUI(true); err == nil {
		t.Fatal("closed native Session launched replacement GUI work")
	}
	if err := session.Close(retire); err != nil {
		t.Fatalf("joined native Session cleanup was not idempotent: %v", err)
	}
	for path, captured := range state {
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, captured) {
			t.Fatalf("owned Session changed an existing user's saved preference: %s: %v", filepath.Base(path), err)
		}
	}
	// With all retained parents/children joined, this exact code input becomes
	// writable again. Reaching this line with a stale pin would fail on Windows.
	file, err := os.OpenFile(filepath.Join(packageRoot, "client", "RouterVPN-Windows-ControllerTransport.cs"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("joined Session left its code pin open: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("shipping controller, captured App/Tray pipes, exact-volume code and checked retirement completed")
}

func assertSessionPortableData(t *testing.T, session *Session, packageRoot, dataRoot string) {
	t.Helper()
	for _, path := range []string{dataRoot, filepath.Join(dataRoot, "generated")} {
		assertPortablePrivateNative(t, path, session.desktop.SID, true)
	}
	for _, name := range []string{"client.json", "routers.json"} {
		assertPortablePrivateNative(t, filepath.Join(dataRoot, name), session.desktop.SID, false)
	}
	body, err := os.ReadFile(filepath.Join(dataRoot, "client.json"))
	config, parseErr := portableJSONObject(body)
	if err != nil || parseErr != nil {
		t.Fatal("the actual Portable Session lost its prepared private configuration", errors.Join(err, parseErr))
	}
	for name, expected := range map[string]string{
		"modes_file":    filepath.Join(packageRoot, "modes.json"),
		"scripts_dir":   filepath.Join(packageRoot, "modes"),
		"profiles_file": filepath.Join(dataRoot, "routers.json"),
	} {
		var actual string
		if json.Unmarshal(config[name], &actual) != nil {
			t.Fatal("the actual Portable Session lost its captured location", name)
		}
		assertSessionSameFile(t, actual, expected)
	}
	var state string
	if json.Unmarshal(config["state_file"], &state) != nil || filepath.Base(state) != "state.json" {
		t.Fatal("the actual Portable Session lost its captured state location")
	}
	assertSessionSameFile(t, filepath.Dir(state), dataRoot)
	values := make(map[string]string)
	for _, item := range session.environment {
		name, value, found := strings.Cut(item, "=")
		name = strings.ToUpper(name)
		if !found || values[name] != "" {
			t.Fatal("Portable Session published an ambiguous GUI environment")
		}
		values[name] = value
	}
	for _, name := range []string{"APPDATA", "LOCALAPPDATA", "HOME"} {
		if values[name] != session.dataRoot {
			t.Fatal("Portable GUI cache escaped its captured Data directory", name)
		}
	}
	for _, name := range []string{"TEMP", "TMP"} {
		if strings.HasPrefix(values[name], `\\`) || !filepath.IsAbs(values[name]) {
			t.Fatal("Portable GUI temporary handoff used a CodeDOM-incompatible path", name)
		}
		assertSessionSameFile(t, values[name], filepath.Join(session.dataRoot, "generated"))
	}
	if values["HOMEVPN_PORTABLE"] != "1" {
		t.Fatal("Portable GUI lost its captured Portable mode")
	}
	profile, err := session.self.UserDirectories()
	if err != nil {
		t.Fatal(err)
	}
	assertSessionSameFile(t, values["USERPROFILE"], profile.Profile)
}

func assertSessionSameFile(t *testing.T, actual, expected string) {
	t.Helper()
	left, leftErr := os.Stat(actual)
	right, rightErr := os.Stat(expected)
	if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
		t.Fatalf("native Session captured another physical package/data owner: %v", errors.Join(leftErr, rightErr))
	}
}

func assertSessionCodePinned(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		_ = file.Close()
		t.Fatal("live Session allowed its actual packaged controller code to change")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatal("native Session pin test lost its actual packaged input")
	}
}

func assertSessionStatusOff(t *testing.T, session *Session) {
	t.Helper()
	probe, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := session.client.Request(probe, http.MethodGet, "/api/status", nil, 64<<10)
	var status struct {
		Mode      string `json:"mode"`
		Phase     string `json:"phase"`
		Connected bool   `json:"connected"`
	}
	if err != nil || response.Status != http.StatusOK || json.Unmarshal(response.Body, &status) != nil ||
		status.Mode != "off" || status.Phase != "off" || status.Connected {
		t.Fatalf("the actual production controller did not retain its disconnected state: %v", err)
	}
}

func capturedSessionPreferences(t *testing.T, packageRoot, dataRoot string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, root := range []string{filepath.Join(packageRoot, "client", ".routervpn-state"), filepath.Join(dataRoot, ".routervpn-state")} {
		for _, name := range []string{"windows-onboarding-v3.json", "windows-selected-mode-v1.txt", "windows-custom-presets-v1.json"} {
			path := filepath.Join(root, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			result[path] = raw
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("retaining immutable code made captured mutable UI state unwritable: %v", err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	return result
}
