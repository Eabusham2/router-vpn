//go:build windows && routervpn_controller_windows_native

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowsbootstrap"
	"router-vpn/internal/windowscontroller"
)

// Only this test compilation dispatches the copied executable's public entry
// arguments before testing parses flags. Production has no fixture/environment
// override; the child runs the actual shipping preparation and HTTP lifecycle.
func init() {
	if len(os.Args) > 1 && os.Args[1] == windowsbootstrap.ControllerArgument {
		if err := windowsOwnedNativeChild(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func windowsOwnedNativeChild() error {
	owner, err := prepareNativeOwnedController(os.Args[1:])
	if err != nil {
		return err
	}
	if owner == nil {
		return errors.New("actual Windows child did not capture an owner")
	}
	defer owner.close()
	if err := validateNativeOwnedStartup(owner); err != nil {
		return err
	}
	capture, ok := owner.nativeOwner.(*windowsOwnedController)
	if !ok {
		return errors.New("actual child did not adopt the Windows owner")
	}
	user, err := windowsRuntimeCurrentUser()
	if err != nil || user != capture.desktop.SID {
		return errors.New("actual controller private state replaced the original desktop owner")
	}
	for _, name := range []string{"HOMEVPN_CONTROLLER_OWNER", "HTTP_PROXY", "HTTPS_PROXY", "ROUTERVPN_CONTROLLER_UNSELECTED"} {
		if os.Getenv(name) != "" {
			return errors.New("ambient authority survived owned Windows preparation: " + name)
		}
	}
	if os.Getenv("HOMEVPN_ROOT") != capture.dataRoot || os.Getenv("HOMEVPN_CONTROLLER_TRANSPORT") != "pinned-tls" || os.Getenv("HOMEVPN_CONTROLLER_TLS_PIN") != owner.pinnedTLS.Pin() || os.Getenv("HOMEVPN_CONTROLLER_EXECUTABLE") != capture.selfImage.Path() {
		return errors.New("actual Windows child lost its public pinned drain projection")
	}
	configBytes, err := readPrivateRuntimeSnapshot(filepath.Join(capture.dataRoot, "client.json"), maxPrivateStoreBytes)
	if err != nil {
		return err
	}
	var config common.ClientConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return err
	}
	if err := owner.validateConfiguration(&config); err != nil {
		return err
	}
	catalog, err := os.ReadFile(config.ModesFile)
	if err != nil {
		return err
	}
	var modes []common.Mode
	if err := json.Unmarshal(catalog, &modes); err != nil {
		return err
	}
	if _, err := owner.captureModes(modes); err != nil {
		return err
	}
	if file, err := os.OpenFile(filepath.Join(capture.packageRoot, "client", "held-code.ps1"), os.O_WRONLY, 0); err == nil {
		file.Close()
		return errors.New("captured Windows package code became writable")
	}
	if err := os.WriteFile(filepath.Join(capture.packageRoot, "client", ".routervpn-state", "windows-selected-mode-v1.txt"), []byte("wg\n"), 0600); err != nil {
		return errors.New("capturing immutable Windows code locked mutable GUI state")
	}
	a := &app{localController: owner, state: state{Mode: "off", Phase: "off"}}
	listener, err := net.Listen("tcp", linuxOwnedControllerAddress)
	if err != nil {
		return err
	}
	secured, err := owner.captureListener(listener)
	if err != nil {
		listener.Close()
		return err
	}
	// Hold the real operation lock. The parent must observe draining over TLS
	// while this captured cleanup is pending, then release only this fixture.
	a.operationMu.Lock()
	go func() {
		<-owner.ownerDone
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(capture.dataRoot, "release-native-drain")); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		a.operationMu.Unlock()
	}()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/native-capture" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schema": 1, "portable": capture.portable, "data_root": capture.dataRoot, "package_root": capture.packageRoot})
	})
	return serveClientHTTP(newControllerShutdown(a, owner.ownerToken), secured, handler, nil)
}

func TestWindowsOwnedControllerLauncherFixture(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 2 {
		t.Fatal("native launcher fixture arguments invalid")
	}
	root, mode := arguments[0], arguments[1]
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	packageRoot, dataRoot := root, root
	if strings.HasPrefix(mode, "portable") {
		packageRoot = filepath.Join(root, "App", "RouterVPN")
		dataRoot = filepath.Join(root, "Data")
	}
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	image, err := windowscontroller.PinImage(filepath.Join(packageRoot, "router-vpn-client.exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	parentImage := executable
	if mode == "foreign-layout" {
		parentImage = filepath.Join(root, "unrelated.exe")
	}
	launch, err := windowsbootstrap.Arguments(pipe.Name(), uint32(os.Getpid()), parentImage)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(root, "controller-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	requireFailure := func(witness string) {
		t.Helper()
		_, _ = output.Seek(0, io.SeekStart)
		body, _ := io.ReadAll(io.LimitReader(output, 16384))
		if !strings.Contains(string(body), witness) {
			t.Fatalf("native rejection did not reach its intended boundary %q: %s", witness, body)
		}
	}
	command := exec.Command(filepath.Join(packageRoot, "router-vpn-client.exe"), launch...)
	command.Stdout, command.Stderr = output, output
	command.Env = append(os.Environ(), "HOMEVPN_ROOT=C:\\unselected-root", "HOMEVPN_CLIENT_CONFIG=C:\\unselected-client.json", "HOMEVPN_CONTROLLER_OWNER=unselected-secret", "HTTP_PROXY=http://unselected.invalid", "ROUTERVPN_CONTROLLER_UNSELECTED=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process, err := windowscontroller.OpenProcess(uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	t.Cleanup(func() {
		_ = pipe.Close()
		_ = os.WriteFile(filepath.Join(dataRoot, "release-native-drain"), []byte("release"), 0600)
		select {
		case <-joined:
		case <-time.After(3 * time.Second):
			_ = command.Process.Kill()
			select {
			case <-joined:
			case <-time.After(3 * time.Second):
				t.Error("native child fixture did not join")
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if mode == "foreign-layout" {
		select {
		case err := <-joined:
			if err == nil {
				t.Fatal("foreign launcher layout acquired an elevated controller")
			}
			joined <- err
			requireFailure("retained Windows launcher does not own this exact installed or Portable package")
		case <-ctx.Done():
			t.Fatal("foreign-layout child did not reject before rendezvous")
		}
		return
	}
	if err := pipe.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	frame, err := pipe.ReadFrame(ctx)
	if mode == "unsafe-config" || mode == "code-hardlink" || mode == "config-hardlink" || mode == "private-public-read" || mode == "portable-runtime-hardlink" {
		if err == nil || len(frame) != 0 {
			t.Fatal("unsafe Windows package/configuration reached private handshake")
		}
		select {
		case err := <-joined:
			if err == nil {
				t.Fatal("unsafe Windows preparation reported success")
			}
			joined <- err
			witness := map[string]string{
				"unsafe-config":             "state_file escaped its captured data/package layout",
				"code-hardlink":             "image has a reparse, hardlink or unexpected path component",
				"config-hardlink":           "private runtime file has another Windows hardlink",
				"private-public-read":       "DACL grants access outside its Windows owner boundary",
				"portable-runtime-hardlink": "image has a reparse, hardlink or unexpected path component",
			}[mode]
			requireFailure(witness)
		case <-ctx.Done():
			t.Fatal("unsafe Windows preparation did not join")
		}
		return
	}
	if err != nil {
		_, _ = output.Seek(0, io.SeekStart)
		body, _ := io.ReadAll(io.LimitReader(output, 16384))
		t.Fatalf("actual child hello failed: %v; %s", err, body)
	}
	peer, err := pipe.VerifyPeer(process, image)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := process.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if peer.Identity.Primary || !primary.Primary || !primary.Elevated || !primary.Administrator || peer.Identity.SID != primary.SID || peer.Identity.AuthenticationID != primary.AuthenticationID {
		t.Fatal("actual native child did not prove administrator primary/writer identity")
	}
	if err := peer.Process.Close(); err != nil {
		t.Fatal(err)
	}
	hello, err := windowsbootstrap.DecodeHello(frame, process.PID())
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := windowsbootstrap.NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	private, err := windowsbootstrap.EncodeCredentials(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "malformed-private" {
		private = []byte("{\"schema\":1,\"access_token\":null,\"owner_token\":null}\n")
	}
	if err := pipe.WriteFrame(ctx, private); err != nil {
		t.Fatal(err)
	}
	if mode == "malformed-private" || mode == "injected-catalog" {
		select {
		case err := <-joined:
			if err == nil {
				t.Fatal("invalid private launch or catalog acquired a controller")
			}
			joined <- err
			if mode == "malformed-private" {
				requireFailure("launch credentials are invalid or ambiguous")
			} else {
				requireFailure("Windows wg up command escaped its retained adapter")
			}
		case <-ctx.Done():
			t.Fatal("invalid private launch or catalog did not join")
		}
		return
	}
	client, err := controllertransport.NewClient(process, hello.TLSPin, credentials.AccessToken, credentials.OwnerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for {
		err = client.VerifyIdentity(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("owned Windows TLS identity never became ready:", err)
		}
		if err := process.Alive(); err != nil {
			_, _ = output.Seek(0, io.SeekStart)
			body, _ := io.ReadAll(io.LimitReader(output, 16384))
			t.Fatalf("actual Windows child exited before TLS: %v; %s", err, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	response, err := client.Request(ctx, http.MethodGet, "/api/native-capture", nil, 4096)
	if err != nil || response.Status != 200 {
		t.Fatal("actual native TLS capture request failed", err, response.Status)
	}
	var capture struct {
		Schema      int    `json:"schema"`
		Portable    bool   `json:"portable"`
		DataRoot    string `json:"data_root"`
		PackageRoot string `json:"package_root"`
	}
	if json.Unmarshal(response.Body, &capture) != nil || capture.Schema != 1 || capture.Portable != strings.HasPrefix(mode, "portable") || !windowsOwnedSamePath(capture.DataRoot, dataRoot) || !windowsOwnedSamePath(capture.PackageRoot, packageRoot) {
		t.Fatal("actual child mixed installed/Portable data ownership")
	}
	if mode == "installed-extra-byte" {
		if err := pipe.WriteFrame(ctx, []byte("invalid second frame\n")); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := pipe.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for {
		draining, err := controllertransport.ReadDrain(ctx, process, hello.TLSPin)
		if err == nil && draining {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("retired owner did not keep the actual pinned drain available", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	retired, err := client.Request(ctx, http.MethodGet, "/api/native-capture", nil, 4096)
	if err != nil || retired.Status != http.StatusServiceUnavailable {
		t.Fatal("retired actual launcher did not return its checked retirement status", err, retired.Status)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "release-native-drain"), []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-joined:
		joined <- err
		if err != nil {
			_, _ = output.Seek(0, io.SeekStart)
			body, _ := io.ReadAll(io.LimitReader(output, 16384))
			t.Fatalf("actual controller did not join checked cleanup: %v; %s", err, body)
		}
	case <-ctx.Done():
		t.Fatal("actual Windows controller did not join its captured cleanup")
	}
	if err := process.Alive(); err == nil {
		t.Fatal("native cleanup receipt left the actual child alive")
	}
}

func TestWindowsOwnedControllerPrivateRootRetainsNamespace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if err := ensurePrivateRuntimeDirectory(root); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	capture := &windowsOwnedController{dataRoot: root}
	closePins := func() error {
		var result error
		for index, file := range capture.directories {
			if file != nil {
				err := file.Close()
				result = errors.Join(result, err)
				if err == nil {
					capture.directories[index] = nil
				}
			}
		}
		return result
	}
	defer func() {
		if err := closePins(); err != nil {
			t.Error(err)
		}
	}()
	if err := capture.pinDataDirectory(); err != nil {
		t.Fatal(err)
	}
	// The private root stays writable. No open descendant file may mask a
	// metadata-only directory handle in the following namespace check.
	state := filepath.Join(root, "mutable-state.json")
	if err := os.WriteFile(state, []byte("{}\n"), 0600); err != nil {
		t.Fatal("captured controller data lost mutable state", err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	moved := root + ".retired"
	if err := os.Rename(root, moved); err == nil {
		restoreErr := os.Rename(moved, root)
		t.Fatal("captured controller private root allowed namespace replacement", restoreErr)
	}
	if err := closePins(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, moved); err != nil {
		t.Fatal("joined controller data retirement retained its namespace lock", err)
	}
	if err := ensurePrivateRuntimeDirectory(root); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(root)
	if err != nil || os.SameFile(before, after) {
		t.Fatal("released controller data fixture did not replace its directory identity", err)
	}
}

func TestWindowsOwnedControllerCodeAndPrivateACLPolicy(t *testing.T) {
	user := windowsRuntimeTestUser(t)
	for _, test := range []struct {
		name, sddl    string
		code, private bool
	}{
		{"private", "O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;FA;;;BA)", true, true},
		{"public-read", "O:" + user + "D:P(A;;FA;;;" + user + ")(A;;GRGX;;;WD)", true, false},
		{"public-write", "O:" + user + "D:P(A;;FA;;;" + user + ")(A;;GW;;;WD)", false, false},
		{"public-write-attributes", "O:" + user + "D:P(A;;FA;;;" + user + ")(A;;0x100;;;WD)", false, false},
		{"foreign-owner", "O:S-1-5-21-111-222-333-444D:P(A;;FA;;;" + user + ")", false, false},
		{"absent", "O:" + user, false, false},
		{"empty", "O:" + user + "D:P", false, false},
		{"inherit-only", "O:" + user + "D:P(A;OICIIO;GR;;;WD)", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			security, err := windowsRuntimeSecurityFromSDDL(test.sddl)
			if err != nil {
				t.Fatal("Windows rejected the intended native security descriptor", err)
			}
			defer security.close()
			if got := windowsRuntimeValidateCodeSecurity(security, user) == nil; got != test.code {
				t.Fatal("immutable Windows package admitted the wrong code ACL", got, test.code)
			}
			if got := windowsRuntimeValidateSecurity(security, user) == nil; got != test.private {
				t.Fatal("private Windows state admitted the wrong read boundary", got, test.private)
			}
		})
	}
}

func TestWindowsOwnedControllerNativeEntry(t *testing.T) {
	identity, err := windowscontroller.CurrentIdentity()
	if err != nil || !identity.Elevated || !identity.Administrator {
		t.Fatal("Windows child entry requires the actual elevated native test host", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyExecutable := func(target string) {
		source, err := os.Open(executable)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		dest, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(dest, source)
		closeErr := dest.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal(copyErr, closeErr)
		}
	}
	for _, mode := range []string{"installed-eof", "portable-eof", "portable-outer-eof", "installed-extra-byte", "foreign-layout", "unsafe-config", "code-hardlink", "config-hardlink", "private-public-read", "portable-runtime-hardlink", "malformed-private", "injected-catalog"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			if err := ensurePrivateRuntimeDirectory(root); err != nil {
				t.Fatal(err)
			}
			packageRoot, dataRoot, parent := root, root, filepath.Join(root, "RouterVPN.exe")
			if strings.HasPrefix(mode, "portable") {
				packageRoot = filepath.Join(root, "App", "RouterVPN")
				dataRoot = filepath.Join(root, "Data")
				parent = filepath.Join(root, "RouterVPNPortableCore.exe")
				if mode == "portable-outer-eof" {
					parent = filepath.Join(root, "RouterVPNPortable.exe")
				}
			}
			for _, directory := range []string{packageRoot, dataRoot, filepath.Join(packageRoot, "client"), filepath.Join(packageRoot, "client", ".routervpn-state"), filepath.Join(packageRoot, "modes"), filepath.Join(packageRoot, "runtime")} {
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			copyExecutable(parent)
			copyExecutable(filepath.Join(packageRoot, "router-vpn-client.exe"))
			if mode == "foreign-layout" {
				copyExecutable(filepath.Join(root, "unrelated.exe"))
			}
			config := map[string]any{"listen": linuxOwnedControllerAddress, "modes_file": filepath.Join(packageRoot, "modes.json"), "scripts_dir": filepath.Join(packageRoot, "modes"), "state_file": filepath.Join(dataRoot, "state.json"), "profiles_file": filepath.Join(dataRoot, "routers.json")}
			if mode == "unsafe-config" {
				config["state_file"] = filepath.Join(root, "unselected-state.json")
			}
			if mode == "injected-catalog" {
				config["modes_file"] = filepath.Join(dataRoot, "modes.windows.json")
			}
			body, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			sourceCatalog := []byte(`[{"id":"wg","name":"WireGuard","command":["./run-platform.sh","run-mode.sh","wg"],"check_command":["./check-mode.sh","wg"],"stop_command":["./stop-mode-platform.sh"]}]`)
			for name, data := range map[string][]byte{filepath.Join(dataRoot, "client.json"): body, filepath.Join(packageRoot, "modes.json"): sourceCatalog, filepath.Join(packageRoot, "logical-modes.json"): []byte("[]"), filepath.Join(packageRoot, "client", "held-code.ps1"): []byte("# owned fixture\n"), filepath.Join(packageRoot, "client", "native-wireguard-windows.ps1"): []byte("# retained native adapter\n"), filepath.Join(packageRoot, "client", "native-windows-mode.ps1"): []byte("# retained native adapter\n")} {
				if err := os.WriteFile(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(packageRoot, "client", ".routervpn-state", "windows-selected-mode-v1.txt"), []byte("smart-auto\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "code-hardlink" {
				if err := os.Link(filepath.Join(packageRoot, "client", "held-code.ps1"), filepath.Join(packageRoot, "client", "code-alias.ps1")); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "config-hardlink" {
				if err := os.Link(filepath.Join(dataRoot, "client.json"), filepath.Join(dataRoot, "client-alias.json")); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "private-public-read" {
				user := windowsRuntimeTestUser(t)
				setWindowsRuntimeTestDACL(t, filepath.Join(dataRoot, "client.json"), "O:"+user+"D:P(A;;FA;;;"+user+")(A;;GR;;;WD)")
			}
			if mode == "portable-runtime-hardlink" {
				directory := filepath.Join(dataRoot, "runtime", "windows")
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(directory, "retained-runtime.dll")
				if err := os.WriteFile(path, []byte("owned runtime fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(path, filepath.Join(directory, "runtime-alias.dll")); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "injected-catalog" {
				var modes []common.Mode
				if err := json.Unmarshal(sourceCatalog, &modes); err != nil {
					t.Fatal(err)
				}
				modes[0].Command = []string{"unselected-command.exe"}
				bytes, err := json.Marshal(modes)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dataRoot, "modes.windows.json"), bytes, 0600); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command(parent, "-test.run=^TestWindowsOwnedControllerLauncherFixture$", "-test.count=1", "-test.timeout=35s", "--", root, mode)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("actual owned Windows entry fixture %s failed: %v; %s", mode, err, output)
			}
		})
	}
}
