//go:build darwin && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const macOSControllerFixtureMarker = "ROUTERVPN_MACOS_CONTROLLER_PRIVILEGE_FIXTURE"

func init() {
	// Only this explicit test binary contains these entry points. They are
	// absent from the shipping controller and never weaken a production flag.
	privilegedRole := len(os.Args) == 2 && (os.Args[1] == macOSControllerSupervisorArgument || os.Args[1] == macOSOwnedControllerArgument)
	if privilegedRole {
		marker := filepath.Join(macOSOwnedControllerRoot, "fixture-native-authority")
		info, err := os.Lstat(marker)
		body, readErr := os.ReadFile(marker)
		if err != nil || readErr != nil || !info.Mode().IsRegular() || !ownedDesktopInfo(info) || info.Mode().Perm() != 0600 || string(body) != "explicit disposable macOS controller fixture\n" {
			fmt.Fprintln(os.Stderr, "privileged test entry point has no explicit root-owned fixture authority")
			os.Exit(120)
		}
	}
	if len(os.Args) == 2 && os.Args[1] == macOSControllerSupervisorArgument {
		main()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == macOSOwnedControllerArgument {
		if err := macOSControllerFixtureChild(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(121)
		}
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "--routervpn-test-macos-peer" {
		if err := macOSControllerFixturePeer(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(122)
		}
		os.Exit(0)
	}
}

func macOSControllerFixturePeer() error {
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: macOSOwnedControllerSocket, Net: "unix"})
	if err != nil {
		return err
	}
	defer connection.Close()
	file, err := connection.File()
	if err != nil {
		return err
	}
	defer file.Close()
	return syscall.Sendmsg(3, []byte{1}, syscall.UnixRights(int(file.Fd())), nil, 0)
}

func macOSControllerFixtureChild() error {
	owned, err := prepareNativeOwnedController(os.Args[1:])
	if err != nil {
		return err
	}
	defer owned.close()
	if err = validateNativeOwnedStartup(owned); err != nil {
		return err
	}
	if owned == nil || owned.accessToken == "" || owned.ownerToken == "" {
		return errors.New("native fixture lost actual inherited launch credentials")
	}
	for _, value := range append(os.Args, os.Environ()...) {
		if strings.Contains(value, owned.accessToken) || strings.Contains(value, owned.ownerToken) {
			return errors.New("native credentials leaked into process discovery")
		}
	}
	if os.Getenv("PATH") != macOSOwnedControllerRoot+"/bin:/usr/bin:/bin:/usr/sbin:/sbin" || os.Getenv("HOMEVPN_ROOT") != macOSOwnedControllerRoot {
		return errors.New("native bootstrap inherited a caller-selected root or tool path")
	}
	a := &app{state: state{Mode: "off", Phase: "off"}, localController: owned}
	operation, release, err := a.beginConnectionOperation()
	if err != nil {
		return err
	}
	var once sync.Once
	finish := func() { once.Do(release) }
	defer finish()
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		done <- serveClientHTTP(closing, listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/multihop/status" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"comparison": map[string]any{"id": "native-controller-auth", "request_id": strings.Repeat("a", 32), "last_node_measurement": "tor-last-relay-http", "external_measurement": "same-captured-endpoint-http", "complete": false}})
				return
			}
			_, _ = io.WriteString(w, "captured installed controller")
		}), make(chan os.Signal))
	}()
	<-operation.Done()
	if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "fixture-canceled"), []byte("captured cancellation\n"), 0600); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err = os.Stat(filepath.Join(macOSOwnedControllerRoot, "fixture-release")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("fixture refused to invent an owned-operation join")
		}
		time.Sleep(5 * time.Millisecond)
	}
	finish()
	return <-done
}

type macOSControllerNativeFixture struct {
	t          *testing.T
	uid        uint32
	root       os.FileInfo
	log        *os.File
	supervisor *exec.Cmd
	joined     chan error
}

func macOSControllerNativeInstall(t *testing.T) *macOSControllerNativeFixture {
	t.Helper()
	if os.Getenv(macOSControllerFixtureMarker) != "1" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("actual macOS controller gate requires its explicit disposable-host root runner")
	}
	uid, err := strconv.ParseUint(os.Getenv("ROUTERVPN_MACOS_FIXTURE_UID"), 10, 32)
	if err != nil || uid == 0 || uid >= uint64(^uint32(0)) {
		t.Fatal("native gate has no captured ordinary desktop UID")
	}
	for _, path := range []string{macOSOwnedControllerRoot, macOSOwnedInstallLock, macOSOwnedProcessLock, macOSOwnedSupervisorLock, macOSOwnedControllerSocketDirectory} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("native fixture refuses any existing install/socket/lock", path, err)
		}
	}
	if _, err := os.Lstat("/opt"); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir("/opt", 0755); err != nil {
			t.Fatal(err)
		}
		// Remove only this newly created, now-empty ancestor. A concurrent
		// unrelated installation is never recursively removed by the fixture.
		t.Cleanup(func() {
			if err := os.Remove("/opt"); err != nil {
				t.Error("native fixture retained its nonempty /opt ancestor", err)
			}
		})
	}
	if err = ownedDesktopAncestors("/opt"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{macOSOwnedControllerRoot, filepath.Join(macOSOwnedControllerRoot, "modes"), filepath.Join(macOSOwnedControllerRoot, "bin")} {
		if err = os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	rootIdentity, err := os.Lstat(macOSOwnedControllerRoot)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &macOSControllerNativeFixture{t: t, uid: uint32(uid), root: rootIdentity}
	t.Cleanup(func() {
		defer func() {
			if fixture.log == nil {
				return
			}
			defer fixture.log.Close()
			if !t.Failed() {
				return
			}
			// A missing socket or receipt may be caused by the actual nested
			// supervisor/child bootstrap. Keep its bounded diagnostic after
			// cleanup/join, including when ownership prevents path removal.
			// Read the retained file descriptor: TempDir cleanup may already
			// have unlinked its pathname, without retiring the child writer.
			if info, err := fixture.log.Stat(); err == nil {
				start := max(int64(0), info.Size()-24*1024)
				body := make([]byte, info.Size()-start)
				count, _ := fixture.log.ReadAt(body, start)
				if count > 0 {
					t.Logf("actual native supervisor/child failure output (bounded tail):\n%s", body[:count])
				}
			}
		}()
		current, err := os.Lstat(macOSOwnedControllerRoot)
		if err != nil || !os.SameFile(fixture.root, current) {
			t.Error("native fixture root changed; refusing replacement cleanup", err)
			return
		}
		_ = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "fixture-release"), []byte("joined\n"), 0600)
		if fixture.supervisor != nil {
			_ = fixture.supervisor.Process.Signal(syscall.SIGTERM)
			select {
			case <-fixture.joined:
			case <-time.After(20 * time.Second):
				t.Error("captured supervisor did not join; fixture paths retained")
				return
			}
		}
		// Do not delete state under a child that still owns its upgrade/process
		// locks. A lost join is a failed gate, not permission to force cleanup.
		var locks []*os.File
		for _, path := range []string{macOSOwnedInstallLock, macOSOwnedProcessLock, macOSOwnedSupervisorLock} {
			file, err := ownedDesktopLock(path, true)
			if err != nil {
				t.Error("native fixture retains a live owner; refusing path cleanup", err)
				for _, held := range locks {
					held.Close()
				}
				return
			}
			locks = append(locks, file)
		}
		defer func() {
			for _, held := range locks {
				held.Close()
			}
		}()
		// Keep the exclusive install lock through owned path removal. Its
		// pathname is removed last, after no other cleanup mutation remains.
		for _, path := range []string{macOSOwnedControllerRoot, macOSOwnedControllerSocketDirectory, macOSOwnedProcessLock, macOSOwnedSupervisorLock, macOSOwnedInstallLock} {
			if err := os.RemoveAll(path); err != nil {
				t.Error(err)
			}
		}
	})
	installed, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(macOSOwnedExecutable(), data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(macOSOwnedExecutable(), 0755); err != nil {
		t.Fatal(err)
	}
	record, _ := json.Marshal(map[string]any{"schema": 1, "caller_uid": uid})
	if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "fixture-native-authority"), []byte("explicit disposable macOS controller fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"controller-owner.json": record, "client.json": []byte(`{"listen":"127.0.0.1:8788","modes_file":"modes.json","scripts_dir":"modes","profiles_file":"routers.json","state_file":"state.json"}`), "modes.json": []byte(`[]`), "routers.json": []byte(`{}`), "state.json": []byte(`{}`)} {
		if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Copy the actual source closure and invoke its real empty-policy reassert.
	// There is no kill-switch state and no PF, route or launchd mutation.
	source := os.Getenv("ROUTERVPN_MACOS_FIXTURE_SOURCE")
	for _, name := range []string{"kill-switch-platform.py", "kill-switch.py", "darwin_kill_switch.py", "profile_id.py"} {
		data, err = os.ReadFile(filepath.Join(source, "modes", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "modes", name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	python, _, err := macOSPythonTrustRoot(os.Getenv("ROUTERVPN_MACOS_FIXTURE_PYTHON"))
	if err != nil {
		t.Fatal("native fixture requires the same trusted root Python boundary as installation", err)
	}
	if strings.ContainsAny(python, "'\n\r") {
		t.Fatal("invalid captured interpreter")
	}
	wrapper := "#!/bin/sh\nexec '" + python + "' -Es \"$@\"\n"
	if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "bin", "python3"), []byte(wrapper), 0755); err != nil {
		t.Fatal(err)
	}
	fixture.log, err = os.CreateTemp(t.TempDir(), "native-supervisor-")
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *macOSControllerNativeFixture) start() {
	f.t.Helper()
	f.supervisor = exec.Command(macOSOwnedExecutable(), macOSControllerSupervisorArgument)
	f.supervisor.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root", "LANG=en_US.UTF-8", "GORACE=atexit_sleep_ms=0"}
	f.supervisor.Stdout, f.supervisor.Stderr = f.log, f.log
	if err := f.supervisor.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.joined = make(chan error, 1)
	go func() { f.joined <- f.supervisor.Wait() }()
	macOSControllerNativeAwait(f.t, func() bool {
		info, err := os.Lstat(macOSOwnedControllerSocket)
		return err == nil && info.Mode()&os.ModeSocket != 0
	}, "root supervisor did not expose its protected socket")
}

func macOSControllerNativeAwait(t *testing.T, ready func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *macOSControllerNativeFixture) connection(uid uint32) *net.UnixConn {
	f.t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	defer syscall.Close(pair[0])
	child := os.NewFile(uintptr(pair[1]), "fixture-peer-rights")
	defer child.Close()
	command := exec.Command(macOSOwnedExecutable(), "--routervpn-test-macos-peer")
	command.Env = []string{"PATH=/usr/bin:/bin", "GORACE=atexit_sleep_ms=0"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	command.ExtraFiles = []*os.File{child}
	command.Stdout, command.Stderr = f.log, f.log
	if err = command.Start(); err != nil {
		f.t.Fatal(err)
	}
	_ = child.Close()
	timeout := syscall.NsecToTimeval((5 * time.Second).Nanoseconds())
	if err = syscall.SetsockoptTimeval(pair[0], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		f.t.Fatal(err)
	}
	payload, rights := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	n, control, flags, _, err := syscall.Recvmsg(pair[0], payload, rights, 0)
	waitErr := command.Wait()
	if err != nil || waitErr != nil || n != 1 || flags != 0 {
		f.t.Fatal("actual ordinary-user peer failed", err, waitErr)
	}
	messages, err := syscall.ParseSocketControlMessage(rights[:control])
	if err != nil || len(messages) != 1 {
		f.t.Fatal("peer did not transfer exactly its socket", err)
	}
	fds, err := syscall.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 1 {
		f.t.Fatal("peer did not transfer one actual descriptor", err)
	}
	file := os.NewFile(uintptr(fds[0]), "fixture-authorized-user-socket")
	defer file.Close()
	connection, err := net.FileConn(file)
	if err != nil {
		f.t.Fatal(err)
	}
	return connection.(*net.UnixConn)
}

func macOSControllerNativeFrame() []byte {
	return []byte(`{"schema":1,"access_token":"` + testLocalControllerAccess + `","owner_token":"` + testControllerOwner + `"}` + "\n")
}

func macOSControllerNativeReceipt(t *testing.T, c *net.UnixConn, phase string, pid int) ownedControllerSupervisorReceipt {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
	frame, err := readOwnedControllerFrame(c)
	if err != nil {
		t.Fatal("actual supervisor receipt missing", phase, err)
	}
	var receipt ownedControllerSupervisorReceipt
	if decodeRelayControlJSON(frame, &receipt) != nil || receipt.Schema != 1 || receipt.Phase != phase || receipt.ProcessID <= 0 || (pid != 0 && receipt.ProcessID != pid) ||
		receipt.Proof != ownedControllerSupervisorMAC(testLocalControllerAccess, phase, receipt.ProcessID, testControllerOwner, receipt.ExitCode) || bytes.Contains(frame, []byte(testLocalControllerAccess)) || bytes.Contains(frame, []byte(testControllerOwner)) {
		t.Fatal("actual root supervisor receipt did not authenticate its captured process")
	}
	return receipt
}

func macOSControllerNativeHTTP(t *testing.T) *http.Client {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestMacOSOwnedControllerNativeLifetimeAndInheritedLocks(t *testing.T) {
	for _, ending := range []string{"eof", "second-byte", "supervisor-stop"} {
		t.Run(ending, func(t *testing.T) {
			fixture := macOSControllerNativeInstall(t)
			fixture.start()
			connection := fixture.connection(fixture.uid)
			defer connection.Close()
			if _, err := connection.Write(macOSControllerNativeFrame()); err != nil {
				t.Fatal(err)
			}
			started := macOSControllerNativeReceipt(t, connection, "started", 0)
			client := macOSControllerNativeHTTP(t)
			macOSControllerNativeAwait(t, func() bool {
				request, _ := http.NewRequest("GET", "http://"+linuxOwnedControllerAddress+"/api/status", nil)
				request.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
				response, err := client.Do(request)
				if err != nil {
					return false
				}
				defer response.Body.Close()
				return response.StatusCode == 200
			}, "actual child did not serve its authenticated HTTP owner")
			request, _ := http.NewRequest("GET", "http://"+linuxOwnedControllerAddress+"/api/status", nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 403 {
				t.Fatal("installed child accepted an unauthenticated read")
			}
			for _, path := range []string{macOSOwnedInstallLock, macOSOwnedProcessLock} {
				if held, err := ownedDesktopLock(path, true); err == nil {
					held.Close()
					t.Fatal("exact child did not inherit lock before admission", path)
				}
			}
			if ending == "eof" {
				err = connection.CloseWrite()
			} else if ending == "second-byte" {
				_, err = connection.Write([]byte{'x'})
			} else {
				err = fixture.supervisor.Process.Signal(syscall.SIGTERM)
			}
			if err != nil {
				t.Fatal(err)
			}
			macOSControllerNativeAwait(t, func() bool {
				_, err := os.Stat(filepath.Join(macOSOwnedControllerRoot, "fixture-canceled"))
				return err == nil
			}, "captured desktop EOF did not cancel actual connection ownership")
			for _, path := range []string{macOSOwnedInstallLock, macOSOwnedProcessLock} {
				if held, err := ownedDesktopLock(path, true); err == nil {
					held.Close()
					t.Fatal("cleanup released inherited lock before owned operation joined", path)
				}
			}
			_ = connection.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			var probe [1]byte
			if n, err := connection.Read(probe[:]); n != 0 || err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("supervisor invented joined receipt before held cleanup", n, err)
			}
			if err = os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "fixture-release"), []byte("release captured operation\n"), 0600); err != nil {
				t.Fatal(err)
			}
			joined := macOSControllerNativeReceipt(t, connection, "joined", started.ProcessID)
			if joined.ExitCode != 0 {
				t.Fatal("captured controller did not join successfully", joined.ExitCode)
			}
			for _, path := range []string{macOSOwnedInstallLock, macOSOwnedProcessLock} {
				held, err := ownedDesktopLock(path, true)
				if err != nil {
					t.Fatal("actual joined child retained lock", err)
				}
				held.Close()
			}
		})
	}
}

func TestMacOSOwnedControllerNativeRejectsForeignUIDAndInvalidFrames(t *testing.T) {
	fixture := macOSControllerNativeInstall(t)
	fixture.start()
	for _, tc := range []struct {
		name  string
		uid   uint32
		frame []byte
	}{
		{"root-peer", 0, macOSControllerNativeFrame()},
		{"unknown-field", fixture.uid, bytes.Replace(macOSControllerNativeFrame(), []byte(`"schema":1`), []byte(`"schema":1,"extra":1`), 1)},
		{"duplicate-schema", fixture.uid, bytes.Replace(macOSControllerNativeFrame(), []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)},
		{"uppercase-secret", fixture.uid, bytes.ReplaceAll(macOSControllerNativeFrame(), []byte(testLocalControllerAccess), []byte(strings.Repeat("A", 64)))},
		{"oversized", fixture.uid, append(bytes.Repeat([]byte{'x'}, 385), '\n')},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connection := fixture.connection(tc.uid)
			defer connection.Close()
			_, _ = connection.Write(tc.frame)
			_ = connection.SetReadDeadline(time.Now().Add(6 * time.Second))
			var frame [1]byte
			n, err := connection.Read(frame[:])
			if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("foreign or invalid peer received authority", n, err)
			}
			lock, err := ownedDesktopLock(macOSOwnedProcessLock, true)
			if err != nil {
				t.Fatal("rejected request retained a controller child", err)
			}
			lock.Close()
		})
	}
}

func TestMacOSOwnedControllerNativeRejectsUnsafeInstalledAuthority(t *testing.T) {
	for _, name := range []string{"owner-readable", "owner-root", "configuration-escape", "writable-code", "linked-code", "acl-writable-code", "acl-readable-owner"} {
		t.Run(name, func(t *testing.T) {
			fixture := macOSControllerNativeInstall(t)
			switch name {
			case "owner-readable":
				if err := os.Chmod(macOSOwnedControllerRecord, 0644); err != nil {
					t.Fatal(err)
				}
			case "owner-root":
				if err := os.WriteFile(macOSOwnedControllerRecord, []byte(`{"schema":1,"caller_uid":0}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "configuration-escape":
				if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "client.json"), []byte(`{"scripts_dir":"/tmp/user-controlled"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "writable-code":
				if err := os.Chmod(filepath.Join(macOSOwnedControllerRoot, "bin", "python3"), 0777); err != nil {
					t.Fatal(err)
				}
			case "linked-code":
				if err := os.Symlink("/bin/sh", filepath.Join(macOSOwnedControllerRoot, "modes", "foreign")); err != nil {
					t.Fatal(err)
				}
			case "acl-writable-code", "acl-readable-owner":
				path, rule := filepath.Join(macOSOwnedControllerRoot, "bin", "python3"), "everyone allow write"
				if name == "acl-readable-owner" {
					path, rule = macOSOwnedControllerRecord, "everyone allow read"
				}
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if output, err := exec.Command("/bin/chmod", "+a", rule, path).CombinedOutput(); err != nil {
					t.Fatal("actual native ACL fixture failed", err, string(output))
				}
				t.Cleanup(func() {
					if output, err := exec.Command("/bin/chmod", "-N", path).CombinedOutput(); err != nil {
						t.Error("native ACL fixture removal failed", err, string(output))
					}
				})
				after, err := os.Lstat(path)
				if err != nil || before.Mode().Perm() != after.Mode().Perm() {
					t.Fatal("ACL test must exercise authority hidden from unchanged Unix mode bits", err)
				}
			}
			command := exec.Command(macOSOwnedExecutable(), macOSControllerSupervisorArgument)
			command.Env = macOSOwnedEnvironment()
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("unsafe installed source acquired privileged supervisor", name)
			}
			if len(output) == 0 || bytes.Contains(output, []byte(testLocalControllerAccess)) {
				t.Fatal("rejection was not a bounded safe diagnostic")
			}
			if _, err := os.Lstat(macOSOwnedControllerSocket); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid install exposed a socket before validation")
			}
			_ = fixture
		})
	}
}

func TestMacOSOwnedControllerNativeSupervisorRestartDoesNotAdoptLiveChild(t *testing.T) {
	fixture := macOSControllerNativeInstall(t)
	fixture.start()
	connection := fixture.connection(fixture.uid)
	defer connection.Close()
	_, _ = connection.Write(macOSControllerNativeFrame())
	started := macOSControllerNativeReceipt(t, connection, "started", 0)
	client := macOSControllerNativeHTTP(t)
	macOSControllerNativeAwait(t, func() bool {
		r, _ := http.NewRequest("GET", "http://"+linuxOwnedControllerAddress+"/api/status", nil)
		r.Header.Set("Authorization", "Bearer "+testLocalControllerAccess)
		response, err := client.Do(r)
		if err != nil {
			return false
		}
		response.Body.Close()
		return response.StatusCode == 200
	}, "child was not ready before captured supervisor crash")
	if err := fixture.supervisor.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := <-fixture.joined; err == nil {
		t.Fatal("killed supervisor reported a successful process exit")
	}
	fixture.supervisor = nil
	newOwner := exec.Command(macOSOwnedExecutable(), macOSControllerSupervisorArgument)
	newOwner.Env = macOSOwnedEnvironment()
	if output, err := newOwner.CombinedOutput(); err == nil || !bytes.Contains(output, []byte("previous owned controller")) {
		t.Fatal("replacement supervisor adopted or reasserted over a live child", err, string(output))
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	macOSControllerNativeAwait(t, func() bool {
		_, err := os.Stat(filepath.Join(macOSOwnedControllerRoot, "fixture-canceled"))
		return err == nil
	}, "orphaned owner ignored actual desktop EOF")
	if held, err := ownedDesktopLock(macOSOwnedInstallLock, true); err == nil {
		held.Close()
		t.Fatal("orphaned child lost its installation lock before cleanup")
	}
	if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "fixture-release"), []byte("release\n"), 0600); err != nil {
		t.Fatal(err)
	}
	macOSControllerNativeAwait(t, func() bool {
		held, err := ownedDesktopLock(macOSOwnedInstallLock, true)
		if err != nil {
			return false
		}
		held.Close()
		return true
	}, "orphaned child did not drain its owned locks")
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	var response [1]byte
	if n, err := connection.Read(response[:]); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("missing supervisor produced a false joined receipt", started.ProcessID, n, err)
	}
}

func TestMacOSOwnedControllerNativeAppKitClient(t *testing.T) {
	fixture := macOSControllerNativeInstall(t)
	check := os.Getenv("ROUTERVPN_MACOS_FIXTURE_APPKIT")
	if check == "" {
		t.Fatal("native gate must execute the real AppKit authenticated-launch client")
	}
	app := filepath.Join(macOSOwnedControllerRoot, "RouterVPN.app", "Contents")
	if err := os.MkdirAll(filepath.Join(app, "MacOS"), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(check)
	if err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(app, "MacOS", "RouterVPN")
	if err = os.WriteFile(installed, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(installed, 0755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>RouterVPN</string><key>CFBundleIdentifier</key><string>com.routervpn.controller.nativefixture</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleName</key><string>Router VPN Native Controller Fixture</string><key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict></dict></plist>`
	if err = os.WriteFile(filepath.Join(app, "Info.plist"), []byte(plist), 0644); err != nil {
		t.Fatal(err)
	}
	fixture.start()
	command := exec.Command(installed)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "LANG=en_US.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: fixture.uid, Gid: fixture.uid, Groups: []uint32{}}}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	var joinErr error
	go func() { joinErr = command.Wait(); close(joined) }()
	t.Cleanup(func() {
		// This is only the exact ordinary-user test harness we started. The
		// privileged child remains owned by the supervisor and its checked drain.
		select {
		case <-joined:
		default:
			_ = command.Process.Kill()
			select {
			case <-joined:
			case <-time.After(5 * time.Second):
				t.Error("the captured native test harness did not join")
			}
		}
		if t.Failed() {
			select {
			case <-joined:
				// Wait has joined exec's output-copy goroutines. Reading the
				// buffer before that acknowledgement would race the native UI.
				body := output.Bytes()
				if len(body) > 24*1024 {
					body = body[len(body)-24*1024:]
				}
				if len(body) > 0 {
					t.Logf("actual native AppKit failure output (bounded tail):\n%s", body)
				}
			default:
				t.Log("actual native AppKit output remains owned by an unjoined child")
			}
		}
	})
	macOSControllerNativeAwait(t, func() bool {
		_, err := os.Stat(filepath.Join(macOSOwnedControllerRoot, "fixture-canceled"))
		return err == nil
	}, "actual AppKit client did not request captured cleanup")
	if err := os.WriteFile(filepath.Join(macOSOwnedControllerRoot, "fixture-release"), []byte("release\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
		if joinErr != nil {
			t.Fatal("actual AppKit authenticated launch failed", joinErr, output.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("actual AppKit client did not wait for authenticated join")
	}
	if !strings.Contains(output.String(), "Actual native AppKit root peer, HTTP identity, bearer admission and joined exit: PASS") {
		t.Fatal("native AppKit evidence missing", output.String())
	}
	if output, err := exec.Command("/bin/chmod", "+a", "everyone allow write", macOSOwnedControllerSocketDirectory).CombinedOutput(); err != nil {
		t.Fatal("actual native socket-directory ACL fixture failed", err, string(output))
	}
	t.Cleanup(func() {
		if output, err := exec.Command("/bin/chmod", "-N", macOSOwnedControllerSocketDirectory).CombinedOutput(); err != nil {
			t.Error("native socket-directory ACL fixture removal failed", err, string(output))
		}
	})
	bounded, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rejected := exec.CommandContext(bounded, installed, "--reject-unsafe-supervisor-acl")
	rejected.Env, rejected.SysProcAttr = command.Env, command.SysProcAttr
	if evidence, err := rejected.CombinedOutput(); err != nil || !bytes.Contains(evidence, []byte("Actual native AppKit unsafe supervisor ACL rejected: PASS")) {
		t.Fatal("actual AppKit socket-path ACL gate failed", err, string(evidence))
	}
}
