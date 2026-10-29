//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
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

const linuxControllerNamespaceMarker = "ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS"
const linuxControllerFixtureUID = 65534

func init() {
	if os.Getenv(linuxControllerNamespaceMarker) != "1" {
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "--routervpn-test-real-installed-main" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
		main()
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "--routervpn-test-create-owner-pipe" {
		if err := linuxControllerFixtureCreatePipe(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(124)
		}
		os.Exit(0)
	}
	if containsOwnedControllerArgument(os.Args[1:]) {
		if err := linuxControllerFixtureBootstrap(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(123)
		}
		os.Exit(0)
	}
}

func linuxControllerFixtureCreatePipe() error {
	if os.Getuid() != linuxControllerFixtureUID || os.Geteuid() != linuxControllerFixtureUID {
		return errors.New("fixture pipe creator has wrong actual UID")
	}
	channelFile := os.NewFile(3, "fixture-pipe-transfer")
	defer channelFile.Close()
	channel, err := net.FileConn(channelFile)
	if err != nil {
		return err
	}
	defer channel.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer reader.Close()
	defer writer.Close()
	_, _, err = channel.(*net.UnixConn).WriteMsgUnix([]byte{1}, syscall.UnixRights(int(reader.Fd()), int(writer.Fd())), nil)
	return err
}

func linuxControllerFixtureBootstrap() error {
	held := os.Getenv("ROUTERVPN_CONTROLLER_FIXTURE_HELD") == "1"
	owned, err := prepareLinuxOwnedController(os.Args[1:])
	if err != nil {
		return err
	}
	if owned == nil {
		return errors.New("fixed bootstrap did not produce an owner")
	}
	defer owned.close()
	if err = validateLinuxOwnedStartup(owned); err != nil {
		return err
	}
	if owned.processID != os.Getpid() || owned.callerUID != linuxControllerFixtureUID || owned.accessToken != testLocalControllerAccess || owned.ownerToken != testControllerOwner {
		return errors.New("bootstrap changed its actual private owner")
	}
	for _, key := range []string{"HOMEVPN_CONTROLLER_OWNER", "HTTPS_PROXY", "HTTP_PROXY", "PKEXEC_UID", "ROUTERVPN_CONTROLLER_FIXTURE_HELD", linuxControllerNamespaceMarker} {
		if os.Getenv(key) != "" {
			return errors.New("bootstrap retained caller-selected environment")
		}
	}
	if os.Getenv("HOMEVPN_ROOT") != linuxOwnedControllerRoot || os.Getenv("HOMEVPN_CLIENT_CONFIG") != filepath.Join(linuxOwnedControllerRoot, "client.json") {
		return errors.New("bootstrap retained caller-selected installed paths")
	}
	if cwd, err := os.Getwd(); err != nil || cwd != linuxOwnedControllerRoot {
		return errors.New("bootstrap did not select its installed working directory")
	}
	for _, value := range append(os.Args, os.Environ()...) {
		if strings.Contains(value, testLocalControllerAccess) || strings.Contains(value, testControllerOwner) {
			return errors.New("bootstrap published its private stdin identity")
		}
	}
	for _, name := range []string{"cmdline", "environ"} {
		raw, err := os.ReadFile("/proc/self/" + name)
		if err != nil || bytes.Contains(raw, []byte(testLocalControllerAccess)) || bytes.Contains(raw, []byte(testControllerOwner)) {
			return errors.New("private stdin credentials entered actual process discovery")
		}
	}
	if !held {
		fmt.Fprintln(os.Stdout, "prepared")
		return nil
	}
	a := &app{state: state{Mode: "off", Phase: "off"}, localController: owned}
	operation, release, err := a.beginConnectionOperation()
	if err != nil {
		return err
	}
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(release) }
	defer finish()
	closing := newControllerShutdown(a, owned.ownerToken)
	listener, err := net.Listen("tcp4", linuxOwnedControllerAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		finished <- serveClientHTTP(closing, listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/status" {
				_, _ = io.WriteString(w, "owned status")
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}), make(chan os.Signal))
	}()
	fmt.Fprintf(os.Stdout, "ready %d\n", os.Getpid())
	<-operation.Done()
	fmt.Fprintln(os.Stdout, "canceled")
	gate := os.NewFile(3, "fixture-held-operation-release")
	defer gate.Close()
	var signal [1]byte
	if _, err = io.ReadFull(gate, signal[:]); err != nil {
		return err
	}
	finish()
	if err = <-finished; err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "drained")
	return nil
}

func linuxControllerNamespaceInstall(t *testing.T) string {
	t.Helper()
	if os.Getenv(linuxControllerNamespaceMarker) != "1" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("privileged controller tests require the explicit private namespace runner")
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs("/opt", &filesystem); err != nil || uint64(filesystem.Type) != 0x01021994 {
		t.Fatal("controller fixture refuses to mutate a non-private /opt", err)
	}
	for _, path := range []string{linuxOwnedControllerRoot, linuxOwnedControllerRoot + ".moved", linuxOwnedInstallLock, linuxOwnedProcessLock} {
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(linuxOwnedControllerRoot, "modes"), 0755); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(linuxOwnedControllerRoot, "router-vpn-client")
	if err = os.WriteFile(installed, raw, 0755); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		"client.json": `{"listen":"127.0.0.1:8788","modes_file":"modes.json","scripts_dir":"modes","profiles_file":"routers.json","state_file":"state.json"}`,
		"modes.json":  `[]`, "routers.json": `{}`, "state.json": `{}`, "modes/owned.sh": "#!/bin/sh\nexit 0\n",
	} {
		if err = os.WriteFile(filepath.Join(linuxOwnedControllerRoot, path), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return installed
}

func linuxControllerUserPipe(t *testing.T, executable string) (*os.File, *os.File) {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(pair[0]), "fixture-owner-pipe-receiver"), os.NewFile(uintptr(pair[1]), "fixture-owner-pipe-sender")
	defer parent.Close()
	defer child.Close()
	connection, err := net.FileConn(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	command := exec.Command(executable, "--routervpn-test-create-owner-pipe")
	command.Env = []string{linuxControllerNamespaceMarker + "=1", "GORACE=atexit_sleep_ms=0"}
	command.ExtraFiles = []*os.File{child}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: linuxControllerFixtureUID, Gid: linuxControllerFixtureUID, Groups: []uint32{}}}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	child.Close()
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	data, ancillary := make([]byte, 1), make([]byte, syscall.CmsgSpace(8))
	n, oob, flags, _, err := connection.(*net.UnixConn).ReadMsgUnix(data, ancillary)
	if err != nil {
		command.Process.Kill()
	}
	joinErr := command.Wait()
	if err != nil || joinErr != nil || n != 1 || flags & ^syscall.MSG_CMSG_CLOEXEC != 0 {
		t.Fatal("actual user pipe creator did not join", err, joinErr, diagnostic.String())
	}
	messages, err := syscall.ParseSocketControlMessage(ancillary[:oob])
	if err != nil || len(messages) != 1 {
		t.Fatal("missing pipe transfer", err)
	}
	fds, err := syscall.ParseUnixRights(&messages[0])
	if err != nil || len(fds) != 2 {
		t.Fatal("invalid pipe transfer", err)
	}
	for _, fd := range fds {
		syscall.CloseOnExec(fd)
	}
	reader, writer := os.NewFile(uintptr(fds[0]), "actual-user-controller-input"), os.NewFile(uintptr(fds[1]), "actual-user-controller-lifetime")
	for _, file := range []*os.File{reader, writer} {
		info, err := file.Stat()
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != linuxControllerFixtureUID {
			t.Fatal("transferred pipe lost its real user creator", err)
		}
		t.Cleanup(func() { file.Close() })
	}
	return reader, writer
}

func linuxControllerBootstrapCommand(executable string, input *os.File) *exec.Cmd {
	command := exec.Command(executable, linuxOwnedControllerArgument)
	command.Stdin = input
	command.Env = []string{linuxControllerNamespaceMarker + "=1", "PKEXEC_UID=65534", "GORACE=atexit_sleep_ms=0",
		"HOMEVPN_ROOT=/tmp/unselected-root", "HOMEVPN_CLIENT_CONFIG=/tmp/unselected-config", "HOMEVPN_CONTROLLER_OWNER=unselected-owner",
		"HTTPS_PROXY=http://unselected.invalid", "PATH=/tmp/unselected-executables", "HOME=/tmp/unselected-home"}
	return command
}

func linuxControllerExpectBootstrapRejected(t *testing.T, command *exec.Cmd, writer *os.File) {
	t.Helper()
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(testLinuxOwnedHandshake())
	writer.Close()
	if err := command.Wait(); err == nil {
		t.Fatal("unsafe fixed-install bootstrap succeeded", output.String())
	}
	if strings.Contains(output.String(), testLocalControllerAccess) || strings.Contains(output.String(), testControllerOwner) || strings.Contains(output.String(), "prepared") {
		t.Fatal("rejected bootstrap disclosed or acquired private authority", output.String())
	}
}

func TestLinuxOwnedControllerNamespaceFixedInstallAndPipeLifetime(t *testing.T) {
	for _, ending := range []string{"eof", "second-byte"} {
		t.Run(ending, func(t *testing.T) {
			executable := linuxControllerNamespaceInstall(t)
			reader, writer := linuxControllerUserPipe(t, executable)
			gateRead, gateWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer gateRead.Close()
			defer gateWrite.Close()
			command := linuxControllerBootstrapCommand(executable, reader)
			command.Env = append(command.Env, "ROUTERVPN_CONTROLLER_FIXTURE_HELD=1")
			command.ExtraFiles = []*os.File{gateRead}
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var diagnostic bytes.Buffer
			command.Stderr = &diagnostic
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			var joinOnce sync.Once
			join := func() error { var err error; joinOnce.Do(func() { err = command.Wait() }); return err }
			defer func() {
				writer.Close()
				gateWrite.Write([]byte{1})
				gateWrite.Close()
				command.Process.Kill()
				_ = join()
			}()
			reader.Close()
			gateRead.Close()
			if _, err = writer.Write(testLinuxOwnedHandshake()); err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewReader(output)
			line, err := lines.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "ready "+strconv.Itoa(command.Process.Pid) {
				t.Fatal("actual fixed bootstrap did not retain its native PID", line, err, diagnostic.String())
			}
			if lock, err := linuxOwnedLock(linuxOwnedInstallLock, true); err == nil {
				lock.Close()
				t.Fatal("active native controller did not hold the install transaction lock")
			}
			if lock, err := linuxOwnedLock(linuxOwnedProcessLock, true); err == nil {
				lock.Close()
				t.Fatal("active native controller did not hold its unique process lock")
			}
			client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second}
			status, body, _ := testLocalControllerRequest(t, client, "http://"+linuxOwnedControllerAddress, http.MethodGet, "/api/status", "Bearer "+testLocalControllerAccess, nil)
			if status != http.StatusOK || body != "owned status" {
				t.Fatal("stdin authority did not reach actual controller HTTP", status, body)
			}
			if ending == "eof" {
				writer.Close()
			} else {
				if _, err = writer.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			line, err = lines.ReadString('\n')
			if err != nil || line != "canceled\n" {
				t.Fatal("actual pipe retirement did not cancel owned work", line, err)
			}
			if err = command.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatal("pipe retirement exited before held work drained", err)
			}
			if lock, err := linuxOwnedLock(linuxOwnedInstallLock, true); err == nil {
				lock.Close()
				t.Fatal("pending cleanup released its install owner")
			}
			status, _, _ = testLocalControllerRequest(t, client, "http://"+linuxOwnedControllerAddress, http.MethodPost, "/api/connect", "Bearer "+testLocalControllerAccess, nil)
			if status != http.StatusServiceUnavailable {
				t.Fatal("pipe retirement admitted replacement work", status)
			}
			if _, err = gateWrite.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			line, err = lines.ReadString('\n')
			if err != nil || line != "drained\n" {
				t.Fatal("held owner did not drain", line, err, diagnostic.String())
			}
			if err = join(); err != nil {
				t.Fatal("drained native child did not join", err, diagnostic.String())
			}
			for _, path := range []string{linuxOwnedInstallLock, linuxOwnedProcessLock} {
				lock, err := linuxOwnedLock(path, true)
				if err != nil {
					t.Fatal("joined child retained its install/process lock", path, err)
				}
				lock.Close()
			}
		})
	}
}

func TestLinuxOwnedControllerNamespaceRejectsUnsafeInstallAndConfig(t *testing.T) {
	cases := map[string]func(*testing.T){
		"writable-config": func(t *testing.T) {
			if err := os.Chmod(filepath.Join(linuxOwnedControllerRoot, "client.json"), 0666); err != nil {
				t.Fatal(err)
			}
		},
		"foreign-script-owner": func(t *testing.T) {
			if err := os.Chown(filepath.Join(linuxOwnedControllerRoot, "modes/owned.sh"), 65534, 0); err != nil {
				t.Fatal(err)
			}
		},
		"foreign-script-group": func(t *testing.T) {
			if err := os.Chown(filepath.Join(linuxOwnedControllerRoot, "modes/owned.sh"), 0, 65534); err != nil {
				t.Fatal(err)
			}
		},
		"writable-script-directory": func(t *testing.T) {
			if err := os.Chmod(filepath.Join(linuxOwnedControllerRoot, "modes"), 0777); err != nil {
				t.Fatal(err)
			}
		},
		"linked-config": func(t *testing.T) {
			path := filepath.Join(linuxOwnedControllerRoot, "client.json")
			if err := os.Rename(path, path+".original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("client.json.original", path); err != nil {
				t.Fatal(err)
			}
		},
		"hardlinked-executable": func(t *testing.T) {
			if err := os.Link(filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"), filepath.Join(linuxOwnedControllerRoot, "alias")); err != nil {
				t.Fatal(err)
			}
		},
		"fifo-code-tree": func(t *testing.T) {
			if err := syscall.Mkfifo(filepath.Join(linuxOwnedControllerRoot, "fifo"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"escaped-config-path": func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "client.json"), []byte(`{"scripts_dir":"/tmp/foreign-scripts"}`), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"duplicate-config-field": func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "client.json"), []byte(`{"scripts_dir":"modes","scripts_dir":"/tmp/foreign-scripts"}`), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"foreign-listener": func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "client.json"), []byte(`{"listen":"0.0.0.0:8788"}`), 0600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			executable := linuxControllerNamespaceInstall(t)
			reader, writer := linuxControllerUserPipe(t, executable)
			change(t)
			linuxControllerExpectBootstrapRejected(t, linuxControllerBootstrapCommand(executable, reader), writer)
		})
	}
}

func TestLinuxOwnedControllerNamespaceRejectsForeignIdentityAndInput(t *testing.T) {
	for _, uid := range []string{"", "0", "065534", "-1", "4294967295", "4294967296", "123456789"} {
		t.Run("caller-"+uid, func(t *testing.T) {
			executable := linuxControllerNamespaceInstall(t)
			reader, writer := linuxControllerUserPipe(t, executable)
			command := linuxControllerBootstrapCommand(executable, reader)
			command.Env = append(command.Env, "PKEXEC_UID="+uid)
			linuxControllerExpectBootstrapRejected(t, command, writer)
		})
	}
	for _, kind := range []string{"wrong-pipe-owner", "regular-file", "non-root", "extra-argument", "different-executable"} {
		t.Run(kind, func(t *testing.T) {
			executable := linuxControllerNamespaceInstall(t)
			reader, writer := linuxControllerUserPipe(t, executable)
			command := linuxControllerBootstrapCommand(executable, reader)
			switch kind {
			case "wrong-pipe-owner":
				rootRead, rootWrite, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer rootRead.Close()
				defer rootWrite.Close()
				command.Stdin = rootRead
				writer = rootWrite
			case "regular-file":
				regular, err := os.Open(filepath.Join(linuxOwnedControllerRoot, "state.json"))
				if err != nil {
					t.Fatal(err)
				}
				defer regular.Close()
				command.Stdin = regular
			case "non-root":
				command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
			case "extra-argument":
				command.Args = append(command.Args, "--config=/tmp/foreign.json")
			case "different-executable":
				other := filepath.Join(linuxOwnedControllerRoot, "other-controller")
				raw, err := os.ReadFile(executable)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(other, raw, 0755); err != nil {
					t.Fatal(err)
				}
				command.Path = other
				command.Args[0] = other
			}
			linuxControllerExpectBootstrapRejected(t, command, writer)
		})
	}
}

func TestLinuxOwnedControllerNamespaceHonorsInstallAndProcessLocks(t *testing.T) {
	for _, path := range []string{linuxOwnedInstallLock, linuxOwnedProcessLock} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			executable := linuxControllerNamespaceInstall(t)
			reader, writer := linuxControllerUserPipe(t, executable)
			lock, err := linuxOwnedLock(path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			linuxControllerExpectBootstrapRejected(t, linuxControllerBootstrapCommand(executable, reader), writer)
		})
	}
	executable := linuxControllerNamespaceInstall(t)
	for _, kind := range []string{"symlink", "hardlink", "broad-mode", "foreign-uid"} {
		t.Run(kind, func(t *testing.T) {
			os.Remove(linuxOwnedInstallLock)
			os.Remove(linuxOwnedInstallLock + ".target")
			if err := os.WriteFile(linuxOwnedInstallLock, []byte{}, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				os.Rename(linuxOwnedInstallLock, linuxOwnedInstallLock+".target")
				if err := os.Symlink(linuxOwnedInstallLock+".target", linuxOwnedInstallLock); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(linuxOwnedInstallLock, linuxOwnedInstallLock+".target"); err != nil {
					t.Fatal(err)
				}
			case "broad-mode":
				if err := os.Chmod(linuxOwnedInstallLock, 0666); err != nil {
					t.Fatal(err)
				}
			case "foreign-uid":
				if err := os.Chown(linuxOwnedInstallLock, 65534, 0); err != nil {
					t.Fatal(err)
				}
			}
			reader, writer := linuxControllerUserPipe(t, executable)
			linuxControllerExpectBootstrapRejected(t, linuxControllerBootstrapCommand(executable, reader), writer)
		})
	}
}

func TestLinuxOwnedControllerNamespaceRequiresBoundedHandshake(t *testing.T) {
	for _, frame := range [][]byte{[]byte("{}\n"), append([]byte(strings.Repeat("x", 513)), '\n'), []byte(`{"schema":1}`)} {
		executable := linuxControllerNamespaceInstall(t)
		reader, writer := linuxControllerUserPipe(t, executable)
		command := linuxControllerBootstrapCommand(executable, reader)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		writer.Write(frame)
		writer.Close()
		if err := command.Wait(); err == nil {
			t.Fatal("malformed actual stdin acquired authority", output.String())
		}
	}
	executable := linuxControllerNamespaceInstall(t)
	reader, writer := linuxControllerUserPipe(t, executable)
	defer writer.Close()
	command := linuxControllerBootstrapCommand(executable, reader)
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	select {
	case err := <-joined:
		if err == nil || time.Since(started) < 4*time.Second {
			t.Fatal("missing handshake did not enforce its bounded wait", err)
		}
	case <-ctx.Done():
		command.Process.Kill()
		<-joined
		t.Fatal("silent actual stdin outlived the bootstrap deadline")
	}
}

func TestLinuxOwnedControllerNamespaceRejectsUnownedInstalledMainPreservesUtilities(t *testing.T) {
	executable := linuxControllerNamespaceInstall(t)
	configPath := filepath.Join(linuxOwnedControllerRoot, "client.json")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		arguments []string
		message   string
	}{
		{"normal-root-startup", nil, "authorize its owned controller"},
		{"native-read-only-utility", []string{"--verify-native-runtime"}, "--verify-native-runtime requires one application root"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, append([]string{"--routervpn-test-real-installed-main"}, test.arguments...)...)
			command.Dir = linuxOwnedControllerRoot
			command.Env = []string{linuxControllerNamespaceMarker + "=1", "GORACE=atexit_sleep_ms=0", "HOMEVPN_ROOT=" + linuxOwnedControllerRoot, "HOMEVPN_CLIENT_CONFIG=" + configPath}
			output, err := command.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(output), test.message) {
				t.Fatal("actual installed main bypassed its startup/utility ordering", err, string(output))
			}
			after, err := os.ReadFile(configPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected or read-only startup mutated application configuration", err)
			}
		})
	}
}
