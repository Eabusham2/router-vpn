//go:build linux && routervpn_controller_privileged && routervpn_standard_service_native

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobiletor"
)

const linuxImageNamespaceCase = "ROUTERVPN_IMAGE_UPGRADE_NATIVE_CASE"

func init() {
	if os.Getenv(linuxControllerNamespaceMarker) == "1" && len(os.Args) == 2 && os.Args[1] == linuxStandardImageUpgradeArgument {
		main()
		os.Exit(0)
	}
}

// Each case has a separate, explicitly private mount/network namespace. A
// failed upgrade deliberately retains its original native protection; destroying
// only that test namespace at teardown must not be confused with production
// recovery, native deletion authority, or a successful upgrade.
func TestLinuxStandardServiceNamespaceImageUpgradeOriginal(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "original")
}
func TestLinuxStandardServiceNamespaceImageUpgradeAbortPrepared(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "abort-prepared")
}
func TestLinuxStandardServiceNamespaceImageUpgradeAbortPromoted(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "abort-promoted")
}
func TestLinuxStandardServiceNamespaceImageUpgradeLostFreezeReply(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "lost-freeze-reply")
}
func TestLinuxStandardServiceNamespaceImageUpgradeLostCommitReply(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "lost-commit-reply")
}
func TestLinuxStandardServiceNamespaceImageUpgradeLostReadyReply(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "lost-ready-reply")
}
func TestLinuxStandardServiceNamespaceImageUpgradeChangedSequence(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "changed-sequence")
}
func TestLinuxStandardServiceNamespaceImageUpgradeExpiredPrepare(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "expired-prepare")
}
func TestLinuxStandardServiceNamespaceImageUpgradeRepeatAfterSuccess(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "repeat-after-success")
}
func TestLinuxStandardServiceNamespaceImageUpgradeRepeatAfterAbort(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "repeat-after-abort")
}
func TestLinuxStandardServiceNamespaceImageUpgradeGuardLostAfterReady(t *testing.T) {
	linuxImageNamespaceAcceptance(t, "guard-lost-after-ready")
}

func linuxImageNamespaceAcceptance(t *testing.T, scenario string) {
	if captured := os.Getenv(linuxImageNamespaceCase); captured != "" {
		if captured != scenario || os.Getenv(linuxControllerNamespaceMarker) != "1" || os.Geteuid() != 0 {
			t.Fatal("image fixture requires its explicit original private namespace")
		}
		var mounted syscall.Statfs_t
		if err := syscall.Statfs("/opt", &mounted); err != nil || uint64(mounted.Type) != 0x01021994 {
			t.Fatal("image fixture refuses a non-private installation mount", err)
		}
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/opt", "/run"} {
			if err := syscall.Mount("tmpfs", path, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755"); err != nil {
				t.Fatal(err)
			}
		}
		ip, err := exec.LookPath("ip")
		if err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(ip, "link", "set", "lo", "up").CombinedOutput(); err != nil {
			t.Fatal("private image namespace loopback", err, string(output))
		}
		linuxImageNamespaceRun(t, scenario)
		fmt.Fprintln(os.Stdout, "installed-image-upgrade-verified:"+scenario)
		return
	}
	if os.Getenv(linuxControllerNamespaceMarker) != "1" || os.Geteuid() != 0 {
		t.Fatal("image acceptance requires the original privileged namespace runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	command.Env = append(os.Environ(), linuxImageNamespaceCase+"="+scenario, "GORACE=atexit_sleep_ms=0")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Setpgid: true, Pdeathsig: syscall.SIGKILL}
	// A timed-out fixture must not orphan its actual services or journal in
	// the private mount/network namespaces. All descendants retain this
	// fixture-only process group; production service teardown is unchanged.
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("installed-image-upgrade-verified:"+scenario+"\n")) {
		t.Fatalf("actual installed image upgrade %s: %v\n%s", scenario, err, output)
	}
}

type linuxImageNativeProcess struct {
	command    *exec.Cmd
	done       chan struct{}
	err        error
	diagnostic linuxStandardServiceDiagnostic
}

func linuxImageNativeStart(t *testing.T, command *exec.Cmd) *linuxImageNativeProcess {
	t.Helper()
	p := &linuxImageNativeProcess{command: command, done: make(chan struct{})}
	command.Stderr = &p.diagnostic
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Pdeathsig = syscall.SIGKILL
	if err := command.Start(); err != nil {
		t.Fatal("actual image process start", err)
	}
	go func() { p.err = command.Wait(); close(p.done) }()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			// These are the actual children of this isolated fixture only.
			_ = command.Process.Kill()
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
				t.Error("private image fixture child did not join")
			}
		}
	})
	return p
}

func (p *linuxImageNativeProcess) joined(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatal("original image process join", p.err, p.diagnostic.String())
		}
	case <-ctx.Done():
		t.Fatal("image completion preceded original process join", p.diagnostic.String())
	}
}

func linuxImageNativeNotify(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Net: "unixgram", Name: filepath.Join("/run", name)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func linuxImageNativeReady(t *testing.T, notify *net.UnixConn, expected bool, process *linuxImageNativeProcess) {
	t.Helper()
	limit := 40 * time.Millisecond
	if expected {
		limit = 15 * time.Second
	}
	if err := notify.SetReadDeadline(time.Now().Add(limit)); err != nil {
		t.Fatal(err)
	}
	for {
		body := make([]byte, 4096)
		n, _, err := notify.ReadFromUnix(body)
		if err != nil {
			if timeout, ok := err.(net.Error); !expected && ok && timeout.Timeout() {
				return
			}
			t.Fatal("actual image readiness", err, process.diagnostic.String())
		}
		if strings.Contains(string(body[:n]), "READY=1") {
			if !expected {
				t.Fatal("successor reported READY before native state and activation settlement")
			}
			return
		}
	}
}

// This worker calls the shipping Python generation builder and the same live
// ActiveCodeJournal instance for promotion/rollback. It substitutes neither a
// rewritten code mover nor a metadata-based native owner. Systemd invocation is
// outside this namespace test; exact service processes and notify datagrams are
// real, and installer systemd framing has its own mandatory executable tests.
const linuxImageNativeJournalPython = `
import importlib.util,json,os,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('actual_installer',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=Path(sys.argv[2]);temporary=Path(sys.argv[3]);temporary.mkdir(mode=0o700)
stage=temporary/'next';stage.mkdir(mode=0o700)
old=m.activated_service_image(root).parent if (root/m.GENERATION_ACTIVATION).exists() else m.stage_service_generation(root,root)
old_selection=m.image_decode((root/m.GENERATION_ACTIVATION).read_bytes())
for name in sorted(m.CODE_FILES|m.CODE_TREES):
    if (root/name).exists():m.copy_checked(root/name,stage/name)
version=(stage/'client'/'image-fixture-version').read_text()
(stage/'client'/'image-fixture-version').write_text(version+'next exact code generation\n')
new=m.stage_service_generation(stage,root)
new_selection=m.image_decode((stage/m.GENERATION_ACTIVATION).read_bytes())
print(json.dumps({'old':old_selection,'new':new_selection,'old_path':str(old),'new_path':str(new),'stage':str(stage)}),flush=True)
journal=None
while True:
    raw=sys.stdin.buffer.readline((128<<10)+1)
    if not raw:break
    if len(raw)>128<<10:raise ValueError('fixture control exceeded bound')
    request=json.loads(raw)
    try:
        action=request['action']
        if action=='bind':
            if journal is not None:raise ValueError('fixture journal already retained')
            journal=m.ActiveCodeJournal(root,temporary,stage)
            journal.bind(request['envelope'])
        elif action=='promote':journal.promote(request['deadline_ns'])
        elif action=='restore':journal.restore(request['deadline_ns'])
        elif action=='activate':
            value=m.image_decode((stage/m.GENERATION_ACTIVATION).read_bytes())
            if value!=new_selection:raise ValueError('fixture activation changed')
            m.image_atomic_json(root/m.GENERATION_ACTIVATION,value)
        else:raise ValueError('unknown fixture journal action')
        print(json.dumps({'complete':True,'phase':journal.record['phase'] if journal else ''}),flush=True)
    except Exception as error:
        print(json.dumps({'complete':False,'error':str(error)}),flush=True)
`

type linuxImageNativeJournal struct {
	process                 *linuxImageNativeProcess
	input                   io.WriteCloser
	scanner                 *bufio.Scanner
	Old, New                linuxStandardGenerationSelection
	OldPath, NewPath, Stage string
}

func linuxImageNativeJournalStart(t *testing.T, ctx context.Context, label string) *linuxImageNativeJournal {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "client", "install-linux-native.py"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-Es", "-u", "-c", linuxImageNativeJournalPython, source, linuxOwnedControllerRoot, "/opt/router-vpn-image-test-"+label)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	j := &linuxImageNativeJournal{input: input, scanner: bufio.NewScanner(output)}
	j.scanner.Buffer(make([]byte, 4096), 128<<10)
	j.process = linuxImageNativeStart(t, command)
	t.Cleanup(func() { _ = input.Close() })
	var ready struct {
		Old     linuxStandardGenerationSelection `json:"old"`
		New     linuxStandardGenerationSelection `json:"new"`
		OldPath string                           `json:"old_path"`
		NewPath string                           `json:"new_path"`
		Stage   string                           `json:"stage"`
	}
	if !j.scanner.Scan() || json.Unmarshal(j.scanner.Bytes(), &ready) != nil {
		t.Fatal("actual generation builder", j.scanner.Err(), j.process.diagnostic.String())
	}
	j.Old, j.New, j.OldPath, j.NewPath, j.Stage = ready.Old, ready.New, ready.OldPath, ready.NewPath, ready.Stage
	if j.Old.Generation == j.New.Generation || !linuxStandardImageSelectionValid(j.Old) || !linuxStandardImageSelectionValid(j.New) {
		t.Fatal("fixture did not create two distinct actual generations")
	}
	return j
}

func (j *linuxImageNativeJournal) call(t *testing.T, value any) {
	t.Helper()
	if err := json.NewEncoder(j.input).Encode(value); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Complete bool   `json:"complete"`
		Error    string `json:"error"`
	}
	if !j.scanner.Scan() || json.Unmarshal(j.scanner.Bytes(), &result) != nil || !result.Complete {
		t.Fatal("actual code journal", result.Error, j.scanner.Err(), j.process.diagnostic.String())
	}
}

type linuxImageNativeControl struct {
	channel  *net.UnixConn
	process  *linuxImageNativeProcess
	request  linuxStandardImageUpgradeControl
	envelope *linuxStandardImageUpgradeEnvelope
}

func linuxImageNativeControlStart(t *testing.T, ctx context.Context, executable string) *linuxImageNativeControl {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(fds[0]), "image-installer-control"), os.NewFile(uintptr(fds[1]), "image-coordinator-control")
	connection, err := net.FileConn(parent)
	_ = parent.Close()
	if err != nil {
		_ = child.Close()
		t.Fatal(err)
	}
	channel, ok := connection.(*net.UnixConn)
	if !ok {
		_ = child.Close()
		_ = connection.Close()
		t.Fatal("image control lost Unix packet channel")
	}
	command := exec.CommandContext(ctx, executable, linuxStandardImageUpgradeArgument)
	command.Env = []string{linuxControllerNamespaceMarker + "=1", "GORACE=atexit_sleep_ms=0"}
	command.ExtraFiles = []*os.File{child}
	c := &linuxImageNativeControl{channel: channel}
	c.process = linuxImageNativeStart(t, command)
	_ = child.Close()
	t.Cleanup(func() { _ = channel.Close() })
	return c
}

func (c *linuxImageNativeControl) exchange(t *testing.T, request linuxStandardImageUpgradeControl) (linuxStandardImageUpgradeControlReply, []*os.File) {
	t.Helper()
	c.send(t, request)
	return c.receive(t, request)
}

func (c *linuxImageNativeControl) send(t *testing.T, request linuxStandardImageUpgradeControl) {
	t.Helper()
	if err := c.channel.SetDeadline(time.Now().Add(40 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := linuxStandardServiceWrite(c.channel, request, nil); err != nil {
		t.Fatal("actual image coordinator write", err, c.process.diagnostic.String())
	}
}

func (c *linuxImageNativeControl) receive(t *testing.T, request linuxStandardImageUpgradeControl) (linuxStandardImageUpgradeControlReply, []*os.File) {
	t.Helper()
	packet, control := make([]byte, linuxStandardServicePacketLimit+1), make([]byte, syscall.CmsgSpace(16*4))
	n, oob, flags, _, err := c.channel.ReadMsgUnix(packet, control)
	if err != nil {
		t.Fatal("actual image coordinator read", err, c.process.diagnostic.String())
	}
	messages, err := syscall.ParseSocketControlMessage(control[:oob])
	if err != nil {
		t.Fatal(err)
	}
	var files []*os.File
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET || message.Header.Type != syscall.SCM_RIGHTS {
			t.Fatal("image reply included foreign native authority")
		}
		rights, err := syscall.ParseUnixRights(&message)
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range rights {
			syscall.CloseOnExec(fd)
			file := os.NewFile(uintptr(fd), "actual-image-peer-pidfd")
			files = append(files, file)
			t.Cleanup(func() { _ = file.Close() })
		}
	}
	if n < 1 || n > linuxStandardServicePacketLimit || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || len(files) > 3 {
		t.Fatal("incomplete actual image response")
	}
	var response linuxStandardImageUpgradeControlReply
	if err := linuxStandardServiceDecode(packet[:n], &response); err != nil {
		t.Fatal("actual image response schema", err)
	}
	if response.Schema != 1 || response.Sequence != request.Sequence || response.Action != request.Action || response.Complete == (response.Error != "") {
		t.Fatal("image response changed original request")
	}
	return response, files
}

func (c *linuxImageNativeControl) action(t *testing.T, action string, deadline int64, selection *linuxStandardGenerationSelection, cleanup int64, lost bool) (linuxStandardServiceImageUpgradeResponse, []*os.File) {
	t.Helper()
	request := linuxStandardImageUpgradeControl{Schema: 1, Sequence: c.request.Sequence + 1, Action: action, DeadlineNS: deadline, NewGeneration: selection, Envelope: c.envelope, CleanupDeadlineNS: cleanup}
	response, files := c.exchange(t, request)
	if !response.Complete || response.Upgrade == nil {
		t.Fatal("actual image phase", action, response.Error, c.process.diagnostic.String())
	}
	if c.envelope != nil && !reflect.DeepEqual(*c.envelope, response.Upgrade.Envelope) {
		t.Fatal("image phase replaced immutable envelope", action)
	}
	if err := response.Upgrade.Envelope.validate(); err != nil {
		t.Fatal(err)
	}
	if lost {
		// The first successful response really follows its native effect. Drop
		// its application result, then replay the identical original frame.
		for _, file := range files {
			_ = file.Close()
		}
		original := *response.Upgrade
		response, files = c.exchange(t, request)
		if !response.Complete || response.Upgrade == nil || !reflect.DeepEqual(original, *response.Upgrade) {
			t.Fatal("lost reply did not retain exact original result", action, response.Error)
		}
	}
	c.request = request
	copy := response.Upgrade.Envelope
	c.envelope = &copy
	return *response.Upgrade, files
}

func linuxImageNativePrivate(t *testing.T) func() {
	t.Helper()
	type object struct {
		path string
		info os.FileInfo
		body []byte
	}
	var original []object
	for _, relative := range []string{"", "run", "run/kill-switch.lock", "client.json", "routers.json", "state.json", "private-node-link.json", linuxOwnedInstallLock} {
		path := filepath.Join(linuxOwnedControllerRoot, relative)
		if filepath.IsAbs(relative) {
			path = relative
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		var body []byte
		if !info.IsDir() {
			body, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		original = append(original, object{path, info, body})
	}
	return func() {
		for _, saved := range original {
			info, err := os.Lstat(saved.path)
			if err != nil || !os.SameFile(saved.info, info) || saved.info.Mode() != info.Mode() {
				t.Fatal("upgrade replaced original private object", saved.path, err)
			}
			if !info.IsDir() {
				body, err := os.ReadFile(saved.path)
				if err != nil || !bytes.Equal(saved.body, body) {
					t.Fatal("upgrade changed original private bytes", saved.path, err)
				}
			}
		}
	}
}

func linuxImageNativeLocked(t *testing.T, path string) {
	t.Helper()
	lock, err := ownedDesktopLock(path, true)
	if err == nil {
		_ = lock.Close()
		t.Fatal("live image owner lost original exclusive exclusion", path)
	}
}

func linuxImageNativeSource(t *testing.T, ctx context.Context, snapshot *mobiletor.DesktopLinuxClosedTransferSnapshot, exclusive bool) {
	t.Helper()
	if snapshot == nil {
		t.Fatal("image reply omitted actual native inventory")
	}
	var err error
	if exclusive {
		err = mobiletor.ReadDesktopLinuxClosedTransferExclusive(ctx, *snapshot)
	} else {
		err = mobiletor.ReadDesktopLinuxClosedTransferCurrent(ctx, *snapshot)
	}
	if err != nil {
		t.Fatal("independent actual native image inventory", err)
	}
}

func linuxImageNamespaceRun(t *testing.T, scenario string) {
	// Both cycles of a repeated upgrade share this one test allowance. It
	// also terminates the exact journal worker to bound its pipe reads.
	// Twenty seconds remain before the outer fixture watchdog for joins.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	linuxControllerNamespaceInstall(t)
	// The generic controller fixture uses private modes for its tiny source
	// files. This test uses the real installer, whose shipped code inventory
	// is normalized to 0644 before its immutable manifest is captured.
	for _, code := range []string{"modes.json", "modes/owned.sh"} {
		if err := os.Chmod(filepath.Join(linuxOwnedControllerRoot, code), 0644); err != nil {
			t.Fatal(err)
		}
	}
	profile := common.RouterProfile{ID: "control", Name: "Original private node", KillSwitch: true, KillSwitchPolicy: "always", Endpoint: "203.0.113.77", DNSMode: "custom", DNSProtocol: "udp", DNSHost: "203.0.113.53", DNSPort: 53}
	applyProfileDefaults(&profile)
	body, err := json.Marshal(common.RouterProfileStore{SchemaVersion: 4, SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "routers.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "private-node-link.json"), []byte("{\"fixture_private_reference\":\"original-node-only\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(linuxOwnedControllerRoot, "client"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(linuxOwnedControllerRoot, "client", "image-fixture-version"), []byte("first exact code generation\n"), 0644); err != nil {
		t.Fatal(err)
	}
	linuxStandardServicePreviousBootState(t, linuxOwnedControllerRoot, profile.ID, profile.Endpoint)
	journal := linuxImageNativeJournalStart(t, ctx, "first")
	oldNotify := linuxImageNativeNotify(t, "image-old-ready")
	oldCommand := exec.CommandContext(ctx, filepath.Join(journal.OldPath, "router-vpn-client"), linuxStandardServiceArgument)
	oldCommand.Env = []string{linuxControllerNamespaceMarker + "=1", "NOTIFY_SOCKET=/run/image-old-ready", "GORACE=atexit_sleep_ms=0"}
	old := linuxImageNativeStart(t, oldCommand)
	linuxImageNativeReady(t, oldNotify, true, old)
	private := linuxImageNativePrivate(t)
	controller, err := ownedDesktopLock(linuxOwnedProcessLock, true)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	first := scenario
	if scenario == "repeat-after-success" {
		first = "original"
	}
	if scenario == "repeat-after-abort" {
		first = "abort-prepared"
	}
	retained := linuxImageNamespaceCycle(t, ctx, first, journal, old, private)
	if scenario == "repeat-after-success" || scenario == "repeat-after-abort" {
		if err := journal.input.Close(); err != nil {
			t.Fatal(err)
		}
		joined, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		journal.process.joined(t, joined)
		cancel()
		nextJournal := linuxImageNativeJournalStart(t, ctx, "second")
		_ = linuxImageNamespaceCycle(t, ctx, "original", nextJournal, retained, private)
		if scenario == "repeat-after-success" {
			retired, err := ownedDesktopLock(journal.OldPath+".lock", true)
			if err != nil {
				t.Fatal("next upgrade retained two-generations-old observer", err)
			}
			_ = retired.Close()
		}
	}
}

func linuxImageNamespaceCycle(t *testing.T, ctx context.Context, scenario string, journal *linuxImageNativeJournal, old *linuxImageNativeProcess, private func()) *linuxImageNativeProcess {
	t.Helper()
	control := linuxImageNativeControlStart(t, ctx, filepath.Join(journal.OldPath, "router-vpn-client"))
	deadline, _ := ctx.Deadline()
	if scenario == "expired-prepare" {
		response, files := control.exchange(t, linuxStandardImageUpgradeControl{Schema: 1, Sequence: 1, Action: "prepare", DeadlineNS: time.Now().Add(-time.Second).UnixNano(), NewGeneration: &journal.New})
		if response.Complete || len(files) != 0 {
			t.Fatal("expired preparation entered image mutation")
		}
		private()
		linuxImageNativeLocked(t, linuxOwnedInstallLock)
		linuxImageNativeLocked(t, journal.OldPath+".lock")
		return old
	}
	reserved, files := control.action(t, "prepare", deadline.UnixNano(), &journal.New, 0, false)
	if reserved.Phase != "reserved" || len(files) != 0 || reserved.SourceRemoved {
		t.Fatal("prepare did not retain original reservation")
	}
	linuxImageNativeSource(t, ctx, reserved.Source, true)
	journal.call(t, map[string]any{"action": "bind", "envelope": reserved.Envelope})
	notifyName := "image-new-ready-" + filepath.Base(filepath.Dir(journal.Stage))
	newNotify := linuxImageNativeNotify(t, notifyName)
	newCommand := exec.CommandContext(ctx, filepath.Join(journal.NewPath, "router-vpn-client"), linuxStandardServiceArgument)
	newCommand.Env = []string{linuxControllerNamespaceMarker + "=1", "NOTIFY_SOCKET=" + filepath.Join("/run", notifyName), "GORACE=atexit_sleep_ms=0"}
	next := linuxImageNativeStart(t, newCommand)
	prepared, files := control.action(t, "successor-started", deadline.UnixNano(), nil, 0, false)
	if prepared.Phase != "successor-prepared" || len(files) != 0 || prepared.SourceRemoved {
		t.Fatal("successor was not separately prepared")
	}
	linuxImageNativeSource(t, ctx, prepared.Source, false)
	linuxImageNativeSource(t, ctx, prepared.Destination, false)
	linuxImageNativeReady(t, newNotify, false, next)
	linuxImageNativeLocked(t, linuxOwnedInstallLock)
	linuxImageNativeLocked(t, journal.OldPath+".lock")
	linuxImageNativeLocked(t, journal.NewPath+".lock")
	if scenario == "changed-sequence" {
		wrong := control.request
		wrong.Action = "freeze"
		response, rights := control.exchange(t, wrong)
		if response.Complete || len(rights) != 0 {
			t.Fatal("same sequence admitted another image action")
		}
		linuxImageNativeSource(t, ctx, prepared.Source, false)
		linuxImageNativeSource(t, ctx, prepared.Destination, false)
	}
	if scenario == "abort-prepared" || scenario == "changed-sequence" {
		aborting, _ := control.action(t, "abort", deadline.UnixNano(), nil, 0, false)
		if aborting.Phase != "aborting" || !aborting.RollbackAllowed || aborting.SourceRemoved || aborting.CleanupDeadlineNS <= 0 {
			t.Fatal("prepared abort omitted original rollback allowance")
		}
		rollbackLease, err := ownedDesktopLock(linuxOwnedInstallLock, true)
		if err != nil {
			t.Fatal("prepared abort retained canonical code lease", err)
		}
		journal.call(t, map[string]any{"action": "restore", "deadline_ns": aborting.CleanupDeadlineNS})
		if err := rollbackLease.Close(); err != nil {
			t.Fatal(err)
		}
		aborted, _ := control.action(t, "code-restored", deadline.UnixNano(), nil, aborting.CleanupDeadlineNS, false)
		if aborted.Phase != "aborted" || aborted.SourceRemoved {
			t.Fatal("prepared abort discarded original source")
		}
		linuxImageNativeSource(t, ctx, prepared.Source, true)
		private()
		next.joined(t, ctx)
		linuxImageNativeLocked(t, linuxOwnedInstallLock)
		linuxImageNativeLocked(t, journal.OldPath+".lock")
		if err := control.channel.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		control.process.joined(t, ctx)
		return old
	}
	frozen, files := control.action(t, "freeze", deadline.UnixNano(), nil, 0, scenario == "lost-freeze-reply")
	if frozen.Phase != "frozen" || !frozen.Frozen || len(files) != 3 {
		t.Fatal("frozen handoff omitted three actual original peers")
	}
	observations := []*linuxprocess.Observation{frozen.OldPeer, frozen.NewPeer, frozen.CoordinatorPeer}
	processes := []*linuxImageNativeProcess{old, next, control.process}
	for i, file := range files {
		proc, err := linuxStandardPeerProcID(file, processes[i].command.Process.Pid)
		if err != nil || observations[i] == nil || proc != observations[i].ProcProcessID || observations[i].ProcessID != processes[i].command.Process.Pid {
			t.Fatal("frozen descriptor replaced original peer", i, err)
		}
	}
	linuxImageNativeSource(t, ctx, frozen.Source, false)
	linuxImageNativeSource(t, ctx, frozen.Destination, false)
	linuxImageNativeLocked(t, filepath.Join(linuxStandardServiceDirectory, "owner.lock"))
	if scenario == "original" {
		// Use the actual canonical, authenticated ordinary upgrade role.
		// A foreign executable's refusal would not exercise the phase fence.
		ordinary := exec.CommandContext(ctx, filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"), linuxStandardServiceUpgradeArgument)
		ordinary.Env = []string{linuxControllerNamespaceMarker + "=1", "GORACE=atexit_sleep_ms=0"}
		ordinary.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		ordinary.WaitDelay = 5 * time.Second
		output, err := ordinary.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "original image handoff freezes ordinary service requests") {
			t.Fatal("authenticated ordinary mutation did not reach the frozen admission fence", err, string(output))
		}
		linuxImageNativeSource(t, ctx, frozen.Source, false)
		linuxImageNativeSource(t, ctx, frozen.Destination, false)
		private()
	}
	source, err := ownedDesktopLock(linuxOwnedInstallLock, true)
	if err != nil {
		t.Fatal("actual frozen owners retained canonical code lease", err)
	}
	journal.call(t, map[string]any{"action": "promote", "deadline_ns": deadline.UnixNano()})
	private()
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	if scenario == "abort-promoted" {
		aborting, _ := control.action(t, "abort", deadline.UnixNano(), nil, 0, false)
		if aborting.Phase != "aborting" || !aborting.RollbackAllowed || aborting.SourceRemoved || aborting.CleanupDeadlineNS <= 0 {
			t.Fatal("entered code abort omitted original rollback authority")
		}
		linuxImageNativeSource(t, ctx, frozen.Source, false)
		linuxImageNativeSource(t, ctx, frozen.Destination, false)
		source, err = ownedDesktopLock(linuxOwnedInstallLock, true)
		if err != nil {
			t.Fatal(err)
		}
		journal.call(t, map[string]any{"action": "restore", "deadline_ns": aborting.CleanupDeadlineNS})
		private()
		_ = source.Close()
		aborted, _ := control.action(t, "code-restored", deadline.UnixNano(), nil, aborting.CleanupDeadlineNS, false)
		if aborted.Phase != "aborted" || aborted.SourceRemoved {
			t.Fatal("original code rollback did not retain source")
		}
		linuxImageNativeSource(t, ctx, frozen.Source, true)
		next.joined(t, ctx)
		linuxImageNativeLocked(t, linuxOwnedInstallLock)
		if err := control.channel.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		control.process.joined(t, ctx)
		return old
	}
	verified, _ := control.action(t, "code-promoted", deadline.UnixNano(), nil, 0, false)
	if verified.Phase != "code-verified" || verified.SourceRemoved {
		t.Fatal("code verification prematurely removed source")
	}
	linuxImageNativeSource(t, ctx, verified.Source, false)
	linuxImageNativeSource(t, ctx, verified.Destination, false)
	linuxImageNativeLocked(t, linuxOwnedInstallLock)
	linuxImageNativeReady(t, newNotify, false, next)
	committed, _ := control.action(t, "commit", deadline.UnixNano(), nil, 0, scenario == "lost-commit-reply")
	if committed.Phase != "successor-published" || !committed.SourceRemoved || !committed.ActivationAllowed || committed.RollbackAllowed {
		t.Fatal("native commit did not settle exact successor state")
	}
	linuxImageNativeSource(t, ctx, committed.Destination, true)
	private()
	linuxImageNativeReady(t, newNotify, false, next)
	journal.call(t, map[string]any{"action": "activate"})
	ready, _ := control.action(t, "activation-published", deadline.UnixNano(), nil, committed.CleanupDeadlineNS, scenario == "lost-ready-reply")
	if ready.Phase != "successor-ready" || !ready.Ready || !ready.SourceRemoved {
		t.Fatal("actual activation did not prove successor readiness")
	}
	linuxImageNativeReady(t, newNotify, true, next)
	if scenario == "guard-lost-after-ready" {
		// Stop only this fixture's successor after its real READY. The old
		// creator must actually finish and join before the successor can
		// receive settle, so the loss targets the final current-native proof.
		if err := next.command.Process.Signal(syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
		request := linuxStandardImageUpgradeControl{Schema: 1, Sequence: control.request.Sequence + 1, Action: "settle", DeadlineNS: deadline.UnixNano(), Envelope: control.envelope, CleanupDeadlineNS: ready.CleanupDeadlineNS}
		control.send(t, request)
		old.joined(t, ctx)
		var inventory struct{ TableName string }
		if ready.Destination == nil || json.Unmarshal(ready.Destination.Inventory, &inventory) != nil || inventory.TableName != "router_vpn_standard_"+ready.Envelope.DestinationSession {
			t.Fatal("guard loss fixture lost exact actual successor table")
		}
		command := exec.CommandContext(ctx, "/usr/sbin/nft", "delete", "table", "inet", inventory.TableName)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatal("private fixture native guard loss", err, string(output))
		}
		if err := mobiletor.ReadDesktopLinuxClosedTransferExclusive(ctx, *ready.Destination); err == nil {
			t.Fatal("actual successor guard was not removed")
		}
		if err := next.command.Process.Signal(syscall.SIGCONT); err != nil {
			t.Fatal(err)
		}
		failed, rights := control.receive(t, request)
		if failed.Complete || len(rights) != 0 || failed.Upgrade == nil || failed.Upgrade.Phase == "settled" || !failed.Upgrade.SourceRemoved {
			t.Fatal("final settlement accepted lost successor native protection")
		}
		request.Sequence++
		request.Action = "status"
		failed, rights = control.exchange(t, request)
		if failed.Complete || len(rights) != 0 || failed.Upgrade == nil || failed.Upgrade.Phase == "settled" {
			t.Fatal("fresh status treated historical READY as current native proof")
		}
		linuxImageNativeReady(t, newNotify, false, next)
		private()
		linuxImageNativeLocked(t, linuxOwnedInstallLock)
		linuxImageNativeLocked(t, journal.NewPath+".lock")
		linuxImageNativeLocked(t, filepath.Join(linuxStandardServiceDirectory, "owner.lock"))
		return next
	}
	settled, _ := control.action(t, "settle", deadline.UnixNano(), nil, ready.CleanupDeadlineNS, false)
	if settled.Phase != "settled" || !settled.OldJoined || !settled.Ready {
		t.Fatal("settlement did not join original service")
	}
	old.joined(t, ctx)
	if err := control.channel.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	control.process.joined(t, ctx)
	if _, err = os.Lstat(filepath.Join(linuxStandardServiceDirectory, "g-"+journal.Old.Generation+".sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old generation listener survived completed join", err)
	}
	linuxImageNativeSource(t, ctx, settled.Destination, true)
	private()
	linuxImageNativeLocked(t, linuxOwnedInstallLock)
	linuxImageNativeLocked(t, journal.NewPath+".lock")
	linuxImageNativeLocked(t, filepath.Join(linuxStandardServiceDirectory, "owner.lock"))
	// The successor retains bounded original history until the next
	// authenticated prepare proves terminal peers joined. It may still
	// hold the old generation observer here; current leases stay mandatory.
	selected, err := captureLinuxStandardServiceGeneration(ctx, linuxOwnedControllerRoot)
	if err != nil || selected == nil {
		t.Fatal("fresh discovery did not find exact successor", err)
	}
	defer selected.Close()
	if selected.root != journal.NewPath {
		t.Fatal("fresh discovery changed completed generation")
	}
	canonical, err := os.Stat(filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"))
	if err != nil || os.SameFile(canonical, selected.imageInfo) {
		t.Fatal("generation and canonical code unexpectedly share mutable inode", err)
	}
	return next
}
