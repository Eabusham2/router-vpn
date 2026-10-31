//go:build linux && routervpn_controller_privileged

package linuxprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type inheritedExecDescriptor struct {
	Number int    `json:"number"`
	Object Object `json:"object"`
}

type inheritedExecInventory struct {
	ProcessID   int                       `json:"process_id"`
	ParentID    int                       `json:"parent_id"`
	Image       Object                    `json:"image"`
	Descriptors []inheritedExecDescriptor `json:"descriptors"`
}

type inheritedExecReport struct {
	Originals map[string]Object      `json:"originals"`
	Flags     map[string]uintptr     `json:"initial_flags"`
	Inventory inheritedExecInventory `json:"inventory"`
}

// This real exec descendant receives no ExtraFiles. Its inventory comes from
// its own kernel descriptor table, including any original object that escaped
// through the preceding authenticated child's capture. Reused fd numbers alone
// cannot count as a leak; the parent compares complete native object identities.
func TestLinuxProcessNamespaceExecInventoryWorker(t *testing.T) {
	if os.Getenv("ROUTERVPN_LINUX_EXEC_INVENTORY") != "1" {
		return
	}
	requireProcessNamespace(t)
	info, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	image, err := objectOf(info)
	if err != nil {
		t.Fatal(err)
	}
	report := inheritedExecInventory{ProcessID: os.Getpid(), ParentID: os.Getppid(), Image: image}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(entries) > 128 {
		t.Fatal("actual exec inventory lost its bounded original descriptor table", err)
	}
	for _, entry := range entries {
		number, err := strconv.Atoi(entry.Name())
		if err != nil || number < 0 || strconv.Itoa(number) != entry.Name() {
			t.Fatal("actual exec inventory received a noncanonical descriptor")
		}
		info, err := os.Stat("/proc/self/fd/" + entry.Name())
		if os.IsNotExist(err) {
			// ReadDir's own temporary descriptor is closed before this scan.
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		object, err := objectOf(info)
		if err != nil {
			t.Fatal(err)
		}
		report.Descriptors = append(report.Descriptors, inheritedExecDescriptor{number, object})
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("actual-exec-inventory:" + string(body))
}

func TestLinuxProcessNamespaceInheritedExecWorker(t *testing.T) {
	if os.Getenv("ROUTERVPN_LINUX_INHERITED_EXEC") != "1" {
		return
	}
	requireProcessNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	channelFile := os.NewFile(3, "original-inherited-exec-channel")
	directory := os.NewFile(4, "original-inherited-exec-parent")
	image := os.NewFile(5, "original-inherited-exec-image")
	defer image.Close()
	report := inheritedExecReport{Originals: make(map[string]Object), Flags: make(map[string]uintptr)}
	for name, file := range map[string]*os.File{"channel": channelFile, "directory": directory, "image": image} {
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		object, err := objectOf(info)
		if err != nil {
			t.Fatal(err)
		}
		report.Originals[name] = object
		report.Flags[name], _ = retainedDescriptorFlags(t, file)
	}
	channel, err := CaptureChannel(channelFile)
	if err != nil {
		if channel != nil {
			_ = channel.Close(context.Background())
		}
		_ = directory.Close()
		t.Fatal(err)
	}
	// The image is a separate retained launch owner. It is not consumed by
	// either the channel or directory constructor and needs its own marking.
	if err := SetCloseOnExec(image); err != nil {
		_ = channel.Close(context.Background())
		_ = directory.Close()
		t.Fatal(err)
	}
	bootstrap, err := BindInheritedParent(ctx, channel, directory, processFixtureCapture)
	if bootstrap != nil {
		defer func() {
			if err := bootstrap.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil || bootstrap.childRecord.Image != report.Originals["image"] {
		t.Fatal("inherited exec fixture lost its authenticated original image", err)
	}
	if err := bootstrap.Send(ctx, []byte("native-child-ready")); err != nil {
		t.Fatal(err)
	}
	request, err := bootstrap.Receive(ctx)
	if err != nil || string(request) != "observe-descendant" {
		t.Fatal("inherited exec fixture lost its original authenticated request", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestLinuxProcessNamespaceExecInventoryWorker$", "-test.count=1", "-test.timeout=8s")
	command.Env = []string{"PATH=/usr/bin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS=1", "ROUTERVPN_LINUX_EXEC_INVENTORY=1"}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal("actual exec inventory did not finish", err, output.String())
	}
	count := 0
	for _, line := range strings.Split(output.String(), "\n") {
		if body, ok := strings.CutPrefix(line, "actual-exec-inventory:"); ok {
			count++
			if err := json.Unmarshal([]byte(body), &report.Inventory); err != nil {
				t.Fatal(err)
			}
		}
	}
	if count != 1 || report.Inventory.ProcessID != command.Process.Pid || report.Inventory.ParentID != os.Getpid() ||
		report.Inventory.Image != bootstrap.childRecord.Image || len(report.Inventory.Descriptors) == 0 {
		t.Fatal("exec inventory did not describe the actual created descendant", output.String())
	}
	body, err := json.Marshal(report)
	if err != nil || len(body) > MessageLimit {
		t.Fatal("actual descendant inventory exceeded its authenticated frame", err)
	}
	if err := bootstrap.Send(ctx, body); err != nil {
		t.Fatal(err)
	}
	for {
		request, err := bootstrap.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil {
				t.Fatal(err)
			}
			return
		}
		if string(request) != "ping" {
			t.Fatal("unexpected inherited exec fixture request")
		}
		if err := bootstrap.Send(ctx, []byte("pong")); err != nil {
			t.Fatal(err)
		}
	}
}

func startInheritedExecChild(t *testing.T) (*processNativeChild, map[string]Object) {
	t.Helper()
	requireProcessNamespace(t)
	parent, err := CaptureSelf(context.Background())
	if parent != nil {
		t.Cleanup(func() { _ = parent.Close(context.Background()) })
	}
	if err != nil {
		t.Fatal(err)
	}
	observation, err := parent.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := parent.DuplicateDirectory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	channel, childEndpoint, err := ChannelPair()
	if channel != nil {
		t.Cleanup(func() { _ = channel.Close(context.Background()) })
	}
	if childEndpoint != nil {
		t.Cleanup(func() { _ = childEndpoint.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = image.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, executable, "-test.run=^TestLinuxProcessNamespaceInheritedExecWorker$", "-test.count=1", "-test.timeout=14s")
	command.Env = []string{"PATH=/usr/bin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS=1", "ROUTERVPN_LINUX_INHERITED_EXEC=1"}
	command.ExtraFiles = []*os.File{childEndpoint, directory, image}
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	child := &processNativeChild{parent: parent, observation: observation, channel: channel, command: command, joined: make(chan struct{}), cancel: cancel}
	command.Stdout, command.Stderr = &child.output, &child.output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { child.joinErr = command.Wait(); close(child.joined) }()
	t.Cleanup(func() { child.finish(t) })
	if pidfd < 0 {
		t.Fatal("inherited exec fixture did not retain its actual clone-created child")
	}
	child.pidfd = os.NewFile(uintptr(pidfd), "actual-inherited-exec-clone")
	if err := errors.Join(childEndpoint.Close(), directory.Close(), image.Close()); err != nil {
		t.Fatal(err)
	}
	return child, map[string]Object{"channel": channel.peerIdentity, "directory": parent.directoryIdentity, "image": observation.Image}
}

func TestLinuxProcessNamespaceInheritedCloseOnExec(t *testing.T) {
	child, originals := startInheritedExecChild(t)
	child.ready(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := child.bootstrap.Send(ctx, []byte("observe-descendant")); err != nil {
		t.Fatal(err)
	}
	body, err := child.bootstrap.Receive(ctx)
	var report inheritedExecReport
	if err != nil || json.Unmarshal(body, &report) != nil || len(report.Originals) != 3 || len(report.Flags) != 3 ||
		report.Inventory.ParentID != child.command.Process.Pid || report.Inventory.Image != child.observation.Image ||
		report.Inventory.ProcessID <= 0 || report.Inventory.ProcessID == report.Inventory.ParentID || len(report.Inventory.Descriptors) == 0 {
		child.finish(t)
		t.Fatal("original bootstrap did not report its actual exec descendant", err, string(body), child.output.String())
	}
	for _, role := range []string{"channel", "directory", "image"} {
		t.Run(role, func(t *testing.T) {
			if report.Originals[role] != originals[role] || report.Flags[role]&syscall.FD_CLOEXEC != 0 {
				t.Fatal("fixture did not inherit the original unmarked launch descriptor", role)
			}
			for _, inherited := range report.Inventory.Descriptors {
				if inherited.Object == originals[role] {
					t.Fatal("actual exec descendant inherited retained "+role+" object", inherited.Number, inherited.Object)
				}
			}
		})
	}
	t.Run("still-authenticated", func(t *testing.T) {
		if err := child.bootstrap.CheckCapture(ctx, processFixtureCapture); err != nil {
			t.Fatal("CLOEXEC retired the original authenticated bootstrap", err)
		}
		if err := child.bootstrap.Send(ctx, []byte("ping")); err != nil {
			t.Fatal(err)
		}
		body, err := child.bootstrap.Receive(ctx)
		if err != nil || string(body) != "pong" {
			t.Fatal("original authenticated channel stopped working after descendant exec", err, string(body))
		}
		if _, err := child.parent.Current(ctx); err != nil {
			t.Fatal("CLOEXEC changed the original retained parent witness", err)
		}
	})
}
