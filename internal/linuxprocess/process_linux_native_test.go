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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const processFixtureCapture = "ad46c0daa75a8be898d9b9e224e52037023ae1159e1cb46762bd82c327961eec"

func requireProcessNamespace(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS") != "1" {
		t.Fatal("native process proof requires the actual isolated controller namespace gate")
	}
}

func TestLinuxProcessNamespaceWorker(t *testing.T) {
	scenario := os.Getenv("ROUTERVPN_LINUX_PROCESS_NATIVE_CHILD")
	if scenario == "" {
		return
	}
	requireProcessNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	channel, err := CaptureChannel(os.NewFile(3, "native-process-fixture-channel"))
	if err != nil {
		if channel != nil {
			_ = channel.Close(context.Background())
		}
		t.Fatal(err)
	}
	directory := os.NewFile(4, "native-process-fixture-original-parent")
	capture := processFixtureCapture
	if scenario == "wrong-capture" {
		capture = strings.Repeat("b", 64)
	}
	if scenario == "task-and-exit" {
		defer channel.Close(context.Background())
		defer directory.Close()
		self, err := CaptureSelf(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer self.Close(context.Background())
		task, err := self.DuplicateDirectory(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer task.Close()
		if err := channel.Send(ctx, []byte("original-task-before-exit"), task); err != nil {
			t.Fatal(err)
		}
		return
	}
	bootstrap, err := BindInheritedParent(ctx, channel, directory, capture)
	if bootstrap != nil {
		defer func() {
			if err := bootstrap.Close(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	refusal := strings.HasPrefix(scenario, "reject/") || scenario == "wrong-capture"
	if err != nil {
		if refusal {
			fmt.Println("original-bootstrap-refused")
			return
		}
		t.Fatal(err)
	}
	if refusal {
		t.Fatal("foreign bootstrap unexpectedly authenticated")
	}
	if err := bootstrap.Send(ctx, []byte("native-child-ready")); err != nil {
		t.Fatal(err)
	}
	for {
		body, err := bootstrap.Receive(ctx)
		if err != nil {
			// The only normal end in this fixture is the original parent's
			// joined channel Close. No successful native retirement is implied.
			if ctx.Err() != nil {
				t.Fatal(err)
			}
			return
		}
		switch string(body) {
		case "ping":
			if err := bootstrap.Send(ctx, []byte("pong")); err != nil {
				t.Fatal(err)
			}
		case "exec":
			if err := bootstrap.Send(ctx, []byte("executing-different-image")); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Exec("/bin/sleep", []string{"sleep", "8"}, []string{"PATH=/usr/bin:/bin"}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("unknown native fixture request")
		}
	}
}

type processNativeChild struct {
	parent      *Witness
	observation Observation
	channel     *Channel
	pidfd       *os.File
	command     *exec.Cmd
	bootstrap   *Bootstrap
	output      bytes.Buffer
	joined      chan struct{}
	joinErr     error
	cancel      context.CancelFunc
	finishOnce  sync.Once
}

func startProcessNativeChild(t *testing.T, scenario string, changeParent func(*os.File) *os.File) *processNativeChild {
	t.Helper()
	requireProcessNamespace(t)
	parent, err := CaptureSelf(context.Background())
	if err != nil {
		if parent != nil {
			_ = parent.Close(context.Background())
		}
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
	if changeParent != nil {
		directory = changeParent(directory)
	}
	channel, childEndpoint, err := ChannelPair()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, image, "-test.run=^TestLinuxProcessNamespaceWorker$", "-test.count=1", "-test.timeout=14s")
	command.Env = []string{"PATH=/usr/bin:/bin", "ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS=1", "ROUTERVPN_LINUX_PROCESS_NATIVE_CHILD=" + scenario}
	command.ExtraFiles = []*os.File{childEndpoint, directory}
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	child := &processNativeChild{parent: parent, observation: observation, channel: channel, command: command,
		joined: make(chan struct{}), cancel: cancel}
	command.Stdout, command.Stderr = &child.output, &child.output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	if pidfd < 0 {
		cancel()
		_ = command.Wait()
		t.Fatal("actual clone did not return its created pidfd")
	}
	child.pidfd = os.NewFile(uintptr(pidfd), "actual-clone-created-fixture-pidfd")
	if err := errors.Join(childEndpoint.Close(), directory.Close()); err != nil {
		t.Fatal(err)
	}
	go func() { child.joinErr = command.Wait(); close(child.joined) }()
	t.Cleanup(func() { child.finish(t) })
	return child
}

func (c *processNativeChild) finish(t *testing.T) {
	t.Helper()
	c.finishOnce.Do(func() {
		if c.bootstrap != nil {
			if err := c.bootstrap.Close(context.Background()); err != nil {
				t.Error("native bootstrap did not join its retained handles", err)
			}
		} else if c.channel != nil {
			_ = c.channel.Close(context.Background())
		}
		if c.pidfd != nil {
			_ = c.pidfd.Close()
		}
		c.cancel()
		<-c.joined
		if err := c.parent.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
}

func (c *processNativeChild) bind(ctx context.Context, pid int, image Object, capture string) error {
	var err error
	c.bootstrap, err = BindCreatedChild(ctx, c.channel, c.parent, c.pidfd, pid, image, capture)
	c.pidfd = nil
	return err
}

func (c *processNativeChild) ready(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.bind(ctx, c.command.Process.Pid, c.observation.Image, processFixtureCapture); err != nil {
		c.finish(t)
		t.Fatal("actual inherited child did not authenticate", err, c.output.String())
	}
	body, err := c.bootstrap.Receive(ctx)
	if err != nil || string(body) != "native-child-ready" {
		c.finish(t)
		t.Fatal("actual authenticated child did not reach its bounded ready fixture", string(body), err, c.output.String())
	}
}

func TestLinuxProcessNamespaceWitness(t *testing.T) {
	requireProcessNamespace(t)
	ctx := context.Background()
	for _, scenario := range []string{"original", "wrong-pid", "foreign-directory", "closed-image", "closed-directory"} {
		t.Run(scenario, func(t *testing.T) {
			witness, err := CaptureSelf(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer witness.Close(ctx)
			original, err := witness.Current(ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "original", "wrong-pid", "foreign-directory":
				directory, err := witness.DuplicateDirectory(ctx)
				if err != nil {
					t.Fatal(err)
				}
				pid := os.Getpid()
				if scenario == "wrong-pid" {
					pid++
				} else if scenario == "foreign-directory" {
					directory.Close()
					directory, err = os.Open(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
				}
				copy, err := CaptureDirectory(ctx, directory, pid)
				if copy == nil {
					t.Fatal("partial native directory owner disappeared")
				}
				defer copy.Close(ctx)
				if scenario == "original" {
					actual, currentErr := copy.Current(ctx)
					if err != nil || currentErr != nil || actual != original {
						t.Fatal("duplicate did not preserve the exact native task", err, currentErr)
					}
				} else if err == nil {
					t.Fatal("foreign native process directory was accepted")
				}
				if err := copy.Close(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := witness.Current(ctx); err != nil {
					t.Fatal("closing a duplicate retired the original native witness", err)
				}
			case "closed-image", "closed-directory":
				file := witness.image
				if scenario == "closed-directory" {
					file = witness.directory
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := witness.Current(ctx); err == nil {
					t.Fatal("retired original native descriptor remained current")
				}
			}
			if err := witness.Close(ctx); err != nil {
				t.Fatal("exact already-closed handles prevented joined cleanup", err)
			}
		})
	}
}

func TestLinuxProcessNamespaceCreatedBootstrap(t *testing.T) {
	child := startProcessNativeChild(t, "normal", nil)
	child.ready(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := child.bootstrap.Send(ctx, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	body, err := child.bootstrap.Receive(ctx)
	if err != nil || string(body) != "pong" {
		t.Fatal("authenticated actual process exchange failed", string(body), err)
	}
	if child.bootstrap.childRecord.ProcessID != child.command.Process.Pid || child.bootstrap.childRecord.ProcParentID != child.observation.ProcProcessID {
		t.Fatal("created process witness lost its namespace-aware original parent")
	}
	if err := child.bootstrap.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.joined:
	case <-time.After(3 * time.Second):
		t.Fatal("original channel Close did not retire its actual cooperative fixture child")
	}
	if child.joinErr != nil {
		t.Fatal(child.joinErr, child.output.String())
	}
	if _, err := child.parent.Current(ctx); err != nil {
		t.Fatal("child retirement closed a borrowed original parent", err)
	}
}

func TestLinuxProcessNamespaceRejectsForeignBootstrap(t *testing.T) {
	for _, scenario := range []string{"wrong-capture", "wrong-pid", "wrong-image", "wrong-channel", "reopened-channel", "parent-directory", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			workerScenario := "reject/" + scenario
			if scenario == "wrong-capture" {
				workerScenario = scenario
			}
			var changed func(*os.File) *os.File
			if scenario == "parent-directory" {
				changed = func(original *os.File) *os.File {
					original.Close()
					foreign, err := os.Open("/opt")
					if err != nil {
						t.Fatal(err)
					}
					return foreign
				}
			}
			child := startProcessNativeChild(t, workerScenario, changed)
			if scenario == "wrong-channel" {
				child.channel.peerIdentity.Inode++
			} else if scenario == "reopened-channel" {
				file, err := duplicateFile(context.Background(), child.channel.file, "native-fixture-recreated-channel")
				if err != nil {
					t.Fatal(err)
				}
				reopened, err := CaptureChannel(file)
				if err != nil {
					t.Fatal(err)
				}
				// Matching decoded/native inode observations do not recreate
				// the original in-memory pair-construction capability.
				reopened.peerIdentity = child.channel.peerIdentity
				if err := child.channel.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				child.channel = reopened
			}
			pid, image := child.command.Process.Pid, child.observation.Image
			if scenario == "wrong-pid" {
				pid++
			} else if scenario == "wrong-image" {
				image.Inode++
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			if err := child.bind(ctx, pid, image, processFixtureCapture); err == nil || child.bootstrap == nil {
				t.Fatal("foreign or cancelled bootstrap did not retain its rejected owner", err)
			}
			if err := child.bootstrap.Close(context.Background()); err != nil {
				t.Fatal("partial bootstrap did not join its actual handles", err)
			}
			<-child.joined
			if child.joinErr != nil || !strings.Contains(child.output.String(), "original-bootstrap-refused") {
				t.Fatal("child did not independently reject its original bootstrap", child.joinErr, child.output.String())
			}
			if _, err := child.parent.Current(context.Background()); err != nil {
				t.Fatal("rejected bootstrap closed or changed its original parent", err)
			}
		})
	}
}

func TestLinuxProcessNamespaceRetainsOriginalProcView(t *testing.T) {
	for _, scenario := range []string{"covered-fdinfo-directory", "rejects-bind-crossing"} {
		t.Run(scenario, func(t *testing.T) {
			child := startProcessNativeChild(t, "normal", nil)
			child.ready(t)
			descriptor := child.bootstrap.child.descriptor
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			target := "/proc/self/fdinfo"
			source := t.TempDir()
			var readerDirectory *os.File
			if scenario == "rejects-bind-crossing" {
				// Linux refuses an attempted bind directly over its ephemeral
				// proc fdinfo leaf with ENOENT, even while both paths stat. Prove
				// the actual openat2 mount barrier independently on this owned
				// directory; it is never accepted as a process/task witness.
				private, err := os.MkdirTemp("/opt", "native-fdinfo-mount-proof-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(private)
				target = filepath.Join(private, fmt.Sprint(descriptor.Fd()))
				source = filepath.Join(private, "foreign-readback")
				for _, path := range []string{target, source} {
					if err := os.WriteFile(path, []byte("mount barrier fixture only"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				readerDirectory, err = os.Open(private)
				if err != nil {
					t.Fatal(err)
				}
				defer readerDirectory.Close()
			}
			for label, path := range map[string]string{"source": source, "target": target} {
				if _, err := os.Stat(path); err != nil {
					t.Fatal("native proc-view fixture lost its actual "+label, err)
				}
			}
			if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
				t.Fatal("native isolated fixture could not install its replacement proc view", err)
			}
			defer func() {
				if err := syscall.Unmount(target, syscall.MNT_DETACH); err != nil {
					t.Error(err)
				}
			}()
			if scenario == "covered-fdinfo-directory" {
				if _, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", descriptor.Fd())); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("ambient proc view was not independently replaced", err)
				}
				if err := child.bootstrap.Current(ctx); err != nil {
					t.Fatal("child observer reopened the replacement ambient proc view", err)
				}
			} else {
				file, err := openRetainedFDInfo(readerDirectory, descriptor.Fd())
				if file != nil {
					file.Close()
				}
				if !errors.Is(err, syscall.EXDEV) {
					t.Fatal("retained fdinfo opener crossed a real native bind mount", err)
				}
				if err := child.bootstrap.Current(ctx); err != nil {
					t.Fatal("independent mount barrier probe changed the original child proof", err)
				}
			}
		})
	}
}

func TestLinuxProcessNamespaceRejectsRetiredAndReexecutedTask(t *testing.T) {
	t.Run("retired-task-directory", func(t *testing.T) {
		child := startProcessNativeChild(t, "task-and-exit", nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		packet, err := child.channel.Receive(ctx, child.command.Process.Pid, true)
		if packet != nil {
			defer packet.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		directory, err := packet.TakeFile()
		if err != nil {
			t.Fatal(err)
		}
		<-child.joined
		if child.joinErr != nil {
			t.Fatal(child.joinErr, child.output.String())
		}
		retired, err := CaptureDirectory(ctx, directory, child.command.Process.Pid)
		if retired == nil || err == nil {
			t.Fatal("retired original task directory was treated as a live process", err)
		}
		defer retired.Close(context.Background())
		replacement := startProcessNativeChild(t, "normal", nil)
		replacement.ready(t)
		if _, err := retired.Current(ctx); err == nil {
			t.Fatal("a replacement process revived the old retained task directory")
		}
		if err := retired.Close(context.Background()); err != nil || replacement.bootstrap.Current(ctx) != nil {
			t.Fatal("retiring the old process affected its independently created replacement", err)
		}
	})
	t.Run("reexecuted-image", func(t *testing.T) {
		child := startProcessNativeChild(t, "normal", nil)
		child.ready(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := child.bootstrap.Send(ctx, []byte("exec")); err != nil {
			t.Fatal(err)
		}
		// Exec may already complete before this response's post-read proof;
		// that is a valid refusal. Never count the body as a successful proof.
		_, _ = child.bootstrap.Receive(ctx)
		for child.bootstrap.Current(ctx) == nil && ctx.Err() == nil {
			time.Sleep(time.Millisecond)
		}
		if ctx.Err() != nil {
			t.Fatal("actual changed executable retained original child authority")
		}
		if _, err := child.parent.Current(context.Background()); err != nil {
			t.Fatal("child executable substitution retired its original parent", err)
		}
	})
}

func TestLinuxProcessNamespaceRetainsFailedClose(t *testing.T) {
	requireProcessNamespace(t)
	witness, err := CaptureSelf(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	original := witness.image
	defer original.Close()
	var bound syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &bound); err != nil || bound.Max >= 1<<30 {
		t.Fatal("fixture cannot prove its invalid descriptor lies beyond the real hard limit", err)
	}
	witness.image = os.NewFile(1<<30, "native-close-failure-beyond-descriptor-limit")
	if err := witness.Close(context.Background()); !errors.Is(err, syscall.EBADF) {
		t.Fatal("native close failure was normalized", err)
	}
	if err := witness.Close(context.Background()); !errors.Is(err, syscall.EBADF) || witness.closed {
		t.Fatal("retry normalized the original ambiguous native retirement", err)
	}
	if _, err := original.Stat(); err != nil {
		t.Fatal("fault injection or failed cleanup closed an unrelated retained image", err)
	}
}

func TestLinuxProcessNamespaceRejectsForeignPidFD(t *testing.T) {
	first := startProcessNativeChild(t, "reject/foreign-pidfd", nil)
	second := startProcessNativeChild(t, "normal", nil)
	// Exchange the exact descriptors only in the fixture: both actual children
	// remain owned by their original exec.Cmd and independent channels.
	first.pidfd, second.pidfd = second.pidfd, first.pidfd
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := first.bind(ctx, first.command.Process.Pid, first.observation.Image, processFixtureCapture); err == nil {
		t.Fatal("a different actual child's pidfd authorized the claimed task directory")
	}
	if err := first.bootstrap.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-first.joined
	if first.joinErr != nil {
		t.Fatal(first.joinErr, first.output.String())
	}
	if err := second.command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("closing a foreign comparison witness signaled or reaped its live process", err)
	}
}

func TestLinuxProcessNamespacePreservesBorrowedParent(t *testing.T) {
	child := startProcessNativeChild(t, "reject/borrowed-parent", nil)
	witness, err := CaptureCreated(context.Background(), child.pidfd, child.parent, child.parent, child.observation.Image)
	child.pidfd = nil
	if witness == nil || err == nil {
		t.Fatal("child constructor accepted its borrowed parent as an owned child witness", err)
	}
	if err := witness.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := child.parent.Current(context.Background()); err != nil {
		t.Fatal("partial child cleanup closed its borrowed original parent", err)
	}
	if err := child.channel.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-child.joined
	if child.joinErr != nil || !strings.Contains(child.output.String(), "original-bootstrap-refused") {
		t.Fatal(child.joinErr, child.output.String())
	}
}

type observedNativeContext struct {
	base       context.Context
	registered chan struct{}
}

func (c *observedNativeContext) Deadline() (time.Time, bool) { return c.base.Deadline() }
func (c *observedNativeContext) Done() <-chan struct{}       { return c.base.Done() }
func (c *observedNativeContext) Err() error                  { return c.base.Err() }
func (c *observedNativeContext) Value(any) any               { return nil }
func (c *observedNativeContext) AfterFunc(f func()) func() bool {
	close(c.registered)
	return context.AfterFunc(c.base, f)
}

func TestLinuxProcessNamespaceChannelBoundsAndCancellation(t *testing.T) {
	requireProcessNamespace(t)
	for _, scenario := range []string{"wrong-sender", "extra-descriptor", "oversize", "cancelled-receive", "close-joins-receive"} {
		t.Run(scenario, func(t *testing.T) {
			first, endpoint, err := ChannelPair()
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close(context.Background())
			second, err := CaptureChannel(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			pid := os.Getpid()
			if scenario == "wrong-sender" {
				pid++
			}
			if scenario == "cancelled-receive" || scenario == "close-joins-receive" {
				observed := &observedNativeContext{base: ctx, registered: make(chan struct{})}
				result := make(chan error, 1)
				go func() {
					packet, err := first.Receive(observed, pid, false)
					if packet != nil {
						err = errors.Join(err, packet.Close())
					}
					result <- err
				}()
				select {
				case <-observed.registered:
				case <-ctx.Done():
					t.Fatal("actual receive never registered its original cancellation owner")
				}
				if scenario == "cancelled-receive" {
					cancel()
				} else if err := first.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("cancelled or retired native receive was acknowledged")
					}
				case <-time.After(time.Second):
					t.Fatal("native receive retained an unjoined cancellation callback")
				}
				if err := first.Close(context.Background()); err != nil {
					t.Fatal("joined native cancellation could not retire its exact owner", err)
				}
				return
			}
			var descriptor *os.File
			if scenario == "extra-descriptor" {
				descriptor, err = os.Open("/proc/self")
				if err != nil {
					t.Fatal(err)
				}
				defer descriptor.Close()
			}
			if scenario == "oversize" {
				if _, _, err := second.conn.WriteMsgUnix(bytes.Repeat([]byte{'x'}, MessageLimit+1), nil, nil); err != nil {
					t.Fatal(err)
				}
			} else if err := second.Send(ctx, []byte("bounded-negative"), descriptor); err != nil {
				t.Fatal(err)
			}
			packet, err := first.Receive(ctx, pid, false)
			if packet == nil || err == nil {
				t.Fatal("native channel accepted a foreign sender or unowned descriptor inventory", err)
			}
			if scenario == "extra-descriptor" && len(packet.files) != 1 {
				t.Fatal("rejected native descriptor was not retained for joined cleanup")
			}
			if _, err := packet.TakeFile(); err == nil {
				t.Fatal("failed message transferred a native descriptor as accepted authority")
			}
			if err := packet.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Keep the actual task-record fields visible in native diagnostics without
// printing process paths, arguments, environment or unrelated host inventory.
func TestLinuxProcessNamespaceObservationReceipt(t *testing.T) {
	requireProcessNamespace(t)
	witness, err := CaptureSelf(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer witness.Close(context.Background())
	value, err := witness.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		PID, ProcPID int
		Start        uint64
	}{value.ProcessID, value.ProcProcessID, value.StartTicks})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))
}
