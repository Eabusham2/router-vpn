//go:build linux && routervpn_controller_privileged

package linuxprocess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func peerClosePair(t *testing.T) (*Channel, *Channel) {
	t.Helper()
	requireProcessNamespace(t)
	first, endpoint, err := ChannelPair()
	if first != nil {
		t.Cleanup(func() { _ = first.Close(context.Background()) })
	}
	if endpoint != nil {
		t.Cleanup(func() { _ = endpoint.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := CaptureChannel(endpoint)
	if second != nil {
		t.Cleanup(func() { _ = second.Close(context.Background()) })
	}
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

func nativeChannelControl(t *testing.T, channel *Channel, operation func(int) error) {
	t.Helper()
	raw, err := channel.conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var nativeErr error
	if err := raw.Control(func(fd uintptr) { nativeErr = operation(int(fd)) }); err != nil || nativeErr != nil {
		t.Fatal("actual channel fixture lost its native operation", err, nativeErr)
	}
}

func sendEmptyNativePacket(t *testing.T, channel *Channel, file *os.File) {
	t.Helper()
	send := func(control []byte) {
		nativeChannelControl(t, channel, func(fd int) error {
			n, err := syscall.SendmsgN(fd, nil, control, nil, 0)
			if err == nil && n != 0 {
				return errors.New("actual empty packet was replaced with payload")
			}
			return err
		})
	}
	if file == nil {
		send(nil)
		return
	}
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) { send(syscall.UnixRights(int(fd))) }); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxProcessNamespaceChannelPeerClosed(t *testing.T) {
	for _, scenario := range []string{"original-peer-eof", "write-half-close", "empty-credential-frame", "empty-rights-frame",
		"disabled-credentials", "replaced-original", "replaced-connection", "changed-creator",
		"cancelled-receive", "local-close", "receive-timeout", "cancelled-completion", "retired-completion"} {
		t.Run(scenario, func(t *testing.T) {
			first, second := peerClosePair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if scenario == "cancelled-completion" || scenario == "retired-completion" {
				// The actual operation joins its cancellation callback and local
				// retirement after the read. Neither may retain a usable EOF sentinel.
				err := first.operation(ctx, func() error {
					if scenario == "cancelled-completion" {
						cancel()
					} else {
						first.stopping.Store(true)
					}
					return ErrPeerClosed
				})
				if err == nil || errors.Is(err, ErrPeerClosed) {
					t.Fatal("cancelled or retired completion retained peer EOF authority", err)
				}
				if scenario == "cancelled-completion" && !errors.Is(err, context.Canceled) {
					t.Fatal("joined completion lost its original cancellation", err)
				}
				return
			}
			if scenario == "cancelled-receive" || scenario == "local-close" {
				observed := &observedNativeContext{base: ctx, registered: make(chan struct{})}
				result := make(chan error, 1)
				go func() {
					packet, err := first.Receive(observed, os.Getpid(), false)
					if packet != nil {
						err = errors.Join(err, packet.Close())
					}
					result <- err
				}()
				select {
				case <-observed.registered:
				case <-ctx.Done():
					t.Fatal("actual EOF fixture did not enter its bounded receive")
				}
				if scenario == "cancelled-receive" {
					cancel()
				} else if err := first.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-result:
					if err == nil || errors.Is(err, ErrPeerClosed) {
						t.Fatal("cancelled or locally closed receive was mistaken for peer closure", err)
					}
				case <-time.After(time.Second):
					t.Fatal("actual channel cancellation did not join")
				}
				return
			}
			var source *os.File
			switch scenario {
			case "original-peer-eof":
				if err := second.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "write-half-close":
				nativeChannelControl(t, second, func(fd int) error { return syscall.Shutdown(fd, syscall.SHUT_WR) })
			case "empty-credential-frame":
				sendEmptyNativePacket(t, second, nil)
			case "empty-rights-frame":
				var err error
				source, err = os.Open("/proc/self")
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				sendEmptyNativePacket(t, second, source)
			case "disabled-credentials":
				// Disable both actual endpoints before the first send. Leaving
				// the sender's option enabled would autobind an abstract address,
				// letting that separate guard mask a missing credential readback.
				for _, channel := range []*Channel{first, second} {
					nativeChannelControl(t, channel, func(fd int) error {
						return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 0)
					})
				}
				sendEmptyNativePacket(t, second, nil)
			case "replaced-original", "replaced-connection":
				other, otherPeer := peerClosePair(t)
				if err := errors.Join(second.Close(context.Background()), otherPeer.Close(context.Background())); err != nil {
					t.Fatal(err)
				}
				if scenario == "replaced-original" {
					original := first.file
					first.file = other.file
					defer func() { first.file = original }()
				} else {
					original := first.conn
					first.conn = other.conn
					defer func() { first.conn = original }()
				}
			case "changed-creator":
				first.creator.Pid++
				if err := second.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "receive-timeout":
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 50*time.Millisecond)
				defer stop()
			}
			packet, err := first.Receive(ctx, os.Getpid(), false)
			if packet == nil {
				t.Fatal("failed native receive lost its partial packet owner")
			}
			defer packet.Close()
			if scenario == "original-peer-eof" || scenario == "write-half-close" {
				if !errors.Is(err, ErrPeerClosed) {
					t.Fatal("actual original channel EOF did not reach the bounded sentinel", err)
				}
				if scenario == "write-half-close" {
					if _, err := second.currentIdentity(); err != nil {
						t.Fatal("receive EOF was incorrectly treated as retiring the live peer owner", err)
					}
				}
			} else if err == nil || errors.Is(err, ErrPeerClosed) {
				t.Fatal("native "+scenario+" was mistaken for peer closure", err)
			}
			if packet.valid || len(packet.Payload) != 0 {
				t.Fatal("EOF or rejected frame became an accepted message")
			}
			if _, err := packet.TakeFile(); err == nil {
				t.Fatal("EOF or rejected frame transferred descriptor authority")
			}
			if source != nil {
				if len(packet.files) != 1 || packet.files[0] == nil {
					t.Fatal("rejected empty frame lost its actual received descriptor")
				}
				received := packet.files[0]
				original, originalErr := source.Stat()
				actual, actualErr := received.Stat()
				if originalErr != nil || actualErr != nil || !os.SameFile(original, actual) {
					t.Fatal("rejected empty frame retained a different native object", originalErr, actualErr)
				}
				if err := packet.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := received.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("rejected empty frame did not close its owned received descriptor", err)
				}
				if _, err := source.Stat(); err != nil {
					t.Fatal("rejected empty frame closed the independent original sender object", err)
				}
			} else if len(packet.files) != 0 {
				t.Fatal("empty receive invented native descriptors")
			}
		})
	}
}

func TestLinuxProcessNamespacePeerCloseWorker(t *testing.T) {
	if os.Getenv("ROUTERVPN_LINUX_ACKNOWLEDGED_EOF") != "1" {
		return
	}
	requireProcessNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	channel, err := CaptureChannel(os.NewFile(3, "acknowledged-eof-original-channel"))
	directory := os.NewFile(4, "acknowledged-eof-original-parent")
	if err != nil {
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
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Send(ctx, []byte("native-child-ready")); err != nil {
		t.Fatal(err)
	}
	body, err := bootstrap.Receive(ctx)
	if err != nil || string(body) != "final-closed-ack" {
		t.Fatal("child did not receive the original authenticated final acknowledgement", err)
	}
	if err := bootstrap.Send(ctx, []byte("final-ack-observed")); err != nil {
		t.Fatal(err)
	}
	body, err = bootstrap.Receive(ctx)
	if !errors.Is(err, ErrPeerClosed) || len(body) != 0 || ctx.Err() != nil {
		t.Fatal("authenticated child did not distinguish final channel EOF", err)
	}
	// EOF itself proves no process retirement: the original parent witness is
	// still live here, and the parent separately joins this exact exec.Cmd.
	parent, err := bootstrap.parent.Current(ctx)
	if err != nil || parent != bootstrap.parentRecord {
		t.Fatal("EOF discarded the original still-live parent witness", err)
	}
	fmt.Println("actual-final-ack-then-original-channel-eof")
}

func TestLinuxProcessNamespaceAcknowledgedPeerClose(t *testing.T) {
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
	channel, endpoint, err := ChannelPair()
	if channel != nil {
		t.Cleanup(func() { _ = channel.Close(context.Background()) })
	}
	if endpoint != nil {
		t.Cleanup(func() { _ = endpoint.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, executable, "-test.run=^TestLinuxProcessNamespacePeerCloseWorker$", "-test.count=1", "-test.timeout=14s")
	command.Env = []string{"PATH=/usr/bin:/bin", "GORACE=atexit_sleep_ms=0", "ROUTERVPN_CONTROLLER_PRIVILEGE_TEST_NS=1", "ROUTERVPN_LINUX_ACKNOWLEDGED_EOF=1"}
	command.ExtraFiles = []*os.File{endpoint, directory}
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
		t.Fatal("acknowledged EOF fixture lost its actual clone-created pidfd")
	}
	child.pidfd = os.NewFile(uintptr(pidfd), "actual-acknowledged-eof-child-pidfd")
	if err := errors.Join(endpoint.Close(), directory.Close()); err != nil {
		t.Fatal(err)
	}
	child.ready(t)
	if err := child.bootstrap.Send(ctx, []byte("final-closed-ack")); err != nil {
		t.Fatal("final acknowledgement did not retain its live authenticated child", err)
	}
	body, err := child.bootstrap.Receive(ctx)
	if err != nil || string(body) != "final-ack-observed" {
		t.Fatal("actual child did not acknowledge its final protocol message", err)
	}
	if err := child.bootstrap.Close(ctx); err != nil {
		t.Fatal("parent did not close its original channel after the final acknowledgement", err)
	}
	select {
	case <-child.joined:
	case <-ctx.Done():
		t.Fatal("actual child did not join after acknowledged channel EOF")
	}
	if child.joinErr != nil || !strings.Contains(child.output.String(), "actual-final-ack-then-original-channel-eof") {
		t.Fatal("actual authenticated EOF sequence did not complete", child.joinErr, child.output.String())
	}
	if current, err := parent.Current(context.Background()); err != nil || current != observation {
		t.Fatal("child EOF or join closed the independent original parent witness", err)
	}
}
