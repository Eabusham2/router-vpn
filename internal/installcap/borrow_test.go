//go:build linux || darwin

package installcap

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--installer-channel-test-child" {
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 3, syscall.F_GETFL, 0)
		if errno != 0 || flags&syscall.O_NONBLOCK == 0 {
			os.Exit(71)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fixtureChannels(t *testing.T) []*net.UnixConn {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	var channels []*net.UnixConn
	for _, descriptor := range pair {
		file := os.NewFile(uintptr(descriptor), "fixture-private-channel")
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		channel := connection.(*net.UnixConn)
		t.Cleanup(func() { _ = channel.Close() })
		channels = append(channels, channel)
	}
	return channels
}

func TestInstallerDescendantRetainsNonblockingCompletionDeadline(t *testing.T) {
	channels := fixtureChannels(t)
	retained, err := channelForProcess(channels[0])
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	raw, err := channels[0].SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	// Fill the exact private stream before running a real descendant. No
	// peer reads until cleanup, so a completion write must hit its deadline.
	var fillError error
	if err := raw.Control(func(fd uintptr) {
		if fillError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1024); fillError != nil {
			return
		}
		buffer := make([]byte, 1024)
		for total := 0; total < 4<<20; {
			n, failure := syscall.Write(int(fd), buffer)
			if errors.Is(failure, syscall.EAGAIN) || errors.Is(failure, syscall.EWOULDBLOCK) {
				return
			}
			if failure != nil || n == 0 {
				fillError = errors.Join(failure, errors.New("fixture could not saturate its captured stream"))
				return
			}
			total += n
		}
		fillError = errors.New("fixture exceeded its socket buffer bound")
	}); err != nil || fillError != nil {
		t.Fatal(err, fillError)
	}
	child := exec.Command(os.Args[0], "--installer-channel-test-child")
	child.Env = []string{"GORACE=atexit_sleep_ms=0"}
	child.ExtraFiles = []*os.File{retained}
	if err := child.Run(); err != nil {
		t.Error("real ExtraFiles descendant changed its original channel to blocking", err)
	}
	var flags uintptr
	if err := raw.Control(func(fd uintptr) { flags, _, _ = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0) }); err != nil || flags&syscall.O_NONBLOCK == 0 {
		t.Error("descendant changed the shared Python/Go channel flags", err)
	}
	owner := &Borrowed{channel: channels[0], channelFile: retained, adopted: true, ready: fixtureRecord()}
	complete := make(chan error, 1)
	go func() { complete <- owner.Close() }()
	select {
	case err := <-complete:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("saturated completion lost its original three-second deadline", err)
		}
	case <-time.After(6 * time.Second):
		// Release only this captured peer so even the deliberate old-code
		// negative joins; a blocked goroutine never outlives the test.
		channels[1].Close()
		select {
		case <-complete:
		case <-time.After(time.Second):
			t.Fatal("failed completion did not join after its exact peer retired")
		}
		t.Fatal("blocking inherited description bypassed the completion deadline")
	}
}

func fixtureRecord() record {
	return record{Schema: 1, Generation: strings.Repeat("1", 32), Operation: "grant", Phase: "plan", Sequence: 1,
		PID: os.Getpid(), Device: 1, Inode: 2, RootDevice: 3, RootInode: 4, LeaseDevice: 5, LeaseInode: 6}
}

func TestInstallerFrameRejectsAmbiguousAuthority(t *testing.T) {
	expected := fixtureRecord()
	raw, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := decodeRecord(raw); err != nil || actual != expected {
		t.Fatal("exact bounded capability frame changed identity", actual, err)
	}
	for _, malformed := range []string{
		string(raw[:len(raw)-1]) + `,"inode":2}`, string(raw[:len(raw)-1]) + `,"root":"/tmp/foreign"}`,
		strings.Replace(string(raw), `"schema":1,`, "", 1), strings.Replace(string(raw), `"schema":1`, `"schema":true`, 1),
		strings.Replace(string(raw), `"device":1`, `"device":null`, 1),
		strings.Replace(string(raw), `"sequence":1`, `"sequence":65`, 1), strings.Replace(string(raw), `"sequence":1`, `"sequence":1.0`, 1),
		strings.Replace(string(raw), `"phase":"plan"`, `"phase":"watch"`, 1),
		strings.Replace(string(raw), `"operation":"grant"`, `"operation":"unlock"`, 1),
		strings.Replace(string(raw), `"inode":2`, `"inode":18446744073709551616`, 1), string(raw) + `{}`,
	} {
		if _, err := decodeRecord([]byte(malformed)); err == nil {
			t.Fatal("ambiguous or caller-selected capability authority was accepted", malformed)
		}
	}
}

func TestInstallerRejectedTransferClosesEveryReceivedDescription(t *testing.T) {
	for _, fault := range []string{"descriptor-count", "malformed-json", "oversized-frame", "truncated-rights"} {
		t.Run(fault, func(t *testing.T) {
			channels := fixtureChannels(t)
			file, err := os.CreateTemp(t.TempDir(), "captured-lease-")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(fixtureRecord())
			count := 2
			if fault == "descriptor-count" {
				count = 1
			} else if fault == "truncated-rights" {
				count = 64
			} else if fault == "malformed-json" {
				raw = []byte(`{"schema":`)
			}
			frame := make([]byte, 4+len(raw))
			binary.BigEndian.PutUint32(frame, uint32(len(raw)))
			copy(frame[4:], raw)
			if fault == "oversized-frame" {
				binary.BigEndian.PutUint32(frame, frameLimit+1)
			}
			descriptors := make([]int, count)
			for index := range descriptors {
				descriptors[index] = int(file.Fd())
			}
			if _, _, err := channels[0].WriteMsgUnix(frame, syscall.UnixRights(descriptors...), nil); err != nil {
				t.Fatal(err)
			}
			file.Close()
			if _, files, err := receive(channels[1], 2); err == nil || len(files) != 0 {
				t.Fatal("malformed private transfer retained usable descriptors", files, err)
			}
			probe, err := os.OpenFile(file.Name(), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal("rejected SCM_RIGHTS transfer leaked an original locked description", err)
			}
		})
	}
}
