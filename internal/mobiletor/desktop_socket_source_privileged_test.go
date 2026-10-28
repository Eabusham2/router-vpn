//go:build (linux || darwin) && routervpn_privileged

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const desktopSocketCreatorFixture = "ROUTERVPN_OWNED_SOCKET_UID_FIXTURE"

// This child runs only from the explicit privileged fixture executable. It
// neither connects nor binds a network socket and never reads host DNS. The
// actual setuid happens in fork/exec, before this Go process creates the FD.
func init() {
	value := os.Getenv(desktopSocketCreatorFixture)
	if value == "" {
		return
	}
	uid, err := strconv.ParseUint(value, 10, 32)
	if err != nil || uid == 0 || uint32(os.Getuid()) != uint32(uid) || uint32(os.Geteuid()) != uint32(uid) || uint32(os.Getgid()) != uint32(uid) {
		os.Exit(71)
	}
	if err := desktopSocketCreatorFixtureRun(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(72)
	}
	os.Exit(0)
}

func desktopSocketCreatorFixtureRun() error {
	const channel = 3
	deadline := syscall.NsecToTimeval((3 * time.Second).Nanoseconds())
	if err := syscall.SetsockoptTimeval(channel, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &deadline); err != nil {
		return err
	}
	data := make([]byte, 4096)
	n, _, flags, _, err := syscall.Recvmsg(channel, data, nil, 0)
	if err != nil || flags != 0 {
		return errors.Join(err, errors.New("creator request frame rejected"))
	}
	var request DesktopSocketCreation
	decoder := json.NewDecoder(bytes.NewReader(data[:n]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return err
	}
	if !request.Capture.valid() || !request.Binding.Owner.valid() || !desktopSocketHex(request.SocketID, 32) || (request.Network != "tcp" && request.Network != "udp") {
		return errors.New("creator received an invalid source capture")
	}
	family, socketType := syscall.AF_INET6, syscall.SOCK_STREAM
	if request.Binding.LocalAddress.Is4() {
		family = syscall.AF_INET
	}
	if request.Network == "udp" {
		socketType = syscall.SOCK_DGRAM
	}
	fd, err := syscall.Socket(family, socketType, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	syscall.CloseOnExec(fd)
	// The receiver independently reads the creator UID from this kernel socket.
	// There is deliberately no UID assertion in the helper's reply payload.
	if err := syscall.Sendmsg(channel, data[:n], syscall.UnixRights(fd), nil, 0); err != nil {
		return err
	}
	n, _, flags, _, err = syscall.Recvmsg(channel, data, nil, 0)
	if err != nil || flags != 0 || string(data[:n]) != "received-owned-fd" {
		return errors.Join(err, errors.New("creator transfer was not acknowledged"))
	}
	return nil
}

type desktopSocketPrivilegedFixture struct {
	executable string
	uid        uint32
}

func newDesktopSocketPrivilegedFixture(t *testing.T) *desktopSocketPrivilegedFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("routervpn_privileged socket tests require real root to fork the isolated creator UID; this requirement is not skipped")
	}
	// This is a random test-only numeric UID, not production account allocation.
	// Production must retain/quarantine its independent privileged identity lease.
	var uid uint32
	for attempts := 0; attempts < 16; attempts++ {
		var nonce [4]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		uid = 0x40000000 | (binary.BigEndian.Uint32(nonce[:]) & 0x3fffffff)
		_, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		var unknown user.UnknownUserIdError
		if errors.As(err, &unknown) {
			break
		}
		if err != nil {
			t.Fatal("cannot independently reject an existing test UID", err)
		}
		uid = 0
	}
	if uid == 0 {
		t.Fatal("could not reserve an unused random test UID")
	}
	directory, err := os.MkdirTemp("", "routervpn-owned-uid-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	// The helper can search this directory and execute only the copied test
	// binary. No node credentials or inherited environment are placed here.
	if err := os.Chmod(directory, 0711); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	path := filepath.Join(directory, "owned-creator-fixture")
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0555)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, output.Close()); err != nil {
		t.Fatal(err)
	}
	return &desktopSocketPrivilegedFixture{executable: path, uid: uid}
}

func (fixture *desktopSocketPrivilegedFixture) create(ctx context.Context, request DesktopSocketCreation) (DesktopSocketCreated, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return DesktopSocketCreated{}, err
	}
	parent := os.NewFile(uintptr(pair[0]), "fixture-parent-control")
	child := os.NewFile(uintptr(pair[1]), "fixture-child-control")
	defer parent.Close()
	defer child.Close()
	for _, fd := range pair {
		syscall.CloseOnExec(fd)
	}
	command := exec.CommandContext(ctx, fixture.executable)
	command.Env = []string{desktopSocketCreatorFixture + "=" + strconv.FormatUint(uint64(fixture.uid), 10)}
	command.ExtraFiles = []*os.File{child}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: fixture.uid, Gid: fixture.uid, Groups: []uint32{}}}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Start(); err != nil {
		return DesktopSocketCreated{}, err
	}
	_ = child.Close()
	deadline := syscall.NsecToTimeval((3 * time.Second).Nanoseconds())
	if err := syscall.SetsockoptTimeval(pair[0], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &deadline); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return DesktopSocketCreated{}, err
	}
	encoded := desktopSocketSourceEncode(request)
	if err := syscall.Sendmsg(pair[0], encoded, nil, nil, 0); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return DesktopSocketCreated{}, err
	}
	file, readErr := desktopSocketSCMReceive(pair[0], encoded)
	if readErr == nil {
		readErr = syscall.Sendmsg(pair[0], []byte("received-owned-fd"), nil, nil, 0)
	}
	if readErr != nil {
		_ = command.Process.Kill()
	}
	joinErr := command.Wait()
	if joinErr != nil {
		joinErr = fmt.Errorf("actual UID helper failed: %w: %s", joinErr, diagnostic.String())
	}
	return DesktopSocketCreated{Creation: request, File: file}, errors.Join(readErr, joinErr)
}

func desktopSocketAssertActualUID(t *testing.T, raw syscall.RawConn, want uint32) {
	t.Helper()
	uid, err := desktopSocketFileUID(raw)
	if err != nil || uid != want || uid == uint32(os.Getuid()) {
		t.Fatalf("actual imported socket lost its independently forked creator: UID=%d want=%d err=%v", uid, want, err)
	}
}

func TestDesktopSocketPrivilegedUIDSurvivesTransferImportAndDup(t *testing.T) {
	fixture := newDesktopSocketPrivilegedFixture(t)
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			p := desktopSocketNewSourceFixture(t)
			p.uid = fixture.uid
			p.create = fixture.create
			broker, _ := desktopSocketSourceBroker(t, p)
			address := "127.0.0.1:0"
			if network[len(network)-1] == '6' {
				address = "[::1]:0"
			}
			var socket *desktopSocket
			if network[:3] == "tcp" {
				listener, err := net.Listen(network, address)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				accepted := make(chan net.Conn, 1)
				go func() { connection, _ := listener.Accept(); accepted <- connection }()
				connection, err := broker.DialContext(context.Background(), network, listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				peer := desktopSocketAwait(t, accepted)
				if peer == nil {
					t.Fatal("actual UID TCP peer did not accept")
				}
				defer peer.Close()
				socket = connection.(*desktopSocketConn).socket
				raw, err := socket.conn.(syscall.Conn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				desktopSocketAssertActualUID(t, raw, fixture.uid)
				if _, err := connection.Write([]byte("isolated creator")); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, len("isolated creator"))
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := io.ReadFull(peer, buffer); err != nil || string(buffer) != "isolated creator" {
					t.Fatal("actual isolated TCP data failed", err)
				}
			} else {
				peer, err := net.ListenPacket(network, address)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				connection, err := broker.DialContext(context.Background(), network, peer.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				socket = connection.(*desktopConnectedPacket).packet.socket
				raw, err := socket.packet.(syscall.Conn).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				desktopSocketAssertActualUID(t, raw, fixture.uid)
				if _, err := connection.Write([]byte("isolated UDP")); err != nil {
					t.Fatal(err)
				}
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 64)
				if n, _, err := peer.ReadFrom(buffer); err != nil || string(buffer[:n]) != "isolated UDP" {
					t.Fatal("actual isolated UDP data failed", err)
				}
			}
			for _, file := range []*os.File{socket.sourceFile, socket.keeper.file} {
				raw, err := file.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				desktopSocketAssertActualUID(t, raw, fixture.uid)
			}
			if err := broker.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if p.count() != 0 || p.joined.Load() != 1 {
				t.Fatal("actual isolated source was not fully drained")
			}
		})
	}
}

func TestDesktopSocketPrivilegedWrongKernelUIDCannotGrant(t *testing.T) {
	fixture := newDesktopSocketPrivilegedFixture(t)
	p := desktopSocketNewSourceFixture(t)
	p.uid = fixture.uid + 1
	p.create = fixture.create
	broker, _ := desktopSocketSourceBroker(t, p)
	listener := desktopSocketListener(t)
	connection, err := broker.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if connection != nil || err == nil || p.count() != 0 {
		t.Fatal("matching metadata replaced independent kernel UID proof", err)
	}
	if err := broker.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
