//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func standardServiceTestConnection(t *testing.T, file *os.File) *net.UnixConn {
	t.Helper()
	connection, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		t.Fatal("not original Unix connection")
	}
	return unix
}
func TestLinuxStandardServicePeerFixture(t *testing.T) {
	if os.Getenv("ROUTERVPN_STANDARD_PEER_FIXTURE") != "1" {
		return
	}
	transport := standardServiceTestConnection(t, os.NewFile(3, "original-parent-transfer"))
	defer transport.Close()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connection := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "original-child-created-peer"))
	defer connection.Close()
	transfer := os.NewFile(uintptr(pair[1]), "original-child-created-server")
	_, _, err = transport.WriteMsgUnix([]byte("R"), syscall.UnixRights(int(transfer.Fd())), nil)
	_ = transfer.Close()
	if err != nil {
		t.Fatal(err)
	}
	var wait [1]byte
	n, _ := connection.Read(wait[:])
	if n == 1 && wait[0] == 'E' {
		if err := syscall.Exec(os.Args[0], []string{os.Args[0], "-test.run=^TestLinuxStandardServiceReexecTargetFixture$"}, append(os.Environ(), "ROUTERVPN_STANDARD_REEXEC_TARGET=1")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxStandardServiceReexecTargetFixture(t *testing.T) {
	if os.Getenv("ROUTERVPN_STANDARD_REEXEC_TARGET") == "1" {
		time.Sleep(3 * time.Second)
	}
}

func TestLinuxStandardServiceRetainedPeerRejectsSameImageRoleReexec(t *testing.T) {
	peer, channel, _ := linuxStandardPeerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := channel.Write([]byte("E")); err != nil {
		t.Fatal(err)
	}
	for {
		if err := peer.Current(ctx); err != nil {
			retired, pollErr := peer.Retired()
			if pollErr != nil || retired {
				t.Fatal("peer death substituted for actual same-image role rejection", pollErr)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("same image exec into another role retained original command authority")
		case <-time.After(time.Millisecond):
		}
	}
}
func linuxStandardPeerFixture(t *testing.T) (*linuxStandardServicePeer, *net.UnixConn, func()) {
	t.Helper()
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("native standard service peer gate requires actual privileged processes")
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	transport := standardServiceTestConnection(t, os.NewFile(uintptr(pair[0]), "original-parent-transfer"))
	defer transport.Close()
	inherited := os.NewFile(uintptr(pair[1]), "original-child-transfer")
	defer inherited.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{executable, "-test.run=^TestLinuxStandardServicePeerFixture$"}
	command := exec.Command(arguments[0], arguments[1:]...)
	command.ExtraFiles = []*os.File{inherited}
	command.Env = append(os.Environ(), "ROUTERVPN_STANDARD_PEER_FIXTURE=1")
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = inherited.Close()
	joined := make(chan struct{})
	go func() { _ = command.Wait(); close(joined) }()
	var connection *net.UnixConn
	stop := func() {
		if connection != nil {
			_ = connection.Close()
		}
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-joined
		}
	}
	t.Cleanup(stop)
	_ = transport.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload, files, err := linuxStandardServiceRead(transport)
	if err != nil || string(payload) != "R" || len(files) != 1 {
		for _, file := range files {
			_ = file.Close()
		}
		t.Fatal("original child socket transfer", err)
	}
	connection = standardServiceTestConnection(t, files[0])
	image, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Stat("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := captureLinuxStandardServicePeer(ctx, connection, image, arguments, namespace)
	if err != nil {
		t.Fatal("actual original connected peer was rejected", err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return peer, connection, stop
}

func TestLinuxStandardServiceOriginalPeerAndForeignPIDFD(t *testing.T) {
	peer, connection, stop := linuxStandardPeerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := peer.Current(ctx); err != nil {
		t.Fatal(err)
	}
	foreign, _, _ := linuxStandardPeerFixture(t)
	original := peer.pidfd
	peer.pidfd = foreign.pidfd
	if err := peer.Current(ctx); err == nil {
		t.Fatal("real foreign pidfd became original standard service peer")
	}
	peer.pidfd = original
	image, _ := os.Stat("/proc/self/exe")
	namespace, _ := os.Stat("/proc/thread-self/ns/net")
	if accepted, err := captureLinuxStandardServicePeer(ctx, connection, image, []string{os.Args[0], linuxOwnedControllerArgument}, namespace); err == nil {
		_ = accepted.Close()
		t.Fatal("another command role authenticated as the original controller")
	}
	wrongNamespace, _ := os.Stat("/proc/thread-self/ns/pid")
	if accepted, err := captureLinuxStandardServicePeer(ctx, connection, image, []string{os.Args[0], "-test.run=^TestLinuxStandardServicePeerFixture$"}, wrongNamespace); err == nil {
		_ = accepted.Close()
		t.Fatal("another native namespace authenticated as the original scope")
	}
	stop()
	retired, err := peer.Retired()
	if err != nil || !retired {
		t.Fatal("joined original process lost native retirement receipt", err)
	}
	if err = peer.Current(ctx); err == nil {
		t.Fatal("retired original peer remained current")
	}
}
