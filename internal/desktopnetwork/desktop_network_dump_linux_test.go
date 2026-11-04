//go:build linux

package desktopnetwork

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLinuxNetworkDumpCancellationJoinsOriginalSocket(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := os.NewFile(uintptr(pair[0]), "original-dump-read")
	defer original.Close()
	peer := os.NewFile(uintptr(pair[1]), "unrelated-live-peer")
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	joined := make(chan error, 1)
	go func() { _, err := linuxReceiveDump(ctx, original, 123); joined <- err }()
	blocked := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		stack := make([]byte, 1<<20)
		count := runtime.Stack(stack, true)
		for _, worker := range strings.Split(string(stack[:count]), "\n\n") {
			if strings.Contains(worker, "linuxReceiveDump(") && strings.Contains(worker, "IO wait") {
				blocked = true
				break
			}
		}
		if blocked {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !blocked {
		t.Fatal("original dump worker never entered actual descriptor poller")
	}
	cancel()
	select {
	case err := <-joined:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("dump did not report its original cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled kernel dump reader did not join")
	}
	if _, err := original.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("completed dump retained its original descriptor", err)
	}
	if _, err := peer.Stat(); err != nil {
		t.Fatal("dump cancellation closed unrelated peer", err)
	}
}

func TestLinuxNetworkDumpStrictOriginalDatagrams(t *testing.T) {
	packet := func(kind uint16) []byte {
		body := make([]byte, 20)
		binary.LittleEndian.PutUint32(body, 20)
		binary.LittleEndian.PutUint16(body[4:], kind)
		binary.LittleEndian.PutUint32(body[8:], 1)
		binary.LittleEndian.PutUint32(body[12:], 123)
		return body
	}
	for trailing := 1; trailing < syscall.NLMSG_HDRLEN; trailing++ {
		body := append(packet(syscall.NLMSG_DONE), make([]byte, trailing)...)
		if _, err := linuxDumpDatagram(body, 0, &syscall.SockaddrNetlink{}, 123); err == nil {
			t.Fatal("short trailing bytes became a complete native dump", trailing)
		}
	}
	for _, kind := range []string{"complete", "row", "foreign-sender", "foreign-sequence", "foreign-port", "truncated", "interrupted", "overrun", "native-error", "malformed", "trailing-after-done"} {
		t.Run(kind, func(t *testing.T) {
			body := packet(syscall.NLMSG_DONE)
			flags := 0
			sender := syscall.Sockaddr(&syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
			switch kind {
			case "row":
				body = packet(syscall.RTM_NEWLINK)
			case "foreign-sender":
				sender = &syscall.SockaddrNetlink{Pid: 4}
			case "foreign-sequence":
				binary.LittleEndian.PutUint32(body[8:], 2)
			case "foreign-port":
				binary.LittleEndian.PutUint32(body[12:], 456)
			case "truncated":
				flags = syscall.MSG_TRUNC
			case "interrupted":
				binary.LittleEndian.PutUint16(body[6:], 0x10)
			case "overrun":
				body = packet(syscall.NLMSG_OVERRUN)
			case "native-error":
				body = packet(syscall.NLMSG_ERROR)
			case "malformed":
				body = body[:8]
			case "trailing-after-done":
				body = append(body, packet(syscall.RTM_NEWLINK)...)
			}
			done, err := linuxDumpDatagram(body, flags, sender, 123)
			if kind == "complete" {
				if err != nil || !done {
					t.Fatal(err)
				}
			} else if kind == "row" {
				if err != nil || done {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("foreign/incomplete native dump became complete", kind)
			}
		})
	}
}
