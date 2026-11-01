//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The socket, kernel peer identity, framing and transferred descriptor are real.
// This adapter places the old idle deadline just after the first actual bytes,
// then tells the writer when that boundary has been reached. It never supplies
// bytes, a peer identity, or a successful native receive in place of the socket.
type desktopDarwinFrameAdmissionFixture struct {
	*net.UnixConn
	first       sync.Once
	admitted    chan struct{}
	deadlines   []time.Time
	rejectReset bool
	holdPayload bool
	expires     time.Time
}

func (f *desktopDarwinFrameAdmissionFixture) ReadMsgUnix(body, control []byte) (int, int, int, *net.UnixAddr, error) {
	n, ancillary, flags, address, err := f.UnixConn.ReadMsgUnix(body, control)
	if n > 0 && err == nil {
		f.first.Do(func() {
			// Model admission near the end of the existing 100ms idle poll.
			if reset := f.UnixConn.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); reset != nil {
				err = reset
			}
			close(f.admitted)
		})
		if f.holdPayload && bytes.HasSuffix(body[:n], []byte("}")) {
			<-time.After(time.Until(f.expires.Add(20 * time.Millisecond)))
		}
	}
	return n, ancillary, flags, address, err
}

func (f *desktopDarwinFrameAdmissionFixture) SetReadDeadline(deadline time.Time) error {
	f.deadlines = append(f.deadlines, deadline)
	if f.rejectReset {
		return errors.New("captured frame deadline installation refused")
	}
	return f.UnixConn.SetReadDeadline(deadline)
}

func TestDesktopDarwinGuardianKernelFrameAdmission(t *testing.T) {
	t.Run("captured-expiry-bounds", func(t *testing.T) {
		now := time.Now()
		g := &desktopDarwinGuardian{pf: &desktopDarwinPF{permits: make(map[string]desktopDarwinPFPermit)}}
		if got := g.receiveDeadline(now, now); got != now.Add(desktopSocketControlWait) {
			t.Fatal("admitted frame changed the original control budget")
		}
		last := now.Add(-5 * time.Second)
		if got := g.receiveDeadline(now, last); got != last.Add(6*time.Second) {
			t.Fatal("admitted frame extended its original idle-owner lifetime")
		}
		soon := now.Add(150 * time.Millisecond)
		g.pf.permits["later"] = desktopDarwinPFPermit{Expires: now.Add(time.Second)}
		g.pf.permits["earlier"] = desktopDarwinPFPermit{Expires: soon}
		if got := g.receiveDeadline(now, last); got != soon {
			t.Fatal("admitted frame postponed the earliest captured permit expiry")
		}
		g.pf.permits["expired"] = desktopDarwinPFPermit{Expires: now.Add(-time.Millisecond)}
		if got := g.receiveDeadline(now, last); got.After(now) {
			t.Fatal("admitted frame revived an expired native permit")
		}
	})
	for _, fault := range []string{"complete-after-idle", "partial-expired", "late-rights", "wrong-pid", "deadline-error", "expired-after-read"} {
		t.Run(fault, func(t *testing.T) {
			receiver, senderFile, err := desktopDarwinSocketPair()
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			senderConnection, err := net.FileConn(senderFile)
			_ = senderFile.Close()
			if err != nil {
				t.Fatal(err)
			}
			sender := senderConnection.(*net.UnixConn)
			defer sender.Close()
			packet, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			port := packet.LocalAddr().String()
			owned, err := packet.File()
			_ = packet.Close()
			if err != nil {
				t.Fatal(err)
			}
			defer owned.Close()
			fixture := &desktopDarwinFrameAdmissionFixture{UnixConn: receiver, admitted: make(chan struct{}), rejectReset: fault == "deadline-error"}
			frameDeadline := time.Now().Add(2 * time.Second)
			if fault == "partial-expired" || fault == "expired-after-read" {
				frameDeadline = time.Now().Add(250 * time.Millisecond)
			}
			fixture.holdPayload, fixture.expires = fault == "expired-after-read", frameDeadline
			if err := receiver.SetReadDeadline(frameDeadline); err != nil {
				t.Fatal(err)
			}
			if err := sender.SetWriteDeadline(frameDeadline); err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"Operation":"bind"}`)
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
			done := make(chan error, 1)
			senderJoined := make(chan struct{})
			go func() {
				defer close(senderJoined)
				defer owned.Close()
				rights := syscall.UnixRights(int(owned.Fd()))
				if fault == "late-rights" {
					rights = nil
				}
				if _, _, err := sender.WriteMsgUnix(header[:2], rights, nil); err != nil {
					done <- err
					return
				}
				select {
				case <-fixture.admitted:
				case <-time.After(2 * time.Second):
					done <- errors.New("first captured fragment was never read")
					return
				}
				if fault == "partial-expired" {
					done <- nil
					return
				}
				// The remaining bytes arrive after the old idle deadline, within
				// this frame's single already-captured completion deadline.
				<-time.After(100 * time.Millisecond)
				rights = nil
				if fault == "late-rights" {
					rights = syscall.UnixRights(int(owned.Fd()))
				}
				_, _, err := sender.WriteMsgUnix(append(header[2:], raw...), rights, nil)
				done <- err
			}()
			peer := uint32(os.Getpid())
			if fault == "wrong-pid" {
				peer++
			}
			var request desktopDarwinRequest
			file, receiveErr := desktopDarwinReceiveBounded(fixture, &request, peer, 0, frameDeadline)
			if file != nil {
				_ = file.Close()
			}
			_ = receiver.Close()
			_ = sender.Close()
			writeErr := <-done
			<-senderJoined
			if fault == "complete-after-idle" {
				if receiveErr != nil || writeErr != nil || request.Operation != "bind" || file == nil {
					t.Fatal("admitted Darwin frame reused its idle polling deadline", receiveErr, writeErr)
				}
			} else if receiveErr == nil || file != nil || errors.Is(receiveErr, desktopDarwinIdle) {
				t.Fatal("incomplete or unauthenticated admitted frame escaped its original owner", fault, receiveErr)
			}
			if len(fixture.deadlines) != 1 || fixture.deadlines[0] != frameDeadline {
				t.Fatal("fragment arrival renewed or omitted the single captured frame budget", fixture.deadlines)
			}
			replacement, err := net.ListenPacket("udp4", port)
			if err != nil {
				t.Fatal("admitted frame retained an unowned descriptor", err)
			}
			_ = replacement.Close()
		})
	}
}
