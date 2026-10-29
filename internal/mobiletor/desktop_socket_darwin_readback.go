//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Libinfo can retain an occupied UID in the long-lived guardian after local
// deletion. Query through a fresh execution of this protected native binary,
// using the same system-namespace lookup rather than changing global caches.
// The inherited stream authenticates the exact child, and no observation is
// accepted until that child acknowledges its captured request and joins.
func desktopDarwinFreshUIDReadback(ctx context.Context, capture DesktopSocketCapture, uid uint32) (bool, error) {
	request := desktopDarwinUIDRequest{Operation: "observe-uid", Sequence: 1, Capture: capture, UID: uid}
	if ctx == nil || request.validate() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || !desktopDarwinKernelAvailable() {
		return false, errors.New("Darwin identity observer requires its captured privileged owner")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	executable, err := desktopDarwinExecutable()
	if err != nil {
		return false, err
	}
	pin, err := os.OpenFile(executable, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer pin.Close()
	pinned, err := pin.Stat()
	if err != nil {
		return false, err
	}
	verifyImage := func() error {
		actual, err := os.Lstat(executable)
		if err != nil || !os.SameFile(pinned, actual) {
			return errors.Join(err, errors.New("Darwin identity observer executable changed its retained object"))
		}
		return desktopDarwinProtectedPath(executable, false)
	}
	if err := verifyImage(); err != nil {
		return false, err
	}
	channel, child, err := desktopDarwinSocketPair()
	if err != nil {
		return false, err
	}
	defer channel.Close()
	defer child.Close()
	command := exec.CommandContext(ctx, executable, "routervpn-owned-socket-helper", "uid-observer")
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
	command.ExtraFiles = []*os.File{child}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		return false, err
	}
	child.Close()
	// Interrupt an in-flight receive as soon as its captured operation is
	// cancelled. CommandContext kills only this owned read-only child; Wait
	// below always reaps it, including every malformed/late/error response.
	stop := context.AfterFunc(ctx, func() { channel.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	err = channel.SetDeadline(deadline)
	if err == nil {
		err = verifyImage()
	}
	if err == nil {
		err = desktopDarwinSend(channel, request, nil)
	}
	var reply desktopDarwinUIDReply
	var transferred *os.File
	if err == nil {
		transferred, err = desktopDarwinReceive(channel, &reply, uint32(command.Process.Pid), 0)
	}
	if transferred != nil {
		transferred.Close()
		err = errors.Join(err, errors.New("Darwin identity observer transferred an unexpected descriptor"))
	}
	absent := false
	if err == nil {
		absent, err = reply.absent(request)
	}
	if err == nil {
		err = desktopDarwinSend(channel, request.acknowledgment(), nil)
	}
	if err != nil {
		command.Process.Kill()
	}
	joinErr := command.Wait()
	if err != nil || joinErr != nil || ctx.Err() != nil {
		return false, errors.Join(err, joinErr, ctx.Err(), errors.New("Darwin identity observer did not complete and join within its captured deadline"))
	}
	if err := verifyImage(); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return absent, nil
}

func desktopDarwinUIDObserver(channel *net.UnixConn, parent uint32) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || !desktopDarwinKernelAvailable() {
		return errors.New("Darwin identity observer requires its privileged native role")
	}
	if err := channel.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	var request desktopDarwinUIDRequest
	file, err := desktopDarwinReceive(channel, &request, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("Darwin identity observer received an unexpected descriptor")
	}
	if err != nil || request.validate() != nil {
		return errors.Join(err, errors.New("Darwin identity observer rejected its captured request"))
	}
	absent, err := desktopDarwinUIDAbsentReadback(request.UID)
	if err != nil {
		return err
	}
	state := "occupied"
	if absent {
		state = "absent"
	}
	reply := desktopDarwinUIDReply{Sequence: request.Sequence, Capture: request.Capture, UID: request.UID, State: state}
	if err := desktopDarwinSend(channel, reply, nil); err != nil {
		return err
	}
	var ack desktopDarwinUIDRequest
	file, err = desktopDarwinReceive(channel, &ack, parent, 0)
	if file != nil {
		file.Close()
		return errors.New("Darwin identity observer acknowledgment transferred a descriptor")
	}
	if err != nil || ack != request.acknowledgment() {
		return errors.Join(err, errors.New("Darwin identity observer acknowledgment lost its exact parent or capture"))
	}
	return nil
}
