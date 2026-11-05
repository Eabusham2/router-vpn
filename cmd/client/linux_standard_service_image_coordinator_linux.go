//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"router-vpn/internal/linuxprocess"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type linuxStandardImageCoordinator struct {
	caller                           *linuxStandardServicePeer
	admittedDeadline                 int64
	cleanupDeadline, proposedCleanup int64
	removed                          bool
	root                             string
	old, next                        *linuxStandardImageClient
	source                           *os.File
	self                             *linuxprocess.Witness
	selfPIDFD                        *os.File
	envelope                         *linuxStandardImageUpgradeEnvelope
	state                            *linuxStandardServiceImageUpgradeResponse
	sequence                         uint64
	last                             []byte
	reply                            *linuxStandardImageUpgradeControlReply
}

func linuxStandardImageWriteFiles(c *net.UnixConn, value any, files []*os.File) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > linuxStandardServicePacketLimit {
		return errors.Join(err, errors.New("image control reply exceeded bound"))
	}
	fds := make([]int, 0, len(files))
	for _, f := range files {
		if f == nil {
			return errors.New("image reply omitted original descriptor")
		}
		fds = append(fds, int(f.Fd()))
	}
	var rights []byte
	if len(fds) > 0 {
		rights = syscall.UnixRights(fds...)
	}
	n, a, err := c.WriteMsgUnix(body, rights, nil)
	if err == nil && (n != len(body) || a != len(rights)) {
		err = errors.New("image control reply was incomplete")
	}
	return err
}
func (r *linuxStandardImageCoordinator) rpc(ctx context.Context, client *linuxStandardImageClient, action string, destination bool) (*linuxStandardServiceImageUpgradeResponse, error) {
	q := &linuxStandardServiceImageUpgradeRequest{Envelope: r.envelope}
	if r.state != nil {
		q.CleanupDeadlineNS = r.cleanupDeadline
		if q.CleanupDeadlineNS == 0 {
			q.CleanupDeadlineNS = r.proposedCleanup
		}
		if destination {
			q.Destination = r.state.Destination
		}
	}
	reply, file, err := client.call(ctx, "image-"+action, r.envelope.ID, q)
	if file != nil {
		file.Close()
		return nil, errors.New("coordinator received unrelated owner descriptor")
	}
	if reply != nil {
		if !reflectImageEnvelope(reply.Envelope, *r.envelope) {
			return nil, errors.New("image service replaced original envelope")
		}
		if reply.CleanupDeadlineNS != 0 {
			if r.cleanupDeadline != 0 && reply.CleanupDeadlineNS != r.cleanupDeadline {
				return nil, errors.New("service changed original accepted cleanup clock")
			}
			r.cleanupDeadline = reply.CleanupDeadlineNS
		}
		r.removed = r.removed || reply.SourceRemoved
		reply.SourceRemoved = r.removed
		reply.CleanupDeadlineNS = r.cleanupDeadline
		r.state = reply
	}
	return reply, err
}
func reflectImageEnvelope(a, b linuxStandardImageUpgradeEnvelope) bool {
	return linuxStandardImageDigest(a) == linuxStandardImageDigest(b)
}
func (r *linuxStandardImageCoordinator) action(ctx context.Context, q linuxStandardImageUpgradeControl) (*linuxStandardServiceImageUpgradeResponse, error) {
	if q.Action == "prepare" {
		if r.envelope != nil || q.NewGeneration == nil || q.Envelope != nil || q.CleanupDeadlineNS != 0 || q.DeadlineNS <= time.Now().UnixNano() || time.Until(time.Unix(0, q.DeadlineNS)) > linuxStandardImageUpgradeWorkLimit {
			return nil, errors.New("image prepare changed original staged admission")
		}
		next, err := captureLinuxStandardServiceGenerationSelection(ctx, r.root, *q.NewGeneration)
		if err != nil {
			return nil, err
		}
		r.next = &linuxStandardImageClient{generation: next, namespace: r.old.namespace}
		r.admittedDeadline = q.DeadlineNS
		reply, file, err := r.old.call(ctx, "image-prepare", q.NewGeneration.Generation[:32], &linuxStandardServiceImageUpgradeRequest{Generation: q.NewGeneration, DeadlineNS: q.DeadlineNS})
		if file != nil {
			file.Close()
			return nil, errors.New("prepare transferred unexpected authority")
		}
		if reply != nil {
			r.envelope = &reply.Envelope
			r.state = reply
		}
		return reply, err
	}
	recovered := false
	if r.envelope == nil && r.next != nil && r.admittedDeadline == q.DeadlineNS && (q.Action == "status" || q.Action == "abort") {
		reply, file, err := r.old.call(ctx, "image-reservation", r.next.generation.selection.Generation[:32], &linuxStandardServiceImageUpgradeRequest{Generation: &r.next.generation.selection, DeadlineNS: r.admittedDeadline})
		if file != nil {
			file.Close()
			return nil, errors.New("reservation lookup supplied authority")
		}
		if err != nil {
			return nil, err
		}
		r.envelope = &reply.Envelope
		r.state = reply
		recovered = true
	}
	if r.envelope == nil || !recovered && (q.Envelope == nil || !reflectImageEnvelope(*q.Envelope, *r.envelope)) || q.NewGeneration != nil || q.DeadlineNS != r.envelope.DeadlineNS {
		return r.state, errors.New("control changed original image operation")
	}
	if q.Action == "status" {
		if r.old.peer != nil {
			dead, err := r.old.peer.Retired()
			if err != nil {
				return r.state, err
			}
			if dead {
				return r.rpc(ctx, r.next, "status", false)
			}
		}
		return r.rpc(ctx, r.old, "status", false)
	}
	var result *linuxStandardServiceImageUpgradeResponse
	var err error
	if q.CleanupDeadlineNS != 0 {
		if r.cleanupDeadline != 0 && q.CleanupDeadlineNS != r.cleanupDeadline {
			return r.state, errors.New("control attempted cleanup clock renewal")
		}
		r.proposedCleanup = q.CleanupDeadlineNS
	}

	if q.Action != "abort" && q.Action != "code-restored" && time.Now().UnixNano() >= r.envelope.DeadlineNS && r.state.SourceRemoved && r.cleanupDeadline == 0 {
		dead, e := r.old.peer.Retired()
		if e != nil {
			return r.state, e
		}
		if !dead {
			if _, e = r.rpc(ctx, r.old, "cleanup", false); e != nil {
				return r.state, e
			}
		} else {
			d, ok := ctx.Deadline()
			if !ok {
				return r.state, errors.New("joined source cleanup omitted original bound")
			}
			r.cleanupDeadline = d.UnixNano()
			r.state.CleanupDeadlineNS = r.cleanupDeadline
		}
	}
	switch q.Action {
	case "successor-started":
		result, err = linuxStandardImageWaitForListener(ctx, func() (*linuxStandardServiceImageUpgradeResponse, error) {
			if e := r.old.peer.Current(ctx); e != nil {
				return nil, e
			}
			return r.rpc(ctx, r.next, "successor-started", false)
		})
		if err == nil {
			result, err = r.rpc(ctx, r.old, "successor-started", true)
		}
	case "freeze":
		result, err = r.rpc(ctx, r.next, "freeze", false)
		if err == nil {
			result, err = r.rpc(ctx, r.old, "freeze", false)
		}
		if err == nil && r.source != nil {
			err = r.source.Close()
			if err == nil {
				r.source = nil
			}
		}
	case "code-promoted":
		result, err = r.rpc(ctx, r.next, "code-promoted", false)
		if err == nil {
			result, err = r.rpc(ctx, r.old, "code-promoted", false)
		}
	case "commit":
		result, err = r.rpc(ctx, r.old, "commit", false)
		if err == nil {
			result, err = r.rpc(ctx, r.next, "commit", false)
		}
	case "activation-published":
		result, err = r.rpc(ctx, r.next, "activation-published", false)
	case "settle":
		dead := false
		if r.old.peer != nil {
			dead, err = r.old.peer.Retired()
		}
		if err != nil {
			break
		}
		if !dead {
			_, err = r.rpc(ctx, r.old, "settle", false)
			if err != nil {
				dead, _ = r.old.peer.Retired()
				if !dead {
					break
				}
			}
		}
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !dead {
			dead, err = r.old.peer.Retired()
			if err != nil {
				break
			}
			if !dead {
				select {
				case <-ctx.Done():
					err = ctx.Err()
				case <-ticker.C:
				}
				if err != nil {
					break
				}
			}
		}
		if err == nil {
			result, err = r.rpc(ctx, r.next, "settle", false)
		}
	case "abort":
		if r.removed {
			dead, e := r.old.peer.Retired()
			if e != nil {
				return r.state, e
			}
			if dead {
				return r.rpc(ctx, r.next, "status", false)
			}
		}
		result, err = r.rpc(ctx, r.old, "abort", false)
		if err == nil && !r.removed && (r.next.peer != nil || result != nil && result.NewPeer != nil) {
			result, err = r.rpc(ctx, r.next, "abort", false)
		}
		if err == nil && r.source != nil {
			err = r.source.Close()
			if err == nil {
				r.source = nil
			}
		}
	case "code-restored":
		if r.next.peer != nil {
			dead, e := r.next.peer.Retired()
			if e != nil {
				return r.state, e
			}
			if !dead {
				result, err = r.rpc(ctx, r.next, "code-restored", false)
			}
		}
		if err == nil {
			result, err = r.rpc(ctx, r.old, "code-restored", false)
		}
	default:
		err = errors.New("image installer action is unavailable")
	}
	if result == nil {
		result = r.state
	}
	return result, err
}
func (r *linuxStandardImageCoordinator) decorate(ctx context.Context, v *linuxStandardServiceImageUpgradeResponse) error {
	if v == nil {
		return nil
	}
	if r.old.peer != nil {
		x := r.old.peer.record
		v.OldPeer = &x
	}
	if r.next != nil && r.next.peer != nil {
		x := r.next.peer.record
		v.NewPeer = &x
	}
	self, err := r.self.Current(ctx)
	if err != nil {
		return err
	}
	v.CoordinatorPeer = &self
	return nil
}
func (r *linuxStandardImageCoordinator) serve(ctx context.Context, c *net.UnixConn) error {
	for {
		body, files, err := linuxStandardServiceRead(c)
		for _, f := range files {
			f.Close()
		}
		if err != nil {
			if r.state != nil && (r.state.Phase == "settled" || r.state.Phase == "aborted") {
				return nil
			}
			return errors.Join(err, errors.New("installer channel ended with original image authority retained"))
		}
		if len(files) != 0 {
			return errors.New("installer supplied unexpected native authority")
		}
		var q linuxStandardImageUpgradeControl
		if err = linuxStandardServiceDecode(body, &q); err != nil {
			return err
		}
		if q.Schema != 1 || q.Sequence == 0 {
			return errors.New("installer control lost canonical sequence")
		}
		duplicate := q.Sequence == r.sequence && bytes.Equal(body, r.last)
		if !duplicate && q.Sequence != r.sequence+1 {
			if err = linuxStandardImageWriteFiles(c, &linuxStandardImageUpgradeControlReply{Schema: 1, Sequence: q.Sequence, Action: q.Action, Error: "installer control replay changed original sequence", Upgrade: r.state}, nil); err != nil {
				return err
			}
			continue
		}
		if !duplicate {
			deadline := q.DeadlineNS
			if q.Action == "status" {
				deadline = time.Now().Add(5 * time.Second).UnixNano()
			}
			if q.Action == "abort" || q.Action == "code-restored" || q.Action != "status" && r.state != nil && r.state.SourceRemoved && (r.cleanupDeadline > 0 || time.Now().UnixNano() >= deadline) {
				deadline = q.CleanupDeadlineNS
				if r.state != nil && r.state.CleanupDeadlineNS != 0 {
					deadline = r.state.CleanupDeadlineNS
				}
				if deadline <= 0 {
					deadline = time.Now().Add(linuxStandardImageUpgradeCleanupLimit).UnixNano()
				}
			}
			call, stop := context.WithDeadline(ctx, time.Unix(0, deadline))
			var result *linuxStandardServiceImageUpgradeResponse
			var failure error
			if r.caller != nil {
				failure = r.caller.Current(call)
			}
			if failure == nil {
				result, failure = r.action(call, q)
			}
			if result != nil {
				failure = errors.Join(failure, r.decorate(call, result))
			}
			stop()
			reply := &linuxStandardImageUpgradeControlReply{Schema: 1, Sequence: q.Sequence, Action: q.Action, Complete: failure == nil, Upgrade: result}
			if failure != nil {
				reply.Error = "original image operation incomplete: " + failure.Error()
				if len(reply.Error) > 2048 {
					reply.Error = "original image operation incomplete"
				}
			}
			r.sequence = q.Sequence
			r.last = append(r.last[:0], body...)
			r.reply = reply
		}
		if duplicate && r.caller != nil {
			observation, stop := context.WithTimeout(ctx, 5*time.Second)
			failure := r.caller.Current(observation)
			stop()
			if failure != nil {
				return failure
			}
		}
		var rights []*os.File
		if r.reply.Complete && q.Action == "freeze" {
			rights = []*os.File{r.old.peer.pidfd, r.next.peer.pidfd, r.selfPIDFD}
		}
		if err = linuxStandardImageWriteFiles(c, r.reply, rights); err != nil {
			return err
		}
	}
}
func linuxStandardServiceImageUpgradeUtility(arguments []string) (bool, error) {
	selected := false
	for _, arg := range arguments {
		if arg == linuxStandardImageUpgradeArgument {
			selected = true
		}
	}
	if !selected {
		return false, nil
	}
	if len(arguments) != 1 || arguments[0] != linuxStandardImageUpgradeArgument || os.Getuid() != 0 || os.Geteuid() != 0 {
		return true, errors.New("image coordinator requires fixed privileged inherited channel")
	}
	file := os.NewFile(3, "original-image-installer-channel")
	if file == nil {
		return true, errors.New("image coordinator omitted original channel")
	}
	raw, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return true, err
	}
	defer raw.Close()
	channel, ok := raw.(*net.UnixConn)
	if !ok {
		return true, errors.New("image coordinator inherited non-Unix channel")
	}
	var credential *syscall.Ucred
	var socketType int
	var nativeErr error
	control, err := channel.SyscallConn()
	if err != nil {
		return true, err
	}
	err = control.Control(func(fd uintptr) {
		credential, nativeErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if nativeErr == nil {
			socketType, nativeErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		}
	})
	if err != nil || nativeErr != nil || credential == nil || credential.Uid != 0 || credential.Gid != 0 || credential.Pid < 1 || socketType != syscall.SOCK_SEQPACKET {
		return true, errors.Join(err, nativeErr, errors.New("image coordinator lost privileged original packet peer"))
	}
	ctx, stop := context.WithTimeout(context.Background(), linuxStandardImageUpgradeWorkLimit)
	defer stop()
	namespace, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return true, err
	}
	// Credentials select only the actual inherited socket peer. Strict capture
	// pins its task/pidfd, image, argv and namespace before any native request.
	parentRoot := "/proc/" + strconv.Itoa(int(credential.Pid))
	parentImage, err := os.Stat(parentRoot + "/exe")
	if err != nil {
		return true, err
	}
	cmd, err := os.Open(parentRoot + "/cmdline")
	if err != nil {
		return true, err
	}
	argv, err := io.ReadAll(io.LimitReader(cmd, 8193))
	cmd.Close()
	if err != nil || len(argv) < 2 || len(argv) > 8192 || argv[len(argv)-1] != 0 {
		return true, errors.Join(err, errors.New("installer original argv unavailable"))
	}
	parent, err := captureLinuxStandardServicePeer(ctx, channel, parentImage, strings.Split(string(argv[:len(argv)-1]), "\x00"), namespace)
	if err != nil {
		return true, err
	}
	defer parent.Close()
	install, err := ownedDesktopLock(linuxOwnedInstallLock, false)
	if err != nil {
		return true, err
	}
	defer install.Close()
	generation, err := captureLinuxStandardServiceGeneration(ctx, linuxOwnedControllerRoot)
	if err != nil || generation == nil {
		return true, errors.Join(err, errors.New("active image coordinator requires original immutable generation"))
	}
	defer generation.Close()
	image, err := os.Stat("/proc/self/exe")
	if err != nil || !os.SameFile(image, generation.imageInfo) {
		return true, errors.Join(err, errors.New("coordinator is not original selected immutable image"))
	}
	self, err := linuxprocess.CaptureSelf(ctx)
	if err != nil {
		return true, err
	}
	defer self.Close(context.Background())
	descriptor, _, errno := syscall.Syscall(434, uintptr(os.Getpid()), 0, 0)
	if errno != 0 {
		return true, errno
	}
	selfPIDFD := os.NewFile(descriptor, "original-image-coordinator")
	syscall.CloseOnExec(int(descriptor))
	defer selfPIDFD.Close()
	coordinator := &linuxStandardImageCoordinator{caller: parent, root: linuxOwnedControllerRoot, old: &linuxStandardImageClient{generation: generation, namespace: namespace}, source: install, self: self, selfPIDFD: selfPIDFD}
	// Work and cleanup stamps belong to typed original requests, not this initial
	// admission observer. The inherited caller remains pinned for the lifetime.
	lifetime, stopLifetime := context.WithCancel(context.Background())
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
			}
			dead, err := parent.Retired()
			if err != nil || dead {
				stopLifetime()
				_ = channel.SetDeadline(time.Now())
				return
			}
		}
	}()
	defer func() { stopLifetime(); <-joined }()
	return true, coordinator.serve(lifetime, channel)
}
