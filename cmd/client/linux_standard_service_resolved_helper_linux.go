//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"router-vpn/internal/desktopnetwork"
	"strings"
	"sync"
	"syscall"
	"time"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/standardengine"
	"runtime"
)

// This owner launches only the installed fixed resolver command. A decoded
// policy never recreates its process, authenticated channel or daemon owner.
// Callers retain the partial owner on every error and join Close before retry.
type linuxResolvedHelper struct {
	mu                                                            sync.Mutex
	failure                                                       error
	sources                                                       *linuxStandardEngine
	image, capture, padding, parentDirectory, childChannel, pidfd *os.File
	parent                                                        *linuxprocess.Witness
	channel                                                       *linuxprocess.Channel
	peer                                                          *linuxprocess.Bootstrap
	command                                                       *exec.Cmd
	joined                                                        chan struct{}
	waitErr                                                       error
	name, captureSHA                                              string
	original                                                      context.Context
	retainedCancel                                                context.CancelFunc
	request                                                       context.Context
	stopCancellation                                              func() bool
	cancellationJoined                                            chan struct{}
	sequence                                                      uint32
	policy                                                        []byte
	closedFiles                                                   map[*os.File]bool
	closed                                                        bool
}

func startLinuxResolvedHelper(ctx context.Context, root, session, name string) (*linuxResolvedHelper, error) {
	h := &linuxResolvedHelper{original: ctx, name: name, closedFiles: make(map[*os.File]bool)}
	if ctx == nil || ctx.Err() != nil {
		return h, errors.New("resolved helper needs original live operation")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Minute {
		return h, errors.New("resolved helper requires its original bounded deadline")
	}
	// Bridge request cancellation before any image/process proof begins. Only
	// an explicitly accepted completed lookup may detach this bridge.
	h.request = ctx
	h.original, h.retainedCancel = context.WithDeadline(context.WithoutCancel(ctx), deadline)
	h.cancellationJoined = make(chan struct{})
	h.stopCancellation = context.AfterFunc(ctx, func() {
		h.retainedCancel()
		close(h.cancellationJoined)
	})
	raw, err := (standardengine.ResolvedCapture{Schema: 1, Session: session, DeadlineNS: deadline.UnixNano(), Name: name}).Canonical()
	if err != nil {
		return h, err
	}
	h.captureSHA = standardengine.SHA256(raw)
	h.sources = &linuxStandardEngine{owner: &linuxLegacyStandardExitOwner{protectionRoot: root}}
	if err = h.sources.captureSources(); err != nil {
		return h, err
	}
	if err = h.sources.verifySources(ctx, verifyBundledNativeContext); err != nil {
		return h, err
	}
	h.image, err = sealLegacyExitFile("resolved-original-image", h.sources.imageSource, bundledNativeMaxBytes)
	if err != nil {
		return h, err
	}
	bytes, err := standardengine.ReadSealed(h.image, bundledNativeMaxBytes)
	if err != nil || int64(len(bytes)) != h.sources.imageExpected.Size || standardengine.SHA256(bytes) != h.sources.imageExpected.SHA256 {
		return h, errors.New("resolved helper image differs from original verified catalog")
	}
	image, err := linuxprocess.CaptureSealedImage(h.image)
	if err != nil {
		return h, err
	}
	// Shipping initialization loads Cronet before fixed-command dispatch.
	// Preserve the original verified library through the same sealed FD ABI
	// as the standard engine; a memfd image has no ambient sibling library.
	h.sources.library, err = sealLegacyExitFile("resolved-original-library", h.sources.librarySource, 128<<20)
	if err != nil {
		return h, err
	}
	if err = standardengine.VerifyLibrary(h.sources.library, h.sources.libraryExpected.Size, h.sources.libraryExpected.SHA256); err != nil {
		return h, err
	}
	h.capture, err = sealLegacyExitFile("resolved-original-capture", strings.NewReader(string(raw)), 2048)
	if err != nil {
		return h, err
	}
	h.padding, err = os.Open("/dev/null")
	if err != nil {
		return h, err
	}
	h.parent, err = linuxprocess.CaptureSelf(ctx)
	if err != nil {
		return h, err
	}
	h.parentDirectory, err = h.parent.DuplicateDirectory(ctx)
	if err != nil {
		return h, err
	}
	h.channel, h.childChannel, err = linuxprocess.ChannelPair()
	if err != nil {
		return h, err
	}
	if err = h.sources.sourcesCurrent(); err != nil {
		return h, err
	}
	pidfd := -1
	h.command = exec.Command("/proc/self/fd/3", "routervpn-resolved-policy", "--capture-sha256", h.captureSHA)
	h.command.Env = h.sources.environment([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
	h.command.ExtraFiles = []*os.File{h.image, h.padding, h.padding, h.sources.library, h.childChannel, h.parentDirectory, h.capture}
	h.command.Stdout, h.command.Stderr = io.Discard, io.Discard
	h.command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err = h.command.Start(); err != nil {
		return h, err
	}
	h.joined = make(chan struct{})
	go func() { h.waitErr = h.command.Wait(); close(h.joined) }()
	if pidfd < 0 {
		return h, errors.New("resolved child omitted original creation pidfd")
	}
	h.pidfd = os.NewFile(uintptr(pidfd), "resolved-original-creation-pidfd")
	duplicate, _, errno := syscall.Syscall(syscall.SYS_FCNTL, h.pidfd.Fd(), 1030, 0)
	var duplicateErr error
	if errno != 0 {
		duplicateErr = errno
	}
	err = duplicateErr
	if err != nil {
		return h, err
	}
	h.peer, err = linuxprocess.BindCreatedSealedChild(ctx, h.channel, h.parent, os.NewFile(uintptr(duplicate), "resolved-bootstrap-creation-pidfd"), h.command.Process.Pid, image, h.captureSHA)
	h.channel = nil // The partial bootstrap owns the channel and duplicate.
	if err != nil {
		return h, err
	}
	for _, f := range []*os.File{h.childChannel, h.parentDirectory} {
		if err = h.closeFile(f); err != nil {
			return h, err
		}
	}
	return h, nil
}

// retainCompleted transfers only the read-only observation owner from a
// successful RPC to its already captured transaction deadline. The cancellation
// bridge was installed before source verification or child creation.
func (h *linuxResolvedHelper) retainCompleted(ctx context.Context) error {
	if h == nil {
		return errors.New("resolved helper absent")
	}
	if err := desktopnetwork.LockContext(ctx, &h.mu); err != nil {
		return err
	}
	defer h.mu.Unlock()
	if err := h.currentLocked(ctx); err != nil {
		return err
	}
	return h.retainObservationLifetime(ctx)
}
func (h *linuxResolvedHelper) retainObservationLifetime(ctx context.Context) error {
	if h.request == nil || h.stopCancellation == nil || h.request.Err() != nil {
		return errors.New("resolved observation handoff lost original request")
	}
	if !h.stopCancellation() {
		select {
		case <-h.cancellationJoined:
		case <-ctx.Done():
			return ctx.Err()
		}
		return errors.New("resolved observation cancelled before completed handoff")
	}
	h.stopCancellation = nil
	if h.request.Err() != nil || h.original.Err() != nil {
		h.retainedCancel()
		return errors.New("resolved observation cancelled during completed handoff")
	}
	return nil
}

func (h *linuxResolvedHelper) current(ctx context.Context) error {
	if h == nil {
		return errors.New("resolved helper absent")
	}
	if err := desktopnetwork.LockContext(ctx, &h.mu); err != nil {
		return err
	}
	defer h.mu.Unlock()
	return h.currentLocked(ctx)
}
func (h *linuxResolvedHelper) currentLocked(ctx context.Context) error {
	if h == nil || h.closed || h.original == nil || h.original.Err() != nil || h.failure != nil || h.peer == nil || h.joined == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("resolved helper lost its original live operation")
	}
	select {
	case <-h.joined:
		return errors.Join(h.waitErr, errors.New("original resolved helper exited"))
	default:
	}
	if err := h.sources.sourcesCurrent(); err != nil {
		return err
	}
	return h.peer.CheckCapture(ctx, h.captureSHA)
}

// observe consumes the original sequence-zero greeting once, then asks that
// same helper to recheck the original daemon, full policy and local-only name.
func (h *linuxResolvedHelper) observe(ctx context.Context, name string) (standardengine.ResolvedPolicy, standardengine.ResolvedLocalResult, error) {
	if h == nil {
		return standardengine.ResolvedPolicy{}, standardengine.ResolvedLocalResult{}, errors.New("resolved helper absent")
	}
	if err := desktopnetwork.LockContext(ctx, &h.mu); err != nil {
		return standardengine.ResolvedPolicy{}, standardengine.ResolvedLocalResult{}, err
	}
	defer h.mu.Unlock()
	policy, local, err := h.readObservation(ctx, name)
	if err != nil && h != nil {
		h.failure = errors.Join(h.failure, err)
	}
	return policy, local, err
}
func (h *linuxResolvedHelper) readObservation(ctx context.Context, name string) (standardengine.ResolvedPolicy, standardengine.ResolvedLocalResult, error) {
	var policy standardengine.ResolvedPolicy
	var local standardengine.ResolvedLocalResult
	if !standardengine.ResolvedName(name, false) {
		return policy, local, errors.New("resolved observation omitted exact question")
	}
	if h != nil && h.policy == nil && name != h.name {
		if _, _, err := h.readObservation(ctx, h.name); err != nil {
			return policy, local, err
		}
	}
	if err := h.currentLocked(ctx); err != nil {
		return policy, local, err
	}
	if h.policy != nil {
		if h.sequence >= 63 {
			return policy, local, errors.New("resolved original observation budget exhausted")
		}
		h.sequence++
		raw, err := (standardengine.ResolvedRequest{Schema: 1, CaptureSHA256: h.captureSHA, Sequence: h.sequence, Action: "observe", Name: name}).Canonical()
		if err != nil {
			return policy, local, err
		}
		if err = h.peer.Send(ctx, raw); err != nil {
			return policy, local, err
		}
	}
	var frames [][]byte
	for i := uint32(0); ; i++ {
		raw, err := h.peer.Receive(ctx)
		if err != nil {
			return policy, local, err
		}
		var frame standardengine.ResolvedFrame
		if len(raw) > 12<<10 || json.Unmarshal(raw, &frame) != nil || frame.Parts == 0 || frame.Parts > 35 || frame.Part != i {
			return policy, local, errors.New("resolved helper omitted bounded ordered whole observation")
		}
		frames = append(frames, raw)
		if i+1 == frame.Parts {
			break
		}
		if i >= 34 {
			return policy, local, errors.New("resolved helper exceeded original frame budget")
		}
	}
	observation, err := standardengine.DecodeResolvedFrames(frames, h.captureSHA, h.sequence, name)
	if err != nil {
		return policy, local, err
	}
	if h.policy != nil && string(h.policy) != string(observation.Policy) {
		return policy, local, errors.New("original resolved daemon policy changed")
	}
	policy, err = standardengine.DecodeResolvedPolicy(observation.Policy, standardengine.SHA256(observation.Policy))
	if err != nil {
		return policy, local, err
	}
	local, err = standardengine.DecodeResolvedLocal(observation.Local, standardengine.SHA256(observation.Policy), name)
	if err != nil {
		return policy, local, err
	}
	if err = h.currentLocked(ctx); err != nil {
		return policy, local, err
	}
	if h.policy == nil {
		h.policy = append([]byte(nil), observation.Policy...)
	}
	return policy, local, nil
}

func (h *linuxResolvedHelper) closeFile(f *os.File) error {
	if f == nil || h.closedFiles[f] {
		return nil
	}
	if err := f.Close(); err != nil {
		return err
	}
	h.closedFiles[f] = true
	return nil
}

func (h *linuxResolvedHelper) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if err := desktopnetwork.LockContext(ctx, &h.mu); err != nil {
		return err
	}
	defer h.mu.Unlock()
	return h.closeLocked(ctx)
}
func (h *linuxResolvedHelper) closeLocked(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("resolved retirement requires bounded caller")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("resolved retirement omitted deadline")
	}
	// An authenticated close requests joined daemon/channel retirement. A
	// cancellation or partial handshake still retains the original child below.
	if h.policy != nil && h.failure == nil && h.original.Err() == nil && h.sequence < 64 {
		h.sequence++
		raw, err := (standardengine.ResolvedRequest{Schema: 1, CaptureSHA256: h.captureSHA, Sequence: h.sequence, Action: "close"}).Canonical()
		if err != nil {
			return err
		}
		if err = h.peer.Send(ctx, raw); err == nil {
			select {
			case <-h.joined:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	// Close is read-only retirement. Use only the retained creation pidfd, never
	// a numeric PID; even a failed authentication leaves this child to join.
	if h.joined != nil {
		select {
		case <-h.joined:
		default:
			if h.pidfd == nil {
				return errors.New("resolved retirement lost creation pidfd")
			}
			if err := resolvedSignalOriginal(h.pidfd); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
			select {
			case <-h.joined:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if h.peer != nil {
		if err := h.peer.Close(ctx); err != nil {
			return err
		}
	}
	if h.channel != nil {
		if err := h.channel.Close(ctx); err != nil {
			return err
		}
	}
	if h.parent != nil {
		if err := h.parent.Close(ctx); err != nil {
			return err
		}
	}
	files := []*os.File{h.image, h.capture, h.padding, h.parentDirectory, h.childChannel, h.pidfd}
	if h.sources != nil {
		files = append(files, h.sources.manifest, h.sources.imageSource, h.sources.librarySource, h.sources.library)
	}
	for _, f := range files {
		if err := h.closeFile(f); err != nil {
			return err
		}
	}
	// This fixed helper owns no persistent native mutation. The exact join
	// proves its process-local observers/descriptors are gone; waitErr remains
	// diagnostic and never repairs a failed observation. Mutating engines do
	// not use this retirement rule.
	if h.stopCancellation != nil && !h.stopCancellation() {
		select {
		case <-h.cancellationJoined:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if h.retainedCancel != nil {
		h.retainedCancel()
	}
	h.closed = true
	return nil
}

func resolvedSignalOriginal(file *os.File) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("resolved helper has no validated pidfd signal ABI")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var signalErr error
	err = raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(424, fd, uintptr(syscall.SIGTERM), 0, 0, 0, 0)
		if errno != 0 {
			signalErr = errno
		}
	})
	return errors.Join(err, signalErr)
}

// anchor returns a loaded trust-store observation from the same live helper.
// It does not itself validate any upstream DNSSEC chain.
func (h *linuxResolvedHelper) anchor(ctx context.Context, index int32, name string, kind uint16) (result standardengine.ResolvedAnchorResult, failure error) {
	if h == nil {
		return result, errors.New("resolved helper absent")
	}
	if err := desktopnetwork.LockContext(ctx, &h.mu); err != nil {
		return result, err
	}
	defer h.mu.Unlock()
	defer func() {
		if failure != nil && h != nil {
			h.failure = errors.Join(h.failure, failure)
		}
	}()
	if err := h.currentLocked(ctx); err != nil {
		return result, err
	}
	if h.policy == nil {
		if _, _, err := h.readObservation(ctx, h.name); err != nil {
			return result, err
		}
	}
	if h.sequence >= 63 {
		return result, errors.New("resolved original anchor observation budget exhausted")
	}
	h.sequence++
	raw, err := (standardengine.ResolvedRequest{Schema: 1, CaptureSHA256: h.captureSHA, Sequence: h.sequence, Action: "anchor", Name: name, Index: index, Type: kind}).Canonical()
	if err != nil {
		return result, err
	}
	if err = h.peer.Send(ctx, raw); err != nil {
		return result, err
	}
	var frames [][]byte
	for i := uint32(0); ; i++ {
		raw, err := h.peer.Receive(ctx)
		if err != nil {
			return result, err
		}
		var frame standardengine.ResolvedFrame
		if len(raw) > 12<<10 || json.Unmarshal(raw, &frame) != nil || frame.Parts == 0 || frame.Parts > 8 || frame.Part != i {
			return result, errors.New("resolved anchor lost bounded ordered frames")
		}
		frames = append(frames, raw)
		if i+1 == frame.Parts {
			break
		}
		if i >= 7 {
			return result, errors.New("resolved anchor exceeded frame budget")
		}
	}
	result, err = standardengine.DecodeResolvedAnchorFrames(frames, h.captureSHA, h.sequence, standardengine.SHA256(h.policy), index, name, kind)
	if err != nil {
		return result, err
	}
	return result, h.currentLocked(ctx)
}
