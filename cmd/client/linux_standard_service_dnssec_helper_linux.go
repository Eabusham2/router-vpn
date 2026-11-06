//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/standardengine"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type linuxDNSSECChild struct {
	parentRecord           linuxprocess.Observation
	imageProof             *linuxprocess.SealedImage
	base                   *linuxResolvedHelper
	capture                standardengine.DNSSECCapture
	librarySource, library *os.File
	libraryInfo            os.FileInfo
	libraryPath            string
	expected               bundledNativeFile
	original               context.Context
	cancel                 context.CancelFunc
	watchDone              chan struct{}
	watchErr               error
	mu, closeMu            sync.Mutex
	started, closing       bool
	callbackDone           chan struct{}
}

func startLinuxDNSSECChild(ctx context.Context, root string, capture standardengine.DNSSECCapture) (*linuxDNSSECChild, error) {
	h := &linuxResolvedHelper{original: ctx, closedFiles: make(map[*os.File]bool)}
	c := &linuxDNSSECChild{base: h}
	if ctx == nil || ctx.Err() != nil {
		return c, errors.New("validator child omitted original live operation")
	}
	outer, ok := ctx.Deadline()
	deadline := time.Unix(0, capture.DeadlineNS)
	if !ok || deadline.After(outer) || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Minute {
		return c, errors.New("validator child omitted original bounded deadline")
	}
	raw, err := capture.Canonical()
	if err != nil {
		return c, err
	}
	// Retain only decoded canonical copies; callers cannot mutate an active
	// child request by changing their exported anchor slice after launch.
	c.capture, err = standardengine.DecodeDNSSECCapture(raw, standardengine.SHA256(raw))
	if err != nil {
		return c, err
	}
	c.original, c.cancel = context.WithDeadline(ctx, deadline)
	ctx = c.original
	h.original = ctx
	h.captureSHA = standardengine.SHA256(raw)
	h.sources = &linuxStandardEngine{owner: &linuxLegacyStandardExitOwner{protectionRoot: root}}
	if err = h.sources.captureSources(); err != nil {
		return c, err
	}
	if err = c.captureLibrary(); err != nil {
		return c, err
	}
	if err = h.sources.verifySources(ctx, verifyBundledNativeContext); err != nil {
		return c, err
	}
	h.image, err = sealLegacyExitFile("resolved-original-image", h.sources.imageSource, bundledNativeMaxBytes)
	if err != nil {
		return c, err
	}
	bytes, err := standardengine.ReadSealed(h.image, bundledNativeMaxBytes)
	if err != nil || int64(len(bytes)) != h.sources.imageExpected.Size || standardengine.SHA256(bytes) != h.sources.imageExpected.SHA256 {
		return c, errors.New("resolved helper image differs from original verified catalog")
	}
	image, err := linuxprocess.CaptureSealedImage(h.image)
	c.imageProof = image
	if err != nil {
		return c, err
	}
	// Shipping initialization loads Cronet before fixed-command dispatch.
	// Preserve the original verified library through the same sealed FD ABI
	// as the standard engine; a memfd image has no ambient sibling library.
	h.sources.library, err = sealLegacyExitFile("resolved-original-library", h.sources.librarySource, 128<<20)
	if err != nil {
		return c, err
	}
	if err = standardengine.VerifyLibrary(h.sources.library, h.sources.libraryExpected.Size, h.sources.libraryExpected.SHA256); err != nil {
		return c, err
	}
	h.capture, err = sealLegacyExitFile("resolved-original-capture", strings.NewReader(string(raw)), standardengine.MaxDNSSECCapture)
	if err != nil {
		return c, err
	}
	h.padding, err = os.Open("/dev/null")
	if err != nil {
		return c, err
	}
	h.parent, err = linuxprocess.CaptureSelf(ctx)
	if err != nil {
		return c, err
	}
	c.parentRecord, err = h.parent.Current(ctx)
	if err != nil {
		return c, err
	}
	h.parentDirectory, err = h.parent.DuplicateDirectory(ctx)
	if err != nil {
		return c, err
	}
	h.channel, h.childChannel, err = linuxprocess.ChannelPair()
	if err != nil {
		return c, err
	}
	if err = h.sources.sourcesCurrent(); err != nil {
		return c, err
	}
	if err = c.libraryCurrent(); err != nil {
		return c, err
	}
	pidfd := -1
	h.command = exec.Command("/proc/self/fd/3", "routervpn-dnssec-validate", "--capture-sha256", h.captureSHA)
	h.command.Env = h.sources.environment([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"})
	h.command.ExtraFiles = []*os.File{h.image, h.padding, h.padding, h.sources.library, h.childChannel, h.parentDirectory, h.capture, c.library}
	h.command.Stdout, h.command.Stderr = io.Discard, io.Discard
	h.command.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err = h.command.Start(); err != nil {
		return c, err
	}
	h.joined = make(chan struct{})
	go func() { h.waitErr = h.command.Wait(); close(h.joined) }()
	if pidfd < 0 {
		return c, errors.New("resolved child omitted original creation pidfd")
	}
	h.pidfd = os.NewFile(uintptr(pidfd), "resolved-original-creation-pidfd")
	c.watchDone = make(chan struct{})
	go c.watchOriginal()
	duplicate, _, errno := syscall.Syscall(syscall.SYS_FCNTL, h.pidfd.Fd(), 1030, 0)
	var duplicateErr error
	if errno != 0 {
		duplicateErr = errno
	}
	err = duplicateErr
	if err != nil {
		return c, err
	}
	h.peer, err = linuxprocess.BindCreatedSealedChild(ctx, h.channel, h.parent, os.NewFile(uintptr(duplicate), "resolved-bootstrap-creation-pidfd"), h.command.Process.Pid, image, h.captureSHA)
	h.channel = nil // The partial bootstrap owns the channel and duplicate.
	if err != nil {
		return c, err
	}
	for _, f := range []*os.File{h.childChannel, h.parentDirectory} {
		if err = h.closeFile(f); err != nil {
			return c, err
		}
	}
	return c, nil
}
func (c *linuxDNSSECChild) captureLibrary() error {
	raw, err := io.ReadAll(io.NewSectionReader(c.base.sources.manifest, 0, 32769))
	if err != nil {
		return err
	}
	receipt, err := validateNativeReceipt(raw)
	if err != nil || standardengine.SHA256(raw) != c.base.sources.manifestSHA {
		return errors.New("validator catalog changed after original capture")
	}
	c.expected = receipt.Files[bundledDNSSECLibrary]
	if c.expected.Size < 1 || c.expected.Size > 32<<20 {
		return errors.New("original catalog omitted bounded validator")
	}
	c.libraryPath = filepath.Join(filepath.Dir(c.base.sources.imagePath), bundledDNSSECLibrary)
	c.librarySource, err = openLinuxStandardSource(c.libraryPath)
	if err != nil {
		return err
	}
	c.libraryInfo, err = c.librarySource.Stat()
	if err != nil {
		return err
	}
	if err = c.libraryCurrent(); err != nil {
		return err
	}
	c.library, err = sealLegacyExitFile("original-dnssec-validator", c.librarySource, 32<<20)
	if err != nil {
		return err
	}
	if err = standardengine.VerifyLibrary(c.library, c.expected.Size, c.expected.SHA256); err != nil {
		return err
	}
	return c.libraryCurrent()
}
func (c *linuxDNSSECChild) libraryCurrent() error {
	if c == nil || c.librarySource == nil || c.libraryInfo == nil {
		return errors.New("validator source owner absent")
	}
	opened, err := c.librarySource.Stat()
	named, namedErr := os.Lstat(c.libraryPath)
	if err != nil || namedErr != nil || !ownedDesktopInfo(opened) || !ownedDesktopInfo(named) || !os.SameFile(opened, c.libraryInfo) || !os.SameFile(named, c.libraryInfo) || opened.Size() != c.libraryInfo.Size() {
		return errors.New("validator original source was replaced")
	}
	before, ok := c.libraryInfo.Sys().(*syscall.Stat_t)
	after, valid := opened.Sys().(*syscall.Stat_t)
	if !ok || !valid || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return errors.New("validator original source changed in place")
	}
	return nil
}
func dnssecKillOriginal(file *os.File) error {
	if file == nil || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("validator original pidfd unavailable")
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var failure error
	err = conn.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(424, fd, uintptr(syscall.SIGKILL), 0, 0, 0, 0)
		if errno != 0 && errno != syscall.ESRCH {
			failure = errno
		}
	})
	return errors.Join(err, failure)
}
func (c *linuxDNSSECChild) watchOriginal() {
	defer close(c.watchDone)
	select {
	case <-c.base.joined:
		return
	case <-c.original.Done():
	}
	// SIGTERM cannot bound a C call which ignores cancellation. The retained
	// creation pidfd names only this original child, never a reused numeric PID.
	c.watchErr = dnssecKillOriginal(c.base.pidfd)
}
func (c *linuxDNSSECChild) current(ctx context.Context) error {
	if c == nil || c.original == nil || c.original.Err() != nil {
		return errors.New("validator original operation retired")
	}
	if err := c.libraryCurrent(); err != nil {
		return err
	}
	return c.base.current(ctx)
}
func (c *linuxDNSSECChild) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	if err := desktopnetwork.LockContext(ctx, &c.closeMu); err != nil {
		return err
	}
	defer c.closeMu.Unlock()
	if c.watchDone != nil {
		select {
		case <-c.watchDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if c.watchErr != nil {
		return c.watchErr
	}
	if c.base.joined != nil {
		select {
		case <-c.base.joined:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	callback := c.callbackDone
	c.mu.Unlock()
	if callback != nil {
		select {
		case <-callback:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := c.base.Close(ctx); err != nil {
		return err
	}
	for _, f := range []*os.File{c.library, c.librarySource} {
		if err := c.base.closeFile(f); err != nil {
			return err
		}
	}
	return nil
}
func (c *linuxDNSSECChild) Validate(ctx context.Context, exchange func(context.Context, standardengine.DNSSECQuery) ([]byte, error)) (verdict standardengine.DNSSECVerdict, failure error) {
	if c == nil || exchange == nil {
		return verdict, errors.New("validator omitted original physical query broker")
	}
	if err := desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		return verdict, err
	}
	if c.started || c.closing {
		c.mu.Unlock()
		return verdict, errors.New("validator child already consumed its original request")
	}
	c.started = true
	c.mu.Unlock()
	if c.original == nil {
		return verdict, errors.New("validator original context absent")
	}
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.original, cancel)
	defer func() { stop(); cancel() }()
	ctx = operation
	defer func() {
		cleanup, finish := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
		defer finish()
		failure = errors.Join(failure, c.Close(cleanup))
		if failure != nil {
			verdict = standardengine.DNSSECVerdict{}
		}
	}()
	if err := c.current(ctx); err != nil {
		return verdict, err
	}
	total := 0
	for sequence := uint32(1); sequence <= standardengine.MaxDNSSECQueries+1; sequence++ {
		var frames [][]byte
		kind := ""
		for i := uint32(0); i < 8; i++ {
			raw, err := c.base.peer.Receive(ctx)
			if err != nil {
				return verdict, err
			}
			frame, err := standardengine.DecodeDNSSECFrame(raw)
			if err != nil {
				return verdict, err
			}
			if i == 0 {
				kind = frame.Kind
			}
			if frame.CaptureSHA256 != c.base.captureSHA || frame.Sequence != sequence || frame.Kind != kind || frame.Part != i || kind != "query" && kind != "verdict" {
				return verdict, errors.New("validator child changed original stream identity")
			}
			frames = append(frames, raw)
			if i+1 == frame.Parts {
				break
			}
		}
		message, err := standardengine.DecodeDNSSECFrames(frames, c.base.captureSHA, sequence, kind)
		if err != nil {
			return verdict, err
		}
		if kind == "verdict" {
			receipt, err := standardengine.DNSSECTerminalReceipt(c.base.captureSHA, sequence, frames)
			if err != nil {
				return verdict, err
			}
			// A successful exact child exit proves the authenticated receipt was read.
			// Send's post-frame liveness check may observe that intended natural exit.
			receiptWritten, receiptErr := c.base.peer.SendTerminalReceipt(ctx, receipt)
			if !receiptWritten {
				return verdict, errors.Join(errors.New("validator terminal receipt was not fully written"), receiptErr)
			}

			select {
			case <-c.base.joined:
			case <-ctx.Done():
				return verdict, ctx.Err()
			}
			if c.base.waitErr != nil {
				return verdict, errors.Join(c.base.waitErr, receiptErr)
			}
			actualParent, parentErr := c.base.parent.Current(ctx)
			if parentErr != nil || actualParent != c.parentRecord {
				return verdict, errors.Join(errors.New("validator terminal join lost original parent witness"), parentErr)
			}
			if err = c.imageProof.Current(); err != nil {
				return verdict, err
			}
			if err = c.libraryCurrent(); err != nil {
				return verdict, err
			}
			if err = c.base.sources.sourcesCurrent(); err != nil {
				return verdict, err
			}
			return message, errors.Join(ctx.Err(), c.original.Err())
		}
		if err = c.current(ctx); err != nil {
			return verdict, err
		}
		if err = common.ValidateDNSForwardQuery(message.Packet); err != nil {
			return verdict, err
		}
		if _, err = c.capture.Question(message.Packet); err != nil {
			return verdict, err
		}
		total += len(message.Packet)
		if total > standardengine.MaxDNSSECExchangeBytes {
			return verdict, errors.New("validator original broker byte budget exhausted")
		}
		request := standardengine.DNSSECQuery{CaptureSHA256: c.base.captureSHA, PlanSHA256: c.capture.PlanSHA256, Name: c.capture.Name, Type: c.capture.Type, Sequence: sequence, Packet: append([]byte(nil), message.Packet...)}
		type response struct {
			packet []byte
			err    error
		}
		answer := make(chan response, 1)
		joined := make(chan struct{})
		c.mu.Lock()
		if c.closing || c.original.Err() != nil {
			c.mu.Unlock()
			return verdict, errors.New("validator retired before physical callback admission")
		}
		c.callbackDone = joined
		c.mu.Unlock()
		go func() { defer close(joined); packet, err := exchange(ctx, request); answer <- response{packet, err} }()
		var result response
		select {
		case result = <-answer:
		case <-ctx.Done():
			return verdict, ctx.Err()
		}
		<-joined
		if result.err != nil {
			return verdict, result.err
		}
		if err = c.current(ctx); err != nil {
			return verdict, err
		}
		if err = common.ValidateDNSForwardResponse(message.Packet, result.packet); err != nil {
			return verdict, err
		}
		total += len(result.packet)
		if total > standardengine.MaxDNSSECExchangeBytes {
			return verdict, errors.New("validator original broker answer budget exhausted")
		}
		frames, err = standardengine.BuildDNSSECFrames(c.base.captureSHA, sequence, "reply", standardengine.DNSSECVerdict{Packet: result.packet})
		if err != nil {
			return verdict, err
		}
		for _, frame := range frames {
			if err = c.base.peer.Send(ctx, frame); err != nil {
				return verdict, err
			}
		}
	}
	return verdict, errors.New("validator exhausted original query budget without joined verdict")
}
