//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/standardengine"
)

// This capability belongs to the service's original stock-protocol engine.
// The generated executable adds an authenticated routing ledger; it does not
// inherit a Router Node guardian, adopt a TUN or reconstruct protection.
type linuxStandardStartupObserver interface {
	linuxStandardNetworkObserver
	Begin(context.Context, *desktopnetwork.DesktopNetworkReceipt) error
	Record(desktopnetwork.DesktopNetworkReceipt) error
	End(context.Context, *desktopnetwork.DesktopNetworkReceipt) error
}

type linuxStandardEngine struct {
	cleanup                                                                               *standardengine.CleanupFile
	operations                                                                            *standardengine.OperationFile
	cleanupSequence                                                                       uint64
	cleanupDeadline                                                                       int64
	cleanupRequests                                                                       map[uint64]int64
	mtuStopOwner                                                                          *linuxStandardServiceMTU
	mtuRetirements                                                                        []desktopnetwork.DesktopNetworkRetirementReceipt
	routingReceipt                                                                        *desktopnetwork.DesktopNetworkReceipt
	readyBody                                                                             []byte
	imageCapability                                                                       *linuxprocess.SealedImage
	owner                                                                                 *linuxLegacyStandardExitOwner
	imagePath, manifestPath, manifestSHA                                                  string
	manifest, imageSource, librarySource, library, capture, parentDirectory, childChannel *os.File
	imageInfo, libraryInfo, manifestInfo                                                  os.FileInfo
	libraryExpected, imageExpected                                                        bundledNativeFile
	parent                                                                                *linuxprocess.Witness
	channel                                                                               *linuxprocess.Channel
	bootstrap                                                                             *linuxprocess.Bootstrap
	tracker                                                                               linuxStandardStartupObserver
	lifetime                                                                              context.Context
	cancel                                                                                context.CancelFunc
	captureSHA                                                                            string
	shape                                                                                 standardengine.TUN
	adopted, ready, closed                                                                bool
	closedFiles                                                                           map[*os.File]bool
}

func (o *linuxLegacyStandardExitOwner) prepareNativeEngine(ctx context.Context) error {
	return o.prepareNativeEngineWithObserver(ctx, func(operation, lifetime context.Context) (linuxStandardStartupObserver, error) {
		return desktopnetwork.OpenWithLifetime(operation, lifetime, nil)
	})
}

// Explicit observer seam for isolated capability tests. Production opens the
// original kernel stream before any version/config-check child or TUN read.
func (o *linuxLegacyStandardExitOwner) prepareNativeEngineWithObserver(ctx context.Context, open func(context.Context, context.Context) (linuxStandardStartupObserver, error)) error {
	n := &linuxStandardEngine{owner: o, closedFiles: make(map[*os.File]bool)}
	o.native = n // Retain every original partial descriptor before another step.
	var err error
	if open == nil {
		return errors.New("standard native preparation has no original kernel observer")
	}
	n.lifetime, n.cancel = context.WithCancel(context.Background())
	n.tracker, err = open(ctx, n.lifetime)
	if err != nil {
		return err
	}
	if n.tracker == nil {
		return errors.New("standard native preparation omitted its retained observer")
	}
	if err = n.captureSources(); err != nil {
		return err
	}
	if err = n.verifySources(ctx, verifyBundledNativeContext); err != nil {
		return err
	}
	n.library, err = sealLegacyExitFile("standard-native-library", n.librarySource, 128<<20)
	if err != nil {
		return err
	}
	if err = standardengine.VerifyLibrary(n.library, n.libraryExpected.Size, n.libraryExpected.SHA256); err != nil {
		return err
	}
	if err = n.sourcesCurrent(); err != nil {
		return err
	}
	return n.tracker.CurrentContext(ctx)
}

// Retain the original catalog and payload objects before the full verifier
// reads them. Supported installer mutation is also excluded by the service's
// lifetime install lease; later sealing uses these exact captured descriptors.
func (n *linuxStandardEngine) captureSources() error {
	directory := filepath.Join(n.owner.protectionRoot, "runtime", "native")
	n.manifestPath = filepath.Join(directory, "NATIVE-RUNTIME.json")
	var err error
	n.manifest, err = openLinuxStandardSource(n.manifestPath)
	if err != nil {
		return err
	}
	n.manifestInfo, err = n.manifest.Stat()
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(n.manifest, 32769))
	if err != nil || len(raw) > 32768 {
		return errors.New("standard engine lost its original native catalog")
	}
	receipt, err := validateNativeReceipt(raw)
	if err != nil {
		return err
	}
	n.manifestSHA = standardengine.SHA256(raw)
	n.imageExpected, n.libraryExpected = receipt.Files[nativeBinaryName()], receipt.Files["libcronet.so"]
	n.imagePath = filepath.Join(directory, nativeBinaryName())
	n.imageSource, err = openLinuxStandardSource(n.imagePath)
	if err != nil {
		return err
	}
	n.imageInfo, err = n.imageSource.Stat()
	if err != nil {
		return err
	}
	n.librarySource, err = openLinuxStandardSource(filepath.Join(directory, "libcronet.so"))
	if err != nil {
		return err
	}
	n.libraryInfo, err = n.librarySource.Stat()
	if err != nil {
		return err
	}
	return n.sourcesCurrent()
}

func openLinuxStandardSource(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (n *linuxStandardEngine) verifySources(ctx context.Context, verify func(context.Context, string) (string, error)) error {
	if err := n.sourcesCurrent(); err != nil {
		return err
	}
	verified, err := verify(ctx, n.owner.protectionRoot)
	if err != nil {
		return err
	}
	if verified != n.imagePath {
		return errors.New("standard verifier returned another captured executable")
	}
	if err := n.sourcesCurrent(); err != nil {
		return err
	}
	return ctx.Err()
}

func (n *linuxStandardEngine) sourcesCurrent() error {
	if n == nil || n.owner == nil || n.closed || n.manifest == nil || n.imageSource == nil || n.librarySource == nil {
		return errors.New("standard native source capability is unavailable")
	}
	for _, item := range []struct {
		file *os.File
		info os.FileInfo
		path string
	}{
		{n.manifest, n.manifestInfo, n.manifestPath},
		{n.imageSource, n.imageInfo, n.imagePath},
		{n.librarySource, n.libraryInfo, filepath.Join(filepath.Dir(n.imagePath), "libcronet.so")},
	} {
		opened, err := item.file.Stat()
		named, namedErr := os.Lstat(item.path)
		if err != nil || namedErr != nil || item.info == nil || !ownedDesktopInfo(opened) || !ownedDesktopInfo(named) || !os.SameFile(item.info, opened) || !os.SameFile(item.info, named) || opened.Size() != item.info.Size() {
			return errors.New("standard native source was replaced")
		}
		before, ok := item.info.Sys().(*syscall.Stat_t)
		after, valid := opened.Sys().(*syscall.Stat_t)
		if !ok || !valid || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
			return errors.New("standard native source changed in place")
		}
	}
	return nil
}

func (n *linuxStandardEngine) config(raw []byte) error {
	shape, err := standardengine.Config(raw, n.owner.runtimeMode)
	if err != nil {
		return err
	}
	n.shape = shape
	image, err := standardengine.ReadSealed(n.owner.image, bundledNativeMaxBytes)
	if err != nil || int64(len(image)) != n.imageExpected.Size || standardengine.SHA256(image) != n.imageExpected.SHA256 {
		return errors.New("standard native image changed after its exact catalog verification")
	}
	return n.sourcesCurrent()
}

func (n *linuxStandardEngine) environment(original []string) []string {
	result := make([]string, 0, len(original)+1)
	for _, value := range original {
		key, _, _ := strings.Cut(value, "=")
		if key == standardengine.LibraryEnvironment || strings.EqualFold(key, "LD_PRELOAD") || strings.EqualFold(key, "LD_LIBRARY_PATH") {
			continue
		}
		result = append(result, value)
	}
	return append(result, standardengine.LibraryEnvironment+"="+strconv.Itoa(standardengine.LibraryFD))
}

func (n *linuxStandardEngine) prepareStart(ctx context.Context) error {
	if n == nil || n.owner == nil || n.tracker == nil || n.parent != nil || n.capture != nil || n.cleanup != nil || n.operations != nil || ctx == nil || ctx.Err() != nil {
		return errors.New("standard native startup was reused or lost its observer")
	}
	if err := n.sourcesCurrent(); err != nil {
		return err
	}
	if err := n.tracker.CurrentContext(ctx); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("standard engine startup requires its original deadline")
	}
	if maximum := time.Now().Add(2 * time.Minute); deadline.After(maximum) {
		deadline = maximum
	}
	var err error
	n.cleanup, err = standardengine.NewCleanupFile()
	if err != nil {
		return err
	}
	n.operations, err = standardengine.NewOperationFile()
	if err != nil {
		return err
	}
	operationDevice, operationInode := n.operations.Identity()
	device, inode := n.cleanup.Identity()
	body, err := (standardengine.Capture{Schema: 1, Session: n.owner.session, ConfigSHA256: n.owner.digest, Mode: n.owner.runtimeMode, DeadlineNS: deadline.UnixNano(), CleanupDevice: device, CleanupInode: inode, OperationDevice: operationDevice, OperationInode: operationInode, OperationSize: standardengine.OperationSize, OperationLayout: standardengine.OperationLayout}).Canonical()
	if err != nil {
		return err
	}
	n.captureSHA = standardengine.SHA256(body)
	if err := n.operations.BindCapture(ctx, n.captureSHA); err != nil {
		return err
	}
	n.capture, err = sealLegacyExitFile("standard-original-startup", strings.NewReader(string(body)), 2048)
	if err != nil {
		return err
	}
	n.imageCapability, err = linuxprocess.CaptureSealedImage(n.owner.image)
	if err != nil {
		return err
	}
	n.parent, err = linuxprocess.CaptureSelf(ctx)
	if err != nil {
		return err
	}
	n.parentDirectory, err = n.parent.DuplicateDirectory(ctx)
	if err != nil {
		return err
	}
	n.channel, n.childChannel, err = linuxprocess.ChannelPair()
	if err != nil {
		return err
	}
	command := n.owner.command
	command.Args = []string{n.imagePath, "routervpn-standard", "--capture-sha256", n.captureSHA}
	command.ExtraFiles = []*os.File{n.owner.image, n.owner.config, n.owner.directory, n.library, n.childChannel, n.parentDirectory, n.capture, n.cleanup.File(), n.operations.File()}
	if err := n.tracker.Begin(ctx, nil); err != nil {
		return err
	}
	return nil
}

func (n *linuxStandardEngine) finishStart(ctx context.Context) error {
	o := n.owner
	if o == nil || !o.started || o.originalPIDFD == nil || o.pidFile != o.originalPIDFD || n.bootstrap != nil {
		return errors.New("standard ledger has no original created child")
	}
	if n.imageCapability == nil || !n.imageCapability.Uses(o.image) {
		return errors.New("standard startup lost its original sealed executable capability")
	}
	if err := n.imageCapability.Current(); err != nil {
		return err
	}
	raw, err := o.originalPIDFD.SyscallConn()
	if err != nil {
		return err
	}
	var duplicate *os.File
	var failure error
	err = raw.Control(func(fd uintptr) {
		value, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1030, 0)
		if errno != 0 {
			failure = errno
		} else {
			duplicate = os.NewFile(value, "original-standard-bootstrap-pidfd")
		}
	})
	if err != nil || failure != nil {
		return errors.Join(err, failure)
	}
	n.bootstrap, err = linuxprocess.BindCreatedSealedChild(ctx, n.channel, n.parent, duplicate, o.command.Process.Pid, n.imageCapability, n.captureSHA)
	n.channel = nil // Bootstrap consumes the original channel and duplicate even on failure.
	if err != nil {
		return fmt.Errorf("standard child bootstrap: %w", err)
	}
	for _, file := range []*os.File{n.childChannel, n.parentDirectory} {
		if err := n.closeFile(file); err != nil {
			return err
		}
	}
	body, err := n.bootstrap.Receive(ctx)
	if err != nil {
		return fmt.Errorf("standard child routing ledger: %w", err)
	}
	ready, err := standardengine.DecodeReady(body, n.captureSHA)
	if err != nil {
		return err
	}
	if err := n.operations.VerifyLaunch(ctx, ready.NetworkReceipt); err != nil {
		return err
	}
	receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(ready.NetworkReceipt)
	if err != nil || receipt.TargetOS != "linux" || receipt.Name != n.shape.Name || receipt.MTU != n.shape.MTU {
		return errors.New("standard startup ledger changed its captured native TUN policy")
	}
	if err := n.bootstrap.CheckCapture(ctx, n.captureSHA); err != nil {
		return err
	}
	if err := n.sourcesCurrent(); err != nil {
		return err
	}
	// Preserve the authenticated original ledger for independent retirement
	// readback even if the following network-epoch adoption fails.
	n.retainRoutingReceipt(receipt)
	if err := n.tracker.Record(receipt); err != nil {
		return err
	}
	if err := n.tracker.End(ctx, &receipt); err != nil {
		return err
	}
	if err := n.bootstrap.Current(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n.readyBody = append([]byte(nil), body...)
	n.ready = true
	return nil
}

func (n *linuxStandardEngine) current(ctx context.Context) error {
	if n == nil || !n.ready || n.closed || n.bootstrap == nil {
		return errors.New("standard engine has no authenticated original startup ledger")
	}
	if n.imageCapability == nil || !n.imageCapability.Uses(n.owner.image) {
		return errors.New("standard engine replaced its original executable capability")
	}
	if err := n.sourcesCurrent(); err != nil {
		return err
	}
	if err := n.operations.Current(); err != nil {
		return err
	}
	return n.bootstrap.CheckCapture(ctx, n.captureSHA)
}

func (n *linuxStandardEngine) closeFile(file *os.File) error {
	if file == nil || n.closedFiles[file] {
		return nil
	}
	if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	n.closedFiles[file] = true
	return nil
}

func (n *linuxStandardEngine) close(ctx context.Context) error {
	if n == nil || n.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("standard engine cleanup lost its original operation budget")
	}
	if n.tracker != nil && !n.adopted {
		_ = n.tracker.CurrentContext(ctx)
		if err := n.tracker.Close(); err != nil {
			return err
		}
	}
	if n.bootstrap != nil {
		if err := n.bootstrap.Close(ctx); err != nil {
			return err
		}
	}
	if n.channel != nil {
		if err := n.channel.Close(ctx); err != nil {
			return err
		}
	}
	if n.parent != nil {
		if err := n.parent.Close(ctx); err != nil {
			return err
		}
	}
	for _, file := range []*os.File{n.manifest, n.imageSource, n.librarySource, n.library, n.capture, n.parentDirectory, n.childChannel} {
		if err := n.closeFile(file); err != nil {
			return err
		}
	}
	if n.operations != nil {
		if err := n.operations.Close(ctx); err != nil {
			return err
		}
	}
	if n.cleanup != nil {
		if err := n.cleanup.Close(); err != nil {
			return err
		}
	}
	if n.cancel != nil {
		n.cancel()
	}
	n.closed = true
	return ctx.Err()
}
