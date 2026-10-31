//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/linuxprotection"
)

// These values identify retained native objects. They neither construct a
// parent from persisted JSON nor authorize adopting another controller's
// protection. A later journal must retain this actual parent and its locks.
type desktopLinuxNodeObject = linuxprotection.NativeObject
type desktopLinuxNodeParentRecord = linuxprotection.ParentRecord

type desktopLinuxNodeParent struct {
	controller                            *ownedDesktopController
	input, installLock, processLock       *os.File // Borrowed original owners; never closed here.
	ownerDone                             <-chan struct{}
	credentials                           [32]byte
	ctx                                   context.Context
	cancel                                context.CancelFunc
	joined                                chan struct{}
	gate                                  chan struct{}
	installationAnchor, root              *os.Root
	image, networkNamespace, pidNamespace *os.File
	imageInfo                             os.FileInfo
	processWitness                        *linuxprocess.Witness
	record                                desktopLinuxNodeParentRecord
	complete, closed                      bool // Serialized by gate after constructor publication.
	retirementErr                         error
	dependents                            map[ownedDesktopNodeParent]struct{}
}

func desktopLinuxNodeObjectOf(info os.FileInfo) (desktopLinuxNodeObject, error) {
	if info == nil {
		return desktopLinuxNodeObject{}, errors.New("Linux Node parent lost a native object")
	}
	value, ok := info.Sys().(*syscall.Stat_t)
	if !ok || value.Ino == 0 {
		return desktopLinuxNodeObject{}, errors.New("Linux Node parent has no native inode witness")
	}
	return desktopLinuxNodeObject{Device: uint64(value.Dev), Inode: value.Ino, Mode: value.Mode, UID: value.Uid, GID: value.Gid}, nil
}

func desktopLinuxNodeProcessStart(raw []byte) (int, uint64, error) {
	stat, err := linuxprocess.ParseStat(raw)
	return stat.ProcessID, stat.Start, err
}

func readDesktopLinuxNodeProcessStart() (int, uint64, error) {
	file, err := os.Open("/proc/self/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil {
		return 0, 0, err
	}
	return desktopLinuxNodeProcessStart(raw)
}

func readDesktopLinuxNodeBootID() (string, error) {
	return linuxprocess.ReadBootID()
}

func desktopLinuxNodeCredentials(owner *ownedDesktopController) [32]byte {
	return sha256.Sum256([]byte(owner.accessToken + "\n" + owner.ownerToken))
}

// Called only after the installed bootstrap has authenticated the actual
// user's anonymous pipe and acquired its original install/process locks.
// Every returned partial parent remains closeable; it never closes those
// borrowed controller objects or recreates an equivalent lock by pathname.
func newDesktopLinuxNodeParent(owner *ownedDesktopController) (*desktopLinuxNodeParent, error) {
	if owner == nil || owner.nodeParent != nil || owner.nativeOwner != nil || os.Getuid() != 0 || os.Geteuid() != 0 ||
		owner.processID != os.Getpid() || owner.callerUID == 0 || owner.callerUID == ^uint32(0) ||
		!validLocalControllerSecret(owner.accessToken) || !validControllerOwnerToken(owner.ownerToken) ||
		owner.input == nil || owner.installLock == nil || owner.processLock == nil || owner.ownerDone == nil {
		return nil, errors.New("Linux Node parent requires its original authenticated installed controller")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &desktopLinuxNodeParent{controller: owner, input: owner.input, installLock: owner.installLock, processLock: owner.processLock,
		ownerDone: owner.ownerDone, credentials: desktopLinuxNodeCredentials(owner), ctx: ctx, cancel: cancel,
		joined: make(chan struct{}), gate: make(chan struct{}, 1)}
	p.gate <- struct{}{}
	go func() {
		defer close(p.joined)
		select {
		case <-p.ownerDone:
			cancel()
		case <-ctx.Done():
		}
	}()
	p.record.ProcessID, p.record.CallerUID = os.Getpid(), owner.callerUID
	var err error
	if p.record.Generation, err = randomHex(16); err != nil {
		return p, err
	}
	if p.record.BootID, err = readDesktopLinuxNodeBootID(); err != nil {
		return p, err
	}
	p.installationAnchor, err = os.OpenRoot(filepath.Dir(linuxOwnedControllerRoot))
	if err != nil {
		return p, err
	}
	anchor, err := p.installationAnchor.Stat(".")
	if err != nil || !anchor.IsDir() || !ownedDesktopInfo(anchor) {
		return p, errors.Join(err, errors.New("Linux Node parent lost its retained installation ancestry"))
	}
	p.record.InstallationAnchor, err = desktopLinuxNodeObjectOf(anchor)
	if err != nil {
		return p, err
	}
	p.root, err = p.installationAnchor.OpenRoot(filepath.Base(linuxOwnedControllerRoot))
	if err != nil {
		return p, err
	}
	root, err := p.root.Stat(".")
	if err != nil || !root.IsDir() || !ownedDesktopInfo(root) {
		return p, errors.Join(err, errors.New("Linux Node parent lost its protected installation root"))
	}
	p.record.Root, err = desktopLinuxNodeObjectOf(root)
	if err != nil {
		return p, err
	}
	p.image, err = p.root.OpenFile("router-vpn-client", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return p, err
	}
	p.imageInfo, err = p.image.Stat()
	if err != nil || !p.imageInfo.Mode().IsRegular() || !ownedDesktopInfo(p.imageInfo) {
		return p, errors.Join(err, errors.New("Linux Node parent lost its protected executable"))
	}
	p.record.Image, err = desktopLinuxNodeObjectOf(p.imageInfo)
	if err != nil {
		return p, err
	}
	for _, item := range []struct {
		file   *os.File
		target *desktopLinuxNodeObject
	}{
		{p.input, &p.record.Input}, {p.installLock, &p.record.InstallLock}, {p.processLock, &p.record.ProcessLock},
	} {
		info, failure := item.file.Stat()
		if failure == nil {
			*item.target, failure = desktopLinuxNodeObjectOf(info)
		}
		if failure != nil {
			return p, failure
		}
	}
	p.networkNamespace, err = os.Open("/proc/self/ns/net")
	if err != nil {
		return p, err
	}
	p.pidNamespace, err = os.Open("/proc/self/ns/pid")
	if err != nil {
		return p, err
	}
	for _, item := range []struct {
		file   *os.File
		target *desktopLinuxNodeObject
	}{
		{p.networkNamespace, &p.record.NetworkNamespace}, {p.pidNamespace, &p.record.PIDNamespace},
	} {
		info, failure := item.file.Stat()
		if failure == nil {
			*item.target, failure = desktopLinuxNodeObjectOf(info)
		}
		if failure != nil {
			return p, failure
		}
	}
	p.record.ProcProcessID, p.record.StartTicks, err = readDesktopLinuxNodeProcessStart()
	if err != nil {
		return p, err
	}
	p.processWitness, err = linuxprocess.CaptureSelf(ctx)
	if err != nil {
		return p, err
	}
	if err := p.record.Validate(); err != nil {
		return p, err
	}
	p.complete = true
	if err := p.currentLocked(false); err != nil {
		p.complete = false
		p.cancel()
		return p, err
	}
	return p, nil
}

func desktopLinuxNodeRetainedObject(file *os.File, wanted desktopLinuxNodeObject, path string, protected, private bool) error {
	if file == nil {
		return errors.New("Linux Node parent lost its retained descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	actual, err := desktopLinuxNodeObjectOf(info)
	if err != nil || actual != wanted || protected && (!ownedDesktopInfo(info) || private && info.Mode().Perm()&0077 != 0) {
		return errors.Join(err, errors.New("Linux Node parent descriptor changed its captured identity or authority"))
	}
	if path != "" {
		entry, err := os.Lstat(path)
		if err != nil || entry.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, entry) {
			return errors.Join(err, errors.New("Linux Node parent path no longer names its retained object"))
		}
	}
	return nil
}

func (p *desktopLinuxNodeParent) currentLocked(published bool) error {
	if p == nil || p.closed || !p.complete || p.ctx == nil || p.ctx.Err() != nil || p.installationAnchor == nil || p.root == nil || p.image == nil || p.imageInfo == nil || p.processWitness == nil ||
		p.controller == nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getpid() != p.record.ProcessID {
		return errors.New("Linux Node parent has no live complete native capture")
	}
	owner := p.controller
	if owner.processID != p.record.ProcessID || owner.callerUID != p.record.CallerUID || owner.nativeOwner != nil ||
		owner.input != p.input || owner.installLock != p.installLock || owner.processLock != p.processLock ||
		owner.ownerDone != p.ownerDone || desktopLinuxNodeCredentials(owner) != p.credentials || published && owner.nodeParent != p {
		return errors.New("Linux Node parent was replaced by another controller lifetime")
	}
	select {
	case <-p.ownerDone:
		return errors.New("Linux Node parent lost its original desktop lifetime")
	default:
	}
	anchor, err := p.installationAnchor.Stat(".")
	if err != nil {
		return err
	}
	anchorID, err := desktopLinuxNodeObjectOf(anchor)
	anchorPath, pathErr := os.Lstat(filepath.Dir(linuxOwnedControllerRoot))
	if err != nil || pathErr != nil || !anchor.IsDir() || !ownedDesktopInfo(anchor) || anchorID != p.record.InstallationAnchor ||
		!anchorPath.IsDir() || !ownedDesktopInfo(anchorPath) || !os.SameFile(anchor, anchorPath) {
		return errors.Join(err, pathErr, errors.New("Linux Node parent installation ancestry was replaced"))
	}
	root, err := p.root.Stat(".")
	if err != nil {
		return err
	}
	rootID, err := desktopLinuxNodeObjectOf(root)
	entry, entryErr := os.Lstat(linuxOwnedControllerRoot)
	if err != nil || entryErr != nil || !root.IsDir() || !ownedDesktopInfo(root) || rootID != p.record.Root ||
		!entry.IsDir() || !ownedDesktopInfo(entry) || !os.SameFile(root, entry) {
		return errors.Join(err, entryErr, errors.New("Linux Node parent installation directory was replaced"))
	}
	if err := desktopLinuxNodeRetainedObject(p.image, p.record.Image, filepath.Join(linuxOwnedControllerRoot, "router-vpn-client"), true, false); err != nil {
		return err
	}
	image, err := p.image.Stat()
	if err != nil {
		return err
	}
	running, runErr := os.Stat("/proc/self/exe")
	before, beforeOK := p.imageInfo.Sys().(*syscall.Stat_t)
	after, afterOK := image.Sys().(*syscall.Stat_t)
	if err != nil || runErr != nil || !beforeOK || !afterOK || !os.SameFile(image, running) ||
		image.Size() != p.imageInfo.Size() || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return errors.Join(err, runErr, errors.New("Linux Node parent executable changed after native capture"))
	}
	for _, item := range []struct {
		file     *os.File
		identity desktopLinuxNodeObject
		path     string
	}{
		{p.installLock, p.record.InstallLock, linuxOwnedInstallLock}, {p.processLock, p.record.ProcessLock, linuxOwnedProcessLock},
	} {
		if err := desktopLinuxNodeRetainedObject(item.file, item.identity, item.path, true, true); err != nil {
			return err
		}
	}
	if err := desktopLinuxNodeRetainedObject(p.input, p.record.Input, "", false, true); err != nil ||
		p.record.Input.Mode&syscall.S_IFMT != syscall.S_IFIFO || p.record.Input.UID != p.record.CallerUID || p.record.Input.Mode&0077 != 0 {
		return errors.Join(err, errors.New("Linux Node parent lost its original user-created anonymous input"))
	}
	for _, item := range []struct {
		file     *os.File
		identity desktopLinuxNodeObject
		path     string
	}{
		{p.networkNamespace, p.record.NetworkNamespace, "/proc/thread-self/ns/net"}, {p.pidNamespace, p.record.PIDNamespace, "/proc/thread-self/ns/pid"},
	} {
		if err := desktopLinuxNodeRetainedObject(item.file, item.identity, "", false, false); err != nil {
			return err
		}
		current, err := os.Stat(item.path)
		actual, identityErr := desktopLinuxNodeObjectOf(current)
		if err != nil || identityErr != nil || actual != item.identity {
			return errors.Join(err, identityErr, errors.New("Linux Node parent changed its native namespace"))
		}
	}
	procPID, start, err := readDesktopLinuxNodeProcessStart()
	boot, bootErr := readDesktopLinuxNodeBootID()
	if err != nil || bootErr != nil || procPID != p.record.ProcProcessID || start != p.record.StartTicks || boot != p.record.BootID || p.ctx.Err() != nil {
		return errors.Join(err, bootErr, errors.New("Linux Node parent lost its original native process start or boot"))
	}
	process, err := p.processWitness.Current(p.ctx)
	if err != nil || process.ProcessID != p.record.ProcessID || process.ProcProcessID != p.record.ProcProcessID ||
		process.StartTicks != p.record.StartTicks || process.BootID != p.record.BootID ||
		linuxprotection.NativeObject(process.Image) != p.record.Image || linuxprotection.NativeObject(process.NetworkNamespace) != p.record.NetworkNamespace ||
		linuxprotection.NativeObject(process.PIDNamespace) != p.record.PIDNamespace {
		return errors.Join(err, errors.New("Linux Node parent lost its original retained task directory"))
	}
	return nil
}

func (p *desktopLinuxNodeParent) Current(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.ctx == nil || p.ctx.Err() != nil || p.gate == nil {
		return errors.New("Linux Node parent readback has no live captured caller")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return p.ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if err := p.currentLocked(true); err != nil {
		// A later path restoration cannot revive a parent whose native
		// identity was observed missing or replaced. Keep its old descriptors
		// solely for joined teardown; a new bootstrap captures a new parent.
		p.cancel()
		return err
	}
	return ctx.Err()
}

func (p *desktopLinuxNodeParent) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if ctx == nil || p.cancel == nil || p.gate == nil || p.joined == nil {
		return errors.New("Linux Node parent retirement has no bounded native owner")
	}
	p.cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	dependents := make([]ownedDesktopNodeParent, 0, len(p.dependents))
	for dependent := range p.dependents {
		dependents = append(dependents, dependent)
	}
	p.gate <- struct{}{}
	// A dependent may finish a cancelled operation by observing this parent.
	// Never wait for its gate while holding the parent readback gate.
	for _, dependent := range dependents {
		if err := dependent.Close(ctx); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if len(p.dependents) != 0 {
		return errors.New("Linux Node parent has unjoined captured dependents")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.joined:
	}
	if p.processWitness != nil {
		if err := p.processWitness.Close(ctx); err != nil {
			p.retirementErr = errors.Join(p.retirementErr, err)
			return err
		}
		p.processWitness = nil
	}
	for _, retained := range []**os.File{&p.image, &p.networkNamespace, &p.pidNamespace} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if *retained != nil {
			// All operations on these private read-only witnesses have joined
			// under gate. ErrClosed belongs to this exact Go file owner and
			// performs no new raw close on a potentially reused descriptor.
			if err := (*retained).Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				p.retirementErr = errors.Join(p.retirementErr, err)
				return err
			}
			*retained = nil
		}
	}
	if p.root != nil {
		if err := p.root.Close(); err != nil {
			p.retirementErr = errors.Join(p.retirementErr, err)
			return err
		}
		p.root = nil
	}
	if p.installationAnchor != nil {
		if err := p.installationAnchor.Close(); err != nil {
			p.retirementErr = errors.Join(p.retirementErr, err)
			return err
		}
		p.installationAnchor = nil
	}
	// A retry can join remaining descriptors after a genuine native close
	// failure, but their later ErrClosed values cannot erase that failure.
	if p.retirementErr != nil {
		return p.retirementErr
	}
	p.closed = true
	return nil
}

func (p *desktopLinuxNodeParent) releaseDependent(ctx context.Context, dependent ownedDesktopNodeParent) error {
	if p == nil || ctx == nil || dependent == nil {
		return errors.New("Linux Node dependent retirement lost its original parent")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	delete(p.dependents, dependent)
	return nil
}

type desktopLinuxNodeParentCapture struct {
	app        *app
	controller *ownedDesktopController
	parent     *desktopLinuxNodeParent
	record     desktopLinuxNodeParentRecord
	lifetime   context.Context
}

func captureDesktopLinuxNodeParent(a *app) (*desktopLinuxNodeParentCapture, error) {
	if a == nil {
		return nil, errors.New("Linux Node parent requires its captured application")
	}
	a.mu.Lock()
	owner := a.localController
	a.mu.Unlock()
	if owner == nil {
		return nil, errors.New("Linux Node parent requires its authenticated installed controller")
	}
	parent, ok := owner.nodeParent.(*desktopLinuxNodeParent)
	if !ok || parent == nil || parent.controller != owner {
		return nil, errors.New("Linux Node parent has no retained native bootstrap")
	}
	capture := &desktopLinuxNodeParentCapture{app: a, controller: owner, parent: parent, record: parent.record, lifetime: parent.ctx}
	if err := capture.Current(context.Background()); err != nil {
		return nil, err
	}
	return capture, nil
}

func (c *desktopLinuxNodeParentCapture) currentApp() error {
	if c == nil || c.app == nil || c.parent == nil || c.controller == nil || c.lifetime == nil || c.lifetime.Err() != nil {
		return errors.New("Linux Node parent lost its captured application")
	}
	c.app.mu.Lock()
	defer c.app.mu.Unlock()
	if c.app.closing || c.app.localController != c.controller || c.controller.nodeParent != c.parent || c.record != c.parent.record ||
		c.app.cfg.ProfilesFile != filepath.Join(linuxOwnedControllerRoot, "routers.json") ||
		c.app.cfg.ModesFile != filepath.Join(linuxOwnedControllerRoot, "modes.json") ||
		c.app.cfg.ScriptsDir != filepath.Join(linuxOwnedControllerRoot, "modes") ||
		c.app.cfg.StateFile != filepath.Join(linuxOwnedControllerRoot, "state.json") {
		return errors.New("Linux Node parent changed its captured application or private roots")
	}
	return nil
}

func (c *desktopLinuxNodeParentCapture) Current(ctx context.Context) error {
	if err := c.currentApp(); err != nil {
		return err
	}
	if err := c.parent.Current(ctx); err != nil {
		return err
	}
	return c.currentApp()
}
