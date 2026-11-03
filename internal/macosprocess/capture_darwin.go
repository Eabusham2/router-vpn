//go:build darwin

package macosprocess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"router-vpn/internal/common"
)

const InstallRoot = "/opt/router-vpn-client"
const EnginePath = InstallRoot + "/runtime/native/sing-box-routervpn"
const ControllerPath = InstallRoot + "/router-vpn-client"
const CatalogPath = InstallRoot + "/runtime/native/NATIVE-RUNTIME.json"
const InstallLockPath = "/opt/router-vpn-client.install.lock"
const ProcessLockPath = "/opt/router-vpn-client.controller.lock"
const LifetimePath = "/opt/router-vpn-client.control/controller.sock"

// Scope is the expected policy identity, never a substitute for the original
// descriptor and native main-image observations. Source is the policy's
// semantic digest; InputsSHA256 separately binds the exact private documents.
type Scope struct{ Session, Source, Config, Workspace string }

type pinnedFile struct {
	file      *os.File
	info      os.FileInfo
	path      string
	immutable bool
	guiSocket bool // Only fixed inherited FD9; its fstat mode describes readiness.
}
type guiPeer struct {
	UID uint32
	PID int
}

// Capture owns duplicates of the seven original descriptors, in their fixed
// child FD4..FD10 order. It also pins every ancestor and each private input.
// The creator must join its child before Close releases these references.
type Capture struct {
	mu                 sync.RWMutex
	workspaceRoot      *os.Root
	scope              Scope
	selection          Selection
	files              []pinnedFile
	ancestors          []pinnedFile
	inputs             []pinnedFile
	engine, controller Image
	peer               guiPeer
	closed             bool
}

func nativeCPU() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return CPUAMD64, nil
	case "arm64":
		return CPUARM64, nil
	}
	return 0, errors.New("native process has an unsupported Mach-O architecture")
}
func duplicate(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, errors.New("native child lost an original descriptor")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var failure error
	err = raw.Control(func(original uintptr) {
		fd, failure = syscall.Dup(int(original))
		if failure == nil {
			syscall.CloseOnExec(fd)
		}
	})
	if err != nil || failure != nil {
		return nil, errors.Join(err, failure)
	}
	return os.NewFile(uintptr(fd), "original-native-child-capture"), nil
}
func openPinned(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

// OpenCapture opens only the fixed installed images/catalog and duplicates
// the authenticated controller's original workspace, locks and GUI socket.
// The app additionally verifies the complete bundled runtime catalog policy.
func OpenCapture(ctx context.Context, scope Scope, workspace, install, process, lifetime *os.File) (result *Capture, failure error) {
	c := &Capture{scope: scope}
	defer func() {
		if failure != nil {
			_ = c.Close()
		}
	}()
	for index, path := range []string{scope.Workspace, EnginePath, ControllerPath, InstallLockPath, ProcessLockPath, "", CatalogPath} {
		var file *os.File
		var err error
		switch index {
		case 0:
			file, err = duplicate(workspace)
		case 3:
			file, err = duplicate(install)
		case 4:
			file, err = duplicate(process)
		case 5:
			file, err = duplicate(lifetime)
		default:
			file, err = openPinned(path)
		}
		if err != nil {
			return nil, err
		}
		c.files = append(c.files, pinnedFile{file: file, path: path, immutable: index == 1 || index == 2 || index == 6, guiSocket: index == 5})
	}
	if err := c.capture(ctx); err != nil {
		return nil, fmt.Errorf("opened native capture: %w", err)
	}
	return c, nil
}

// InheritCapture consumes exactly FD4..FD10. No flag can redirect these files.
// Adopt all and set close-on-exec before any subsequent native subprocess.
func InheritCapture(ctx context.Context, scope Scope) (result *Capture, failure error) {
	c := &Capture{scope: scope}
	defer func() {
		if failure != nil {
			_ = c.Close()
		}
	}()
	for index, path := range []string{scope.Workspace, EnginePath, ControllerPath, InstallLockPath, ProcessLockPath, "", CatalogPath} {
		fd := 4 + index
		syscall.CloseOnExec(fd)
		file := os.NewFile(uintptr(fd), "inherited-native-child-capture")
		if file == nil {
			return nil, errors.New("native child lacks fixed inherited descriptors")
		}
		c.files = append(c.files, pinnedFile{file: file, path: path, immutable: index == 1 || index == 2 || index == 6, guiSocket: index == 5})
	}
	if err := c.capture(ctx); err != nil {
		return nil, fmt.Errorf("inherited native capture: %w", err)
	}
	cwd, err := os.Stat(".")
	if err != nil || !os.SameFile(cwd, c.files[0].info) {
		return nil, errors.New("native child cwd is not its original private workspace")
	}
	return c, nil
}

func (c *Capture) capture(ctx context.Context) error {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || !shortDigest.MatchString(c.scope.Session) || !longDigest.MatchString(c.scope.Source) || !longDigest.MatchString(c.scope.Config) || filepath.Clean(c.scope.Workspace) != c.scope.Workspace || !strings.HasPrefix(c.scope.Workspace, InstallRoot+"/run/native-node/session-") || filepath.Dir(c.scope.Workspace) != InstallRoot+"/run/native-node" || len(c.files) != 7 {
		return errors.New("native child requires its fixed privileged scope")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for i := range c.files {
		info, err := c.files[i].file.Stat()
		if err != nil {
			return err
		}
		c.files[i].info = info
	}
	paths := map[string]bool{}
	for _, file := range c.files {
		if file.path == "" {
			continue
		}
		for path := filepath.Dir(file.path); path != "/"; path = filepath.Dir(path) {
			paths[path] = true
		}
	}
	for path := range paths {
		file, err := openPinned(path)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		c.ancestors = append(c.ancestors, pinnedFile{file: file, info: info, path: path})
		if err != nil {
			return err
		}
	}
	// Verify protected names and descriptor permissions before reading their
	// contents or reasserting locks on the inherited open descriptions.
	for index, pin := range c.files {
		if err := checkPin(pin, index == 0); err != nil {
			return fmt.Errorf("fixed inherited FD%d: %w", index+4, err)
		}
	}
	for _, pin := range c.ancestors {
		if err := checkPin(pin, true); err != nil {
			return fmt.Errorf("captured ancestor: %w", err)
		}
	}
	if c.files[0].info.Mode().Perm() != 0700 || c.files[3].info.Mode().Perm() != 0600 || c.files[4].info.Mode().Perm() != 0600 || c.files[1].info.Mode().Perm()&0111 == 0 || c.files[2].info.Mode().Perm()&0111 == 0 {
		return errors.New("native capture lacks private directory/locks or executable images")
	}
	for index, operation := range map[int]int{3: syscall.LOCK_SH, 4: syscall.LOCK_EX} {
		if err := syscall.Flock(int(c.files[index].file.Fd()), operation|syscall.LOCK_NB); err != nil {
			return err
		}
	}
	peer, err := readGUIPeer(c.files[5].file)
	if err != nil {
		return err
	}
	c.peer = peer
	cpu, err := nativeCPU()
	if err != nil {
		return err
	}
	c.engine, err = ReadImage(c.files[1].file, c.files[1].info.Size(), cpu)
	if err != nil {
		return fmt.Errorf("captured runtime image: %w", err)
	}
	c.controller, err = ReadImage(c.files[2].file, c.files[2].info.Size(), cpu)
	if err != nil {
		return fmt.Errorf("captured controller image: %w", err)
	}
	catalog, err := readPinned(c.files[6], 32768)
	if err != nil {
		return err
	}
	var receipt struct {
		Runtime, Target string
		Size            int64
		SHA256          string
		Files           map[string]struct {
			Size   int64
			SHA256 string
		}
	}
	if json.Unmarshal(catalog, &receipt) != nil || receipt.Runtime != "sing-box-routervpn" || receipt.Target != "darwin/"+runtime.GOARCH || receipt.Size != c.files[1].info.Size() || receipt.SHA256 != hex.EncodeToString(c.engine.SHA256[:]) || receipt.Files["sing-box-routervpn"].Size != receipt.Size || receipt.Files["sing-box-routervpn"].SHA256 != receipt.SHA256 {
		return errors.New("native runtime image differs from its captured installed catalog")
	}
	c.workspaceRoot, err = os.OpenRoot(c.scope.Workspace)
	if err != nil {
		return err
	}
	rootInfo, err := c.workspaceRoot.Stat(".")
	if err != nil || !os.SameFile(rootInfo, c.files[0].info) {
		return errors.New("private input directory differs from original descriptor")
	}
	inputs := sha256.New()
	for _, name := range []string{"source.json", "capture.json", "sing-box.json"} {
		file, err := c.workspaceRoot.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		pin := pinnedFile{file: file, info: info, path: filepath.Join(c.scope.Workspace, name), immutable: true}
		c.inputs = append(c.inputs, pin)
		if err != nil {
			return err
		}
		data, err := readPinned(pin, 16<<20)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		clear(data)
		if name == "sing-box.json" && hex.EncodeToString(digest[:]) != c.scope.Config {
			return errors.New("native private configuration differs from captured policy")
		}
		_, _ = fmt.Fprintf(inputs, "%s:%x\n", name, digest)
	}
	catalogSHA := sha256.Sum256(catalog)
	st := c.files[0].info.Sys().(*syscall.Stat_t)
	c.selection = Selection{Session: c.scope.Session, Source: c.scope.Source, Config: c.scope.Config, CallerUID: peer.UID, WorkspaceDevice: uint64(st.Dev), WorkspaceInode: st.Ino, EngineSHA256: hex.EncodeToString(c.engine.SHA256[:]), ControllerSHA256: hex.EncodeToString(c.controller.SHA256[:]), CatalogSHA256: hex.EncodeToString(catalogSHA[:]), InputsSHA256: hex.EncodeToString(inputs.Sum(nil))}
	return c.Current(ctx)
}
func readPinned(p pinnedFile, limit int64) ([]byte, error) {
	if p.info == nil || !p.info.Mode().IsRegular() || p.info.Size() <= 0 || p.info.Size() > limit {
		return nil, errors.New("native captured input is not a bounded regular file")
	}
	data, err := io.ReadAll(io.NewSectionReader(p.file, 0, p.info.Size()+1))
	if err != nil || int64(len(data)) != p.info.Size() {
		clear(data)
		return nil, errors.New("native captured input changed length")
	}
	return data, nil
}
func checkPin(p pinnedFile, directory bool) error {
	actual, err := p.file.Stat()
	if err != nil || p.info == nil || !os.SameFile(p.info, actual) {
		return errors.New("native child lost an original captured object")
	}
	before, ok := p.info.Sys().(*syscall.Stat_t)
	after, ok2 := actual.Sys().(*syscall.Stat_t)
	if !ok || !ok2 {
		return fmt.Errorf("native captured object ownership changed: stat-type before=%t after=%t", ok, ok2)
	}
	if !samePinMetadata(pinMetadata{p.info.Mode(), before.Uid, before.Gid, uint64(before.Nlink)},
		pinMetadata{actual.Mode(), after.Uid, after.Gid, uint64(after.Nlink)}, p.guiSocket, directory) || p.guiSocket && (directory || p.path != "" || p.immutable) {
		// Numeric native metadata only: never include private paths, input
		// documents or process credentials in the bounded failure diagnostic.
		return fmt.Errorf("native captured object ownership changed: gui=%t directory=%t named=%t immutable=%t before=(mode=%#o uid=%d gid=%d links=%d) after=(mode=%#o uid=%d gid=%d links=%d)",
			p.guiSocket, directory, p.path != "", p.immutable, uint32(p.info.Mode()), before.Uid, before.Gid, before.Nlink,
			uint32(actual.Mode()), after.Uid, after.Gid, after.Nlink)
	}
	if p.path != "" {
		named, err := os.Lstat(p.path)
		if err != nil || !os.SameFile(actual, named) || named.Mode()&os.ModeSymlink != 0 || directory != named.IsDir() || !directory && !named.Mode().IsRegular() {
			return errors.New("native captured pathname was replaced")
		}
		if err := common.OwnedPathACL(p.path); err != nil {
			return err
		}
	}
	if p.immutable && (before.Mtimespec != after.Mtimespec || before.Ctimespec != after.Ctimespec || actual.Size() != p.info.Size()) {
		return errors.New("native captured image or input changed content")
	}
	return nil
}
func (c *Capture) Current(ctx context.Context) error {
	if c == nil {
		return errors.New("native child capture is not complete")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c == nil || c.closed || ctx == nil || len(c.files) != 7 || len(c.inputs) != 3 || !c.selection.valid() || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("native child capture is not complete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for i, p := range c.files {
		if err := checkPin(p, i == 0); err != nil {
			return fmt.Errorf("current fixed inherited FD%d: %w", i+4, err)
		}
		if (i == 0 && p.info.Mode().Perm() != 0700) || ((i == 3 || i == 4) && p.info.Mode().Perm() != 0600) {
			return errors.New("native child inherited nonprivate workspace or locks")
		}
	}
	for _, p := range c.ancestors {
		if err := checkPin(p, true); err != nil {
			return fmt.Errorf("current captured ancestor: %w", err)
		}
	}
	for _, p := range c.inputs {
		if err := checkPin(p, false); err != nil {
			return fmt.Errorf("current private input: %w", err)
		}
		if p.info.Mode().Perm() != 0600 {
			return errors.New("native child input is not private")
		}
	}
	peer, err := readGUIPeer(c.files[5].file)
	if err != nil || peer != c.peer {
		return errors.Join(err, errors.New("native child lost its original GUI peer"))
	}
	return ctx.Err()
}
func (c *Capture) Selection() Selection {
	if c == nil {
		return Selection{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c == nil || c.closed {
		return Selection{}
	}
	return c.selection
}
func (c *Capture) Files() []*os.File {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c == nil || c.closed {
		return nil
	}
	files := make([]*os.File, len(c.files))
	for i := range c.files {
		files[i] = c.files[i].file
	}
	return files
}
func (c *Capture) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c == nil || c.closed {
		return nil
	}
	var result error
	if c.workspaceRoot != nil {
		result = errors.Join(result, c.workspaceRoot.Close())
		c.workspaceRoot = nil
	}
	for _, group := range [][]pinnedFile{c.inputs, c.ancestors, c.files} {
		for _, p := range group {
			if p.file != nil {
				err := p.file.Close()
				if !errors.Is(err, os.ErrClosed) {
					result = errors.Join(result, err)
				}
			}
		}
	}
	if result == nil {
		c.closed = true
	}
	return result
}

func readGUIPeer(file *os.File) (guiPeer, error) {
	var peer guiPeer
	raw, err := file.SyscallConn()
	if err != nil {
		return peer, err
	}
	var failure error
	err = raw.Control(func(value uintptr) {
		fd := int(value)
		kind, e := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		local, e2 := syscall.Getsockname(fd)
		address, ok := local.(*syscall.SockaddrUnix)
		remote, e3 := syscall.Getpeername(fd)
		_, remoteOK := remote.(*syscall.SockaddrUnix)
		if e != nil || e2 != nil || e3 != nil || kind != syscall.SOCK_STREAM || !ok || !remoteOK || address.Name != LifetimePath {
			failure = errors.New("native child lacks original accepted GUI socket")
			return
		}
		var credential struct {
			Version, UID uint32
			Groups       int16
			Padding      uint16
			GIDs         [16]uint32
		}
		size := uint32(unsafe.Sizeof(credential))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, value, 0, 1, uintptr(unsafe.Pointer(&credential)), uintptr(unsafe.Pointer(&size)), 0)
		pid, e := syscall.GetsockoptInt(fd, 0, 2)
		if errno != 0 || size != 76 || credential.Version != 0 || credential.Groups < 1 || credential.Groups > 16 || credential.UID == 0 || credential.UID == ^uint32(0) || e != nil || pid <= 1 {
			failure = errors.New("native child GUI socket has no original unprivileged peer")
			return
		}
		peer = guiPeer{credential.UID, pid}
	})
	return peer, errors.Join(err, failure)
}
