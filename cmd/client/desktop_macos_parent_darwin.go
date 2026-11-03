//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type desktopMacOSNativeObject struct {
	file     *os.File
	info     os.FileInfo
	path     string
	image    bool
	borrowed bool
}

type desktopMacOSNativeWitness struct {
	anchor, root         *os.Root
	anchorInfo, rootInfo os.FileInfo
	objects              []desktopMacOSNativeObject
	input                *os.File
	peer                 macOSOwnedPeerIdentity
	closed               bool
}

func newDesktopMacOSNativeParent(c *ownedDesktopController) (*desktopMacOSParent, error) {
	if c == nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.processID != os.Getpid() || c.input == nil || c.installLock == nil || c.processLock == nil {
		return nil, errors.New("macOS parent requires the actual privileged bootstrap")
	}
	w := &desktopMacOSNativeWitness{input: c.input}
	parent, err := newDesktopMacOSParent(c, w)
	// Retain the partial parent from this point; controller close owns its cleanup.
	if parent == nil {
		return nil, err
	}
	if err = w.capture(c); err != nil {
		return parent, err
	}
	return parent, parent.currentLocked(context.Background(), false)
}

func (w *desktopMacOSNativeWitness) capture(c *ownedDesktopController) error {
	var err error
	w.anchor, err = os.OpenRoot(filepath.Dir(macOSOwnedControllerRoot))
	if err != nil {
		return err
	}
	w.anchorInfo, err = w.anchor.Stat(".")
	if err != nil {
		return err
	}
	w.root, err = w.anchor.OpenRoot(filepath.Base(macOSOwnedControllerRoot))
	if err != nil {
		return err
	}
	w.rootInfo, err = w.root.Stat(".")
	if err != nil {
		return err
	}
	image, err := w.root.OpenFile("router-vpn-client", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	w.objects = append(w.objects, desktopMacOSNativeObject{file: image, path: macOSOwnedExecutable(), image: true})
	w.objects = append(w.objects, desktopMacOSNativeObject{file: c.installLock, path: macOSOwnedInstallLock, borrowed: true},
		desktopMacOSNativeObject{file: c.processLock, path: macOSOwnedProcessLock, borrowed: true},
		desktopMacOSNativeObject{file: c.input, borrowed: true})
	for index := range w.objects {
		w.objects[index].info, err = w.objects[index].file.Stat()
		if err != nil {
			return err
		}
	}
	raw, err := w.input.SyscallConn()
	if err != nil {
		return err
	}
	w.peer, err = macOSOwnedPeer(raw)
	if err != nil || w.peer.UID != c.callerUID {
		return errors.Join(err, errors.New("macOS parent captured another desktop peer"))
	}
	return w.Current(context.Background())
}

func (w *desktopMacOSNativeWitness) Current(ctx context.Context) error {
	if ctx == nil || w.closed || w.anchor == nil || w.root == nil || w.anchorInfo == nil || w.rootInfo == nil || len(w.objects) != 4 || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("macOS parent has no complete retained native witness")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, directory := range []struct {
		root *os.Root
		info os.FileInfo
		path string
	}{
		{w.anchor, w.anchorInfo, filepath.Dir(macOSOwnedControllerRoot)}, {w.root, w.rootInfo, macOSOwnedControllerRoot},
	} {
		actual, err := directory.root.Stat(".")
		named, nameErr := os.Lstat(directory.path)
		if err != nil || nameErr != nil || !named.IsDir() || !actual.IsDir() || !ownedDesktopInfo(actual) ||
			!os.SameFile(directory.info, actual) || !os.SameFile(actual, named) || ownedPathACL(directory.path) != nil {
			return errors.New("macOS parent installation directory changed its native identity")
		}
	}
	for _, object := range w.objects {
		actual, err := object.file.Stat()
		if err != nil || object.info == nil || !os.SameFile(object.info, actual) {
			return errors.New("macOS parent lost an original retained descriptor")
		}
		// XNU exposes socket receive/send readiness through fstat mode bits.
		// EOF can change them while the original native cleanup still owns the
		// accepted GUI descriptor. Every named object retains exact modes.
		if object.path == "" {
			if object.info.Mode()&^os.FileMode(0666) != os.ModeSocket || actual.Mode()&^os.FileMode(0666) != os.ModeSocket {
				return errors.New("macOS parent lifetime descriptor changed native type")
			}
		} else if object.info.Mode() != actual.Mode() {
			return errors.New("macOS parent filesystem descriptor changed permissions")
		}
		before, beforeOK := object.info.Sys().(*syscall.Stat_t)
		after, afterOK := actual.Sys().(*syscall.Stat_t)
		if !beforeOK || !afterOK || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink {
			return errors.New("macOS parent descriptor changed ownership")
		}
		if object.path != "" {
			named, err := os.Lstat(object.path)
			if err != nil || !named.Mode().IsRegular() || !ownedDesktopInfo(named) || !os.SameFile(actual, named) || ownedPathACL(object.path) != nil ||
				!object.image && named.Mode().Perm() != 0600 {
				return errors.New("macOS parent image or lock pathname was replaced")
			}
		}
		if object.image && (actual.Size() != object.info.Size() || before.Mtimespec != after.Mtimespec || before.Ctimespec != after.Ctimespec) {
			return errors.New("macOS parent executable changed after capture")
		}
	}
	raw, err := w.input.SyscallConn()
	if err != nil {
		return err
	}
	peer, err := macOSOwnedPeer(raw)
	if err != nil || peer != w.peer {
		return errors.Join(err, errors.New("macOS parent lifetime peer changed"))
	}
	var addressErr error
	err = raw.Control(func(fd uintptr) {
		address, failure := syscall.Getsockname(int(fd))
		local, ok := address.(*syscall.SockaddrUnix)
		if failure != nil || !ok || local.Name != macOSOwnedControllerSocket {
			addressErr = errors.New("macOS parent lost its original supervisor socket")
		}
	})
	return errors.Join(err, addressErr, ctx.Err())
}

func (w *desktopMacOSNativeWitness) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("macOS native witness retirement requires a bounded caller")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.closed {
		return nil
	}
	for index := range w.objects {
		object := &w.objects[index]
		if !object.borrowed && object.file != nil {
			if err := object.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				return err
			}
			object.file = nil
		}
	}
	if w.root != nil {
		if err := w.root.Close(); err != nil {
			return err
		}
		w.root = nil
	}
	if w.anchor != nil {
		if err := w.anchor.Close(); err != nil {
			return err
		}
		w.anchor = nil
	}
	w.closed = true
	return nil
}
