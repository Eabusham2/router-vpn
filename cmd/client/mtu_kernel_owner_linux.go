//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type mtuKernelFile interface {
	Stat() (os.FileInfo, error)
	ReadAt([]byte, int64) (int, error)
	WriteAt([]byte, int64) (int, error)
	Close() error
}

type mtuLinuxKernelOwner struct {
	mu                     sync.Mutex
	mtu                    mtuKernelFile
	index                  *os.File
	mtuInfo                os.FileInfo
	idxInfo                os.FileInfo
	path                   string
	state                  mtuKernelState
	closed                 bool
	mtuClosed, indexClosed bool
}

func openMTUKernelOwner(live mtuLiveSnapshot) (mtuKernelOwner, error) {
	if !validMTUKernelCapture(live) {
		return nil, errMTUKernelOwner
	}
	iface, err := net.InterfaceByName(live.Interface)
	if err != nil || iface.Index <= 0 {
		return nil, errMTUKernelOwner
	}
	base := filepath.Join("/sys/class/net", live.Interface)
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil || !strings.HasPrefix(resolved, "/sys/devices/") {
		return nil, errMTUKernelOwner
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, errMTUKernelOwner
	}
	defer root.Close()
	mtu, err := root.OpenFile("mtu", os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open captured kernel MTU attribute: %w", err)
	}
	index, err := root.OpenFile("ifindex", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = mtu.Close()
		return nil, errMTUKernelOwner
	}
	// Reject ordinary writable files masquerading as device attributes. These
	// descriptors remain attached to their original sysfs/kernfs nodes; device
	// deletion cannot retarget a subsequent write to a new same-name interface.
	var filesystem syscall.Statfs_t
	if syscall.Fstatfs(int(mtu.Fd()), &filesystem) != nil || filesystem.Type != 0x62656572 {
		_ = mtu.Close()
		_ = index.Close()
		return nil, errMTUKernelOwner
	}
	owner, err := newMTULinuxKernelOwner(live, iface.Index, filepath.Join(base, "mtu"), mtu, index)
	if err != nil {
		_ = mtu.Close()
		_ = index.Close()
		return nil, err
	}
	return owner, nil
}

func newMTULinuxKernelOwner(live mtuLiveSnapshot, index int, aliasPath string, mtu mtuKernelFile, indexFile *os.File) (*mtuLinuxKernelOwner, error) {
	if !validMTUKernelCapture(live) || index <= 0 || mtu == nil || indexFile == nil {
		return nil, errMTUKernelOwner
	}
	mi, err := mtu.Stat()
	if err != nil || !mi.Mode().IsRegular() {
		return nil, errMTUKernelOwner
	}
	ii, err := indexFile.Stat()
	if err != nil || !ii.Mode().IsRegular() {
		return nil, errMTUKernelOwner
	}
	ms, ok := mi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errMTUKernelOwner
	}
	is, ok := ii.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errMTUKernelOwner
	}
	state := mtuKernelState{Interface: live.Interface, Family: live.Family, Index: index, MTU: live.OriginalMTU,
		Identity: fmt.Sprintf("linux-sysfs:%x:%x:%x:%x", ms.Dev, ms.Ino, is.Dev, is.Ino)}
	owner := &mtuLinuxKernelOwner{mtu: mtu, index: indexFile, mtuInfo: mi, idxInfo: ii, path: aliasPath, state: state}
	current, err := owner.readLocked()
	if err != nil || current != state {
		return nil, errMTUKernelOwner
	}
	return owner, nil
}

func readMTUKernelInteger(file interface {
	ReadAt([]byte, int64) (int, error)
}) (int, error) {
	var raw [32]byte
	count, err := file.ReadAt(raw[:], 0)
	if err != nil && !errors.Is(err, io.EOF) || count <= 0 || count == len(raw) {
		return 0, errMTUKernelOwner
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(raw[:count])))
	if err != nil || value <= 0 {
		return 0, errMTUKernelOwner
	}
	return value, nil
}

func (o *mtuLinuxKernelOwner) readLocked() (mtuKernelState, error) {
	if o.closed {
		return mtuKernelState{}, errMTUKernelOwner
	}
	current, err := o.mtu.Stat()
	if err != nil || !os.SameFile(current, o.mtuInfo) {
		return mtuKernelState{}, errMTUKernelOwner
	}
	alias, err := os.Stat(o.path)
	if err != nil || !os.SameFile(alias, o.mtuInfo) {
		return mtuKernelState{}, errMTUKernelOwner
	}
	current, err = o.index.Stat()
	if err != nil || !os.SameFile(current, o.idxInfo) {
		return mtuKernelState{}, errMTUKernelOwner
	}
	index, err := readMTUKernelInteger(o.index)
	if err != nil || index != o.state.Index {
		return mtuKernelState{}, errMTUKernelOwner
	}
	mtu, err := readMTUKernelInteger(o.mtu)
	if err != nil || mtu < 576 || mtu > 9000 {
		return mtuKernelState{}, errMTUKernelOwner
	}
	state := o.state
	state.MTU = mtu
	return state, nil
}

func (o *mtuLinuxKernelOwner) Read() (mtuKernelState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.readLocked()
}

func (o *mtuLinuxKernelOwner) Change(expected mtuKernelState, mtu int) (mtuKernelState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	before, err := o.readLocked()
	if err != nil || before != expected || mtu < 576 || mtu > 9000 {
		return mtuKernelState{}, errMTUKernelOwner
	}
	// net-sysfs mtu_store writes the net_device attached to this retained
	// attribute. No alias/index lookup occurs at the mutation boundary.
	raw := []byte(strconv.Itoa(mtu) + "\n")
	count, err := o.mtu.WriteAt(raw, 0)
	if err != nil || count != len(raw) {
		return mtuKernelState{}, fmt.Errorf("change captured kernel MTU: %w", errors.Join(err, io.ErrShortWrite))
	}
	after, err := o.readLocked()
	if err != nil || after.MTU != mtu {
		return mtuKernelState{}, errMTUKernelOwner
	}
	return after, nil
}

func (o *mtuLinuxKernelOwner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	var mtuErr, indexErr error
	if !o.mtuClosed {
		mtuErr = o.mtu.Close()
		if mtuFileCloseComplete(mtuErr) {
			o.mtuClosed, mtuErr = true, nil
		}
	}
	if !o.indexClosed {
		indexErr = o.index.Close()
		if mtuFileCloseComplete(indexErr) {
			o.indexClosed, indexErr = true, nil
		}
	}
	return errors.Join(mtuErr, indexErr)
}

func mtuFileCloseComplete(err error) bool {
	if err == nil || err == os.ErrClosed {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !mtuFileCloseComplete(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		child := wrapped.Unwrap()
		return child != nil && mtuFileCloseComplete(child)
	}
	return false
}
