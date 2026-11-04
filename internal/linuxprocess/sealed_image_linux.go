//go:build linux

package linuxprocess

import (
	"context"
	"errors"
	"os"
	"syscall"
)

// SealedImage borrows one original anonymous executable descriptor. It grants
// no process creation or retirement authority, and no pathname/PID can refill
// it. The generic process witness continues to require a protected directory
// entry; only the explicit sealed-child bootstrap consumes this capability.
type SealedImage struct {
	file     *os.File
	identity Object
	size     int64
}

func CaptureSealedImage(file *os.File) (*SealedImage, error) {
	s := &SealedImage{file: file}
	if file == nil {
		return nil, errors.New("sealed child image has no original descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	s.identity, err = objectOf(info)
	if err != nil {
		return nil, err
	}
	s.size = info.Size()
	if err := s.Current(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SealedImage) Current() error {
	if s == nil || s.file == nil || s.size < 1 {
		return errors.New("sealed child image is unavailable")
	}
	raw, err := s.file.SyscallConn()
	if err != nil {
		return err
	}
	var failure error
	err = raw.Control(func(fd uintptr) {
		var st syscall.Stat_t
		if err := syscall.Fstat(int(fd), &st); err != nil {
			failure = err
			return
		}
		actual := Object{Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, UID: st.Uid, GID: st.Gid}
		if actual != s.identity || st.Size != s.size || st.Nlink != 0 || st.Mode&0170000 != 0100000 || st.Mode&0111 == 0 || st.Mode&06222 != 0 || st.Uid != 0 || st.Gid != 0 {
			failure = errors.New("sealed child image lost its original immutable executable object")
			return
		}
		seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1034, 0)
		if errno != 0 || seals&15 != 15 {
			failure = errors.New("sealed child image has no complete write/size/seal locks")
		}
	})
	return errors.Join(err, failure)
}

func (s *SealedImage) Uses(file *os.File) bool { return s != nil && s.file == file }

func captureSealedSelf(ctx context.Context, image *SealedImage) (*Witness, error) {
	directory, err := os.Open("/proc/self")
	if err != nil {
		return nil, err
	}
	return captureDirectory(ctx, directory, os.Getpid(), image)
}
