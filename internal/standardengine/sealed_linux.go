//go:build linux

package standardengine

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// ReadSealed accepts only the original immutable regular descriptor. Reading
// bytes from an unsealed pathname can never supply a native startup input.
func ReadSealed(file *os.File, maximum int64) ([]byte, error) {
	if file == nil || maximum < 1 {
		return nil, errors.New("standard engine lost its inherited sealed file")
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.New("standard engine sealed file has an invalid bound")
	}
	check := func() error {
		raw, err := file.SyscallConn()
		if err != nil {
			return err
		}
		var failure error
		err = raw.Control(func(fd uintptr) {
			seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1034, 0)
			if errno != 0 || seals&15 != 15 {
				failure = errors.New("standard engine input has no immutable write/size/seal locks")
			}
		})
		return errors.Join(err, failure)
	}
	if err := check(); err != nil {
		return nil, err
	}
	body := make([]byte, before.Size())
	n, err := file.ReadAt(body, 0)
	if err != nil && !errors.Is(err, io.EOF) || n != len(body) {
		return nil, errors.New("standard engine sealed input was truncated")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		return nil, errors.New("standard engine inherited file was replaced")
	}
	return body, check()
}

// VerifyLibrary verifies the actual inherited object against the source
// builder's embedded seal. It grants no trust to an environment pathname.
func VerifyLibrary(file *os.File, size int64, expected string) error {
	if size < 1 || size > 128<<20 || !digest(expected, 32) {
		return errors.New("native library lacks its compiled seal")
	}
	raw, err := ReadSealed(file, size)
	if err != nil || int64(len(raw)) != size || SHA256(raw) != expected {
		return errors.Join(err, errors.New("native library differs from its compiled seal"))
	}
	return nil
}
