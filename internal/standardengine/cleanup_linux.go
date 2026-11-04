//go:build linux

package standardengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const CleanupFD = 10
const cleanupSize = 64 << 10
const cleanupRequestSize = 4096

// CleanupFile is the original bounded inherited result/control object. The
// parent reads successful results only after its original child has joined.
// Size/seal locks prevent truncation or substitution, while actual object
// identity and the sealed startup capture bind both writers to this launch.
type CleanupFile struct {
	file      *os.File
	identity  syscall.Stat_t
	closed    bool
	admission error
}

type CleanupRequest struct {
	Schema        int    `json:"schema"`
	CaptureSHA256 string `json:"capture_sha256"`
	Sequence      uint64 `json:"sequence"`
	DeadlineNS    int64  `json:"deadline_ns"`
}
type CleanupResult struct {
	Schema        int    `json:"schema"`
	CaptureSHA256 string `json:"capture_sha256"`
	Sequence      uint64 `json:"sequence"`
	DeadlineNS    int64  `json:"deadline_ns"`
	StartedNS     int64  `json:"started_ns"`
	Authority     string `json:"authority"`
	Complete      bool   `json:"complete"`
	StartupFailed bool   `json:"startup_failed"`
	Ledger        string `json:"ledger"`
	Error         string `json:"error,omitempty"`
}

func NewCleanupFile() (*CleanupFile, error) {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 319
	case "arm64":
		number = 279
	default:
		return nil, errors.New("native cleanup has no validated memfd ABI")
	}
	name, err := syscall.BytePtrFromString("original-standard-cleanup")
	if err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall(number, uintptr(unsafe.Pointer(name)), 3, 0)
	if errno != 0 {
		return nil, errno
	}
	c := &CleanupFile{file: os.NewFile(fd, "original-standard-cleanup")}
	if err := syscall.Fstat(int(fd), &c.identity); err != nil {
		return c, err
	}
	if err := c.file.Truncate(cleanupSize); err != nil {
		return c, err
	}
	if err := c.file.Chmod(0600); err != nil {
		return c, err
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1033, 7); errno != 0 {
		return c, errno
	}
	if err := syscall.Fstat(int(fd), &c.identity); err != nil {
		return c, err
	}
	return c, c.Current()
}

// CaptureCleanupFile consumes the inherited descriptor on every outcome. A
// failed partial capture still belongs to the caller and must be closed.
func CaptureCleanupFile(file *os.File, device, inode uint64) (*CleanupFile, error) {
	c := &CleanupFile{file: file}
	if file == nil {
		return c, errors.New("native cleanup omitted original descriptor")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return c, err
	}
	var native error
	err = raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, syscall.FD_CLOEXEC)
		if errno != 0 {
			native = errno
			return
		}
		native = syscall.Fstat(int(fd), &c.identity)
	})
	if err != nil || native != nil {
		return c, errors.Join(err, native)
	}
	if c.identity.Dev != device || c.identity.Ino != inode {
		c.admission = errors.New("native cleanup descriptor differs from original sealed capture")
		return c, c.admission
	}
	return c, c.Current()
}
func (c *CleanupFile) File() *os.File {
	if c == nil {
		return nil
	}
	return c.file
}
func (c *CleanupFile) Identity() (uint64, uint64) {
	if c == nil {
		return 0, 0
	}
	return c.identity.Dev, c.identity.Ino
}
func (c *CleanupFile) Close() error {
	if c == nil || c.file == nil || c.closed {
		return nil
	}
	raw, err := c.file.SyscallConn()
	if err != nil {
		return err
	}
	var native error
	err = raw.Control(func(fd uintptr) {
		var now syscall.Stat_t
		native = syscall.Fstat(int(fd), &now)
		if native == nil && c.identity.Ino != 0 && (now.Dev != c.identity.Dev || now.Ino != c.identity.Ino) {
			native = errors.New("original cleanup close refuses a replacement descriptor")
		}
	})
	if err != nil || native != nil {
		return errors.Join(err, native)
	}
	if err := c.file.Close(); err != nil {
		return err
	}
	c.closed = true
	return nil
}

func (c *CleanupFile) Current() error {
	if c != nil && c.admission != nil {
		return c.admission
	}
	if c == nil || c.file == nil {
		return errors.New("native cleanup lost original object")
	}
	raw, err := c.file.SyscallConn()
	if err != nil {
		return err
	}
	var native error
	err = raw.Control(func(fd uintptr) {
		var now syscall.Stat_t
		if native = syscall.Fstat(int(fd), &now); native != nil {
			return
		}
		seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1034, 0)
		if errno != 0 || seals != 7 || now.Dev != c.identity.Dev || now.Ino != c.identity.Ino || now.Size != cleanupSize || now.Nlink != 0 || now.Uid != 0 || now.Gid != 0 || now.Mode != syscall.S_IFREG|0600 {
			native = errors.New("native cleanup lost original inode, size, owner or seal locks")
		}
	})
	return errors.Join(err, native)
}
func (c *CleanupFile) write(value any, offset int64, size int) error {
	if err := c.Current(); err != nil {
		return err
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) == 0 || len(body) > size-36 {
		return errors.New("native cleanup frame exceeds original bound")
	}
	frame := make([]byte, size)
	binary.LittleEndian.PutUint32(frame, uint32(len(body)))
	sum := sha256.Sum256(body)
	copy(frame[4:36], sum[:])
	copy(frame[36:], body)
	n, err := c.file.WriteAt(frame, offset)
	if err != nil || n != len(frame) {
		return errors.Join(err, io.ErrShortWrite)
	}
	return c.Current()
}
func (c *CleanupFile) read(offset int64, size int) ([]byte, error) {
	if err := c.Current(); err != nil {
		return nil, err
	}
	frame, again := make([]byte, size), make([]byte, size)
	for _, target := range [][]byte{frame, again} {
		n, err := c.file.ReadAt(target, offset)
		if err != nil || n != len(target) {
			return nil, errors.Join(err, io.ErrUnexpectedEOF)
		}
	}
	if !bytes.Equal(frame, again) {
		return nil, errors.New("native cleanup frame changed during readback")
	}
	count := int(binary.LittleEndian.Uint32(frame))
	if count < 1 || count > size-36 {
		return nil, errors.New("native cleanup frame is absent or malformed")
	}
	body := frame[36 : 36+count]
	sum := sha256.Sum256(body)
	if !bytes.Equal(frame[4:36], sum[:]) || !bytes.Equal(frame[36+count:], make([]byte, size-36-count)) {
		return nil, errors.New("native cleanup frame is incomplete or torn")
	}
	return body, c.Current()
}
func (r CleanupRequest) valid() bool {
	return r.Schema == 1 && digest(r.CaptureSHA256, 32) && r.Sequence > 0 && r.DeadlineNS > 0
}
func (r CleanupResult) valid() bool {
	if r.Schema != 1 || !digest(r.CaptureSHA256, 32) || r.DeadlineNS <= 0 || r.StartedNS <= 0 || r.Complete != (r.Error == "") || len(r.Error) > 256 || len(r.Ledger) > 48<<10 || r.Complete && (r.Ledger == "" || r.StartedNS > r.DeadlineNS) {
		return false
	}
	authority, bound := "request", 15*time.Second
	if r.Sequence == 0 {
		authority, bound = "signal", 4*time.Second
		if r.StartupFailed {
			authority = "startup"
		}
	}
	return r.Authority == authority && (r.DeadlineNS <= r.StartedNS || r.DeadlineNS-r.StartedNS <= int64(bound))
}

func (c *CleanupFile) WriteRequest(r CleanupRequest) error {
	if !r.valid() {
		return errors.New("native cleanup request has no original bounded identity")
	}
	return c.write(r, 0, cleanupRequestSize)
}
func (c *CleanupFile) ReadRequest(expected string) (CleanupRequest, error) {
	var r CleanupRequest
	body, err := c.read(0, cleanupRequestSize)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(body, &r) != nil || !r.valid() || r.CaptureSHA256 != expected {
		return r, errors.New("native cleanup request changed original capture")
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(body, canonical) {
		return r, errors.New("native cleanup request is not canonical")
	}
	return r, nil
}
func (c *CleanupFile) WriteResult(r CleanupResult) error {
	if !r.valid() {
		return errors.New("native cleanup result has no actual complete disposition")
	}
	return c.write(r, cleanupRequestSize, cleanupSize-cleanupRequestSize)
}
func (c *CleanupFile) ReadResult(expected string) (CleanupResult, error) {
	var r CleanupResult
	body, err := c.read(cleanupRequestSize, cleanupSize-cleanupRequestSize)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(body, &r) != nil || !r.valid() || r.CaptureSHA256 != expected {
		return r, errors.New("native cleanup result changed original capture")
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(body, canonical) {
		return r, errors.New("native cleanup result is not canonical")
	}
	return r, nil
}
