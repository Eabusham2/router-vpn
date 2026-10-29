//go:build darwin

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Tagged native tests use their own root-owned directory in the compiled test
// executable. The shipping command has no argument or environment override.
// /private/var/run is group-writable on supported macOS installations. Keep
// allocator and crash-quarantine authority under the protected install prefix
// rather than accepting a mutable ancestor or changing a system directory.
var desktopDarwinIdentities = "/opt/router-vpn-physical"

func desktopDarwinProtectedPath(path string, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("Darwin privileged path is not canonical")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("Darwin privileged path has no native ownership metadata: %q", current)
		}
		// macOS runtime directories can have a read-only daemon group, and
		// children inherit that group. Only root ownership and the effective
		// mutation/read permissions establish authority; a non-wheel group
		// does not grant access when its mode bits and ACL do not allow it.
		if stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 ||
			info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || current != path && !info.IsDir() ||
			current == path && private && info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("Darwin privileged path has unowned mutation authority: %q (uid=%d gid=%d mode=%#o)", current, stat.Uid, stat.Gid, info.Mode().Perm())
		}
		if !info.IsDir() && (!info.Mode().IsRegular() || stat.Nlink != 1) {
			return errors.New("Darwin privileged path is linked or not a regular file")
		}
		if err := desktopDarwinPathACL(current); err != nil {
			return err
		}
		if current == "/" {
			return nil
		}
	}
}

func desktopDarwinExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	if err := desktopDarwinProtectedPath(path, false); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("Darwin physical native helper is not an owned executable")
	}
	return path, nil
}

type desktopDarwinCommandBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *desktopDarwinCommandBuffer) Len() int       { return b.buffer.Len() }
func (b *desktopDarwinCommandBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *desktopDarwinCommandBuffer) String() string { return b.buffer.String() }

func (b *desktopDarwinCommandBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.Len()
	if len(value) > remaining {
		n, _ := b.buffer.Write(value[:remaining])
		return n, errors.New("Darwin privileged command exceeded its readback bound")
	}
	return b.buffer.Write(value)
}

func desktopDarwinCommand(ctx context.Context, path string, input []byte, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, context.Canceled
	}
	if err := desktopDarwinProtectedPath(path, false); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "GORACE=atexit_sleep_ms=0"}
	command.Stdin = bytes.NewReader(input)
	output, diagnostics := desktopDarwinCommandBuffer{limit: 2 << 20}, desktopDarwinCommandBuffer{limit: 128 << 10}
	command.Stdout, command.Stderr = &output, &diagnostics
	err := command.Run()
	if output.Len() > 2<<20 || diagnostics.Len() > 128<<10 {
		return nil, errors.New("Darwin privileged command exceeded its readback bound")
	}
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("Darwin privileged %s failed: %s", filepath.Base(path), diagnostics.String()))
	}
	return output.Bytes(), nil
}

func desktopDarwinIdentityLock() (*os.File, error) {
	if err := os.Mkdir(desktopDarwinIdentities, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := desktopDarwinProtectedPath(desktopDarwinIdentities, true); err != nil {
		return nil, err
	}
	path := filepath.Join(desktopDarwinIdentities, "allocator.lock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = desktopDarwinProtectedPath(path, true); err == nil {
		var actual os.FileInfo
		actual, err = file.Stat()
		if err == nil {
			var named os.FileInfo
			named, err = os.Lstat(path)
			if err == nil && !os.SameFile(actual, named) {
				err = errors.New("Darwin physical allocator lock changed its object")
			}
		}
	}
	if err == nil {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func desktopDarwinAccountRecord(account string, uid uint32) (map[string]string, error) {
	if !strings.HasPrefix(account, "_rvpnt_") || !desktopSocketHex(strings.TrimPrefix(account, "_rvpnt_"), 20) || uid < 0x40000000 || uid >= 0x80000000 {
		return nil, errors.New("Darwin physical account identity is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	args := append([]string{"/Local/Default", "-read", "/Users/" + account}, desktopDarwinAccountAttributes...)
	raw, err := desktopDarwinCommand(ctx, "/usr/bin/dscl", nil, args...)
	if err != nil {
		return nil, err
	}
	values, err := desktopDarwinParseAccountRecord(raw, account, uid)
	if err != nil {
		return nil, err
	}
	search, err := desktopDarwinCommand(ctx, "/usr/bin/dscl", nil, "/Local/Default", "-search", "/Users", "UniqueID", strconv.FormatUint(uint64(uid), 10))
	if err != nil || strings.Join(strings.Fields(string(search)), " ") != account+" "+strconv.FormatUint(uint64(uid), 10) || !desktopDarwinUIDAccount(uid, account) {
		return nil, errors.New("Darwin physical UID has another local or directory owner")
	}
	return values, nil
}

func desktopDarwinVerifyAccount(account string, uid uint32) error {
	values, err := desktopDarwinAccountRecord(account, uid)
	if err != nil {
		return err
	}
	path := filepath.Join(desktopDarwinIdentities, account)
	if err := desktopDarwinProtectedPath(path, true); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return errors.New("Darwin physical recovery ownership is missing")
	}
	var record desktopDarwinIdentityRecord
	if json.Unmarshal(raw, &record) != nil || !record.Capture.valid() || record.UID != uid || record.Account != account || record.GeneratedUID != values["GeneratedUID"] || record.GuardianPID <= 1 {
		return errors.New("Darwin physical account differs from its private recovery capture")
	}
	return nil
}

type desktopDarwinIdentityRecord struct {
	Capture      DesktopSocketCapture
	UID          uint32
	Account      string
	GeneratedUID string
	GuardianPID  int
}

func desktopDarwinAllocateAccount(c DesktopSocketCapture) (string, uint32, error) {
	lock, err := desktopDarwinIdentityLock()
	if err != nil {
		return "", 0, err
	}
	defer lock.Close()
	for attempts := 0; attempts < 16; attempts++ {
		var random [30]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", 0, err
		}
		uid := uint32(0x40000000) | (binary.BigEndian.Uint32(random[:4]) & 0x3fffffff)
		if !desktopDarwinUIDAvailable(uid) || desktopDarwinNoUIDProcesses(uid) != nil {
			continue
		}
		account := "_rvpnt_" + hex.EncodeToString(random[4:14])
		uuid := strings.ToUpper(hex.EncodeToString(random[14:]))
		uuid = uuid[:8] + "-" + uuid[8:12] + "-" + uuid[12:16] + "-" + uuid[16:20] + "-" + uuid[20:]
		path := filepath.Join(desktopDarwinIdentities, account)
		record, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", 0, err
		}
		encoded, _ := json.Marshal(desktopDarwinIdentityRecord{c, uid, account, uuid, os.Getpid()})
		_, writeErr := record.Write(encoded)
		syncErr, closeErr := record.Sync(), record.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return "", 0, err
		}
		// The private recovery record precedes every account mutation. Any
		// partial/unknown creation remains quarantined; it is never guessed away.
		attributes := [][2]string{{"Password", "*"}, {"AuthenticationAuthority", ";DisabledUser;"}, {"UserShell", "/usr/bin/false"}, {"NFSHomeDirectory", "/var/empty"}, {desktopDarwinHiddenAttribute, "1"}, {"PrimaryGroupID", "65534"}, {"GeneratedUID", uuid}, {"UniqueID", strconv.FormatUint(uint64(uid), 10)}}
		for _, pair := range attributes {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err = desktopDarwinCommand(ctx, "/usr/bin/dscl", nil, "/Local/Default", "-create", "/Users/"+account, pair[0], pair[1])
			cancel()
			if err != nil {
				return "", 0, err
			}
		}
		if err := desktopDarwinVerifyAccount(account, uid); err != nil {
			return "", 0, err
		}
		return account, uid, nil
	}
	return "", 0, errors.New("Darwin guardian could not allocate an unused isolated identity")
}

func desktopDarwinRetireAccount(account string, uid uint32) error {
	lock, err := desktopDarwinIdentityLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := desktopDarwinVerifyAccount(account, uid); err != nil {
		return err
	}
	if err := desktopDarwinNoUIDProcesses(uid); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := desktopDarwinCommand(ctx, "/usr/bin/dscl", nil, "/Local/Default", "-delete", "/Users/"+account); err != nil {
		return err
	}
	if !desktopDarwinUIDAvailable(uid) {
		return errors.New("Darwin physical identity retirement has no independent absent readback")
	}
	return os.Remove(filepath.Join(desktopDarwinIdentities, account))
}
