//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"router-vpn/internal/mobilemtu"
)

// History is separate from the active source profile. Its bounded v3 document,
// TTL and eviction rules are shared with mobile MTU; none is current proof.
type linuxStandardMTUCache struct {
	path      string
	directory os.FileInfo
	mu        *sync.Mutex
}

var linuxStandardMTUCacheLocks sync.Map

func openLinuxStandardMTUCache(ctx context.Context, directory string) (*linuxStandardMTUCache, error) {
	if ctx == nil || !filepath.IsAbs(directory) {
		return nil, errors.New("MTU history requires its original private directory")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "mtu-history-v3.json")
	if err := validatePrivateParent(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("MTU history directory was replaced"))
	}
	mu, _ := linuxStandardMTUCacheLocks.LoadOrStore(path, &sync.Mutex{})
	return &linuxStandardMTUCache{path: path, directory: info, mu: mu.(*sync.Mutex)}, ctx.Err()
}
func (c *linuxStandardMTUCache) current(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Dir(c.path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, c.directory) {
		return errors.Join(err, errors.New("MTU history lost its original directory"))
	}
	return ctx.Err()
}
func (c *linuxStandardMTUCache) enter(ctx context.Context) (func(), error) {
	if err := mobilemtu.LockContext(ctx, c.mu); err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { c.mu.Unlock(); return nil, err }
	if err := c.current(ctx); err != nil {
		return fail(err)
	}
	// The process mutex and original private lock file serialize CAS across
	// readers, replacement sessions and separately launched controller processes.
	fd, err := syscall.Open(c.path+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fail(err)
	}
	file := os.NewFile(uintptr(fd), c.path+".lock")
	closeFail := func(err error) (func(), error) { _ = file.Close(); return fail(err) }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return closeFail(errors.Join(err, errors.New("MTU history lock is not private")))
	}
	for {
		if err := ctx.Err(); err != nil {
			return closeFail(err)
		}
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return closeFail(err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return closeFail(ctx.Err())
		case <-timer.C:
		}
	}
	named, err := os.Lstat(c.path + ".lock")
	if err != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, named) {
		return closeFail(errors.Join(err, errors.New("MTU history lock was replaced")))
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close(); c.mu.Unlock() }, nil
}
func (*linuxStandardMTUCache) Lookup(string) (int, bool) { return 0, false }
func (*linuxStandardMTUCache) Save(string, int, func() bool) error {
	return errors.New("MTU history requires its captured operation context")
}
func (c *linuxStandardMTUCache) LookupContext(ctx context.Context, key string) (int, bool, error) {
	release, err := c.enter(ctx)
	if err != nil {
		return 0, false, err
	}
	defer release()
	store := &linuxStandardMTUPreferences{cache: c, ctx: ctx}
	mtu, found := mobilemtu.NewCache(store).Lookup(key)
	return mtu, found, errors.Join(store.failure, ctx.Err())
}
func (c *linuxStandardMTUCache) SaveContext(ctx context.Context, key string, mtu int, valid func(context.Context) error) error {
	if valid == nil {
		return errors.New("MTU history has no original path validator")
	}
	if err := valid(ctx); err != nil {
		return err
	}
	release, err := c.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	store := &linuxStandardMTUPreferences{cache: c, ctx: ctx}
	var validation error
	err = mobilemtu.NewCache(store).Save(key, mtu, func() bool { validation = valid(ctx); return validation == nil })
	return errors.Join(err, validation, store.failure, ctx.Err())
}

// One synchronous cache transaction owns this store. Cancellation can restore
// only bytes it wrote, using the accepted operation's existing cleanup budget.
type linuxStandardMTUPreferences struct {
	cache           *linuxStandardMTUCache
	ctx             context.Context
	before, written string
	wrote           bool
	failure         error
}

func (s *linuxStandardMTUPreferences) read(ctx context.Context) (string, error) {
	if err := s.cache.current(ctx); err != nil {
		return "", err
	}
	raw, err := readPrivateRegular(s.cache.path, 64<<10)
	if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		return "", err
	}
	if err = s.cache.current(ctx); err != nil {
		return "", err
	}
	return string(raw), nil
}
func (s *linuxStandardMTUPreferences) ReadMTUCache() (string, error) {
	raw, err := s.read(s.ctx)
	s.failure = errors.Join(s.failure, err)
	return raw, err
}
func (s *linuxStandardMTUPreferences) CompareAndSwapMTUCache(before, next string) (changed bool, failure error) {
	defer func() { s.failure = errors.Join(s.failure, failure) }()
	ctx := s.ctx
	rollback := s.wrote && before == s.written && next == s.before
	if rollback {
		var err error
		ctx, err = mobilemtu.OperationCleanupContext(s.ctx)
		if err != nil {
			return false, err
		}
	}
	current, err := s.read(ctx)
	if err != nil {
		return false, err
	}
	if current != before {
		return false, nil
	}
	_, err = atomicWritePrivateChecked(s.cache.path, []byte(next), func() error {
		current, err := s.read(ctx)
		if err != nil {
			return err
		}
		if current != before {
			return errors.New("newer MTU history retained")
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if !rollback {
		s.wrote, s.before, s.written = true, before, next
	}
	return true, nil
}
