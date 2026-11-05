//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// These are machine transport-bootstrap sources, not selected tunnel DNS.
// A local stub is never authority to exempt the resolver daemon's sockets.
type linuxBootResolverFile struct {
	path, target    string
	named, original os.FileInfo
	file            *os.File
	digest          [32]byte
}
type linuxBootResolver struct {
	sources []*linuxBootResolverFile
	servers []netip.Addr
}

func linuxBootResolverTrusted(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && info.Mode().Perm()&0022 == 0
}
func linuxBootResolverParents(path string) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, e := os.Lstat(dir)
		if e != nil {
			return e
		}
		if !info.IsDir() || !linuxBootResolverTrusted(info) {
			return errors.New("bootstrap resolver has an untrusted parent")
		}
		if dir == "/" {
			return nil
		}
	}
}
func captureLinuxBootResolverFile(ctx context.Context, path string) (*linuxBootResolverFile, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return nil, nil, errors.New("bootstrap resolver path is not absolute")
	}
	if e := linuxBootResolverParents(path); e != nil {
		return nil, nil, e
	}
	named, e := os.Lstat(path)
	if e != nil {
		return nil, nil, e
	}
	st, ok := named.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || named.Mode()&os.ModeSymlink == 0 && !linuxBootResolverTrusted(named) {
		return nil, nil, errors.New("bootstrap resolver source is not root owned")
	}
	target, e := filepath.EvalSymlinks(path)
	if e != nil {
		return nil, nil, e
	}
	if e = linuxBootResolverParents(target); e != nil {
		return nil, nil, e
	}
	fd, e := syscall.Open(target, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, nil, e
	}
	f := os.NewFile(uintptr(fd), target)
	original, e := f.Stat()
	if e != nil || !original.Mode().IsRegular() || !linuxBootResolverTrusted(original) {
		f.Close()
		return nil, nil, errors.Join(e, errors.New("bootstrap resolver lost its trusted regular source"))
	}
	body, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || len(body) > 64<<10 {
		f.Close()
		return nil, nil, errors.Join(e, errors.New("bootstrap resolver source exceeds its bound"))
	}
	s := &linuxBootResolverFile{path: path, target: target, named: named, original: original, file: f, digest: sha256.Sum256(body)}
	if e = s.current(ctx); e != nil {
		f.Close()
		return nil, nil, e
	}
	return s, body, nil
}
func (s *linuxBootResolverFile) current(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s == nil || s.file == nil {
		return errors.New("bootstrap resolver source is closed")
	}
	named, e := os.Lstat(s.path)
	if e != nil || !os.SameFile(named, s.named) {
		return errors.Join(e, errors.New("bootstrap resolver source was replaced"))
	}
	namedStat, ok := named.Sys().(*syscall.Stat_t)
	if !ok || namedStat.Uid != 0 {
		return errors.New("bootstrap resolver source ownership changed")
	}
	target, e := filepath.EvalSymlinks(s.path)
	if e != nil || target != s.target {
		return errors.Join(e, errors.New("bootstrap resolver link changed"))
	}
	if e = linuxBootResolverParents(s.path); e != nil {
		return e
	}
	if e = linuxBootResolverParents(target); e != nil {
		return e
	}
	actual, e := os.Lstat(target)
	if e != nil || !os.SameFile(actual, s.original) || !linuxBootResolverTrusted(actual) {
		return errors.Join(e, errors.New("bootstrap resolver target changed"))
	}
	body, e := io.ReadAll(io.NewSectionReader(s.file, 0, 64<<10+1))
	if e != nil || len(body) > 64<<10 || sha256.Sum256(body) != s.digest {
		return errors.Join(e, errors.New("bootstrap resolver contents changed"))
	}
	return ctx.Err()
}
func linuxBootResolverServers(body []byte) ([]netip.Addr, bool, error) {
	var servers []netip.Addr
	stub := false
	seen := map[netip.Addr]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0]
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) != 2 {
			return nil, false, errors.New("invalid configured bootstrap nameserver")
		}
		ip, e := netip.ParseAddr(fields[1])
		if e != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, false, errors.New("bootstrap nameserver is not a captured literal")
		}
		if ip.IsLoopback() {
			if ip.String() != "127.0.0.53" && ip.String() != "127.0.0.54" {
				return nil, false, errors.New("local DNS stub has no owned upstream socket authority")
			}
			stub = true
			continue
		}
		if !ip.IsGlobalUnicast() {
			return nil, false, errors.New("bootstrap nameserver is not unicast")
		}
		if !seen[ip] {
			seen[ip] = true
			servers = append(servers, ip)
		}
		if len(servers) > 8 {
			return nil, false, errors.New("configured bootstrap resolver inventory exceeds its bound")
		}
	}
	if stub && len(servers) != 0 {
		return nil, false, errors.New("mixed stub and direct bootstrap sources are ambiguous")
	}
	if !stub && len(servers) == 0 {
		return nil, false, errors.New("no configured literal bootstrap resolver")
	}
	return servers, stub, nil
}
func captureLinuxBootResolver(ctx context.Context) (*linuxBootResolver, error) {
	return captureLinuxBootResolverAt(ctx, "/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf", "/run/systemd/resolve/resolv.conf")
}
func captureLinuxBootResolverAt(ctx context.Context, path, stubPath, upstreamPath string) (result *linuxBootResolver, failure error) {
	result = &linuxBootResolver{}
	defer func() {
		if failure != nil {
			result.close()
			result = nil
		}
	}()
	source, body, e := captureLinuxBootResolverFile(ctx, path)
	if e != nil {
		return result, e
	}
	result.sources = append(result.sources, source)
	servers, stub, e := linuxBootResolverServers(body)
	if e != nil {
		return result, e
	}
	if stub {
		if source.target != stubPath {
			return result, errors.New("local stub is not the captured systemd resolver source")
		}
		upstream, body, e := captureLinuxBootResolverFile(ctx, upstreamPath)
		if e != nil {
			return result, e
		}
		result.sources = append(result.sources, upstream)
		var nested bool
		servers, nested, e = linuxBootResolverServers(body)
		if e != nil || nested {
			return result, errors.Join(e, errors.New("systemd upstream inventory still contains a stub"))
		}
	}
	result.servers = servers
	return result, result.current(ctx)
}
func (r *linuxBootResolver) current(ctx context.Context) error {
	if r == nil || len(r.sources) == 0 || len(r.servers) == 0 {
		return errors.New("bootstrap resolver capture is incomplete")
	}
	for _, s := range r.sources {
		if e := s.current(ctx); e != nil {
			return e
		}
	}
	return ctx.Err()
}
func (r *linuxBootResolver) close() error {
	var failure error
	if r != nil {
		for _, s := range r.sources {
			if s.file != nil {
				if e := s.file.Close(); e != nil && !errors.Is(e, os.ErrClosed) {
					failure = errors.Join(failure, e)
				} else {
					s.file = nil
				}
			}
		}
	}
	return failure
}
