//go:build linux

// Package systembootstrap captures the existing system resolver for one outer
// VPN endpoint. It never selects a provider or changes the tunnel's DNS policy.
package systembootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type source struct {
	path, target string
	named        os.FileInfo
	file         *os.File
	info         os.FileInfo
	body         []byte
	missing      bool
}
type Capture struct {
	hostname                                  string
	machineName                               string
	usesMachineName                           bool
	sources                                   []source
	order                                     []string
	hosts                                     []netip.Addr
	hostsErr                                  error
	servers                                   []netip.AddrPort
	search                                    []string
	ndots, attempts                           int
	timeout                                   time.Duration
	tcp, rotate, noAAAA, trustAD, edns, noTLD bool
	digest                                    string
	ownerUID                                  uint32
	strictParents                             bool
	closed                                    bool
}

func CaptureSystem(ctx context.Context, hostname string) (*Capture, error) {
	for _, key := range []string{"LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES"} {
		if os.Getenv(key) != "" {
			return nil, fmt.Errorf("system bootstrap requires original unsupported %s resolver override", key)
		}
	}
	return capturePolicy(ctx, hostname, [3]string{"/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf"}, 0, true)
}

// CaptureFiles retains explicit protected sources. Production supplies only the
// fixed machine NSS, hosts and resolver paths; requests never supply these paths.
func CaptureFiles(ctx context.Context, hostname string, paths [3]string) (*Capture, error) {
	return capturePolicy(ctx, hostname, paths, 0, true)
}

func trustedParents(path string, ownerUID uint32) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || st.Uid != ownerUID || info.Mode().Perm()&0022 != 0 {
			return errors.New("system resolver has an untrusted parent")
		}
		if dir == "/" {
			return nil
		}
	}
}
func readSource(ctx context.Context, path string, optional bool, ownerUID uint32, strict bool) (out source, failure error) {
	out.path = path
	if ctx == nil || ctx.Err() != nil {
		return out, errors.New("system bootstrap omitted original live context")
	}
	if strict {
		if err := trustedParents(path, ownerUID); err != nil {
			return out, err
		}
	}
	named, err := os.Lstat(path)
	if optional && errors.Is(err, os.ErrNotExist) {
		out.missing = true
		return out, nil
	}
	if err != nil {
		return out, err
	}
	st, ok := named.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID {
		return out, errors.New("system resolver named source is not original owner")
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return out, err
	}
	if strict {
		if err = trustedParents(target, ownerUID); err != nil {
			return out, err
		}
	}
	fd, err := syscall.Open(target, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return out, err
	}
	out.file = os.NewFile(uintptr(fd), target)
	defer func() {
		if failure != nil {
			_ = out.file.Close()
			out.file = nil
		}
	}()
	info, err := out.file.Stat()
	if err != nil {
		return out, err
	}
	st, ok = info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ownerUID || !info.Mode().IsRegular() || info.Size() > 256<<10 || info.Mode().Perm()&0022 != 0 {
		return out, errors.New("system resolver source is not a bounded protected regular file")
	}
	body, err := io.ReadAll(io.LimitReader(out.file, 256<<10+1))
	if err != nil || len(body) > 256<<10 {
		return out, errors.Join(err, errors.New("system resolver source exceeds bound"))
	}
	out.named, out.target, out.info, out.body = named, target, info, body
	return out, out.current(ctx, ownerUID, strict)
}
func (s *source) current(ctx context.Context, uid uint32, strict bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strict {
		if err := trustedParents(s.path, uid); err != nil {
			return err
		}
	}
	named, err := os.Lstat(s.path)
	if s.missing {
		if errors.Is(err, os.ErrNotExist) {
			return ctx.Err()
		}
		return errors.Join(err, errors.New("missing system resolver source appeared"))
	}
	if err != nil || !os.SameFile(named, s.named) || s.file == nil {
		return errors.Join(err, errors.New("system resolver original source was replaced or closed"))
	}
	st, ok := named.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid {
		return errors.New("system resolver source ownership changed")
	}
	target, err := filepath.EvalSymlinks(s.path)
	if err != nil || target != s.target {
		return errors.Join(err, errors.New("system resolver source link changed"))
	}
	if strict {
		if err = trustedParents(target, uid); err != nil {
			return err
		}
	}
	actual, err := os.Lstat(target)
	if err != nil || !os.SameFile(actual, s.info) {
		return errors.Join(err, errors.New("system resolver target was replaced"))
	}
	st, ok = actual.Sys().(*syscall.Stat_t)
	if !ok || !actual.Mode().IsRegular() || st.Uid != uid || actual.Mode().Perm()&0022 != 0 {
		return errors.New("system resolver target lost protection")
	}
	body, err := io.ReadAll(io.NewSectionReader(s.file, 0, 256<<10+1))
	if err != nil || !bytes.Equal(body, s.body) {
		return errors.Join(err, errors.New("system resolver original contents changed"))
	}
	return ctx.Err()
}
func (c *Capture) Current(ctx context.Context) error {
	if c == nil || ctx == nil || c.closed {
		return errors.New("missing captured system bootstrap")
	}
	if c.usesMachineName {
		name, err := os.Hostname()
		if err != nil || name != c.machineName {
			return errors.Join(err, errors.New("captured system DNS default search hostname changed"))
		}
	}
	for i := range c.sources {
		if err := c.sources[i].current(ctx, c.ownerUID, c.strictParents); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (c *Capture) Close() error {
	var failure error
	if c != nil {
		for i := range c.sources {
			v := &c.sources[i]
			if v.file != nil {
				if err := v.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					failure = errors.Join(failure, err)
				} else {
					v.file = nil
				}
			}
		}
	}
	if c != nil && failure == nil {
		c.closed = true
	}
	return failure
}
func (c *Capture) SHA256() string {
	if c == nil {
		return ""
	}
	return c.digest
}
func validName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, v := range label {
			if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || v == '-') {
				return false
			}
		}
	}
	return true
}
func contentLines(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
func capture(ctx context.Context, hostname string, paths [3]string, ownerUID uint32) (*Capture, error) {
	return capturePolicy(ctx, hostname, paths, ownerUID, false)
}
func capturePolicy(ctx context.Context, hostname string, paths [3]string, ownerUID uint32, strict bool) (result *Capture, failure error) {
	if !validName(hostname) || strings.HasSuffix(strings.ToLower(strings.TrimSuffix(hostname, ".")), ".onion") {
		return nil, errors.New("system bootstrap requires one ordinary outer endpoint hostname")
	}
	c := &Capture{strictParents: strict, ownerUID: ownerUID, hostname: strings.ToLower(hostname), order: []string{"files", "dns"}, ndots: 1, attempts: 2, timeout: 5 * time.Second}
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, c.Close())
		}
	}()
	for _, path := range paths[:2] {
		v, err := readSource(ctx, path, true, ownerUID, strict)
		if err != nil {
			return nil, err
		}
		c.sources = append(c.sources, v)
	}
	finish := func() (*Capture, error) {
		hash := sha256.New()
		for _, v := range c.sources {
			hash.Write([]byte(v.path))
			hash.Write([]byte{0})
			hash.Write(v.body)
			hash.Write([]byte{0})
		}
		hash.Write([]byte(c.hostname))
		hash.Write([]byte(c.machineName))
		c.digest = hex.EncodeToString(hash.Sum(nil))
		return c, c.Current(ctx)
	}
	var nssErr error
	found := false
	for _, line := range contentLines(c.sources[0].body) {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "hosts" {
			continue
		}
		if found {
			return nil, errors.New("system NSS hosts order is ambiguous")
		}
		found = true
		c.order = strings.Fields(value)
		if len(c.order) < 1 || len(c.order) > 2 {
			nssErr = errors.New("system bootstrap does not support this NSS hosts transport or action")
		}
		seen := map[string]bool{}
		for _, v := range c.order {
			if v != "files" && v != "dns" || seen[v] {
				nssErr = errors.New("system bootstrap does not support this NSS hosts transport or action")
			}
			seen[v] = true
		}
	}
	for _, line := range contentLines(c.sources[1].body) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, name := range fields[1:] {
			if strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(c.hostname, ".")) {
				if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" {
					c.hostsErr = errors.New("captured endpoint hosts entry is not usable unicast")
					break
				}
				c.hosts = append(c.hosts, ip)
				break
			}
		}
		if len(c.hosts) > 32 {
			c.hostsErr = errors.New("captured endpoint hosts entries exceed bound")
			break
		}
	}
	// An exact files-first success uses NSS's default SUCCESS=return even
	// when a later, unreachable module is unsupported. An action immediately
	// following files can change that disposition and is never guessed.
	if len(c.order) > 0 && c.order[0] == "files" && (len(c.order) == 1 || !strings.HasPrefix(c.order[1], "[")) && (len(c.hosts) > 0 || c.hostsErr != nil) {
		c.order = []string{"files"}
		return finish()
	}
	if nssErr != nil {
		return nil, nssErr
	}
	// A files-first hit (or files-only order) does not consult resolv.conf.
	if c.order[0] == "files" && (len(c.hosts) > 0 || c.hostsErr != nil || len(c.order) == 1) {
		return finish()
	}
	resolver, err := readSource(ctx, paths[2], false, ownerUID, strict)
	if err != nil {
		return nil, err
	}
	c.sources = append(c.sources, resolver)
	for _, line := range contentLines(c.sources[2].body) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) != 2 || len(c.servers) >= 3 {
				return nil, errors.New("system nameserver configuration exceeds supported bound")
			}
			ip, err := netip.ParseAddr(fields[1])
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || ip.Is4In6() {
				return nil, errors.New("system bootstrap requires an exact literal DNS upstream")
			}
			if ip.IsLoopback() {
				return nil, errors.New("system resolver stub requires its original split-DNS/transport authority; direct bootstrap cannot flatten it")
			}
			c.servers = append(c.servers, netip.AddrPortFrom(ip, 53))
		case "domain", "search":
			if len(fields) < 2 || len(fields) > 7 || fields[0] == "domain" && len(fields) != 2 {
				return nil, errors.New("system DNS search list exceeds supported bound")
			}
			c.search = nil
			for _, name := range fields[1:] {
				if name != "." && !validName(name) {
					return nil, errors.New("system DNS search domain is invalid")
				}
				c.search = append(c.search, strings.TrimSuffix(strings.ToLower(name), "."))
			}
		case "options":
			for _, option := range fields[1:] {
				key, value, colon := strings.Cut(option, ":")
				if colon && key != "ndots" && key != "timeout" && key != "attempts" {
					return nil, errors.New("system DNS flag has unexpected option value")
				}
				switch key {
				case "ndots", "timeout", "attempts":
					n, err := strconv.Atoi(value)
					if !colon || err != nil || n < 0 {
						return nil, errors.New("system DNS option is invalid")
					}
					switch key {
					case "ndots":
						if n > 15 {
							n = 15
						}
						c.ndots = n
					case "timeout":
						if n < 1 {
							n = 1
						}
						if n > 30 {
							n = 30
						}
						c.timeout = time.Duration(n) * time.Second
					case "attempts":
						if n < 1 {
							n = 1
						}
						if n > 5 {
							n = 5
						}
						c.attempts = n
					}
				case "use-vc", "usevc", "tcp":
					c.tcp = true
				case "rotate":
					c.rotate = true
				case "no-aaaa":
					c.noAAAA = true
				case "trust-ad":
					c.trustAD = true
				case "edns0":
					c.edns = true
				case "no-tld-query":
					c.noTLD = true
				case "single-request", "single-request-reopen": // Requests below are already sequential and use separate sockets.
				default:
					return nil, fmt.Errorf("system DNS option %q requires its original unsupported resolver behavior", key)
				}
			}
		case "sortlist":
			return nil, errors.New("system DNS sortlist requires its original resolver ordering")
		default:
			return nil, fmt.Errorf("system DNS directive %q is unsupported", fields[0])
		}
	}
	if len(c.search) == 0 {
		name, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		c.machineName, c.usesMachineName = name, true
		if _, domain, ok := strings.Cut(name, "."); ok && domain != "" {
			if !validName(domain) {
				return nil, errors.New("system default search domain is invalid")
			}
			c.search = []string{strings.TrimSuffix(strings.ToLower(domain), ".")}
		}
	}
	dns := false
	for _, v := range c.order {
		dns = dns || v == "dns"
	}
	if dns && len(c.servers) == 0 {
		return nil, errors.New("system DNS omitted a direct upstream; implicit localhost fallback is unsupported")
	}
	return finish()
}
func (c *Capture) names() []string {
	host := strings.TrimSuffix(c.hostname, ".")
	if strings.HasSuffix(c.hostname, ".") {
		return []string{host}
	}
	var names []string
	first := strings.Count(host, ".") >= c.ndots
	if first {
		names = append(names, host)
	}
	for _, domain := range c.search {
		candidate := host + "." + domain
		if validName(candidate) {
			names = append(names, candidate)
		}
	}
	if !first && (!c.noTLD || strings.Contains(host, ".")) {
		names = append(names, host)
	}
	return names
}

// Servers returns only the captured direct OS DNS literals, never Home DNS.
func (c *Capture) Servers() []netip.AddrPort {
	if c == nil {
		return nil
	}
	return append([]netip.AddrPort(nil), c.servers...)
}
func (c *Capture) RequiresDNS() bool {
	if c == nil {
		return false
	}
	if c.order[0] == "files" && (len(c.hosts) > 0 || c.hostsErr != nil) {
		return false
	}
	for _, method := range c.order {
		if method == "dns" {
			return true
		}
	}
	return false
}
