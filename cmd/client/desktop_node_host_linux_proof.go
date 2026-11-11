//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

const linuxNodeProofBindToIfIndex = 62 // Linux asm-generic/socket.h SO_BINDTOIFINDEX.

func desktopLinuxNodeProofBoundName(fd int) (string, error) {
	var name [16]byte
	size := uint32(len(name))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE,
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return "", errno
	}
	if size == 0 || size > uint32(len(name)) || name[size-1] != 0 {
		return "", errors.New("Linux Router proof has no bounded terminated device readback")
	}
	return string(name[:size-1]), nil
}

// Only the retained host can create this result after the actual HTTP exchange
// and both native observations. It grants no independent activation authority.
type desktopLinuxNodeProof struct {
	ready    mobilemultihop.DesktopNodeReadyRecord
	live     desktopNodeMTURecord
	provedAt time.Time
	elapsed  time.Duration
}

func desktopLinuxNodeProofTarget(profile common.RouterProfile) (*url.URL, netip.AddrPort, error) {
	target := strings.TrimSpace(profile.PathProbeURL)
	if target == "" {
		target = strings.TrimRight(strings.TrimSpace(profile.RouterAPI), "/") + "/health"
	}
	u, err := url.Parse(target)
	if err != nil || u == nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, netip.AddrPort{}, errors.New("Linux Router proof requires its captured private HTTP target")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	port, portErr := strconv.Atoi(u.Port())
	if err != nil || portErr != nil || port < 1 || port > 65535 || ip.String() != u.Hostname() || ip.Is4In6() ||
		ip.Zone() != "" || !ip.IsPrivate() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		profile.IPv6Mode == "off" && !ip.Is4() {
		return nil, netip.AddrPort{}, errors.New("Linux Router proof requires its exact private literal endpoint and port")
	}
	return u, netip.AddrPortFrom(ip, uint16(port)), nil
}

// SO_BINDTOIFINDEX captures the kernel interface directly; it cannot resolve a
// reused interface name to a different device. Both index and name are read
// back before connect, with the same live interface checked around the call.
// No physical socket exception or ordinary-network DNS lookup is introduced.
func bindDesktopLinuxNodeProofSocket(ctx context.Context, network string, raw syscall.RawConn, live desktopNodeMTURecord) error {
	if ctx == nil || ctx.Err() != nil || raw == nil || network != "tcp4" && network != "tcp6" {
		return errors.New("Linux Router proof socket has no bounded original TCP owner")
	}
	if err := desktopLinuxNodeTUNCurrent(live); err != nil {
		return err
	}
	var failure error
	err := raw.Control(func(fd uintptr) {
		if ctx.Err() != nil {
			failure = ctx.Err()
			return
		}
		kind, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil || kind != syscall.SOCK_STREAM {
			failure = errors.Join(err, errors.New("Linux Router proof changed its actual TCP socket"))
			return
		}
		family, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_DOMAIN)
		if err != nil || network == "tcp4" && family != syscall.AF_INET || network == "tcp6" && family != syscall.AF_INET6 {
			failure = errors.Join(err, errors.New("Linux Router proof changed its captured address family"))
			return
		}
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, linuxNodeProofBindToIfIndex, live.Index); err != nil {
			failure = fmt.Errorf("bind original Linux Router proof interface: %w", err)
			return
		}
		index, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, linuxNodeProofBindToIfIndex)
		if err != nil || index != live.Index {
			failure = errors.Join(err, errors.New("Linux Router proof did not retain its original kernel interface index"))
			return
		}
		name, err := desktopLinuxNodeProofBoundName(int(fd))
		if err != nil || name != live.Interface {
			failure = errors.Join(err, errors.New("Linux Router proof did not retain its original interface name"))
			return
		}
		failure = desktopLinuxNodeTUNCurrent(live)
	})
	return errors.Join(err, failure, ctx.Err())
}

func sameDesktopLinuxNodeProofTUN(first, second desktopNodeMTURecord) bool {
	// A heartbeat may advance during the exchange. Every owner, reader and
	// active MTU transaction field must remain identical.
	first.Heartbeat, second.Heartbeat = 0, 0
	return first == second
}

func (h *desktopLinuxNodeHost) capturedProofProfile() (common.RouterProfile, error) {
	var profile common.RouterProfile
	if h.imported != nil {
		owner, ok := h.launch.importedPlatform.(*desktopLinuxImportedConnection)
		if !ok || owner.host != h || h.imported.Validate() != nil || string(h.source) != owner.selection.Native.importedInput || h.imported.Metadata().ExitNodeID != owner.selection.Exit.NodeProofID {
			return profile, errors.New("Linux imported proof changed its paired final source")
		}
		return cloneRouterProfile(owner.selection.Exit), nil
	}
	if h.policy == nil || h.policy.Validate() != nil || h.launch == nil || len(h.source) == 0 {
		return profile, errors.New("Linux Router proof lost its sealed original profile")
	}
	original, err := h.policy.OriginalProfile().LaunchInput()
	if err != nil || !bytes.Equal(h.source, []byte(original)) {
		return profile, errors.Join(err, errors.New("Linux Router proof changed its complete captured source"))
	}
	var envelope struct {
		ProfileJSON string `json:"profile_json"`
	}
	if json.Unmarshal(h.source, &envelope) != nil || json.Unmarshal([]byte(envelope.ProfileJSON), &profile) != nil ||
		validateDesktopOwnedNodeSourceProfile(profile, h.launch.endpoint, string(h.source)) != nil ||
		profile.ID != h.launch.profileID || profile.NodeProofID != h.policy.Metadata().NodeID || !common.ValidNodeProofID(profile.NodeProofID) {
		return common.RouterProfile{}, errors.New("Linux Router proof substituted another private node")
	}
	return profile, nil
}

// Prove measures a real HTTP response through this exact TUN. Home LAN access
// cannot make a direct LAN response satisfy it. The selected DNS/TUN receipt,
// original process/control and complete running kernel policy bracket the
// exchange. Successful proof is retained privately; the app remains Starting.
func (h *desktopLinuxNodeHost) Prove(parent context.Context) (elapsed time.Duration, failure error) {
	if err := h.enter(parent); err != nil {
		return 0, err
	}
	defer func() { h.gate <- struct{}{} }()
	if h.imported != nil {
		return h.proveImportedLocked(parent)
	}
	// Preserve the original active proof and its retained observer. A new
	// startup request must capture a new host instead of reusing this one.
	if h.activation != nil {
		return 0, errors.New("Linux Router proof cannot restart an activated host")
	}
	defer func() {
		if failure != nil {
			elapsed = 0
			failure = h.failProofLocked(failure)
		}
	}()
	h.proof = nil
	if h.ready == nil || h.operation == nil {
		return 0, errors.New("Linux Router proof preceded its captured selected DNS and TUN readiness")
	}
	record, live, err := h.readReadyLocked(parent, false)
	if err != nil || live.Active || live.Failure != "" {
		return 0, errors.Join(err, errors.New("Linux Router proof has no idle original TUN reader"))
	}
	profile, err := h.capturedProofProfile()
	if err != nil {
		return 0, err
	}
	target, remote, err := desktopLinuxNodeProofTarget(profile)
	if err != nil {
		return 0, err
	}
	a := h.parent.app
	a.mu.Lock()
	seconds := a.cfg.AutoTestSeconds
	a.mu.Unlock()
	if seconds < 1 || seconds > 300 {
		return 0, errors.New("Linux Router proof has no bounded configured response deadline")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(seconds)*time.Second)
	stop := context.AfterFunc(h.operation, cancel)
	defer func() { stop(); cancel() }()
	network := "tcp4"
	if !remote.Addr().Is4() {
		network = "tcp6"
	}
	dialer := net.Dialer{ControlContext: func(ctx context.Context, actualNetwork, address string, raw syscall.RawConn) error {
		if actualNetwork != network || address != remote.String() {
			return errors.New("Linux Router proof changed its captured dial destination")
		}
		return bindDesktopLinuxNodeProofSocket(ctx, actualNetwork, raw, live)
	}}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: time.Duration(seconds) * time.Second,
		DialContext: func(ctx context.Context, actualNetwork, address string) (net.Conn, error) {
			if actualNetwork != "tcp" || address != remote.String() {
				return nil, errors.New("Linux Router proof cannot resolve or redirect another endpoint")
			}
			return dialer.DialContext(ctx, network, remote.String())
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Linux Router proof cannot redirect its captured endpoint")
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 || response.StatusCode/100 != 2 {
		return 0, errors.Join(err, errors.New("Linux Router proof returned an invalid bounded HTTP response"))
	}
	if err := validateCapturedNodeProof(profile.NodeProofID, body); err != nil {
		return 0, err
	}
	elapsed = time.Since(started)
	after, next, err := h.readReadyLocked(ctx, false)
	if err != nil || after != record || !sameDesktopLinuxNodeProofTUN(live, next) || ctx.Err() != nil {
		return 0, errors.Join(err, ctx.Err(), errors.New("Linux Router proof lost its original path during the exchange"))
	}
	h.proof = &desktopLinuxNodeProof{ready: record, live: next, provedAt: time.Now(), elapsed: elapsed}
	return elapsed, nil
}
