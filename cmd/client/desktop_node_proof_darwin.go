//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"router-vpn/internal/common"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func desktopMacOSPairedNodeProofTarget(profile common.RouterProfile) (*url.URL, netip.AddrPort, error) {
	target := strings.TrimSpace(profile.PathProbeURL)
	if target == "" {
		target = strings.TrimRight(strings.TrimSpace(profile.RouterAPI), "/") + "/health"
	}
	u, err := url.Parse(target)
	if err != nil || u == nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, netip.AddrPort{}, errors.New("macOS Router proof requires its captured private HTTP target")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	port, portErr := strconv.Atoi(u.Port())
	if err != nil || portErr != nil || port < 1 || port > 65535 || ip.String() != u.Hostname() || ip.Is4In6() ||
		ip.Zone() != "" || !ip.IsPrivate() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		profile.IPv6Mode == "off" && !ip.Is4() {
		return nil, netip.AddrPort{}, errors.New("macOS Router proof requires its exact private literal endpoint and port")
	}
	return u, netip.AddrPortFrom(ip, uint16(port)), nil
}

func bindDesktopMacOSPairedNodeProofSocket(ctx context.Context, network string, raw syscall.RawConn, live desktopNodeMTURecord) error {
	if ctx == nil || ctx.Err() != nil || raw == nil || network != "tcp4" && network != "tcp6" {
		return errors.New("macOS Node proof has no original bounded TCP socket")
	}
	if err := desktopMacOSPairedNodeTUNCurrent(ctx, live); err != nil {
		return err
	}
	var failure error
	err := raw.Control(func(fd uintptr) { failure = bindDesktopImportedMTUKernel(ctx, network, fd, live) })
	if err != nil || failure != nil {
		return errors.Join(err, failure)
	}
	return desktopMacOSPairedNodeTUNCurrent(ctx, live)
}

func sameDesktopMacOSPairedNodeProofTUN(first, second desktopNodeMTURecord) bool {
	// A heartbeat may advance during the exchange. Every owner, reader and
	// active MTU transaction field must remain identical.
	first.Heartbeat, second.Heartbeat = 0, 0
	return first == second
}

func (h *desktopMacOSPairedNodeHost) capturedProofProfile() (common.RouterProfile, error) {
	var profile common.RouterProfile
	if h.policy == nil || h.policy.Validate() != nil || h.launch == nil || len(h.source) == 0 {
		return profile, errors.New("macOS Router proof lost its sealed original profile")
	}
	original, err := h.policy.OriginalProfile().LaunchInput()
	if err != nil || !bytes.Equal(h.source, []byte(original)) {
		return profile, errors.Join(err, errors.New("macOS Router proof changed its complete captured source"))
	}
	var envelope struct {
		ProfileJSON string `json:"profile_json"`
	}
	if json.Unmarshal(h.source, &envelope) != nil || json.Unmarshal([]byte(envelope.ProfileJSON), &profile) != nil ||
		validateDesktopOwnedNodeSourceProfile(profile, h.launch.endpoint, string(h.source)) != nil ||
		profile.ID != h.launch.profileID || profile.NodeProofID != h.policy.Metadata().NodeID || !common.ValidNodeProofID(profile.NodeProofID) {
		return common.RouterProfile{}, errors.New("macOS Router proof substituted another private node")
	}
	return profile, nil
}

// Prove measures a real HTTP response through this exact TUN. Home LAN access
// cannot make a direct LAN response satisfy it. The selected DNS/TUN receipt,
// original process/control and complete running kernel policy bracket the
// exchange. Successful proof is retained privately; the app remains Starting.
func (h *desktopMacOSPairedNodeHost) Prove(parent context.Context) (elapsed time.Duration, failure error) {
	if err := h.enter(parent); err != nil {
		return 0, err
	}
	defer func() { h.gate <- struct{}{} }()
	// Preserve the original active proof and its retained observer. A new
	// startup request must capture a new host instead of reusing this one.
	if h.activated {
		return 0, errors.New("macOS Router proof cannot restart an activated host")
	}
	defer func() {
		if failure != nil {
			elapsed = 0
			h.proved = false
		}
	}()
	h.proved = false
	if h.ready == nil || h.operation == nil {
		return 0, errors.New("macOS Router proof preceded its captured selected DNS and TUN readiness")
	}
	record, live, err := h.readReadyLocked(parent, false)
	if err != nil || live.Active || live.Failure != "" {
		return 0, errors.Join(err, errors.New("macOS Router proof has no idle original TUN reader"))
	}
	elapsed, err = h.proveReaderLocked(parent, live)
	if err != nil {
		return 0, err
	}
	after, next, err := h.readReadyLocked(parent, false)
	if err != nil || after != record || !sameDesktopMacOSPairedNodeProofTUN(live, next) || parent.Err() != nil {
		return 0, errors.Join(err, parent.Err(), errors.New("macOS Router proof lost its original path during the exchange"))
	}
	h.proved = true
	return elapsed, nil
}

// proveReaderLocked is used for the original activation and an acknowledged
// MTU successor only; its caller retains the original host gate throughout.
func (h *desktopMacOSPairedNodeHost) proveReaderLocked(parent context.Context, live desktopNodeMTURecord) (time.Duration, error) {
	if err := h.current(parent, true); err != nil {
		return 0, err
	}
	profile, err := h.capturedProofProfile()
	if err != nil {
		return 0, err
	}
	target, remote, err := desktopMacOSPairedNodeProofTarget(profile)
	if err != nil {
		return 0, err
	}
	a := h.parent.app
	a.mu.Lock()
	seconds := a.cfg.AutoTestSeconds
	a.mu.Unlock()
	if seconds < 1 || seconds > 300 {
		return 0, errors.New("macOS Router proof has no bounded configured response deadline")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(seconds)*time.Second)
	lifetime := h.operation
	if h.activated {
		lifetime = h.parent.parent.ctx
	}
	stop := context.AfterFunc(lifetime, cancel)
	defer func() { stop(); cancel() }()
	network := "tcp4"
	if !remote.Addr().Is4() {
		network = "tcp6"
	}
	dialer := net.Dialer{ControlContext: func(ctx context.Context, actualNetwork, address string, raw syscall.RawConn) error {
		if actualNetwork != network || address != remote.String() {
			return errors.New("macOS Router proof changed its captured dial destination")
		}
		return bindDesktopMacOSPairedNodeProofSocket(ctx, actualNetwork, raw, live)
	}}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: time.Duration(seconds) * time.Second,
		DialContext: func(_ context.Context, actualNetwork, address string) (net.Conn, error) {
			if actualNetwork != "tcp" || address != remote.String() {
				return nil, errors.New("macOS Router proof cannot resolve or redirect another endpoint")
			}
			return dialer.DialContext(ctx, network, remote.String())
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("macOS Router proof cannot redirect its captured endpoint")
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
		return 0, errors.Join(err, errors.New("macOS Router proof returned an invalid bounded HTTP response"))
	}
	if err := validateCapturedNodeProof(profile.NodeProofID, body); err != nil {
		return 0, err
	}

	elapsed := time.Since(started)
	next, err := readDesktopNodeMTUContext(ctx, h.launch)
	if err != nil || !sameDesktopMacOSPairedNodeProofTUN(live, next) {
		return 0, errors.Join(err, errors.New("macOS paired proof changed its exact reader during response"))
	}
	if err := desktopMacOSPairedNodeTUNCurrent(ctx, next); err != nil {
		return 0, err
	}
	if err := h.current(ctx, true); err != nil {
		return 0, err
	}
	return elapsed, ctx.Err()
}

func (h *desktopMacOSPairedNodeHost) Reprove(ctx context.Context) error {
	if err := h.enter(ctx); err != nil {
		return err
	}
	defer func() { h.gate <- struct{}{} }()
	if !h.activated || !h.proved {
		return errors.New("macOS Router reproof has no original activation")
	}
	_, live, err := h.readReadyLocked(ctx, false)
	if err != nil {
		return err
	}
	_, err = h.proveReaderLocked(ctx, live)
	return err
}
