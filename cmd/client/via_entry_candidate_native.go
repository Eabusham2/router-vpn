package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// The pinned SOCKS5 lazy-success path replies only after the native entry has
// completed its upstream TCP handshake. HTTP CONNECT is deliberately unsuitable:
// the pinned HTTP input acknowledges CONNECT before opening that upstream. Candidate
// names are passed unchanged to the native WG endpoint and its selected DNS;
// neither this adapter nor net/http may resolve a candidate on the host.
type viaEntryNativeLane struct {
	mu            sync.Mutex
	closeMu       sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	closing       bool
	operations    sync.WaitGroup
	operationsEnd chan struct{}
	conns         map[*viaEntryNativeConn]bool
	proxy         string
	username      string
	password      string
	allowed       map[string]bool
	command       *exec.Cmd
	processDone   chan struct{}
	directory     string
	directoryInfo os.FileInfo
	removed       bool
}

type viaEntryNativeConn struct {
	net.Conn
	owner *viaEntryNativeLane
	once  sync.Once
}

func (c *viaEntryNativeConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return err
}

func viaEntryProofAddress(p common.RouterProfile) (string, string, error) {
	target, err := multihopLaneProofURL(p)
	if err != nil {
		return "", "", err
	}
	u, err := url.Parse(target)
	if err != nil || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return "", "", errors.New("captured entry proof URL is unsafe")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return "", "", errors.New("captured entry proof port is invalid")
	}
	address := net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(value))
	u.Host = address
	return u.String(), address, nil
}

func viaEntryDestinationRule(address string) (map[string]any, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("candidate destination is invalid")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, errors.New("candidate destination port is invalid")
	}
	rule := map[string]any{"inbound": []any{"tun-in"}, "network": "tcp", "port": number, "action": "route", "outbound": "proxy"}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.Is4In6() {
			return nil, errors.New("candidate destination address is invalid")
		}
		rule["ip_cidr"] = []any{netip.PrefixFrom(ip, ip.BitLen()).String()}
	} else {
		normalized, err := normalizeEndpoint(host)
		if err != nil || normalized != host {
			return nil, errors.New("candidate destination hostname is invalid")
		}
		rule["domain"] = []any{host}
	}
	return rule, nil
}

func compileViaEntryLane(ctx context.Context, entry common.RouterProfile, mode string, files, start map[string][]byte, candidates []common.RouterProfile, port int, username, password string) ([]byte, map[string]bool, error) {
	if mode != "wg" && mode != "awg2-fast" && mode != "awg2-strong" {
		return nil, nil, errors.New("candidate entry has an unsupported captured raw base")
	}
	compiled, _, err := compileDesktopNode(ctx, entry, mode, files, start, func(ctx context.Context, host string) ([]netip.Addr, error) {
		// This is only the captured outer entry transport bootstrap. Application
		// candidate names always remain in the private native DNS graph below.
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	})
	if err != nil {
		return nil, nil, err
	}
	if port < 1 || port > 65535 || username == "" || password == "" {
		return nil, nil, errors.New("candidate lane has no private listener identity")
	}
	var graph map[string]any
	if json.Unmarshal([]byte(compiled.Config()), &graph) != nil {
		return nil, nil, errors.New("candidate entry compiler returned an invalid graph")
	}
	ins, ok := graph["inbounds"].([]any)
	if !ok || len(ins) != 1 {
		return nil, nil, errors.New("candidate entry must have one captured input")
	}
	tun, ok := ins[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["tag"] != "tun-in" {
		return nil, nil, errors.New("candidate entry input ownership changed")
	}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return nil, nil, errors.New("candidate entry must retain one userspace base transport")
	}
	wg, ok := endpoints[0].(map[string]any)
	expectedType := "wireguard"
	if mode != "wg" {
		expectedType = mobilemultihop.AmneziaType
	}
	if !ok || wg["type"] != expectedType || wg["tag"] != "proxy" || (wg["system"] != nil && wg["system"] != false) {
		return nil, nil, errors.New("candidate entry must not create a system tunnel")
	}
	// Replacing only the input retains the saved peer keys, AES Start Layer,
	// IPv6/LAN preferences, selected DNS, and transport graph. No route helper or
	// system TUN is launched for this selection-only test.
	graph["inbounds"] = []any{map[string]any{"type": "socks", "tag": "tun-in", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": username, "password": password}}}}
	graph["log"] = map[string]any{"disabled": true}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return nil, nil, errors.New("candidate entry lost its final transport")
	}
	_, proofAddress, err := viaEntryProofAddress(entry)
	if err != nil {
		return nil, nil, err
	}
	proofRule, err := viaEntryDestinationRule(proofAddress)
	if err != nil {
		return nil, nil, err
	}
	allowed := map[string]bool{proofAddress: true}
	original, _ := route["rules"].([]any)
	for _, raw := range original {
		rule, ok := raw.(map[string]any)
		if !ok || (rule["action"] != "reject" && rule["action"] != "hijack-dns") {
			// Sniffing could read a lazy SOCKS input before its remote dial and
			// prematurely report success. This lane accepts only generated device
			// restrictions followed by its exact destination routes.
			return nil, nil, errors.New("candidate entry has an unsupported input-routing action")
		}
	}
	rules := []any{}
	// The private identity check is permitted even when Home LAN browsing is
	// blocked. Preserve IPv6=off before that narrow host/port exception.
	for _, raw := range original {
		if rule, ok := raw.(map[string]any); ok && rule["ip_version"] == float64(6) && rule["action"] == "reject" {
			rules = append(rules, rule)
		}
	}
	rules = append(rules, proofRule)
	for _, raw := range original {
		if rule, ok := raw.(map[string]any); !ok || rule["ip_version"] != float64(6) || rule["action"] != "reject" {
			rules = append(rules, raw)
		}
	}
	for _, candidate := range candidates {
		for _, candidatePort := range viaEntryProbePorts {
			address := net.JoinHostPort(candidate.Endpoint, strconv.Itoa(candidatePort))
			if allowed[address] {
				continue
			}
			rule, err := viaEntryDestinationRule(address)
			if err != nil {
				return nil, nil, err
			}
			allowed[address] = true
			rules = append(rules, rule)
		}
	}
	// The authenticated input is still restricted to the exact captured proof
	// and candidate destinations, never a reusable arbitrary local proxy.
	route["rules"] = append(rules, map[string]any{"action": "reject"})
	data, err := json.Marshal(graph)
	return data, allowed, err
}

func startViaEntryNativeLane(ctx context.Context, root, mode string, entry common.RouterProfile, files, start map[string][]byte, candidates []common.RouterProfile) (viaEntryLane, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	binary, err := verifyBundledNative(desktopAmneziaPackageRoot())
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	username, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	password, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	config, allowed, err := compileViaEntryLane(ctx, entry, mode, files, start, candidates, port, username, password)
	if err != nil {
		return nil, err
	}
	defer clear(config)
	return launchViaEntryNativeLane(ctx, root, binary, config, port, username, password, allowed)
}

func launchViaEntryNativeLane(ctx context.Context, root, binary string, config []byte, port int, username, password string, allowed map[string]bool) (viaEntryLane, error) {
	directory, err := newPrivateRuntimeDir(root, "via-entry-candidates")
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	lane := &viaEntryNativeLane{ctx: owned, cancel: cancel, conns: map[*viaEntryNativeConn]bool{}, allowed: allowed,
		proxy: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), username: username, password: password,
		directory: directory, directoryInfo: info, processDone: make(chan struct{})}
	// Return the owner with any post-staging error. The caller must check its
	// cleanup rather than forget a failed launch and its private source files.
	if err := writePrivateRuntimeFile(filepath.Join(directory, "sing-box.json"), config); err != nil {
		close(lane.processDone)
		return lane, err
	}
	if ctx.Err() != nil {
		close(lane.processDone)
		return lane, ctx.Err()
	}
	command := exec.Command(binary, "run", "-c", filepath.Join(directory, "sing-box.json"), "-D", directory)
	command.Dir, command.Env = directory, nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
	command.Stdout, command.Stderr = io.Discard, io.Discard
	lane.command = command
	if err := command.Start(); err != nil {
		close(lane.processDone)
		return lane, err
	}
	go func() { _ = command.Wait(); close(lane.processDone) }()
	ready, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	for {
		if !lane.Alive() || ready.Err() != nil {
			return lane, errors.New("candidate native listener did not become ready")
		}
		connection, dialErr := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ready, "tcp", lane.proxy)
		if dialErr == nil {
			_ = connection.Close()
			if lane.Alive() {
				return lane, nil
			}
		}
		select {
		case <-ready.Done():
			return lane, ready.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (l *viaEntryNativeLane) Alive() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing || l.ctx.Err() != nil {
		return false
	}
	select {
	case <-l.processDone:
		return false
	default:
		return true
	}
}

func (l *viaEntryNativeLane) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	l.mu.Lock()
	if l.closing || l.ctx.Err() != nil || network != "tcp" || !l.allowed[address] {
		l.mu.Unlock()
		return nil, errors.New("candidate socket is outside its captured entry owner")
	}
	l.operations.Add(1)
	l.mu.Unlock()
	defer l.operations.Done()
	dialCtx, cancel := context.WithCancel(ctx)
	stopOwner := context.AfterFunc(l.ctx, cancel)
	defer func() { stopOwner(); cancel() }()
	raw, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", l.proxy)
	if err != nil {
		return nil, errors.New("owned candidate proxy is unavailable")
	}
	conn := &viaEntryNativeConn{Conn: raw, owner: l}
	l.mu.Lock()
	if l.closing || l.ctx.Err() != nil {
		l.mu.Unlock()
		_ = raw.Close()
		return nil, errors.New("candidate entry was cancelled")
	}
	l.conns[conn] = true
	l.mu.Unlock()
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	stopRequest := context.AfterFunc(dialCtx, func() { _ = conn.Close() })
	defer stopRequest()
	deadline := time.Now().Add(10 * time.Second)
	if value, ok := dialCtx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = raw.SetDeadline(deadline)
	if err := viaEntrySOCKSHandshake(raw, address, l.username, l.password); err != nil || dialCtx.Err() != nil || !l.Alive() {
		return nil, errors.New("captured entry did not complete the routed TCP handshake")
	}
	if !stopRequest() || dialCtx.Err() != nil {
		return nil, errors.New("candidate handshake was cancelled")
	}
	_ = raw.SetDeadline(time.Time{})
	keep = true
	return conn, nil
}

func (l *viaEntryNativeLane) Close(ctx context.Context) error {
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	l.mu.Lock()
	if !l.closing {
		l.closing = true
		l.cancel()
		l.operationsEnd = make(chan struct{})
		go func() { l.operations.Wait(); close(l.operationsEnd) }()
	}
	connections := make([]*viaEntryNativeConn, 0, len(l.conns))
	for conn := range l.conns {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	select {
	case <-l.operationsEnd:
	case <-ctx.Done():
		return errors.New("candidate sockets have not drained")
	}
	select {
	case <-l.processDone:
	default:
		if l.command == nil || l.command.Process == nil {
			return errors.New("candidate process identity is missing")
		}
		if runtime.GOOS != "windows" {
			_ = l.command.Process.Signal(os.Interrupt)
			select {
			case <-l.processDone:
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return errors.New("candidate native process is still draining")
			}
		}
		select {
		case <-l.processDone:
		default:
			_ = l.command.Process.Kill()
		}
		select {
		case <-l.processDone:
		case <-ctx.Done():
			return errors.New("candidate native process retirement is unconfirmed")
		}
	}
	if l.removed {
		return nil
	}
	current, err := os.Lstat(l.directory)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(l.directoryInfo, current) {
		return errors.New("candidate private directory ownership changed; cleanup retained")
	}
	if err := validatePrivateParent(filepath.Join(l.directory, "sing-box.json")); err != nil {
		return errors.New("candidate cleanup path is no longer private")
	}
	if err := os.RemoveAll(l.directory); err != nil {
		return errors.New("candidate private source cleanup failed")
	}
	if _, err := os.Lstat(l.directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("candidate private source retirement is unconfirmed")
	}
	l.removed = true
	l.username, l.password = "", ""
	return nil
}

// RFC 1928 CONNECT with mandatory RFC 1929 credentials. In particular, refuse
// a listener offering no authentication, and consume the complete success
// response before treating the connection as a routed latency sample.
func viaEntrySOCKSHandshake(conn net.Conn, address, username, password string) error {
	bad := errors.New("captured SOCKS5 upstream handshake failed")
	if len(username) < 1 || len(username) > 255 || len(password) < 1 || len(password) > 255 {
		return bad
	}
	write := func(body []byte) error {
		n, err := conn.Write(body)
		if err != nil || n != len(body) {
			return bad
		}
		return nil
	}
	var pair [2]byte
	if write([]byte{5, 1, 2}) != nil {
		return bad
	}
	if _, err := io.ReadFull(conn, pair[:]); err != nil || pair != [2]byte{5, 2} {
		return bad
	}
	auth := append([]byte{1, byte(len(username))}, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	err := write(auth)
	clear(auth)
	if err != nil {
		return bad
	}
	if _, err := io.ReadFull(conn, pair[:]); err != nil || pair != [2]byte{1, 0} {
		return bad
	}
	host, portText, err := net.SplitHostPort(address)
	port, parseErr := strconv.Atoi(portText)
	if err != nil || parseErr != nil || port < 1 || port > 65535 {
		return bad
	}
	request := []byte{5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.Is4In6() {
			return bad
		}
		kind := byte(4)
		if ip.Is4() {
			kind = 1
		}
		request = append(request, kind)
		request = append(request, ip.AsSlice()...)
	} else {
		if len(host) < 1 || len(host) > 255 {
			return bad
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if write(request) != nil {
		return bad
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil || response[0] != 5 || response[1] != 0 || response[2] != 0 {
		return bad
	}
	size := 0
	switch response[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil || length[0] == 0 {
			return bad
		}
		size = int(length[0])
	default:
		return bad
	}
	var tail [257]byte
	if _, err := io.ReadFull(conn, tail[:size+2]); err != nil {
		return bad
	}
	return nil
}

func proveViaEntryLane(ctx context.Context, lane viaEntryLane, entry common.RouterProfile) error {
	if !lane.Alive() || ctx.Err() != nil {
		return errors.New("captured entry proof lane is no longer alive")
	}
	target, _, err := viaEntryProofAddress(entry)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DialContext: lane.DialContext, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("entry proof redirect refused") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return errors.New("captured entry proof request is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+entry.APIToken)
	req.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(req)
	if err != nil {
		return errors.New("selected entry did not return its private node proof through the owned lane")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	_ = response.Body.Close()
	var proof struct {
		OK     bool   `json:"ok"`
		NodeID string `json:"node_id"`
		Proof  string `json:"proof"`
	}
	if readErr != nil || len(body) > 4096 || response.StatusCode/100 != 2 || decodeRelayControlJSON(body, &proof) != nil || !proof.OK || proof.NodeID != entry.NodeProofID || proof.Proof != desktopNodeProofKind || !lane.Alive() || ctx.Err() != nil {
		return errors.New("candidate entry identity proof failed; all routed samples discarded")
	}
	return nil
}
