package mobiletor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type serverLastRelayIntegration struct {
	t                *testing.T
	client           *serverTorClientFixture
	native           *lastRelayProbeFixture
	control          *lastRelayControlWire
	owner            *ServerTorLastRelay
	roots            *x509.CertPool
	external         *httptest.Server
	proof            *httptest.Server
	mu               sync.Mutex
	socket           string
	anchorChanged    bool
	dnsFailure       atomic.Bool
	serverDNSFailure atomic.Bool
	current          atomic.Bool
	joined           atomic.Bool
	dnsCalls         atomic.Int32
	proofCalls       atomic.Int32
	externalRequests atomic.Int32
	externalDials    atomic.Int32
	nativeProofs     atomic.Int32
	comparison       *ServerTorComparison
}

func newServerLastRelayIntegration(t *testing.T, mode string) *serverLastRelayIntegration {
	t.Helper()
	f := &serverLastRelayIntegration{t: t, client: newServerTorClientFixture(t), native: newLastRelayProbeFixture(t)}
	f.current.Store(true)
	if mode == "tor" {
		f.client.policy = serverTorPolicy(t, serverTorSource(mode))
		f.client.client.policy = f.client.policy
	}
	if err := f.client.client.Acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.client.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	capture := f.client.client.capture(f.client.lease)
	digest := sha256.Sum256([]byte(capture.Request.SessionID))
	f.native.mu.Lock()
	f.native.path.SessionSHA256 = hex.EncodeToString(digest[:])
	f.native.path.SourceSHA256 = capture.Source.SourceSHA256
	f.native.mu.Unlock()
	f.external, f.roots, _ = lastRelayExternalTLSFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		f.externalRequests.Add(1)
		if r.Method != "GET" || r.Host != "1.1.1.1" || r.URL.RequestURI() != "/cdn-cgi/trace" {
			t.Error("external request escaped selected target")
		}
		_, _ = io.WriteString(w, "ip=198.51.100.81\nhttp=http/1.1\n")
	})
	cert, _ := proofTLSMaterial(t, "check.torproject.org")
	ca, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	f.roots.AddCert(ca)
	f.proof = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.proofCalls.Add(1)
		if r.Host != "check.torproject.org" || r.URL.RequestURI() != "/api/ip" {
			t.Error("client proof escaped captured Tor origin")
		}
		_, _ = io.WriteString(w, `{"IsTor":true,"IP":"198.51.100.81"}`)
	}))
	f.proof.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	f.proof.StartTLS()
	t.Cleanup(f.proof.Close)
	f.control = newLastRelayControlWire(t, func(command string) string {
		if !strings.HasPrefix(command, "ROUTERVPN_LASTRELAY ANCHOR ") {
			return f.native.control(command)
		}
		parts := strings.Split(command, " ")
		f.mu.Lock()
		socket, changed := f.socket, f.anchorChanged
		f.mu.Unlock()
		f.native.mu.Lock()
		path := f.native.path
		f.native.mu.Unlock()
		if len(parts) != 10 || parts[2] != path.SessionSHA256 || parts[3] != path.SourceSHA256 || parts[4] != path.SOCKSUsername || parts[5] != path.SOCKSPassword || net.JoinHostPort(parts[6], parts[7]) != socket || parts[8] != "1.1.1.1" || parts[9] != "443" {
			return "551 wrong actual socket\r\n"
		}
		anchor := path.AnchorStream
		if changed {
			anchor++
		}
		return fmt.Sprintf("250 version=1 session=%s source=%s anchor=%d circuit=%d exit=%s path_sha256=%s client_ip=%s client_port=%s target_ip=%s target_port=%s\r\n", path.SessionSHA256, path.SourceSHA256, anchor, path.Circuit, path.ExitFingerprint, path.PathSHA256, parts[6], parts[7], parts[8], parts[9])
	})
	f.owner, err = newServerTorLastRelay(context.Background(), f.control.control, capture, ServerTorLastRelayOptions{
		Current: f.current.Load, NativeJoined: f.joined.Load, SOCKSUsername: f.native.path.SOCKSUsername, SOCKSPassword: f.native.path.SOCKSPassword,
		Prove: func(ctx context.Context) (time.Time, time.Time, error) {
			f.nativeProofs.Add(1)
			if ctx.Err() != nil || f.serverDNSFailure.Load() {
				return time.Time{}, time.Time{}, errors.New("selected DNS did not prove")
			}
			now := time.Now()
			return now, now, nil
		},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, net.ErrClosed
			}
			if address == "1.1.1.1:443" {
				f.externalDials.Add(1)
				connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.external.Listener.Addr().String())
				if connection != nil {
					f.mu.Lock()
					f.socket = connection.LocalAddr().String()
					f.mu.Unlock()
				}
				return connection, err
			}
			return f.native.DialProbe(ctx, address)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.client.front.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.client.front, err = newServerTorFront(context.Background(), listener, netip.MustParseAddr("127.0.0.1"), capture.Username, capture.Password, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "check.torproject.org:443" {
			return nil, errServerLastRelay
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", f.proof.Listener.Addr().String())
	})
	if err != nil || f.client.front.SetComparison(f.owner) != nil || f.client.front.Enable() != nil {
		t.Fatal("comparison front startup", err)
	}
	t.Cleanup(func() {
		f.current.Store(true)
		f.joined.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if f.comparison != nil {
			if err := f.comparison.Close(ctx); err != nil {
				t.Error("comparison retained test owner", err)
			}
		}
		if err := f.owner.Close(ctx); err != nil {
			t.Error("server retained test owner", err)
		}
	})
	return f
}

func (f *serverLastRelayIntegration) open() *ServerTorComparison {
	f.t.Helper()
	capture := ComparisonCapture{OwnerID: "exact-client-box", SourceSHA256: strings.Repeat("f", 64), SessionID: "client-session-distinct-from-lease", Current: f.current.Load,
		DNSProof: func(ctx context.Context) error {
			f.dnsCalls.Add(1)
			if ctx.Err() != nil || f.dnsFailure.Load() {
				return errors.New("captured selected DNS failed")
			}
			return nil
		}}
	comparison, err := f.client.client.openLastRelay(f.t.Context(), capture, externalTarget, f.roots)
	f.comparison = comparison
	if err != nil || comparison == nil {
		f.t.Fatal(err)
	}
	return comparison
}

func TestServerLastRelayActualAuthenticatedClientOriginBothResponses(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge"} {
		t.Run(mode, func(t *testing.T) {
			f := newServerLastRelayIntegration(t, mode)
			comparison := f.open()
			if comparison.Identity() != "" || f.dnsCalls.Load() != 0 || f.externalDials.Load() != 0 {
				t.Fatal("construction invented a proved path")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := comparison.Prepare(ctx); err != nil {
				t.Fatal("prepare", err)
			}
			identity := comparison.Identity()
			if identity == "" || f.externalRequests.Load() != 0 || f.externalDials.Load() != 1 || f.nativeProofs.Load() != 1 {
				t.Fatal("prepare lost anchor or prematurely measured HTTP")
			}
			if err := comparison.Verify(ctx); err != nil {
				t.Fatal("verify", err)
			}
			last, err := comparison.ProbeLast(ctx)
			if err != nil || last <= 0 {
				t.Fatal("last relay", last, err)
			}
			external, err := comparison.ProbeExternal(ctx, externalTarget)
			if err != nil || external <= 0 {
				t.Fatal("external", external, err)
			}
			if comparison.Identity() != identity || f.externalDials.Load() != 1 || f.externalRequests.Load() != 1 || f.dnsCalls.Load() != 2 || f.proofCalls.Load() != 2 {
				t.Fatal("comparison reconnected, reused proof or changed native path")
			}
			comparison.mu.Lock()
			originalExpiry := comparison.until
			comparison.mu.Unlock()
			if err := comparison.Verify(ctx); err != nil {
				t.Fatal("post-response verification rejected the retained one-use anchor", err)
			}
			comparison.mu.Lock()
			unchangedExpiry := comparison.until.Equal(originalExpiry)
			comparison.mu.Unlock()
			if !unchangedExpiry || comparison.Identity() != identity || f.externalDials.Load() != 1 || f.externalRequests.Load() != 1 || f.dnsCalls.Load() != 3 || f.proofCalls.Load() != 3 {
				t.Fatal("verification renewed the grant, repeated the operand or changed its anchor")
			}
			f.native.mu.Lock()
			dials, closes, bytes := f.native.dials, f.native.closes, f.native.fields["response_bytes"]
			f.native.mu.Unlock()
			if dials != 1 || closes < 1 || bytes != strconv.Itoa(len(f.native.response)) {
				t.Fatal("client did not receive/count actual relay-local bytes", dials, closes, bytes)
			}
			if err := comparison.Close(ctx); err != nil {
				t.Fatal("measurement close", err)
			}
			if !f.client.client.Ready() || !f.current.Load() {
				t.Fatal("measurement cleanup stopped its whole candidate")
			}
		})
	}
}

func TestServerLastRelayReadbackCannotReviveExpiredCapturedProof(t *testing.T) {
	f := newServerLastRelayIntegration(t, "tor-bridge")
	comparison := f.open()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if comparison.Prepare(ctx) != nil {
		t.Fatal("prepare")
	}
	comparison.mu.Lock()
	expired := time.Now().Add(-time.Millisecond)
	comparison.until = expired
	comparison.mu.Unlock()
	before := f.proofCalls.Load()
	if comparison.Verify(ctx) == nil || comparison.Identity() != "" || f.proofCalls.Load() != before {
		t.Fatal("readback revived an expired path before admission")
	}
	comparison.mu.Lock()
	same := comparison.until.Equal(expired)
	comparison.mu.Unlock()
	if !same {
		t.Fatal("verification replaced original captured deadline")
	}
}

func TestServerLastRelayRequiresBothClientAndServerSelectedDNSBeforeAnchor(t *testing.T) {
	for _, where := range []string{"client", "server", "stale-server-proof"} {
		t.Run(where, func(t *testing.T) {
			f := newServerLastRelayIntegration(t, "tor-bridge")
			switch where {
			case "client":
				f.dnsFailure.Store(true)
			case "server":
				f.serverDNSFailure.Store(true)
			case "stale-server-proof":
				f.owner.options.Prove = func(context.Context) (time.Time, time.Time, error) {
					old := time.Now().Add(-31 * time.Second)
					return old, old, nil
				}
			}
			comparison := f.open()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if comparison.Prepare(ctx) == nil || comparison.Identity() != "" || f.externalDials.Load() != 0 || f.externalRequests.Load() != 0 {
				t.Fatal("unproved DNS/exit manufactured an anchor")
			}
			if err := comparison.Close(ctx); err != nil {
				t.Fatal("failed preparation lost its cleanup owner", err)
			}
		})
	}
}

func TestServerLastRelayInvalidConstructionReturnsNilInterfaceAndCannotReplaceOwner(t *testing.T) {
	f := newServerLastRelayIntegration(t, "tor")
	for _, target := range []string{"https://example.com/cdn-cgi/trace", "https://127.0.0.1/cdn-cgi/trace", "https://1.1.1.1/other"} {
		value, err := f.client.client.OpenLastRelay(t.Context(), ComparisonCapture{}, target)
		if value != nil || err == nil {
			t.Fatal("invalid capture produced a typed-nil interface or owner", value, err)
		}
	}
	comparison := f.open()
	if value, err := f.client.client.OpenLastRelay(t.Context(), comparison.host, externalTarget); value != nil || err == nil {
		t.Fatal("replacement overwrote retained measurement", value, err)
	}
	if f.externalDials.Load() != 0 {
		t.Fatal("constructor opened a native path")
	}
}

func TestServerLastRelayTargetOrderAndOneUseCannotYieldAnUnmatchedOperand(t *testing.T) {
	for _, which := range []string{"external-first", "changed-target", "repeat-last", "repeat-external"} {
		t.Run(which, func(t *testing.T) {
			f := newServerLastRelayIntegration(t, "tor")
			comparison := f.open()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if comparison.Prepare(ctx) != nil {
				t.Fatal("prepare")
			}
			if which != "external-first" {
				if _, err := comparison.ProbeLast(ctx); err != nil {
					t.Fatal(err)
				}
			}
			var elapsed time.Duration
			var err error
			switch which {
			case "external-first":
				elapsed, err = comparison.ProbeExternal(ctx, externalTarget)
			case "changed-target":
				elapsed, err = comparison.ProbeExternal(ctx, "https://1.0.0.1/cdn-cgi/trace")
			case "repeat-last":
				elapsed, err = comparison.ProbeLast(ctx)
			case "repeat-external":
				if _, err := comparison.ProbeExternal(ctx, externalTarget); err != nil {
					t.Fatal(err)
				}
				elapsed, err = comparison.ProbeExternal(ctx, externalTarget)
			}
			if err == nil || elapsed != 0 || comparison.Identity() != "" {
				t.Fatal("invalid sequence produced a score", elapsed, err)
			}
			if which != "repeat-external" && f.externalRequests.Load() != 0 {
				t.Fatal("wrong operand request reached external server")
			}
			if f.externalDials.Load() != 1 {
				t.Fatal("comparison selected a replacement anchor")
			}
		})
	}
}

func TestServerLastRelayNativeControlBridgeCannotBorrowOtherCommandsOrOwners(t *testing.T) {
	for _, attack := range []string{"SETCONF DisableNetwork=0", "ROUTERVPN_PADDING INFO", "ROUTERVPN_LASTRELAY ANCHOR arbitrary", "ROUTERVPN_LASTRELAY INFO extra", "ROUTERVPN_LASTRELAY STATUS " + strings.Repeat("1", 64) + " " + strings.Repeat("2", 64) + " 1 " + strings.Repeat("3", 64)} {
		t.Run(strings.Split(attack, " ")[0]+"/"+strconv.Itoa(len(attack)), func(t *testing.T) {
			f := newServerLastRelayIntegration(t, "tor-bridge")
			comparison := f.open()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if comparison.Prepare(ctx) != nil {
				t.Fatal("prepare")
			}
			before := f.control.writes.Load()
			// Write directly to the authenticated private control stream, bypassing
			// all shared Control argument validation, as a hostile lease client can.
			connection := comparison.control.conn
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(connection, attack+"\r\n")
			var one [1]byte
			if _, err := connection.Read(one[:]); err == nil {
				t.Fatal("expanded native control vocabulary accepted")
			}
			if f.control.writes.Load() != before {
				t.Fatal("unauthorized command reached actual owning controller")
			}
		})
	}
}

func TestServerLastRelayChangedNativeAnchorOrClientOwnerInvalidatesBothScores(t *testing.T) {
	for _, where := range []string{"anchor", "client-owner"} {
		t.Run(where, func(t *testing.T) {
			f := newServerLastRelayIntegration(t, "tor")
			comparison := f.open()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if comparison.Prepare(ctx) != nil {
				t.Fatal("prepare")
			}
			if where == "anchor" {
				f.mu.Lock()
				f.anchorChanged = true
				f.mu.Unlock()
			} else {
				f.current.Store(false)
			}
			elapsed, err := comparison.ProbeLast(ctx)
			if err == nil || elapsed != 0 || comparison.Identity() != "" || f.externalRequests.Load() != 0 {
				t.Fatal("replacement retained a score", elapsed, err)
			}
			f.current.Store(true)
		})
	}
}

func TestServerLastRelayCancellationKeepsPendingNativeFrameAndIdleAnchorOwned(t *testing.T) {
	f := newServerLastRelayIntegration(t, "tor-bridge")
	comparison := f.open()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if comparison.Prepare(ctx) != nil {
		t.Fatal("prepare")
	}
	f.native.mu.Lock()
	entered, release := make(chan struct{}), make(chan struct{})
	f.native.enteredCapture, f.native.releaseCapture = entered, release
	f.native.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := comparison.ProbeLast(ctx); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("capture was not issued")
	}
	comparison.Cancel()
	wait, finish := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if comparison.Close(wait) == nil {
		t.Fatal("pending native frame was declared drained")
	}
	finish()
	f.client.client.mu.Lock()
	retained := f.client.client.comparison == comparison
	f.client.client.mu.Unlock()
	if !retained || comparison.Identity() != "" {
		t.Fatal("cancelled owner escaped its retained slot")
	}
	f.owner.mu.Lock()
	handle := f.owner.active
	f.owner.mu.Unlock()
	if handle == nil || !handle.current() {
		t.Fatal("idle external native anchor was destroyed before control drain")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("cancelled probe returned a measurement")
	}
	if err := comparison.Close(ctx); err != nil {
		t.Fatal("exact pending frame did not drain after release", err)
	}
	if !f.client.client.Ready() {
		t.Fatal("measurement cancellation stopped the whole candidate")
	}
}

func TestServerLastRelayAmbiguousNativeReplyRequiresAuthenticatedExactLeaseStop(t *testing.T) {
	f := newServerLastRelayIntegration(t, "tor")
	comparison := f.open()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if comparison.Prepare(ctx) != nil {
		t.Fatal("prepare")
	}
	f.native.mu.Lock()
	f.native.alter = func(command, reply string) string {
		if strings.Contains(command, " CAPTURE ") {
			return strings.Replace(reply, "source="+f.native.path.SourceSHA256, "source="+strings.Repeat("a", 64), 1)
		}
		return reply
	}
	f.native.mu.Unlock()
	if elapsed, err := comparison.ProbeLast(ctx); err == nil || elapsed != 0 {
		t.Fatal("malformed native receipt produced score", elapsed, err)
	}
	short, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := comparison.Close(short)
	stop()
	if err == nil || comparison.NativeJoined() {
		t.Fatal("closed control was mistaken for native join")
	}
	f.client.mu.Lock()
	f.client.deleteFail = true
	f.client.mu.Unlock()
	if f.client.client.Close(ctx) == nil || comparison.NativeJoined() {
		t.Fatal("failed DELETE fabricated native stop")
	}
	f.client.mu.Lock()
	f.client.deleteFail = false
	f.client.mutate = func(method string, object map[string]any) {
		if method == http.MethodDelete {
			object["stopped"] = false
		}
	}
	f.client.mu.Unlock()
	if f.client.client.Close(ctx) == nil || comparison.NativeJoined() {
		t.Fatal("unacknowledged STOP fabricated native join")
	}
	f.client.mu.Lock()
	f.client.mutate = func(method string, _ map[string]any) {
		if method == http.MethodDelete {
			f.joined.Store(true)
		}
	}
	f.client.mu.Unlock()
	if err := f.client.client.Close(ctx); err != nil {
		t.Fatal("exact authenticated STOP could not discharge comparison drain", err)
	}
	if !comparison.NativeJoined() {
		t.Fatal("verified exact lease stop was not retained")
	}
	f.client.client.mu.Lock()
	if f.client.client.comparison != nil {
		t.Error("joined comparison retained client claim")
	}
	f.client.client.mu.Unlock()
}

func TestServerLastRelayRawPrivateFramesCannotReplaceCapturedLeaseHandleOrTarget(t *testing.T) {
	f := newServerLastRelayIntegration(t, "tor")
	comparison := f.open()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if comparison.Prepare(ctx) != nil {
		t.Fatal("prepare")
	}
	identity := comparison.Identity()
	for name, change := range map[string]func(*serverLastRelayRequest){
		"owner":    func(r *serverLastRelayRequest) { r.OwnerID = strings.Repeat("1", 64) },
		"session":  func(r *serverLastRelayRequest) { r.SessionID = strings.Repeat("1", 32) },
		"source":   func(r *serverLastRelayRequest) { r.SourceSHA256 = strings.Repeat("1", 64) },
		"registry": func(r *serverLastRelayRequest) { r.RegistrySHA256 = strings.Repeat("1", 64) },
		"dns":      func(r *serverLastRelayRequest) { r.DNSPolicySHA256 = strings.Repeat("1", 64) },
		"handle":   func(r *serverLastRelayRequest) { r.Handle = strings.Repeat("1", 64) },
		"target":   func(r *serverLastRelayRequest) { r.Target = "https://1.0.0.1/cdn-cgi/trace" },
	} {
		t.Run(name, func(t *testing.T) {
			r, err := comparison.newRequest("verify", "")
			if err != nil {
				t.Fatal(err)
			}
			change(&r)
			if r.validate() != nil {
				t.Fatal("negative did not preserve valid wire schema")
			}
			connection, err := dialServerTorCommand(ctx, f.client.front.Address(), comparison.lease.Username, comparison.lease.Password, serverLastRelayAddress, serverLastRelayCommand, (&net.Dialer{}).DialContext)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			before := f.control.writes.Load()
			if serverLastRelayWrite(connection, r) != nil {
				t.Fatal("raw private request failed")
			}
			var response serverLastRelayResponse
			if serverLastRelayRead(connection, &response) == nil || f.control.writes.Load() != before {
				t.Fatal("unrelated lease/handle/target reached native owner")
			}
			if comparison.Identity() != identity || f.externalDials.Load() != 1 {
				t.Fatal("rejected request disturbed captured owner")
			}
		})
	}
	// A request nonce is one-use even while its handle remains valid.
	r, err := comparison.newRequest("verify", "")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		connection, err := dialServerTorCommand(ctx, f.client.front.Address(), comparison.lease.Username, comparison.lease.Password, serverLastRelayAddress, serverLastRelayCommand, (&net.Dialer{}).DialContext)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		before := f.control.writes.Load()
		_ = serverLastRelayWrite(connection, r)
		var response serverLastRelayResponse
		err = serverLastRelayRead(connection, &response)
		_ = connection.Close()
		if attempt == 0 && err != nil {
			t.Fatal("fresh nonce rejected", err)
		}
		if attempt == 1 && (err == nil || f.control.writes.Load() != before) {
			t.Fatal("replayed private nonce reached native owner")
		}
	}
}

func TestServerLastRelayBackendIsClaimedOnceByExactAuthenticatedChild(t *testing.T) {
	f := newServerLastRelayIntegration(t, "tor")
	session := newServerTorSessionFixture(t, "tor", nil, f.client.policy)
	capture := f.client.client.capture(f.client.lease)
	before := len(session.wire.snapshot())
	owner, err := NewServerTorLastRelay(t.Context(), session.session, capture, f.owner.options)
	if err != nil || owner == nil {
		t.Fatal("exact disabled child failed to capture comparison authority", err)
	}
	defer owner.Close(context.Background())
	if replacement, err := NewServerTorLastRelay(t.Context(), session.session, capture, f.owner.options); err == nil || replacement != nil {
		t.Fatal("another front borrowed same native controller")
	}
	if len(session.wire.snapshot()) != before {
		t.Fatal("capturing a front enabled networking or issued native commands")
	}
}

type serverLastRelayBlockedIO struct {
	net.Conn
	entered, release, closed chan struct{}
	closeOnce                sync.Once
}

func (c *serverLastRelayBlockedIO) Read([]byte) (int, error) {
	close(c.entered)
	<-c.release
	return 0, io.EOF
}
func (c *serverLastRelayBlockedIO) Close() error {
	c.closeOnce.Do(func() { _ = c.Conn.Close(); close(c.closed) })
	return nil
}

func TestServerLastRelaySocketDrainJoinsEnteredIOAfterLowerClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	lower := &serverLastRelayBlockedIO{Conn: a, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	socket := &serverLastRelaySocket{Conn: lower, current: func() bool { return true }}
	read := make(chan struct{})
	go func() { defer close(read); var one [1]byte; _, _ = socket.Read(one[:]) }()
	<-lower.entered
	done := make(chan error, 1)
	go func() { done <- socket.Close() }()
	<-lower.closed
	select {
	case <-done:
		t.Fatal("raw Close released an entered I/O owner")
	default:
	}
	close(lower.release)
	<-read
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type serverLastRelayRetryClose struct {
	net.Conn
	calls atomic.Int32
}

func (c *serverLastRelayRetryClose) Close() error {
	if c.calls.Add(1) == 1 {
		return errors.New("native close still pending")
	}
	return c.Conn.Close()
}

func TestServerLastRelaySocketFailedCloseStaysReachableForRetry(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	lower := &serverLastRelayRetryClose{Conn: a}
	socket := &serverLastRelaySocket{Conn: lower, current: func() bool { return true }}
	if socket.Close() == nil || socket.closed {
		t.Fatal("failed native close released socket owner")
	}
	if socket.Close() != nil || !socket.closed || lower.calls.Load() != 2 {
		t.Fatal("same captured socket was not retried")
	}
}

func TestServerLastRelayServerExpiryCancelsDataWhileIssuedNativeFrameIsPending(t *testing.T) {
	f := newServerLastRelayIntegration(t, "tor-bridge")
	comparison := f.open()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if comparison.Prepare(ctx) != nil {
		t.Fatal("prepare")
	}
	f.native.mu.Lock()
	entered, release := make(chan struct{}), make(chan struct{})
	f.native.enteredCapture, f.native.releaseCapture = entered, release
	f.native.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := comparison.ProbeLast(ctx); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("capture was not issued")
	}
	f.owner.mu.Lock()
	handle := f.owner.active
	f.owner.mu.Unlock()
	handle.mu.Lock()
	handle.until = time.Now().Add(30 * time.Millisecond)
	handle.timer.Reset(time.Until(handle.until))
	handle.mu.Unlock()
	select {
	case <-handle.ctx.Done():
	case <-time.After(time.Second):
		close(release)
		t.Fatal("data expiry waited for native control I/O")
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired candidate produced a score")
		}
	case <-ctx.Done():
		t.Fatal("issued frame failed to unwind")
	}
	if comparison.Identity() != "" {
		t.Fatal("expired native owner retained a score identity")
	}
	f.client.mu.Lock()
	f.client.mutate = func(method string, _ map[string]any) {
		if method == http.MethodDelete {
			f.joined.Store(true)
		}
	}
	f.client.mu.Unlock()
	if err := f.client.client.Close(ctx); err != nil {
		t.Fatal("exact native-stop fallback did not drain expired measurement", err)
	}
}
