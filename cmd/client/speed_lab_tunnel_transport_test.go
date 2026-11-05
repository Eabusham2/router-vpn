package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type speedLabCapturedDialFunc func(context.Context, string, string) (net.Conn, error)

func (f speedLabCapturedDialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type speedLabDialMarker struct{}

func speedLabCapturedTLSFixture(t *testing.T, hostname string, handler http.Handler) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	var sni atomic.Int32
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == "speed.cloudflare.com" {
			sni.Add(1)
		}
		return nil, nil
	}}
	server.StartTLS()
	var fallback atomic.Int32
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "foreign-default.invalid", InsecureSkipVerify: true} // Deliberately unsafe inherited defaults must not weaken the captured client.
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		fallback.Add(1)
		return nil, errors.New("ordinary dial must not run")
	}
	transport.DialTLS = func(string, string) (net.Conn, error) {
		fallback.Add(1)
		return nil, errors.New("inherited TLS dial must not run")
	}
	transport.DialTLSContext = transport.DialContext
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() {
		if http.DefaultTransport != transport || transport.TLSClientConfig.ServerName != "foreign-default.invalid" || !transport.TLSClientConfig.InsecureSkipVerify || transport.DialTLS == nil || transport.DialTLSContext == nil {
			t.Error("captured client mutated global transport")
		}
		http.DefaultTransport = original
		transport.CloseIdleConnections()
		server.Close()
	})
	return server, &fallback, &sni
}

func TestSpeedLabCapturedTunnelUsesPublicTLSAndActualTransfer(t *testing.T) {
	var gets, uploads atomic.Int32
	server, fallback, sni := speedLabCapturedTLSFixture(t, "speed.cloudflare.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "speed.cloudflare.com" {
			t.Error("request hostname replaced by local dial target", r.Host)
		}
		if r.Method == http.MethodPost {
			uploads.Add(1)
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil || n != r.ContentLength {
				t.Error("actual upload incomplete", n, err)
			}
			_, _ = w.Write([]byte("ok"))
			return
		}
		gets.Add(1)
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.CopyN(w, &speedLabPatternReader{pattern: []byte{7}}, n)
	}))
	owner, stopOwner := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopOwner()
	request, stopRequest := context.WithTimeout(context.WithValue(context.Background(), speedLabDialMarker{}, "original-request"), 3*time.Second)
	defer stopRequest()
	want, _ := request.Deadline()
	var dials atomic.Int32
	captured := withSpeedLabTunnelDialer(owner, speedLabCapturedDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		got, ok := ctx.Deadline()
		if ctx.Value(speedLabDialMarker{}) != "original-request" || !ok || !got.Equal(want) || network != "tcp" || address != "speed.cloudflare.com:443" {
			t.Errorf("dial lost original request: marker=%v deadline=%v network=%s address=%s", ctx.Value(speedLabDialMarker{}), got, network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}))
	client := newSpeedLabHTTPClientContext(captured, 4*time.Second)
	defer client.CloseIdleConnections()
	if _, err := speedLabProbeOnce(request, client); err != nil {
		t.Fatal(err)
	}
	if n, _, err := speedLabDownloadRound(request, client, 32<<10); err != nil || n != 32<<10 {
		t.Fatal("actual captured download", n, err)
	}
	if n, _, err := speedLabUploadRound(request, client, 32<<10, []byte("actual payload")); err != nil || n != 32<<10 {
		t.Fatal("actual captured upload", n, err)
	}
	if dials.Load() == 0 || sni.Load() == 0 || fallback.Load() != 0 || gets.Load() != 2 || uploads.Load() != 1 {
		t.Fatal("captured HTTP/TLS path or exact transfers were bypassed", dials.Load(), sni.Load(), fallback.Load(), gets.Load(), uploads.Load())
	}
	transport := client.Transport.(*speedLabTunnelTransport).transport
	if transport.Proxy != nil || transport.DialTLS != nil || transport.DialTLSContext != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.ServerName != "" {
		t.Fatal("captured TLS/proxy policy changed")
	}
}

func TestSpeedLabCapturedTunnelRejectsForeignTLSAndRedirect(t *testing.T) {
	for _, mode := range []string{"foreign-certificate", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			hostname := "speed.cloudflare.com"
			if mode == "foreign-certificate" {
				hostname = "other.invalid"
			}
			var requests atomic.Int32
			server, fallback, _ := speedLabCapturedTLSFixture(t, hostname, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Redirect(w, r, "https://other.invalid/private", http.StatusFound)
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx = withSpeedLabTunnelDialer(ctx, speedLabCapturedDialFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}))
			client := newSpeedLabHTTPClientContext(ctx, time.Second)
			defer client.CloseIdleConnections()
			_, err := speedLabProbeOnce(ctx, client)
			if err == nil || fallback.Load() != 0 {
				t.Fatal("foreign TLS/redirect accepted or ordinary path used", err)
			}
			if mode == "foreign-certificate" {
				var hostnameErr x509.HostnameError
				if !errors.As(err, &hostnameErr) || requests.Load() != 0 {
					t.Fatal("public TLS hostname verification bypassed", err, requests.Load())
				}
			} else if requests.Load() != 1 {
				t.Fatal("redirect followed captured provider", requests.Load())
			}
		})
	}
}

func TestSpeedLabCapturedTunnelCancellationJoinsLateDial(t *testing.T) {
	for _, mode := range []string{"request-cancel", "request-deadline", "owner-cancel", "late-connection", "refused-no-fallback", "missing-dialer"} {
		t.Run(mode, func(t *testing.T) {
			var fallback atomic.Int32
			original := http.DefaultTransport
			transport := original.(*http.Transport).Clone()
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
				fallback.Add(1)
				return nil, errors.New("ordinary fallback")
			}
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
			owner, stopOwner := context.WithTimeout(context.Background(), 5*time.Second)
			defer stopOwner()
			request, stopRequest := context.WithTimeout(context.WithValue(context.Background(), speedLabDialMarker{}, mode), 3*time.Second)
			defer stopRequest()
			if mode == "request-deadline" {
				var stop context.CancelFunc
				request, stop = context.WithTimeout(request, 40*time.Millisecond)
				defer stop()
			}
			want, _ := request.Deadline()
			entered, joined := make(chan struct{}), make(chan struct{})
			var peer net.Conn
			refused := errors.New("captured tunnel refused")
			dialer := speedLabCapturedDialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
				defer close(joined)
				got, ok := ctx.Deadline()
				if !ok || !got.Equal(want) || ctx.Value(speedLabDialMarker{}) != mode {
					t.Error("HTTP transport stripped original request deadline/identity", got, want)
				}
				if mode == "late-connection" {
					var conn net.Conn
					conn, peer = net.Pipe()
					close(entered)
					<-ctx.Done()
					return conn, nil
				}
				close(entered)
				if mode == "refused-no-fallback" {
					return nil, refused
				}
				<-ctx.Done()
				return nil, ctx.Err()
			})
			var capability speedLabTunnelDialer = dialer
			if mode == "missing-dialer" {
				capability = nil
			}
			client := newSpeedLabHTTPClientContext(withSpeedLabTunnelDialer(owner, capability), 4*time.Second)
			defer client.CloseIdleConnections()
			done := make(chan error, 1)
			go func() { _, err := speedLabProbeOnce(request, client); done <- err }()
			if mode != "missing-dialer" {
				select {
				case <-entered:
				case <-time.After(time.Second):
					stopRequest()
					t.Fatal("original dialer was not reached")
				}
				if mode == "request-cancel" || mode == "late-connection" {
					stopRequest()
				}
				if mode == "owner-cancel" {
					stopOwner()
				}
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(time.Second):
				stopRequest()
				stopOwner()
				<-done
				t.Fatal("request ignored original cancellation")
			}
			if err == nil || fallback.Load() != 0 {
				t.Fatal("captured refusal used ordinary route or succeeded", err, fallback.Load())
			}
			if mode != "missing-dialer" {
				select {
				case <-joined:
				case <-time.After(time.Second):
					stopRequest()
					stopOwner()
					t.Fatal("HTTP detached a native dial after request ended")
				}
			}
			if mode == "request-deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("original deadline lost", err)
			}
			if mode == "refused-no-fallback" && !errors.Is(err, refused) {
				t.Fatal("native refusal hidden", err)
			}
			if mode == "late-connection" {
				defer peer.Close()
				_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := peer.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal("late native connection escaped retirement", err)
				}
			}
			if mode != "owner-cancel" && owner.Err() != nil {
				t.Fatal("request cancellation retired captured path lifetime", owner.Err())
			}
		})
	}
}

func TestSpeedLabMeasurementConstructorsUseCapturedTunnel(t *testing.T) {
	server, fallback, _ := speedLabCapturedTLSFixture(t, "speed.cloudflare.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write([]byte("ok"))
			return
		}
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.CopyN(w, &speedLabPatternReader{pattern: []byte{9}}, n)
	}))
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), speedLabDialMarker{}, "measurement"), 8*time.Second)
	defer cancel()
	var dials atomic.Int32
	ctx = withSpeedLabTunnelDialer(ctx, speedLabCapturedDialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx.Value(speedLabDialMarker{}) != "measurement" || address != "speed.cloudflare.com:443" {
			t.Error("measurement lost original captured path")
		}
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}))
	idle, err := measureSpeedLabIdleLatency(ctx)
	if err != nil || idle.Samples != 10 {
		t.Fatal("idle client bypassed captured tunnel", idle, err)
	}
	for _, direction := range []string{"download", "upload"} {
		result, err := measureSpeedLabDirection(ctx, direction, 350*time.Millisecond, 600*time.Millisecond, idle.MedianMs)
		if err != nil || result.Bytes == 0 || result.LoadedLatency.Samples < 2 {
			t.Fatal("direction or loaded sampler bypassed captured tunnel", direction, result, err)
		}
	}
	if fallback.Load() != 0 || dials.Load() < 5 {
		t.Fatal("one of three production client constructors missed captured dialer", fallback.Load(), dials.Load())
	}
}

func TestSpeedLabCapturedTunnelRejectsLateHTTPResponse(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server, fallback, _ := speedLabCapturedTLSFixture(t, "speed.cloudflare.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("late"))
		close(finished)
	}))
	owner, stopOwner := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopOwner()
	owner = withSpeedLabTunnelDialer(owner, speedLabCapturedDialFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}))
	client := newSpeedLabHTTPClientContext(owner, time.Second)
	defer client.CloseIdleConnections()
	request, cancel := context.WithCancel(owner)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := speedLabProbeOnce(request, client); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("TLS request did not reach the provider")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			close(release)
			t.Fatal("canceled original request accepted a response", err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("HTTP response wait ignored original cancellation")
	}
	close(release)
	<-finished
	if fallback.Load() != 0 || owner.Err() != nil {
		t.Fatal("request cancellation changed route or canceled healthy owner", fallback.Load(), owner.Err())
	}
}

func TestSpeedLabCapturedTunnelSeparatesAdmissionAndSocketLifetime(t *testing.T) {
	for _, which := range []string{"request", "factory"} {
		t.Run(which, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			server, fallback, _ := speedLabCapturedTLSFixture(t, "speed.cloudflare.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				_, _ = w.Write([]byte("late"))
			}))
			defer close(release)
			owner, stopOwner := context.WithTimeout(context.Background(), 5*time.Second)
			defer stopOwner()
			request, stopRequest := context.WithTimeout(context.Background(), 3*time.Second)
			defer stopRequest()
			dialContexts := make(chan context.Context, 1)
			closed := make(chan struct{})
			owner = withSpeedLabTunnelDialer(owner, speedLabCapturedDialFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				context.AfterFunc(speedLabDialLifetime(ctx), func() { _ = conn.Close(); close(closed) })
				dialContexts <- ctx
				return conn, nil
			}))
			client := newSpeedLabHTTPClientContext(owner, 4*time.Second)
			defer client.CloseIdleConnections()
			done := make(chan error, 1)
			go func() { _, err := speedLabProbeOnce(request, client); done <- err }()
			select {
			case <-entered:
			case err := <-done:
				t.Fatal("successful socket ended with dial admission", err)
			case <-time.After(time.Second):
				t.Fatal("original TLS request did not arrive")
			}
			admission := <-dialContexts
			if admission.Err() == nil || speedLabDialLifetime(admission).Err() != nil {
				t.Fatal("dial admission and request socket lifetime were not separated")
			}
			if which == "request" {
				stopRequest()
			} else {
				stopOwner()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expired socket accepted late response")
				}
			case <-time.After(time.Second):
				t.Fatal("request did not follow original cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("captured socket escaped original lifetime")
			}
			if fallback.Load() != 0 {
				t.Fatal("socket used ordinary network")
			}
		})
	}
}
