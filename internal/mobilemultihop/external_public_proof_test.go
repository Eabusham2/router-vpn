package mobilemultihop

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func externalPublicProofCertificate(t *testing.T, address string) (tls.Certificate, *tls.Config) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated external proof"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(address)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func externalPublicProofPeer(t *testing.T, certificate tls.Certificate, response string) (func(context.Context, string, string) (net.Conn, error), *atomic.Int32, *atomic.Value) {
	t.Helper()
	var requests atomic.Int32
	var nonce atomic.Value
	var workers sync.WaitGroup
	dial := func(ctx context.Context, tag, address string) (net.Conn, error) {
		if tag != "captured-entry" || address != "1.1.1.1:443" || ctx.Err() != nil {
			t.Errorf("public proof changed its captured route: %s %s", tag, address)
			return nil, errors.New("wrong route")
		}
		client, server := net.Pipe()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer server.Close()
			secure := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			if secure.Handshake() != nil {
				return
			}
			request, err := http.ReadRequest(bufio.NewReader(secure))
			if err != nil {
				return
			}
			defer request.Body.Close()
			requests.Add(1)
			proofNonce := request.URL.Query().Get("routervpn_proof")
			if request.Method != "GET" || request.URL.Path != "/cdn-cgi/trace" || request.Host != "1.1.1.1" || !proofID.MatchString(proofNonce+proofNonce) ||
				len(request.URL.Query()) != 1 || request.Header.Get("Authorization") != "" || request.Header.Get("Cache-Control") != "no-store" || request.Header.Get("Accept-Encoding") != "identity" {
				t.Error("public proof changed its HTTPS endpoint, nonce, headers or credential ownership")
				return
			}
			nonce.Store(proofNonce)
			_, _ = io.WriteString(secure, response)
		}()
		return client, nil
	}
	t.Cleanup(workers.Wait)
	return dial, &requests, &nonce
}

func TestExternalPublicProofUsesActualCapturedTLSAndSelectedAddress(t *testing.T) {
	certificate, trust := externalPublicProofCertificate(t, "1.1.1.1")
	for _, expected := range []string{"203.0.113.88", "2001:db8::88"} {
		t.Run(expected, func(t *testing.T) {
			body := "fl=isolated\nip=" + expected + "\n"
			dial, requests, nonce := externalPublicProofPeer(t, certificate, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
			var previous string
			for i := 0; i < 2; i++ {
				if err := proveExternalPublicIP(context.Background(), dial, "captured-entry", expected, trust); err != nil {
					t.Fatal(err)
				}
				current, _ := nonce.Load().(string)
				if current == "" || current == previous {
					t.Fatal("public-IP probe reused its nonce")
				}
				previous = current
			}
			if requests.Load() != 2 {
				t.Fatal("proof did not reach the actual encrypted peer twice")
			}
		})
	}
}

func TestExternalPublicProofRejectsWrongTLSBodyStatusAndEncoding(t *testing.T) {
	for _, mode := range []string{"wrong-ip", "duplicate-ip", "private-ip", "large", "redirect", "encoding", "wrong-certificate", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			address, body, status, headers := "1.1.1.1", "ip=203.0.113.88\n", "200 OK", ""
			switch mode {
			case "wrong-ip":
				body = "ip=203.0.113.89\n"
			case "duplicate-ip":
				body += body
			case "private-ip":
				body = "ip=10.0.0.1\n"
			case "large":
				body = strings.Repeat("x", 8193)
			case "redirect":
				status, headers = "302 Found", "Location: https://foreign.example/\r\n"
			case "encoding":
				headers = "Content-Encoding: gzip\r\n"
			case "wrong-certificate":
				address = "1.0.0.1"
			}
			certificate, trust := externalPublicProofCertificate(t, address)
			if mode == "untrusted" {
				trust = nil
			}
			dial, requests, _ := externalPublicProofPeer(t, certificate, fmt.Sprintf("HTTP/1.1 %s\r\n%sContent-Length: %d\r\n\r\n%s", status, headers, len(body), body))
			if err := proveExternalPublicIP(context.Background(), dial, "captured-entry", "203.0.113.88", trust); err == nil {
				t.Fatal("invalid expected-address proof was accepted")
			}
			if strings.Contains(mode, "certificate") || mode == "untrusted" {
				if requests.Load() != 0 {
					t.Fatal("wrong TLS identity reached an HTTP request")
				}
			} else if requests.Load() != 1 {
				t.Fatal("proof followed a redirect or skipped actual peer response")
			}
		})
	}
}

func TestExternalPublicProofShippingRequestUsesSameStrictPrimitive(t *testing.T) {
	certificate, _ := externalPublicProofCertificate(t, "1.1.1.1")
	dial, requests, _ := externalPublicProofPeer(t, certificate, "HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nip=203.0.113.88\n")
	engine := &externalProofFixture{dial: dial}
	request := &ExternalProofRequest{engine: engine}
	for _, prove := range []func(context.Context, string, string) error{
		func(ctx context.Context, tag, expected string) error {
			return ProveExternalPublicIP(ctx, dial, tag, expected)
		}, request.provePublic,
	} {
		if err := prove(context.Background(), "captured-entry", "203.0.113.88"); err == nil {
			t.Fatal("shipping proof accepted the fixture's untrusted TLS root")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("public proof extraction bypassed shipping certificate validation")
	}
}

type externalPublicProofFaultConnection struct {
	net.Conn
	fault  string
	closed atomic.Bool
}

func (c *externalPublicProofFaultConnection) SetDeadline(deadline time.Time) error {
	if c.fault == "deadline" {
		return errors.New("fixture cannot enforce a deadline")
	}
	return c.Conn.SetDeadline(deadline)
}

func (c *externalPublicProofFaultConnection) Close() error {
	c.closed.Store(true)
	err := c.Conn.Close()
	if c.fault == "close" {
		return errors.New("fixture close failed")
	}
	return err
}

func TestExternalPublicProofRequiresEnforcedDeadlineAndCleanJoinedClose(t *testing.T) {
	certificate, trust := externalPublicProofCertificate(t, "1.1.1.1")
	for _, mode := range []string{"deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			body := "ip=203.0.113.88\n"
			peer, requests, _ := externalPublicProofPeer(t, certificate, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
			var owned *externalPublicProofFaultConnection
			dial := func(ctx context.Context, tag, address string) (net.Conn, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 15*time.Second {
					t.Fatal("captured proof lost the existing bounded admission")
				}
				connection, err := peer(ctx, tag, address)
				owned = &externalPublicProofFaultConnection{Conn: connection, fault: mode}
				return owned, err
			}
			if err := proveExternalPublicIP(context.Background(), dial, "captured-entry", "203.0.113.88", trust); err == nil || owned == nil || !owned.closed.Load() {
				t.Fatal("failed deadline/close produced a valid proof or leaked its socket", err)
			}
			if mode == "deadline" && requests.Load() != 0 || mode == "close" && requests.Load() != 1 {
				t.Fatal("fixture did not exercise the intended real IO boundary")
			}
		})
	}
}

func TestExternalPublicProofRejectsMissingOrCanceledOwnershipBeforeDial(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, parent := range []context.Context{nil, ctx} {
		if ProveExternalPublicIP(parent, dial, "entry", "203.0.113.88") == nil {
			t.Fatal("absent/canceled parent was accepted")
		}
	}
	for _, tag := range []string{"", "foreign route", strings.Repeat("a", 129)} {
		if ProveExternalPublicIP(context.Background(), dial, tag, "203.0.113.88") == nil {
			t.Fatal("invalid captured tag was accepted")
		}
	}
	for _, expected := range []string{"", "10.0.0.1", "100.64.0.1", "::ffff:203.0.113.88", "203.0.113.88:80"} {
		if ProveExternalPublicIP(context.Background(), dial, "entry", expected) == nil {
			t.Fatal("invalid public address was accepted")
		}
	}
	if ProveExternalPublicIP(context.Background(), nil, "entry", "203.0.113.88") == nil || calls.Load() != 0 {
		t.Fatal("invalid admission opened networking")
	}
}

type externalPublicProofCloseBarrier struct {
	net.Conn
	entered, release chan struct{}
	writeEntered     chan struct{}
	writeOnce        sync.Once
	calls            atomic.Int32
}

func (c *externalPublicProofCloseBarrier) Write(body []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeEntered) })
	return c.Conn.Write(body)
}

func (c *externalPublicProofCloseBarrier) Close() error {
	if c.calls.Add(1) == 1 {
		close(c.entered)
		<-c.release
	}
	return c.Conn.Close()
}

func TestExternalPublicProofCancellationJoinsCapturedCloseAndLateDial(t *testing.T) {
	for _, mode := range []string{"late-dial", "active-tls"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client, peer := net.Pipe()
			defer peer.Close()
			owned := &externalPublicProofCloseBarrier{Conn: client, entered: make(chan struct{}), release: make(chan struct{}), writeEntered: make(chan struct{})}
			dialEntered, dialRelease := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			dial := func(context.Context, string, string) (net.Conn, error) {
				close(dialEntered)
				if mode == "late-dial" {
					<-dialRelease
				}
				return owned, nil
			}
			go func() { result <- ProveExternalPublicIP(ctx, dial, "captured-entry", "203.0.113.88") }()
			<-dialEntered
			if mode == "active-tls" {
				select {
				case <-owned.writeEntered:
				case <-time.After(time.Second):
					t.Fatal("TLS handshake did not enter its captured stream")
				}
			}
			cancel()
			if mode == "late-dial" {
				select {
				case <-result:
					t.Fatal("late dial was abandoned")
				default:
				}
				close(dialRelease)
			}
			select {
			case <-owned.entered:
			case <-time.After(time.Second):
				t.Fatal("cancel did not close captured socket")
			}
			select {
			case <-result:
				t.Fatal("proof returned before captured close joined")
			default:
			}
			close(owned.release)
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("canceled proof succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("proof did not join")
			}
			if owned.calls.Load() != 1 {
				t.Fatal("captured socket was closed more than once")
			}
		})
	}
}
