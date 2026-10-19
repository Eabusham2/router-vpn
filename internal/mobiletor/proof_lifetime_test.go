package mobiletor

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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

type proofLateRead struct {
	net.Conn
	entered, closed, release chan struct{}
	once, closeOnce          sync.Once
	active                   atomic.Int32
	closes                   atomic.Int32
}

func (c *proofLateRead) Read([]byte) (int, error) {
	c.active.Add(1)
	defer c.active.Add(-1)
	c.once.Do(func() { close(c.entered) })
	<-c.closed
	<-c.release
	return 0, net.ErrClosed
}
func (*proofLateRead) Write(p []byte) (int, error) { return len(p), nil }
func (c *proofLateRead) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*proofLateRead) SetDeadline(time.Time) error      { return nil }
func (*proofLateRead) SetReadDeadline(time.Time) error  { return nil }
func (*proofLateRead) SetWriteDeadline(time.Time) error { return nil }

func TestDynamicTorProofCancellationJoinsPhysicalTLSRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lower := &proofLateRead{entered: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-lower.release:
		default:
			close(lower.release)
		}
	}()
	result := make(chan error, 1)
	go func() {
		proof, err := Prove(ctx, "captured", func(context.Context, string, string) (net.Conn, error) { return lower, nil })
		if proof.IsTor {
			err = errors.New("canceled TLS returned a proof")
		}
		result <- err
	}()
	<-lower.entered
	cancel()
	<-lower.closed
	select {
	case err := <-result:
		t.Fatalf("proof released while actual TLS Read remains active=%d: %v", lower.active.Load(), err)
	case <-time.After(25 * time.Millisecond):
	}
	close(lower.release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled TLS succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("proof did not join released physical read")
	}
	if lower.active.Load() != 0 || lower.closes.Load() != 1 {
		t.Fatal("TLS work/close was not joined", lower.active.Load(), lower.closes.Load())
	}
}

func proofTLSMaterial(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned proof fixture"}, DNSNames: []string{hostname}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}, pool
}

type proofFailClose struct {
	net.Conn
	count atomic.Int32
}

func (c *proofFailClose) Close() error {
	c.count.Add(1)
	_ = c.Conn.Close()
	return errors.New("close leaked private-proof-secret")
}

func TestDynamicTorProofActualVerifiedTLSAndStrictHTTP(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://unowned.invalid:9")
	for _, mode := range []string{"valid", "wrong-cert", "untrusted-cert", "redirect", "oversized", "false-tor", "close-failure"} {
		t.Run(mode, func(t *testing.T) {
			hostname := "check.torproject.org"
			if mode == "wrong-cert" {
				hostname = "other.invalid"
			}
			cert, roots := proofTLSMaterial(t, hostname)
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
			serverDone := make(chan error, 1)
			go func() {
				if err := server.Handshake(); err != nil {
					serverDone <- err
					return
				}
				request, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					serverDone <- err
					return
				}
				if request.Method != "GET" || request.URL.String() != "/api/ip" || request.Host != "check.torproject.org" || request.Header.Get("Accept-Encoding") != "identity" || !request.Close {
					serverDone <- errors.New("proof request changed captured fixed origin")
					return
				}
				body := `{"IsTor":true,"IP":"8.8.8.8"}`
				status := "200 OK"
				extra := ""
				switch mode {
				case "redirect":
					status = "302 Found"
					extra = "Location: https://unowned.invalid/other\r\n"
				case "oversized":
					body = strings.Repeat(" ", 4097)
				case "false-tor":
					body = `{"IsTor":false,"IP":"8.8.8.8"}`
				}
				_, err = fmt.Fprintf(server, "HTTP/1.1 %s\r\n%sContent-Length: %d\r\n\r\n%s", status, extra, len(body), body)
				serverDone <- err
			}()
			var lower net.Conn = client
			failedClose := &proofFailClose{Conn: client}
			if mode == "close-failure" {
				lower = failedClose
			}
			calls := 0
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				calls++
				if ctx.Err() != nil || network != "tcp" || address != "check.torproject.org:443" {
					t.Error("TLS proof escaped captured origin")
				}
				return lower, nil
			}
			if mode == "untrusted-cert" {
				roots = x509.NewCertPool()
			}
			proof, err := proveWithRoots(context.Background(), "actual-tls-session", dial, roots)
			_ = peer.Close()
			<-serverDone
			if mode == "valid" {
				if err != nil || !proof.IsTor || proof.SessionID != "actual-tls-session" || proof.IP != "8.8.8.8" || time.Since(proof.CheckedAt) > time.Second {
					t.Fatal("verified proof lost real response", proof, err)
				}
			} else if err == nil || proof.IsTor || strings.Contains(err.Error(), "private-proof-secret") {
				t.Fatal("invalid TLS/HTTP/close accepted or leaked", proof, err)
			}
			if calls != 1 {
				t.Fatal("proof redirected or retried outside captured origin", calls)
			}
			if mode == "close-failure" && failedClose.count.Load() != 1 {
				t.Fatal("actual close failure was not retained")
			}
		})
	}
}

func TestDynamicTorProofCancellationRetainsLateDialAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	client, server := net.Pipe()
	defer server.Close()
	result := make(chan error, 1)
	go func() {
		_, err := Prove(ctx, "captured", func(context.Context, string, string) (net.Conn, error) { close(entered); <-release; return client, nil })
		result <- err
	}()
	<-entered
	cancel()
	select {
	case <-result:
		t.Fatal("proof abandoned late captured dial")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("late canceled dial proved Tor")
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("canceled late dial wrote TLS bytes", err)
	}
}
