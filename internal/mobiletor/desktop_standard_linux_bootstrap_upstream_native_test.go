//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type bootstrapUpstreamPeerNote struct {
	Accepted, Query bool
	SNI             string
}

func init() {
	if len(os.Args) == 5 && os.Args[1] == "routervpn-bootstrap-upstream-peer" {
		if err := bootstrapUpstreamNativePeer(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(91)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "routervpn-bootstrap-upstream-client" {
		if err := bootstrapUpstreamNativeClient(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(92)
		}
		os.Exit(0)
	}
}
func bootstrapUpstreamNativeChoice(mode string) DesktopLinuxBootstrapDNSUpstream {
	u := DesktopLinuxBootstrapDNSUpstream{Endpoint: netip.MustParseAddrPort("198.18.0.2:2053"), Network: "udp"}
	if mode == "tcp-port" {
		u.Endpoint = netip.MustParseAddrPort("198.18.0.2:3053")
		u.Network = "tcp"
	}
	if strings.HasPrefix(mode, "tls-") {
		u.Endpoint = netip.MustParseAddrPort("198.18.0.2:8853")
		u.Network = "tls"
		u.TLSServerName = "resolver.example"
	}
	if mode == "tls-ip" {
		u.TLSServerName = ""
	}
	if mode == "tls-wrong-name" {
		u.TLSServerName = "replacement.example"
	}
	return u
}
func bootstrapUpstreamNativePeer(mode, certificate, key string) error {
	u := bootstrapUpstreamNativeChoice(mode)
	ready := os.NewFile(3, "upstream-peer-ready")
	defer ready.Close()
	note := bootstrapUpstreamPeerNote{}
	defer func() { _ = json.NewEncoder(os.Stdout).Encode(note) }()
	if u.Network == "udp" {
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(u.Endpoint))
		if err != nil {
			return err
		}
		defer c.Close()
		if _, err = ready.Write([]byte{'R'}); err != nil {
			return err
		}
		buffer := make([]byte, 512)
		n, from, err := c.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		note.Accepted = true
		if !bytes.Equal(buffer[:n], bootstrapUpstreamQuestion()) {
			return errors.New("upstream observed an unowned or substituted question")
		}
		note.Query = true
		_, err = c.WriteToUDPAddrPort(buffer[:n], from)
		return err
	}
	listener, err := net.Listen("tcp4", u.Endpoint.String())
	if err != nil {
		return err
	}
	defer listener.Close()
	if _, err = ready.Write([]byte{'R'}); err != nil {
		return err
	}
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	note.Accepted = true
	if mode == "tls-timeout" {
		// Observe an actual ClientHello, then withhold ServerHello past the
		// original query deadline. Do not require peer FIN after deny retirement.
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		var body [512]byte
		if n, e := connection.Read(body[:]); e != nil || n == 0 {
			return errors.Join(e, errors.New("held TLS peer received no ClientHello"))
		}
		time.Sleep(750 * time.Millisecond)
		return nil
	}
	if u.Network == "tls" {
		pair, err := tls.LoadX509KeyPair(certificate, key)
		if err != nil {
			return err
		}
		secured := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { note.SNI = hello.ServerName; return nil, nil }})
		if err = secured.Handshake(); err != nil {
			if mode == "tls-wrong-name" || mode == "tls-untrusted" {
				return nil
			}
			return err
		}
		connection = secured
	}
	var length [2]byte
	if _, err = io.ReadFull(connection, length[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size != len(bootstrapUpstreamQuestion()) {
		return errors.New("upstream DNS frame length changed")
	}
	body := make([]byte, size)
	if _, err = io.ReadFull(connection, body); err != nil {
		return err
	}
	if !bytes.Equal(body, bootstrapUpstreamQuestion()) {
		return errors.New("upstream DNS frame changed question")
	}
	note.Query = true
	_, err = connection.Write(append(length[:], body...))
	return err
}
func bootstrapUpstreamNativeClient(mode string) (failure error) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		return errors.New("native upstream client lost isolated original namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "routervpn-upstream-client-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	lease, err := os.OpenFile(filepath.Join(dir, "lease"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lease.Close()
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	capture := desktopSocketFixtureCapture()
	p, err := NewDesktopLinuxStandardProtection(ctx, hex.EncodeToString(nonce[:]), capture.SourceSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.99")}, false, lease)
	if err != nil {
		return err
	}
	defer func() {
		failure = errors.Join(failure, p.CleanupBootstrap(ctx, lease), p.Release(ctx, lease), p.Close(ctx))
	}()
	before, err := p.Receipt(ctx)
	if err != nil {
		return err
	}
	u := bootstrapUpstreamNativeChoice(mode)
	route, err := u.route(ctx, 0, netip.AddrPort{})
	if err != nil {
		return err
	}
	u.InterfaceIndex = route.Interface.Index
	if mode == "wrong-link" {
		u.InterfaceIndex += 100000
	}
	// Ordinary sockets remain blocked on the exact nondefault resolver port.
	ordinary, err := net.DialTimeout(u.socketNetwork(), u.Endpoint.String(), 100*time.Millisecond)
	if err == nil {
		_ = ordinary.SetDeadline(time.Now().Add(100 * time.Millisecond))
		if u.Network == "udp" {
			_, err = ordinary.Write([]byte("unowned"))
			if err == nil {
				var reply [32]byte
				_, err = ordinary.Read(reply[:])
			}
		}
		ordinary.Close()
		if err == nil {
			return errors.New("bootstrap upstream admitted ordinary bypass socket")
		}
	}
	query, stop := context.WithTimeout(ctx, 3*time.Second)
	if mode == "tls-timeout" {
		stop()
		query, stop = context.WithTimeout(ctx, 500*time.Millisecond)
	}
	defer stop()
	answer, exchangeErr := p.BootstrapDNSExchangeUpstream(ctx, query, lease, u, bootstrapUpstreamQuestion())
	negative := mode == "tls-wrong-name" || mode == "tls-untrusted" || mode == "tls-timeout" || mode == "wrong-link"
	if negative {
		if exchangeErr == nil || answer != nil {
			return errors.New("negative upstream policy acquired a DNS answer")
		}
		if mode == "tls-wrong-name" || mode == "tls-untrusted" {
			var certificateError *tls.CertificateVerificationError
			if !errors.As(exchangeErr, &certificateError) {
				return errors.Join(exchangeErr, errors.New("TLS refusal did not prove failed certificate verification"))
			}
		}
		if mode == "tls-timeout" && !errors.Is(exchangeErr, context.DeadlineExceeded) {
			return errors.Join(exchangeErr, errors.New("TLS query timeout changed original deadline"))
		}
	} else if exchangeErr != nil || !bytes.Equal(answer, bootstrapUpstreamQuestion()) {
		return errors.Join(exchangeErr, errors.New("captured protected upstream did not return exact framed DNS"))
	}
	after, err := p.Receipt(ctx)
	if err != nil || p.bootstrap != nil || !bytes.Equal(before.Baseline, after.Baseline) || before.TableHandle != after.TableHandle {
		return errors.Join(err, errors.New("upstream operation lost original baseline/finite grant cleanup"))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": mode, "negative": negative, "baseline_restored": true})
}
func TestDesktopLinuxGuardianKernelStandardBootstrapUpstream(t *testing.T) {
	for _, mode := range []string{"udp-port", "tcp-port", "tls-name", "tls-ip", "tls-wrong-name", "tls-untrusted", "tls-timeout", "wrong-link"} {
		t.Run(mode, func(t *testing.T) {
			if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
				t.Fatal("upstream proof requires mandatory isolated native namespace")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			certificate, _ := bootstrapUpstreamCertificate(t, net.ParseIP("198.18.0.2"))
			dir := t.TempDir()
			certFile, keyFile, rootFile := filepath.Join(dir, "peer.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "root.pem")
			var certPEM []byte
			for _, der := range certificate.Certificate {
				certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			}
			key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			root := certificate.Certificate[len(certificate.Certificate)-1]
			if mode == "tls-untrusted" {
				other, _ := bootstrapUpstreamCertificate(t)
				root = other.Certificate[len(other.Certificate)-1]
			}
			for path, body := range map[string][]byte{certFile: certPEM, keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), rootFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})} {
				if err = os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			readyR, readyW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyR.Close()
			image, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			peer := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", image, "routervpn-bootstrap-upstream-peer", mode, certFile, keyFile)
			peer.ExtraFiles = []*os.File{readyW}
			var peerOutput, peerError bytes.Buffer
			peer.Stdout, peer.Stderr = &peerOutput, &peerError
			if err = peer.Start(); err != nil {
				readyW.Close()
				t.Fatal(err)
			}
			readyW.Close()
			joined := false
			defer func() {
				if !joined {
					_ = peer.Process.Kill()
					_ = peer.Wait()
				}
			}()
			var signal [1]byte
			if _, err = io.ReadFull(readyR, signal[:]); err != nil || signal[0] != 'R' {
				t.Fatal("upstream peer readiness", err, peerError.String())
			}
			client := exec.CommandContext(ctx, image, "routervpn-bootstrap-upstream-client", mode)
			rootsDir := filepath.Join(dir, "empty-ca-directory")
			if err = os.Mkdir(rootsDir, 0700); err != nil {
				t.Fatal(err)
			}
			client.Env = append(os.Environ(), "SSL_CERT_FILE="+rootFile, "SSL_CERT_DIR="+rootsDir)
			raw, err := client.CombinedOutput()
			if err != nil {
				t.Fatal("original protected upstream client", err, string(raw))
			}
			var result struct {
				Mode             string `json:"mode"`
				Negative         bool   `json:"negative"`
				BaselineRestored bool   `json:"baseline_restored"`
			}
			if json.Unmarshal(raw, &result) != nil || result.Mode != mode || !result.BaselineRestored {
				t.Fatal("native client omitted original cleanup verdict", string(raw))
			}
			if mode == "wrong-link" {
				_ = peer.Process.Kill()
				_ = peer.Wait()
				joined = true
				if peerOutput.Len() != 0 {
					t.Fatal("changed selected link reached upstream", peerOutput.String())
				}
				return
			}
			if err = peer.Wait(); err != nil {
				joined = true
				t.Fatal("independent upstream peer", err, peerError.String())
			}
			joined = true
			var note bootstrapUpstreamPeerNote
			if json.Unmarshal(peerOutput.Bytes(), &note) != nil || !note.Accepted || note.Query == result.Negative {
				t.Fatal("upstream did not independently prove exact traffic/refusal", peerOutput.String())
			}
			expectedSNI := ""
			if strings.HasPrefix(mode, "tls-") && mode != "tls-ip" && mode != "tls-timeout" {
				expectedSNI = bootstrapUpstreamNativeChoice(mode).TLSServerName
			}
			if note.SNI != expectedSNI {
				t.Fatal("actual TLS SNI changed captured identity", note.SNI, expectedSNI)
			}
		})
	}
}
