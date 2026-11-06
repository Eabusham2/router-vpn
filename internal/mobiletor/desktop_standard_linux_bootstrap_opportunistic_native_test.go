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

func init() {
	if len(os.Args) == 5 && os.Args[1] == "routervpn-opportunistic-peer" {
		if err := bootstrapOpportunisticNativePeer(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(94)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "routervpn-opportunistic-client" {
		if err := bootstrapOpportunisticNativeClient(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(95)
		}
		os.Exit(0)
	}
}
func bootstrapOpportunisticPorts(mode string) (int, int) {
	if mode == "fallback-default" {
		return 853, 53
	}
	return 6653, 6653
}

type bootstrapOpportunisticPeerNote struct {
	TLS, EncryptedDNS, PlainDNS bool
	SNI, PlainNetwork           string
	TLSPort, PlainPort          int
}

func bootstrapOpportunisticNativePeer(mode, certificate, key string) error {
	tlsPort, plainPort := bootstrapOpportunisticPorts(mode)
	listener, err := net.Listen("tcp4", net.JoinHostPort("198.18.0.2", fmt.Sprint(tlsPort)))
	if err != nil {
		return err
	}
	defer listener.Close()
	plain, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: plainPort})
	if err != nil {
		return err
	}
	defer plain.Close()
	ready := os.NewFile(3, "opportunistic-peer-ready")
	if _, err = ready.Write([]byte{'R'}); err != nil {
		return err
	}
	ready.Close()
	note := bootstrapOpportunisticPeerNote{TLSPort: tlsPort, PlainPort: plainPort}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(6 * time.Second))
	raw, err := listener.Accept()
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	note.TLS = true
	fallback := strings.HasPrefix(mode, "fallback-")
	reject := fallback || mode == "owner-loss" || mode == "stale-grant" || mode == "cancel"
	if reject {
		buffer := make([]byte, 5)
		_, e := io.ReadFull(raw, buffer)
		if e != nil || buffer[0] != 22 {
			return errors.Join(e, errors.New("peer did not receive TLS-first ClientHello"))
		}
		if mode == "cancel" {
			signal := os.NewFile(4, "opportunistic-clienthello")
			_, err = signal.Write([]byte{'C'})
			signal.Close()
			if err != nil {
				return err
			}
			time.Sleep(150 * time.Millisecond)
		} else {
			if _, err = raw.Write([]byte("not TLS protocol\r\n")); err != nil {
				return err
			}
		}
		raw.Close()
	} else {
		cert, e := tls.LoadX509KeyPair(certificate, key)
		if e != nil {
			return e
		}
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { note.SNI = hello.ServerName; return nil, nil }})
		err = server.Handshake()
		if mode == "strict-selfsigned" {
			if err == nil {
				return errors.New("strict peer accepted untrusted certificate")
			}
			raw.Close()
		} else {
			if err != nil {
				return err
			}
			var length [2]byte
			if _, err = io.ReadFull(server, length[:]); err != nil {
				return err
			}
			size := int(binary.BigEndian.Uint16(length[:]))
			if size != len(bootstrapUpstreamQuestion()) {
				return errors.New("encrypted DNS frame changed")
			}
			body := make([]byte, size)
			if _, err = io.ReadFull(server, body); err != nil || !bytes.Equal(body, bootstrapUpstreamQuestion()) {
				return errors.Join(err, errors.New("encrypted DNS question changed"))
			}
			note.EncryptedDNS = true
			if mode != "after-tls" {
				if _, err = server.Write(append(length[:], body...)); err != nil {
					return err
				}
			}
			raw.Close()
		}
	}
	if fallback {
		if mode == "fallback-truncated" {
			_ = plain.SetDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 512)
			n, from, e := plain.ReadFromUDPAddrPort(buffer)
			if e != nil || !bytes.Equal(buffer[:n], bootstrapUpstreamQuestion()) {
				return errors.Join(e, errors.New("truncated fallback changed UDP question"))
			}
			response := bytes.Clone(buffer[:n])
			response[2] |= 0x82
			if _, e = plain.WriteToUDPAddrPort(response, from); e != nil {
				return e
			}
		}
		if mode == "fallback-tcp" || mode == "fallback-truncated" {
			next, e := listener.Accept()
			if e != nil {
				return e
			}
			defer next.Close()
			_ = next.SetDeadline(time.Now().Add(2 * time.Second))
			var length [2]byte
			if _, e = io.ReadFull(next, length[:]); e != nil {
				return e
			}
			size := int(binary.BigEndian.Uint16(length[:]))
			if size != len(bootstrapUpstreamQuestion()) {
				return errors.New("plain TCP fallback lost original DNS framing")
			}
			body := make([]byte, size)
			if _, e = io.ReadFull(next, body); e != nil || !bytes.Equal(body, bootstrapUpstreamQuestion()) {
				return errors.Join(e, errors.New("plain TCP fallback changed query"))
			}
			if _, e = next.Write(append(length[:], body...)); e != nil {
				return e
			}
			note.PlainNetwork = "tcp"
		} else {
			_ = plain.SetDeadline(time.Now().Add(3 * time.Second))
			buffer := make([]byte, 512)
			n, from, e := plain.ReadFromUDPAddrPort(buffer)
			if e != nil || !bytes.Equal(buffer[:n], bootstrapUpstreamQuestion()) {
				return errors.Join(e, errors.New("plain fallback did not preserve exact captured port/question"))
			}
			if _, e = plain.WriteToUDPAddrPort(buffer[:n], from); e != nil {
				return e
			}
			note.PlainNetwork = "udp"
		}
		note.PlainDNS = true
	} else {
		wait := 300 * time.Millisecond
		if mode == "owner-loss" || mode == "stale-grant" {
			wait = 3 * time.Second
		}
		_ = plain.SetDeadline(time.Now().Add(wait))
		var buffer [512]byte
		if _, _, e := plain.ReadFromUDPAddrPort(buffer[:]); e == nil {
			return errors.New("forbidden cleartext followed TLS success/cancel/owner loss")
		}
	}
	return json.NewEncoder(os.Stdout).Encode(note)
}
func bootstrapOpportunisticNativeClient(mode string) (failure error) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		return errors.New("opportunistic client lost guarded namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "routervpn-opportunistic-")
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
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
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
	group, err := p.BeginBootstrapDNSGroup(ctx, lease)
	if err != nil {
		return err
	}
	name := "resolver.example"
	if mode == "tls-empty-sni" {
		name = ""
	}
	port := uint16(6653)
	if mode == "fallback-default" {
		port = 0
	}
	policy := bootstrapOpportunisticPolicy("198.18.0.2", port, name)
	network := "udp"
	if mode == "fallback-tcp" {
		network = "tcp"
	}
	capability, err := NewDesktopLinuxOpportunisticDNS(policy, "node.example", 0, network)
	if err != nil {
		return err
	}
	query, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	signal := os.NewFile(3, "opportunistic-clienthello")
	defer signal.Close()
	if mode == "cancel" {
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			var value [1]byte
			if _, e := io.ReadFull(signal, value[:]); e == nil && value[0] == 'C' {
				stop()
			}
		}()
		defer func() { signal.Close(); <-joined }()
	}
	checks := 0
	current := func(check context.Context) error {
		checks++
		if err := check.Err(); err != nil {
			return err
		}
		if !capability.MatchesPolicy(policy) {
			return errors.New("original selected policy changed")
		}
		if mode == "owner-loss" && checks == 2 {
			return errors.New("original daemon owner deliberately retired")
		}
		if mode == "stale-grant" && checks == 2 {
			group.mu.Lock()
			duration := group.members[0].grant.duration
			group.mu.Unlock()
			select {
			case <-time.After(duration + 150*time.Millisecond):
			case <-check.Done():
				return check.Err()
			}
		}
		return nil
	}
	var answer []byte
	if mode == "strict-selfsigned" {
		secure, _, _ := capability.upstreams()
		answer, err = group.Exchange(query, secure, bootstrapUpstreamQuestion())
	} else {
		answer, err = group.ExchangeOpportunistic(query, capability, bootstrapUpstreamQuestion(), current)
	}
	positive := strings.HasPrefix(mode, "tls-") || strings.HasPrefix(mode, "fallback-")
	if positive {
		if err != nil || !bytes.Equal(answer, bootstrapUpstreamQuestion()) {
			return errors.Join(err, errors.New("captured opportunistic policy failed exact owned exchange"))
		}
	} else if err == nil || answer != nil {
		return errors.New("forbidden opportunistic downgrade acquired answer")
	}
	if mode == "strict-selfsigned" {
		var cert *tls.CertificateVerificationError
		if !errors.As(err, &cert) {
			return errors.Join(err, errors.New("strict failure did not prove certificate rejection"))
		}
	}
	if mode == "cancel" && !errors.Is(err, context.Canceled) {
		return errors.Join(err, errors.New("original cancellation did not join TLS attempt"))
	}
	if mode == "stale-grant" && !strings.Contains(err.Error(), "finite permit") {
		return errors.Join(err, errors.New("stale permit was not the actual fallback refusal"))
	}
	if err = group.Close(ctx); err != nil {
		return err
	}
	after, err := p.Receipt(ctx)
	if err != nil || p.bootstrap != nil || !bytes.Equal(before.Baseline, after.Baseline) {
		return errors.Join(err, errors.New("opportunistic exchange did not restore original baseline"))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": mode, "positive": positive, "baseline_restored": true})
}
func TestDesktopLinuxGuardianKernelStandardBootstrapOpportunistic(t *testing.T) {
	for _, mode := range []string{"tls-selfsigned", "tls-empty-sni", "strict-selfsigned", "fallback-udp", "fallback-tcp", "fallback-default", "fallback-truncated", "after-tls", "cancel", "owner-loss", "stale-grant"} {
		t.Run(mode, func(t *testing.T) {
			if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
				t.Fatal("opportunistic proof requires mandatory isolated native namespace")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cert, _ := bootstrapUpstreamCertificate(t, net.ParseIP("198.18.0.2"))
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "peer.pem"), filepath.Join(dir, "peer-key.pem")
			var encoded []byte
			for _, der := range cert.Certificate {
				encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			}
			key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(certFile, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
				t.Fatal(err)
			}
			image, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			readyR, readyW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyR.Close()
			signalR, signalW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer signalR.Close()
			defer signalW.Close()
			peer := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", image, "routervpn-opportunistic-peer", mode, certFile, keyFile)
			peer.ExtraFiles = []*os.File{readyW, signalW}
			var output, diagnostic bytes.Buffer
			peer.Stdout = &output
			peer.Stderr = &diagnostic
			if err = peer.Start(); err != nil {
				readyW.Close()
				t.Fatal(err)
			}
			readyW.Close()
			signalW.Close()
			joined := false
			defer func() {
				if !joined {
					_ = peer.Process.Kill()
					_ = peer.Wait()
				}
			}()
			var ready [1]byte
			if _, err = io.ReadFull(readyR, ready[:]); err != nil || ready[0] != 'R' {
				t.Fatal("opportunistic peer readiness", err, diagnostic.String())
			}
			client := exec.CommandContext(ctx, image, "routervpn-opportunistic-client", mode)
			client.ExtraFiles = []*os.File{signalR}
			raw, err := client.CombinedOutput()
			if err != nil {
				t.Fatal("actual owned opportunistic client", err, string(raw))
			}
			if err = peer.Wait(); err != nil {
				joined = true
				t.Fatal("independent opportunistic peer", err, diagnostic.String())
			}
			joined = true
			var note bootstrapOpportunisticPeerNote
			if json.Unmarshal(output.Bytes(), &note) != nil || !note.TLS {
				t.Fatal("peer omitted actual TLS-first proof", output.String())
			}
			fallback := strings.HasPrefix(mode, "fallback-")
			if note.PlainDNS != fallback || note.EncryptedDNS != (strings.HasPrefix(mode, "tls-") || mode == "after-tls") {
				t.Fatal("actual encrypted/plain traffic contradicted captured policy", note)
			}
			if (mode == "fallback-tcp" || mode == "fallback-truncated") && note.PlainNetwork != "tcp" || fallback && mode != "fallback-tcp" && mode != "fallback-truncated" && note.PlainNetwork != "udp" {
				t.Fatal("plain fallback changed requested transport", note)
			}
			tlsPort, plainPort := bootstrapOpportunisticPorts(mode)
			if note.TLSPort != tlsPort || note.PlainPort != plainPort {
				t.Fatal("captured port changed", note)
			}
			if mode == "tls-empty-sni" && note.SNI != "" || (mode == "tls-selfsigned" || mode == "after-tls" || mode == "strict-selfsigned") && note.SNI != "resolver.example" {
				t.Fatal("TLS changed original SNI", note)
			}
			var result struct {
				Mode     string `json:"mode"`
				Baseline bool   `json:"baseline_restored"`
			}
			if json.Unmarshal(raw, &result) != nil || result.Mode != mode || !result.Baseline {
				t.Fatal("client omitted original cleanup", string(raw))
			}
		})
	}
}
