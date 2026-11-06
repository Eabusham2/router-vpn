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

	"router-vpn/internal/common"
	"router-vpn/internal/standardengine"
)

var bootstrapDNSSECNativeModes = []string{"udp-key", "tcp-large", "udp-truncated", "tls-ds", "tls-wrong-name", "opportunistic-udp", "opportunistic-tcp", "owner-loss", "ordinary-bypass", "foreign-scope", "wrong-response", "recycled-queries"}

func init() {
	if len(os.Args) == 5 && os.Args[1] == "routervpn-dnssec-upstream-peer" {
		if err := bootstrapDNSSECNativePeer(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(96)
		}
		os.Exit(0)
	}
	if len(os.Args) == 3 && os.Args[1] == "routervpn-dnssec-upstream-client" {
		if err := bootstrapDNSSECNativeClient(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(97)
		}
		os.Exit(0)
	}
}

func bootstrapDNSSECNativeWire(mode string, number int) []byte {
	name, kind := "example", uint16(48)
	if strings.HasPrefix(mode, "tls-") {
		kind = 43
	}
	if mode == "recycled-queries" {
		name = []string{"node.example", "example", "."}[number]
		kind = []uint16{1, 43, 48}[number]
	}
	return bootstrapDNSSECWire(name, kind)
}

// This peer proves exact transport/framing, not cryptographic validation. The
// separate signed authority/actual C validator gates prove signature results.
func bootstrapDNSSECNativeReply(wire []byte, large bool) []byte {
	answer := bytes.Clone(wire[:len(wire)-11]) // Strip the captured empty EDNS RR.
	answer[2], answer[3] = 0x81, 0x80
	answer[10], answer[11] = 0, 0
	if large {
		answer[7] = 1
		rr := []byte{0xc0, 0x0c, 0, 48, 0, 1, 0, 0, 0, 10, 0x9c, 0x40}
		answer = append(answer, rr...)
		answer = append(answer, bytes.Repeat([]byte{0x5a}, 40000)...)
	}
	return answer
}

type bootstrapDNSSECNativeNote struct {
	TLS, RejectedTLS bool
	SNI              string
	Queries          int
	Networks         []string
}

func bootstrapDNSSECNativePeer(mode, certificate, key string) error {
	address := "198.18.0.2:7853"
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address)))
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.MustParseAddrPort(address)))
	if err != nil {
		return err
	}
	defer tcp.Close()
	deadline := time.Now().Add(8 * time.Second)
	_ = udp.SetDeadline(deadline)
	_ = tcp.SetDeadline(deadline)
	ready := os.NewFile(3, "dnssec-upstream-ready")
	_, err = ready.Write([]byte{'R'})
	ready.Close()
	if err != nil {
		return err
	}
	note := bootstrapDNSSECNativeNote{}
	if strings.HasPrefix(mode, "opportunistic-") {
		conn, err := tcp.AcceptTCP()
		if err != nil {
			return err
		}
		_ = conn.SetDeadline(deadline)
		var header [5]byte
		_, readErr := io.ReadFull(conn, header[:])
		if readErr != nil || header[0] != 22 {
			conn.Close()
			return errors.Join(readErr, errors.New("DNSSEC peer did not observe TLS before plaintext"))
		}
		note.TLS, note.RejectedTLS = true, true
		_, err = conn.Write([]byte("not a TLS record\r\n"))
		conn.Close()
		if err != nil {
			return err
		}
	}
	count := 1
	if mode == "recycled-queries" {
		count = 3
	}
	for number := 0; number < count; number++ {
		wire := bootstrapDNSSECNativeWire(mode, number)
		wantTCP := mode == "tcp-large" || strings.HasPrefix(mode, "tls-")
		truncated := mode == "udp-truncated" || mode == "opportunistic-tcp"
		if !wantTCP {
			var buffer [4096]byte
			n, from, err := udp.ReadFromUDPAddrPort(buffer[:])
			if err != nil || !bytes.Equal(buffer[:n], wire) {
				return errors.Join(err, errors.New("DNSSEC UDP peer received a different query"))
			}
			note.Queries++
			note.Networks = append(note.Networks, "udp")
			reply := bootstrapDNSSECNativeReply(wire, false)
			if truncated {
				reply[2] |= 2
			}
			if mode == "wrong-response" {
				reply[0] ^= 1
			}
			if _, err = udp.WriteToUDPAddrPort(reply, from); err != nil {
				return err
			}
			if !truncated {
				continue
			}
		}
		raw, err := tcp.AcceptTCP()
		if err != nil {
			return err
		}
		_ = raw.SetDeadline(deadline)
		var conn net.Conn = raw
		if strings.HasPrefix(mode, "tls-") {
			certificate, err := tls.LoadX509KeyPair(certificate, key)
			if err != nil {
				raw.Close()
				return err
			}
			secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				note.TLS, note.SNI = true, hello.ServerName
				return nil, nil
			}})
			err = secured.Handshake()
			if mode == "tls-wrong-name" {
				raw.Close()
				if err == nil {
					return errors.New("strict DNSSEC TLS accepted a foreign certificate name")
				}
				note.RejectedTLS = true
				break
			}
			if err != nil {
				raw.Close()
				return err
			}
			conn = secured
		}
		var length [2]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			raw.Close()
			return err
		}
		if int(binary.BigEndian.Uint16(length[:])) != len(wire) {
			raw.Close()
			return errors.New("DNSSEC peer received an unowned frame length")
		}
		body := make([]byte, len(wire))
		if _, err = io.ReadFull(conn, body); err != nil || !bytes.Equal(body, wire) {
			raw.Close()
			return errors.Join(err, errors.New("DNSSEC TCP peer received a different query"))
		}
		note.Queries++
		note.Networks = append(note.Networks, "tcp")
		reply := bootstrapDNSSECNativeReply(wire, mode == "tcp-large" || truncated)
		binary.BigEndian.PutUint16(length[:], uint16(len(reply)))
		_, err = conn.Write(append(length[:], reply...))
		raw.Close()
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(note)
}

func bootstrapDNSSECNativePlan(policy standardengine.ResolvedPolicy) (*standardengine.ResolvedDNSSECPlan, error) {
	raw, err := policy.Canonical()
	if err != nil {
		return nil, err
	}
	questions, err := standardengine.ResolvedDNSSECQuestions(policy, "node.example", 0)
	if err != nil {
		return nil, err
	}
	var rows []standardengine.ResolvedAnchorResult
	for _, q := range questions {
		rows = append(rows, standardengine.ResolvedAnchorResult{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Name: q.Name, Type: q.Type})
	}
	return standardengine.BuildResolvedDNSSECPlan(policy, "node.example", 0, rows)
}

func bootstrapDNSSECNativeClient(mode string) (failure error) {
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		return errors.New("DNSSEC upstream client lost mandatory isolated namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "routervpn-dnssec-upstream-")
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
	protection, err := NewDesktopLinuxStandardProtection(ctx, hex.EncodeToString(nonce[:]), capture.SourceSHA256, []netip.Addr{netip.MustParseAddr("198.18.0.99")}, false, lease)
	if err != nil {
		return err
	}
	defer func() {
		failure = errors.Join(failure, protection.CleanupBootstrap(ctx, lease), protection.Release(ctx, lease), protection.Close(ctx))
	}()
	before, err := protection.Receipt(ctx)
	if err != nil {
		return err
	}
	policy := bootstrapOpportunisticPolicy("198.18.0.2", 7853, "resolver.example")
	policy.Manager.DNSSEC, policy.Manager.DNSOverTLS = "yes", "no"
	if strings.HasPrefix(mode, "tls-") {
		policy.Manager.DNSOverTLS = "yes"
	}
	if strings.HasPrefix(mode, "opportunistic-") {
		policy.Manager.DNSOverTLS = "opportunistic"
	}
	if mode == "tls-wrong-name" {
		policy.Manager.DNS[0].ServerName = "replacement.example"
		policy.Manager.CurrentDNS.ServerName = "replacement.example"
	}
	plan, err := bootstrapDNSSECNativePlan(policy)
	if err != nil {
		return err
	}
	group, err := protection.BeginBootstrapDNSSECGroup(ctx, lease, policy, []*standardengine.ResolvedDNSSECPlan{plan}, 1)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, group.Close(ctx)) }()
	negative := mode == "tls-wrong-name" || mode == "owner-loss" || mode == "ordinary-bypass" || mode == "foreign-scope" || mode == "wrong-response"
	count := 1
	if mode == "recycled-queries" {
		count = 3
	}
	for number := 0; number < count; number++ {
		wire := bootstrapDNSSECNativeWire(mode, number)
		question, err := NewDesktopLinuxBootstrapDNSSECQuestion(policy, plan, 1, wire)
		if err != nil {
			return err
		}
		network := "udp"
		if mode == "tcp-large" {
			network = "tcp"
		}
		upstream, err := question.upstream(network, strings.HasPrefix(mode, "tls-"))
		if err != nil {
			return err
		}
		if mode == "foreign-scope" {
			upstream.Endpoint = netip.AddrPortFrom(upstream.Endpoint.Addr(), 7854)
		}
		calls := 0
		guard := func(context.Context) error {
			calls++
			if mode == "owner-loss" && calls > 1 {
				return errors.New("original retained resolver owner disappeared")
			}
			return nil
		}
		query, stop := context.WithTimeout(ctx, 5*time.Second)
		var answer []byte
		var exchangeErr error
		switch {
		case mode == "ordinary-bypass":
			answer, exchangeErr = group.Exchange(query, upstream, wire)
		case strings.HasPrefix(mode, "opportunistic-"):
			selected, e := NewDesktopLinuxOpportunisticDNS(policy, "node.example", 0, "udp")
			if e != nil {
				stop()
				return e
			}
			answer, exchangeErr = group.ExchangeOpportunisticDNSSEC(query, selected, question, guard)
		default:
			answer, exchangeErr = group.ExchangeDNSSEC(query, upstream, question, guard)
		}
		stop()
		if negative {
			if exchangeErr == nil || answer != nil {
				return errors.New("invalid DNSSEC scope, reply or owner acquired an answer")
			}
			if (mode == "ordinary-bypass" || mode == "foreign-scope") && (calls != 0 || group.admitted != 0) {
				return errors.New("unadmitted DNSSEC authority acquired a physical attempt")
			}
			if mode == "tls-wrong-name" {
				var verification *tls.CertificateVerificationError
				if !errors.As(exchangeErr, &verification) {
					return errors.Join(exchangeErr, errors.New("strict DNSSEC TLS did not reject the actual certificate"))
				}
			}
		} else {
			large := mode == "tcp-large" || mode == "udp-truncated" || mode == "opportunistic-tcp"
			if exchangeErr != nil || common.ValidateDNSForwardResponse(wire, answer) != nil || !bytes.Equal(answer, bootstrapDNSSECNativeReply(wire, large)) {
				return errors.Join(exchangeErr, errors.New("DNSSEC selected transport lost its exact complete response"))
			}
		}
	}
	if err = group.Close(ctx); err != nil {
		return err
	}
	after, err := protection.Receipt(ctx)
	if err != nil || protection.bootstrap != nil || !bytes.Equal(before.Baseline, after.Baseline) || before.TableHandle != after.TableHandle || group.active != 0 {
		return errors.Join(err, errors.New("DNSSEC group did not join original sockets and restore exact deny baseline"))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": mode, "negative": negative, "baseline_restored": true})
}

func TestDesktopLinuxGuardianKernelStandardBootstrapDNSSEC(t *testing.T) {
	for _, mode := range bootstrapDNSSECNativeModes {
		t.Run(mode, func(t *testing.T) {
			if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
				t.Fatal("DNSSEC protected transport requires mandatory native namespace")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			certificate, _ := bootstrapUpstreamCertificate(t, net.ParseIP("198.18.0.2"))
			dir := t.TempDir()
			certPath, keyPath, rootPath := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "root.pem")
			var chain []byte
			for _, der := range certificate.Certificate {
				chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			}
			privateKey, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string][]byte{certPath: chain, keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), rootPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[len(certificate.Certificate)-1]})} {
				if err = os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
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
			peer := exec.CommandContext(ctx, "/usr/sbin/ip", "netns", "exec", "rvpn-peer", image, "routervpn-dnssec-upstream-peer", mode, certPath, keyPath)
			peer.ExtraFiles = []*os.File{readyW}
			var output, stderr bytes.Buffer
			peer.Stdout, peer.Stderr = &output, &stderr
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
				t.Fatal("DNSSEC peer readiness", err, stderr.String())
			}
			rootsDir := filepath.Join(dir, "empty-roots")
			if err = os.Mkdir(rootsDir, 0700); err != nil {
				t.Fatal(err)
			}
			client := exec.CommandContext(ctx, image, "routervpn-dnssec-upstream-client", mode)
			client.Env = append(os.Environ(), "SSL_CERT_FILE="+rootPath, "SSL_CERT_DIR="+rootsDir)
			raw, err := client.CombinedOutput()
			if err != nil {
				t.Fatal("protected DNSSEC transport", err, string(raw), stderr.String())
			}
			var result struct {
				Mode             string `json:"mode"`
				Negative         bool   `json:"negative"`
				BaselineRestored bool   `json:"baseline_restored"`
			}
			if json.Unmarshal(raw, &result) != nil || result.Mode != mode || !result.BaselineRestored {
				t.Fatal("DNSSEC client omitted exact joined native retirement", string(raw))
			}
			if mode == "ordinary-bypass" || mode == "foreign-scope" {
				_ = peer.Process.Kill()
				_ = peer.Wait()
				joined = true
				if output.Len() != 0 {
					t.Fatal("unadmitted DNSSEC query reached the peer", output.String())
				}
				return
			}
			if err = peer.Wait(); err != nil {
				joined = true
				t.Fatal("DNSSEC independent peer", err, stderr.String())
			}
			joined = true
			var note bootstrapDNSSECNativeNote
			if json.Unmarshal(output.Bytes(), &note) != nil {
				t.Fatal("DNSSEC peer omitted independent observed traffic", output.String())
			}
			queries := 1
			if mode == "udp-truncated" || mode == "opportunistic-tcp" {
				queries = 2
			}
			if mode == "recycled-queries" {
				queries = 3
			}
			if mode == "tls-wrong-name" {
				queries = 0
			}
			if note.Queries != queries || note.TLS != (strings.HasPrefix(mode, "tls-") || strings.HasPrefix(mode, "opportunistic-")) || note.RejectedTLS != (mode == "tls-wrong-name" || strings.HasPrefix(mode, "opportunistic-")) {
				t.Fatal("DNSSEC physical traffic did not match captured policy/refusal", output.String())
			}
			if mode == "tls-ds" && note.SNI != "resolver.example" || mode == "tls-wrong-name" && note.SNI != "replacement.example" {
				t.Fatal("DNSSEC TLS changed actual captured SNI", output.String())
			}
		})
	}
}
