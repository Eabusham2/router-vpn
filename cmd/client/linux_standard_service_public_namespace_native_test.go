//go:build linux && routervpn_controller_privileged

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
)

const standardPublicArm = "/run/routervpn-standard-public-arm.json"
const standardPublicEntered = "/run/routervpn-standard-public-entered"

type standardPublicPause struct {
	Name        string
	OriginalMTU int
	Request     string
}
type standardPublicPeer struct {
	certificate                    tls.Certificate
	requests, downloaded, uploaded atomic.Int64
}

func newStandardPublicPeer() (*standardPublicPeer, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private namespace acceptance CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"speed.cloudflare.com", "api.ipify.org", "api64.ipify.org"}, IPAddresses: []net.IP{net.ParseIP("1.1.1.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return &standardPublicPeer{certificate: tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

// Only the explicit root/private-mount namespace fixture installs this CA.
// Production clients use their ordinary system roots and public DNS/IP names.
func installStandardPublicPeer(t *testing.T) *standardPublicPeer {
	t.Helper()
	if os.Getenv(linuxControllerNamespaceMarker) != "1" || os.Geteuid() != 0 {
		t.Fatal("public fixture requires original private namespace")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/opt", &fs); err != nil || uint64(fs.Type) != 0x01021994 {
		t.Fatal("public fixture refuses non-private namespace", err)
	}
	peer, ca, err := newStandardPublicPeer()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join("/run", "routervpn-standard-public-roots")
	if err = os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "ca-certificates.crt"), ca, 0644); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Mount(directory, "/etc/ssl/certs", "", syscall.MS_BIND, ""); err != nil {
		t.Fatal("private test trust mount", err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount("/etc/ssl/certs", 0); err != nil {
			t.Error(err)
		}
		_ = os.RemoveAll(directory)
		_ = os.Remove(standardPublicArm)
		_ = os.Remove(standardPublicEntered)
		if peer.requests.Load() < 3 || peer.downloaded.Load() == 0 || peer.uploaded.Load() == 0 {
			t.Error("actual selected SOCKS peer did not carry verified HTTPS measurements", peer.requests.Load(), peer.downloaded.Load(), peer.uploaded.Load())
		}
	})
	return peer
}

// The proxy performs the same real username/password exchange as the selected
// exit. It accepts only its selected DNS service and named HTTPS proof targets.
func (p *standardPublicPeer) serve(connection net.Conn, queries *atomic.Int64) error {
	var head [2]byte
	if _, err := io.ReadFull(connection, head[:]); err != nil {
		return err
	}
	if head[0] != 5 || head[1] < 1 || head[1] > 8 {
		return errors.New("invalid public fixture SOCKS greeting")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return err
	}
	if !bytes.Contains(methods, []byte{2}) {
		return errors.New("selected SOCKS authentication omitted")
	}
	if _, err := connection.Write([]byte{5, 2}); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, head[:]); err != nil {
		return err
	}
	if head != [2]byte{1, 1} {
		return errors.New("foreign SOCKS auth length")
	}
	var auth [3]byte
	if _, err := io.ReadFull(connection, auth[:]); err != nil {
		return err
	}
	if auth != [3]byte{'u', 1, 'p'} {
		return errors.New("foreign SOCKS credentials")
	}
	if _, err := connection.Write([]byte{1, 0}); err != nil {
		return err
	}
	var request [4]byte
	if _, err := io.ReadFull(connection, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		return errors.New("invalid public SOCKS request")
	}
	var host string
	switch request[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(connection, ip[:]); err != nil {
			return err
		}
		host = net.IP(ip[:]).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return err
		}
		if length[0] == 0 {
			return errors.New("empty SOCKS host")
		}
		name := make([]byte, int(length[0]))
		if _, err := io.ReadFull(connection, name); err != nil {
			return err
		}
		host = string(name)
	default:
		return errors.New("uncaptured SOCKS address family")
	}
	var portRaw [2]byte
	if _, err := io.ReadFull(connection, portRaw[:]); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portRaw[:])
	dns := host == "203.0.113.53" && port == 5353
	https := port == 443 && (host == "203.0.113.20" || host == "1.1.1.1" || host == "speed.cloudflare.com" || host == "api.ipify.org" || host == "api64.ipify.org")
	if !dns && !https {
		return errors.New("public fixture refused foreign destination")
	}
	if _, err := connection.Write([]byte{5, 0, 0, 1, 203, 0, 113, 10, 1, 187}); err != nil {
		return err
	}
	if dns {
		return standardPublicDNS(connection, queries)
	}
	return p.https(connection)
}

func standardPublicDNS(connection net.Conn, queries *atomic.Int64) error {
	for {
		var size [2]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 17 || n > 16*1024 {
			return errors.New("invalid selected DNS frame")
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(connection, query); err != nil {
			return err
		}
		queries.Add(1)
		response := append([]byte(nil), query[:2]...)
		response = append(response, []byte{0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}...)
		response = append(response, query[12:]...)
		response = append(response, []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 203, 0, 113, 20}...)
		frame := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(frame, uint16(len(response)))
		copy(frame[2:], response)
		if _, err := connection.Write(frame); err != nil {
			return err
		}
	}
}

func (p *standardPublicPeer) https(connection net.Conn) error {
	secure := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{p.certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	defer secure.Close()
	if err := secure.Handshake(); err != nil {
		return err
	}
	request, err := http.ReadRequest(bufio.NewReader(secure))
	if err != nil {
		return err
	}
	defer request.Body.Close()
	p.requests.Add(1)
	if request.Method == http.MethodGet && (request.Host == "api.ipify.org" || request.Host == "api64.ipify.org") && request.URL.Path == "/" {
		return standardPublicReply(secure, []byte("1.1.1.1"))
	}
	if request.Method == http.MethodGet && request.Host == "1.1.1.1" && request.URL.Path == "/cdn-cgi/trace" {
		return standardPublicReply(secure, []byte("ip=1.1.1.1\n"))
	}
	if request.Host != "speed.cloudflare.com" {
		return errors.New("HTTPS measurement changed public host")
	}
	if request.Method == http.MethodPost && request.URL.Path == "/__up" {
		n, err := io.Copy(io.Discard, io.LimitReader(request.Body, 64<<20+1))
		if err != nil || n > 64<<20 {
			return errors.Join(err, errors.New("unbounded upload"))
		}
		p.uploaded.Add(n)
		if err := standardPublicShapeTransfer(); err != nil {
			return err
		}
		return standardPublicReply(secure, []byte("ok"))
	}
	if request.Method != http.MethodGet || request.URL.Path != "/__down" {
		return errors.New("uncaptured HTTPS measurement route")
	}
	n, err := strconv.ParseInt(request.URL.Query().Get("bytes"), 10, 64)
	if err != nil || n < 1 || n > 64<<20 {
		return errors.New("invalid public download length")
	}
	if n > 1 {
		if err := standardPublicShapeTransfer(); err != nil {
			return err
		}
	}
	if _, err = fmt.Fprintf(secure, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", n); err != nil {
		return err
	}
	if n > 1 {
		raw, err := os.ReadFile(standardPublicArm)
		var arm standardPublicPause
		if err == nil && json.Unmarshal(raw, &arm) == nil && arm.Name != "" && arm.Request != "" {
			// This test-only kernel observation chooses when to cancel. It grants no
			// production ownership; the caller independently verifies exact epoch/state.
			iface, err := net.InterfaceByName(arm.Name)
			if err == nil && iface.MTU != arm.OriginalMTU {
				count, writeErr := secure.Write([]byte{7})
				p.downloaded.Add(int64(count))
				if writeErr != nil {
					return writeErr
				}
				if err = os.WriteFile(standardPublicEntered, []byte(arm.Request), 0600); err != nil {
					return err
				}
				var closed [1]byte
				_, err = secure.Read(closed[:])
				return err
			}
		}
	}
	count, err := io.CopyN(secure, &speedLabPatternReader{pattern: []byte{7, 11, 19}}, n)
	p.downloaded.Add(count)
	return err
}
func standardPublicReply(connection net.Conn, body []byte) error {
	if _, err := fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body)); err != nil {
		return err
	}
	_, err := connection.Write(body)
	return err
}

func standardPublicCall(ctx context.Context, mux *http.ServeMux, path string, value any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(value)
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(ctx)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}

func linuxStandardServiceNativePublicMTUFixture(a *app, launch *linuxStandardServiceLaunch) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	mux := http.NewServeMux()
	registerMTURetestRoute(mux, a)
	// Allow the actual connection-owned Auto request to finish before the user
	// invokes force Retest. No fixture creates or publishes its winning status.
	for {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/mtu/status", nil).WithContext(ctx))
		if raw, found := linuxStandardServiceMTUUIs.Load(launch); found {
			ui := raw.(*linuxStandardServiceMTUUI)
			if err := mobilemtu.LockContext(ctx, &ui.mu); err != nil {
				return err
			}
			complete, busy := ui.completed, ui.running || ui.autoWaiting
			ui.mu.Unlock()
			if complete && !busy {
				break
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("actual automatic MTU did not complete before public Retest")
		case <-time.After(20 * time.Millisecond):
		}
	}
	original, profile, _, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
	if err != nil {
		return err
	}
	observer := launch.prepared.requestEpoch.observer
	request := mtuViewRequest{Request: strings.Repeat("a", 32), Session: original.Session, Profile: profile.ID}
	response := standardPublicCall(ctx, mux, "/api/mtu/retest", request)
	var retest struct {
		OK     bool             `json:"ok"`
		MTU    int              `json:"effective_mtu"`
		Result mobilemtu.Status `json:"result"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &retest) != nil || !retest.OK || !retest.Result.Measured || retest.MTU < 1280 {
		return fmt.Errorf("public native Retest failed: %d %s", response.Code, response.Body.String())
	}
	before, _, _, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
	if err != nil || before.MTU != retest.MTU || before.Session != original.Session || before.Path != original.Path {
		return errors.Join(err, errors.New("public Retest winner lacks exact original readback"))
	}
	receipt, err := desktopnetwork.ParseDesktopNetworkReceipt(launch.prepared.requestEpoch.mtuReceipt)
	if err != nil {
		return err
	}
	request.Request = strings.Repeat("b", 32)
	arm, _ := json.Marshal(standardPublicPause{Name: receipt.Name, OriginalMTU: before.MTU, Request: request.Request})
	if err = os.WriteFile(standardPublicArm, arm, 0600); err != nil {
		return err
	}
	defer os.Remove(standardPublicArm)
	defer os.Remove(standardPublicEntered)
	result := make(chan *httptest.ResponseRecorder, 1)
	work, stopWork := context.WithCancel(ctx)
	defer stopWork()
	go func() { result <- standardPublicCall(work, mux, "/api/mtu/retest", request) }()
	for {
		raw, _ := os.ReadFile(standardPublicEntered)
		if string(raw) == request.Request {
			break
		}
		select {
		case finished := <-result:
			return fmt.Errorf("cancel fixture missed changed-reader payload: %d %s", finished.Code, finished.Body.String())
		case <-ctx.Done():
			stopWork()
			<-result
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	changed, _, _, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
	if err != nil || changed.MTU == before.MTU || changed.Interface == before.Interface {
		stopWork()
		<-result
		return errors.Join(err, errors.New("public Cancel preceded actual native replacement"))
	}
	cancelled := standardPublicCall(ctx, mux, "/api/mtu/cancel", request)
	if cancelled.Code != http.StatusOK {
		stopWork()
		<-result
		return fmt.Errorf("public Cancel refused original request: %d %s", cancelled.Code, cancelled.Body.String())
	}
	var finished *httptest.ResponseRecorder
	select {
	case finished = <-result:
	case <-ctx.Done():
		stopWork()
		<-result
		return ctx.Err()
	}
	if finished.Code == http.StatusOK {
		return errors.New("cancelled public Retest reported a late winner")
	}
	_ = os.Remove(standardPublicArm)
	_ = os.Remove(standardPublicEntered)
	restored, _, _, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
	if err != nil || restored.MTU != before.MTU || restored.Session != before.Session || restored.Path != before.Path || launch.prepared.requestEpoch.observer != observer || launch.prepared.requestEpoch.mtuTransition != nil || launch.mtuOwner == nil || launch.mtuOwner.pending != nil {
		return errors.Join(err, errors.New("public Cancel did not join exact original-MTU rollback"))
	}
	speed := standardPublicCall(ctx, mux, "/api/speed-lab/run", speedLabRequest{Scope: "current", DurationMode: "custom", MinSeconds: 1, MaxSeconds: 1, ExpectedSelectedNodeID: a.profiles.SelectedID, ExpectedProfileTokens: map[string]string{profile.ID: publicProfileToken(profile)}})
	var measured struct {
		OK          bool                `json:"ok"`
		Measurement speedLabMeasurement `json:"measurement"`
	}
	if speed.Code != http.StatusOK || json.Unmarshal(speed.Body.Bytes(), &measured) != nil || !measured.OK || measured.Measurement.Download.Bytes == 0 || measured.Measurement.Upload.Bytes == 0 || measured.Measurement.Idle.Samples < 3 {
		return fmt.Errorf("public current Speed Lab failed through retained TUN: %d %s", speed.Code, speed.Body.String())
	}
	after, _, _, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
	if err != nil || after != restored {
		return errors.Join(err, errors.New("Speed Lab changed its captured MTU reader"))
	}
	fmt.Fprintln(os.Stdout, "standard-service-public-retest-cancel-speedlab-joined")
	return nil
}

func TestLinuxStandardServicePublicHTTPSPeer(t *testing.T) {
	for _, mode := range []string{"latency", "download", "upload", "foreign-auth", "foreign-destination", "tls-hostname"} {
		t.Run(mode, func(t *testing.T) {
			peer, ca, err := newStandardPublicPeer()
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			joined := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					joined <- err
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				joined <- peer.serve(connection, &atomic.Int64{})
			}()
			connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = connection.Write([]byte{5, 1, 2})
			if err != nil {
				t.Fatal(err)
			}
			var reply [2]byte
			if _, err = io.ReadFull(connection, reply[:]); err != nil || reply != [2]byte{5, 2} {
				t.Fatal("original SOCKS auth negotiation", reply, err)
			}
			auth := []byte{1, 1, 'u', 1, 'p'}
			if mode == "foreign-auth" {
				auth[4] = 'x'
			}
			_, err = connection.Write(auth)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadFull(connection, reply[:])
			if mode == "foreign-auth" {
				if err == nil {
					t.Fatal("foreign credentials accepted")
				}
				if <-joined == nil {
					t.Fatal("foreign auth not rejected")
				}
				return
			}
			if err != nil || reply != [2]byte{1, 0} {
				t.Fatal("selected SOCKS auth", reply, err)
			}
			address := byte(20)
			if mode == "foreign-destination" {
				address = 99
			}
			_, err = connection.Write([]byte{5, 1, 0, 1, 203, 0, 113, address, 1, 187})
			if err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 10)
			_, err = io.ReadFull(connection, response)
			if mode == "foreign-destination" {
				if err == nil {
					t.Fatal("foreign destination accepted")
				}
				if <-joined == nil {
					t.Fatal("foreign destination not rejected")
				}
				return
			}
			if err != nil || response[1] != 0 {
				t.Fatal("selected SOCKS destination", response, err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				t.Fatal("invalid test CA")
			}
			hostname := "speed.cloudflare.com"
			if mode == "tls-hostname" {
				hostname = "foreign.invalid"
			}
			secure := tls.Client(connection, &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS12})
			defer secure.Close()
			err = secure.Handshake()
			if mode == "tls-hostname" {
				if err == nil {
					t.Fatal("public hostname verification disabled")
				}
				_ = connection.Close()
				<-joined
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			url := "https://speed.cloudflare.com/__down?bytes=1"
			method := http.MethodGet
			var body io.Reader
			expected := 1
			if mode == "download" {
				url = "https://speed.cloudflare.com/__down?bytes=4096"
				expected = 4096
			}
			if mode == "upload" {
				url = "https://speed.cloudflare.com/__up"
				method = http.MethodPost
				body = bytes.NewReader(bytes.Repeat([]byte{9}, 2048))
				expected = 2
			}
			request, err := http.NewRequest(method, url, body)
			if err != nil {
				t.Fatal(err)
			}
			if err = request.Write(secure); err != nil {
				t.Fatal(err)
			}
			received, err := http.ReadResponse(bufio.NewReader(secure), request)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(received.Body)
			_ = received.Body.Close()
			if err != nil || received.StatusCode != http.StatusOK || len(payload) != expected {
				t.Fatal("actual HTTPS payload", len(payload), received.StatusCode, err)
			}
			if err = <-joined; err != nil {
				t.Fatal(err)
			}
			if peer.requests.Load() != 1 || mode == "upload" && peer.uploaded.Load() != 2048 || mode != "upload" && peer.downloaded.Load() != int64(expected) {
				t.Fatal("peer did not count actual transferred payload")
			}
		})
	}
}
