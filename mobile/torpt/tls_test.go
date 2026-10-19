package torpt

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
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
	"router-vpn/mobile/torpt/internal/httpupgrade"
	"router-vpn/mobile/torpt/internal/utlsclient"
)

var (
	fixtureCA     *x509.Certificate
	fixtureCAKey  *ecdsa.PrivateKey
	fixtureSerial atomic.Int64
)

// Only this test binary trusts this generated local CA. Production transports
// retain their normal certificate verification; there is no insecure option
// or test certificate path in the shipping adapter.
func TestMain(m *testing.M) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RouterVPN local transport fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	fixtureCA, err = x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	fixtureCAKey = key
	pool := x509.NewCertPool()
	pool.AddCert(fixtureCA)
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	x509.SetFallbackRoots(pool)
	os.Exit(m.Run())
}

func fixtureCertificate(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(fixtureSerial.Add(1) + 10), DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, fixtureCA, &key.PublicKey, fixtureCAKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestRealMeekHTTPSFrontingTrafficAndNewConnectionIdentity(t *testing.T) {
	var mu sync.Mutex
	identities := make(map[string]bool)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != "front.example" || r.Host != "bridge.example" || r.URL.RequestURI() != "/owned-meek?token=local-fixture" {
			t.Error("meek TLS front, HTTP host or requested URL was not preserved")
		}
		id := r.Header.Get("X-Session-Id")
		if len(id) != 32 {
			t.Error("meek request has no real per-connection session ID")
		}
		mu.Lock()
		identities[id] = true
		mu.Unlock()
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(payload)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{fixtureCertificate(t, "front.example")}}
	server.StartTLS()
	defer server.Close()
	plan, err := mobiletor.NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{
		"meek_lite 192.0.2.20:80 url=https://bridge.example/owned-meek?token=local-fixture front=front.example utls-imitate=HelloRandomizedALPN",
	}})
	if err != nil {
		t.Fatal(err)
	}
	bridges, err := Start(context.Background(), plan, func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "front.example:443" {
			return nil, errors.New("meek did not use its captured front route")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", server.Listener.Addr().String())
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBridges(t, bridges)
	for i := 0; i < 2; i++ {
		client, reply := openPT(t, bridges.Listeners()["meek_lite"], plan.Bridges[0])
		if reply != 0 {
			client.Close()
			t.Fatal("meek connection was rejected", reply)
		}
		payload := bytes.Repeat([]byte("certificate-verified meek application traffic;"), 256)
		if _, err := client.Write(payload); err != nil {
			client.Close()
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		_, err := io.ReadFull(client, received)
		client.Close()
		if err != nil || !bytes.Equal(received, payload) {
			t.Fatal("real meek HTTPS data path failed", err)
		}
	}
	closeBridges(t, bridges)
	mu.Lock()
	defer mu.Unlock()
	if len(identities) != 2 {
		t.Fatal("meek reused a previous connection's session identity", len(identities))
	}
}

func TestRealWebTunnelTLSUpgradeTrafficAndCertificateRejection(t *testing.T) {
	for _, trustedName := range []bool{true, false} {
		name := "verified certificate"
		certificateName := "tunnel.example"
		if !trustedName {
			name = "wrong certificate name"
			certificateName = "unrelated.example"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{fixtureCertificate(t, certificateName)}})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			prefix := []byte("server tunnel prefix can arrive with upgrade headers;")
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				upgrade, err := httpupgrade.NewHTTPUpgradeTransport(&httpupgrade.Config{Host: "tunnel.example", Path: "owned-webtunnel?token=local-fixture"})
				if err != nil {
					done <- err
					return
				}
				captured := &headerCaptureConn{Conn: raw}
				wrapped, err := upgrade.Server(captured)
				if err != nil {
					done <- err
					return
				}
				request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(captured.header.Bytes())))
				if err != nil || request.Host != "tunnel.example" || request.URL.RequestURI() != "/owned-webtunnel?token=local-fixture" || raw.(*tls.Conn).ConnectionState().ServerName != "tunnel.example" {
					done <- errors.New("WebTunnel did not preserve the requested TLS name, HTTP host, or URL query")
					return
				}
				if _, err := wrapped.Write(prefix); err != nil {
					done <- err
					return
				}
				_, err = io.Copy(wrapped, wrapped)
				done <- err
			}()
			plan, err := mobiletor.NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{
				"webtunnel 192.0.2.8:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://tunnel.example/owned-webtunnel?token=local-fixture ver=0.0.1",
			}})
			if err != nil {
				t.Fatal(err)
			}
			bridges, err := Start(context.Background(), plan, func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "tunnel.example:443" {
					return nil, errors.New("WebTunnel bypassed the captured URL endpoint")
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer closeBridges(t, bridges)
			client, reply := openPT(t, bridges.Listeners()["webtunnel"], plan.Bridges[0])
			defer client.Close()
			if !trustedName {
				if reply == 0 {
					t.Fatal("WebTunnel accepted a certificate for another hostname")
				}
				if err := <-done; err == nil {
					t.Fatal("TLS certificate negative control reached application traffic")
				}
				return
			}
			if reply != 0 {
				select {
				case serverErr := <-done:
					t.Fatal("actual WebTunnel TLS upgrade failed", reply, serverErr)
				case <-time.After(time.Second):
					t.Fatal("actual WebTunnel TLS upgrade failed", reply)
				}
			}
			receivedPrefix := make([]byte, len(prefix))
			if _, err := io.ReadFull(client, receivedPrefix); err != nil || !bytes.Equal(prefix, receivedPrefix) {
				t.Fatal("WebTunnel lost initial application bytes", err)
			}
			payload := bytes.Repeat([]byte("actual protected WebTunnel traffic;"), 512)
			client.Write(payload)
			received := make([]byte, len(payload))
			_, err = io.ReadFull(client, received)
			client.Close()
			if err != nil || !bytes.Equal(payload, received) {
				t.Fatal("WebTunnel did not carry application data", err)
			}
			if err := <-done; err != nil {
				t.Fatal("WebTunnel server did not finish cleanly", err)
			}
		})
	}
}

type headerCaptureConn struct {
	net.Conn
	header bytes.Buffer
}

func (c *headerCaptureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if remaining := 4096 - c.header.Len(); remaining > 0 {
		c.header.Write(b[:min(n, remaining)])
	}
	return n, err
}

func TestRandomizedTLSKeepsRealMLKEMAndFixesUpstreamRetryFailure(t *testing.T) {
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{fixtureCertificate(t, "tunnel.example")},
		MinVersion:   tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.CurveIDs_Append_X25519 = 1
	weights.KeyShare_Append_RandomGroups = 0
	weights.FirstKeyShare_Set_CurveP256 = 0
	seed := utls.PRNGSeed{1, 2, 3, 4}
	id := utls.HelloRandomizedNoALPN
	id.Weights, id.Seed = &weights, &seed
	for _, corrected := range []bool{false, true} {
		serverDone := make(chan error, 1)
		go func() {
			connection, err := listener.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(5 * time.Second))
			secured := connection.(*tls.Conn)
			if err := secured.Handshake(); err != nil {
				serverDone <- err
				return
			}
			if secured.ConnectionState().CurveID != tls.X25519MLKEM768 {
				serverDone <- errors.New("corrected hello did not negotiate real hybrid ML-KEM")
				return
			}
			_, err = secured.Write([]byte("proved hybrid TLS traffic"))
			serverDone <- err
		}()
		raw, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		config := &utls.Config{ServerName: "tunnel.example"}
		var connection *utls.UConn
		if corrected {
			connection, err = utlsclient.Client(raw, config, id)
		} else {
			connection = utls.UClient(raw, config, id)
		}
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		err = connection.Handshake()
		if !corrected {
			connection.Close()
			if err == nil || !strings.Contains(err.Error(), "CurvePreferences includes unsupported curve") {
				t.Fatal("exact upstream ML-KEM retry negative control did not fail", err)
			}
			if err := <-serverDone; err == nil {
				t.Fatal("unmodified randomized hello unexpectedly completed hybrid TLS")
			}
			continue
		}
		if err != nil {
			connection.Close()
			t.Fatal("corrected randomized hybrid TLS handshake failed", err)
		}
		data := make([]byte, len("proved hybrid TLS traffic"))
		_, err = io.ReadFull(connection, data)
		connection.Close()
		if err != nil || string(data) != "proved hybrid TLS traffic" {
			t.Fatal("hybrid TLS did not carry actual application bytes", err)
		}
		if err := <-serverDone; err != nil {
			t.Fatal(err)
		}
	}
}
