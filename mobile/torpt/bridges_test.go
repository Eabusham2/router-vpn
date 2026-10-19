package torpt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func TestRealObfs4TrafficUsesCapturedOwnerAndFreshHandshakes(t *testing.T) {
	transport := &obfs4.Transport{}
	args := pt.Args{}
	factory, err := transport.ServerFactory(t.TempDir(), &args)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := factory.Args().Get("cert")
	plan := obfs4Plan(t, cert)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	const rounds = 8
	go func() {
		for round := 0; round < rounds; round++ {
			raw, err := listener.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			wrapped, err := factory.WrapConn(raw)
			if err != nil {
				raw.Close()
				serverDone <- err
				return
			}
			// A real server factory shares its obfs4 replay filter across all
			// eight handshakes. Reusing parsed client ephemeral keys fails it.
			_, err = io.Copy(wrapped, wrapped)
			wrapped.Close()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	var dials atomic.Int32
	bridges, err := Start(context.Background(), plan, func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != plan.Bridges[0].Target {
			return nil, errors.New("transport bypassed its captured bridge destination")
		}
		// The TEST-NET profile address has no route of its own. Only this
		// captured test owner maps it to the real local obfs4 server.
		return (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBridges(t, bridges)
	for round := 0; round < rounds; round++ {
		client, reply := openPT(t, bridges.Listeners()["obfs4"], plan.Bridges[0])
		if reply != 0 {
			client.Close()
			t.Fatalf("real obfs4 handshake %d rejected: %d", round, reply)
		}
		payload := bytes.Repeat([]byte(fmt.Sprintf("owned obfs4 application traffic %d;", round)), 256)
		if _, err := client.Write(payload); err != nil {
			client.Close()
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		_, err := io.ReadFull(client, received)
		client.Close()
		if err != nil || !bytes.Equal(payload, received) {
			t.Fatal("actual obfs4 data path failed", err)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal("real obfs4 server failed", err)
	}
	if dials.Load() != rounds {
		t.Fatal("handshakes did not each use the captured network", dials.Load())
	}
}

func TestPTListenerCannotDialOutsideFrozenBridgeArguments(t *testing.T) {
	plan := obfs4Plan(t, strings.Repeat("A", 70))
	var dials atomic.Int32
	bridges, err := Start(context.Background(), plan, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("this negative control must never dial")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBridges(t, bridges)
	for _, field := range []string{"target", "cert", "missing", "extra"} {
		t.Run(field, func(t *testing.T) {
			request := plan.Bridges[0]
			request.Arguments = make(map[string]string)
			for key, value := range plan.Bridges[0].Arguments {
				request.Arguments[key] = value
			}
			switch field {
			case "target":
				request.Target = "203.0.113.45:443"
			case "cert":
				request.Arguments["cert"] = strings.Repeat("B", 70)
			case "missing":
				delete(request.Arguments, "iat-mode")
			case "extra":
				request.Arguments["arbitrary"] = "value"
			}
			client, reply := openPT(t, bridges.Listeners()["obfs4"], request)
			client.Close()
			if reply != pt.SocksRepConnectionNotAllowed {
				t.Fatal("local PT endpoint accepted a different bridge request", reply)
			}
		})
	}
	if dials.Load() != 0 {
		t.Fatal("rejected bridge request reached the protected network")
	}
}

func TestPTCloseInterruptsActualObfs4HandshakeAndHalfOpenSOCKS(t *testing.T) {
	// Generate a structurally valid real obfs4 certificate. The bridge peer
	// below then deliberately remains silent during the real client handshake.
	args := pt.Args{}
	factory, err := (&obfs4.Transport{}).ServerFactory(t.TempDir(), &args)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := factory.Args().Get("cert")
	plan := obfs4Plan(t, cert)
	entered := make(chan struct{})
	raw, peer := net.Pipe()
	defer peer.Close()
	bridges, err := Start(context.Background(), plan, func(context.Context, string, string) (net.Conn, error) {
		close(entered)
		return raw, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBridges(t, bridges)
	client, err := net.Dial("tcp4", bridges.Listeners()["obfs4"])
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	sendPTRequest(t, client, plan.Bridges[0])
	<-entered
	half, err := net.Dial("tcp4", bridges.Listeners()["obfs4"])
	if err != nil {
		t.Fatal(err)
	}
	defer half.Close()
	half.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := half.Write([]byte{5}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := bridges.Close(ctx); err != nil {
		t.Fatal("PT sockets or handshake outlived disconnect", err)
	}
	for _, connection := range []net.Conn{client, half, peer} {
		var b [1]byte
		if _, err := connection.Read(b[:]); err == nil {
			t.Fatal("closed bridge owner still carried traffic")
		}
	}
	select {
	case <-bridges.Done():
	default:
		t.Fatal("transport worker was declared closed before it drained")
	}
}

func TestPTCloseRetainsAnIgnoringPendingDial(t *testing.T) {
	args := pt.Args{}
	factory, err := (&obfs4.Transport{}).ServerFactory(t.TempDir(), &args)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := factory.Args().Get("cert")
	plan := obfs4Plan(t, cert)
	entered, release := make(chan struct{}), make(chan struct{})
	raw, peer := net.Pipe()
	defer peer.Close()
	var once sync.Once
	defer once.Do(func() { close(release) })
	bridges, err := Start(context.Background(), plan, func(context.Context, string, string) (net.Conn, error) {
		close(entered)
		<-release
		return raw, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp4", bridges.Listeners()["obfs4"])
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	sendPTRequest(t, client, plan.Bridges[0])
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := bridges.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unreturned captured dial was declared drained", err)
	}
	select {
	case <-bridges.Done():
		t.Fatal("pending bridge dial lost ownership")
	default:
	}
	once.Do(func() { close(release) })
	closeBridges(t, bridges)
	var b [1]byte
	if _, err := peer.Read(b[:]); err != io.EOF {
		t.Fatal("late bridge socket survived the close barrier", err)
	}
}

func TestBridgeStartRequiresAnImplementedTransportAndCapturedOwner(t *testing.T) {
	plan := obfs4Plan(t, strings.Repeat("A", 70))
	if b, err := Start(context.Background(), plan, nil, nil); err == nil {
		b.Close(context.Background())
		t.Fatal("native PT substituted an unprotected host dialer")
	}
	plan, err := mobiletor.NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{
		"webtunnel 192.0.2.8:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://bridge.example/secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := Start(context.Background(), plan, func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }, nil); err == nil {
		b.Close(context.Background())
		t.Fatal("transport capability was claimed before integration")
	}
}

func obfs4Plan(t *testing.T, cert string) mobiletor.Plan {
	t.Helper()
	plan, err := mobiletor.NewPlan(common.ExternalTorBridgeConfig{Bridges: []string{
		"obfs4 203.0.113.44:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=" + cert + " iat-mode=0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func openPT(t *testing.T, endpoint string, bridge mobiletor.Bridge) (net.Conn, byte) {
	t.Helper()
	client, err := net.Dial("tcp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(10 * time.Second))
	sendPTRequest(t, client, bridge)
	var response [10]byte
	if _, err := io.ReadFull(client, response[:]); err != nil {
		client.Close()
		t.Fatal("PT SOCKS response failed", err)
	}
	if response[0] != 5 || response[2] != 0 || response[3] != 1 {
		client.Close()
		t.Fatal("invalid PT SOCKS response")
	}
	return client, response[1]
}

func sendPTRequest(t *testing.T, client net.Conn, bridge mobiletor.Bridge) {
	t.Helper()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || response != [2]byte{5, 2} {
		t.Fatal("PT did not select argument authentication", err)
	}
	var keys []string
	for key := range bridge.Arguments {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var fields []string
	escape := strings.NewReplacer("\\", "\\\\", ";", "\\;", "=", "\\=")
	for _, key := range keys {
		fields = append(fields, escape.Replace(key)+"="+escape.Replace(bridge.Arguments[key]))
	}
	encoded := strings.Join(fields, ";")
	if len(encoded) == 0 || len(encoded) > 255 {
		t.Fatal("test SOCKS argument size is invalid")
	}
	auth := append([]byte{1, byte(len(encoded))}, []byte(encoded)...)
	auth = append(auth, 1, 0)
	if _, err := client.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response[:]); err != nil || response != [2]byte{1, 0} {
		t.Fatal("PT argument negotiation failed", err)
	}
	target := netip.MustParseAddrPort(bridge.Target)
	var command []byte
	if target.Addr().Is4() {
		command = append([]byte{5, 1, 0, 1}, target.Addr().AsSlice()...)
	} else {
		command = append([]byte{5, 1, 0, 4}, target.Addr().AsSlice()...)
	}
	command = binary.BigEndian.AppendUint16(command, target.Port())
	if _, err := client.Write(command); err != nil {
		t.Fatal(err)
	}
}

func closeBridges(t *testing.T, bridges *Bridges) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bridges.Close(ctx); err != nil {
		t.Error("native bridge owner failed to drain", err)
	}
}
