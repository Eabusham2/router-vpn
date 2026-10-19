package snowflake_client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"router-vpn/internal/mobiletor"
	"router-vpn/mobile/torpt/internal/pionnet"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/webrtc/v4"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/turbotunnel"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/util"
)

// The fixture explicitly supplies local networking. Shipping always receives
// the captured mobile owner; this test permits only loopback ICE candidates.
type fixtureNetwork struct {
	transport.Net
	stun    *net.UDPAddr
	mu      sync.Mutex
	closed  bool
	packets map[*fixtureUDP]struct{}
	dns     atomic.Int32
	opened  atomic.Int32
}
type fixtureUDP struct {
	transport.UDPConn
	owner *fixtureNetwork
	once  sync.Once
}

func (u *fixtureUDP) Close() error {
	var err error
	u.once.Do(func() { err = u.UDPConn.Close(); u.owner.mu.Lock(); delete(u.owner.packets, u); u.owner.mu.Unlock() })
	return err
}
func newFixtureNetwork(t *testing.T, stunAddr *net.UDPAddr) *fixtureNetwork {
	t.Helper()
	base, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureNetwork{Net: base, stun: stunAddr, packets: make(map[*fixtureUDP]struct{})}
}
func (n *fixtureNetwork) Interfaces() ([]*transport.Interface, error) {
	available, err := n.Net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []*transport.Interface
	for _, iface := range available {
		if iface.Flags&net.FlagLoopback != 0 {
			result = append(result, iface)
		}
	}
	return result, nil
}
func (n *fixtureNetwork) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	if address == "stun.example:3478" && network != "udp6" {
		n.dns.Add(1)
		copy := *n.stun
		copy.IP = append(net.IP(nil), n.stun.IP...)
		return &copy, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, errors.New("unexpected fixture DNS lookup")
	}
	return net.ResolveUDPAddr(network, address)
}
func (n *fixtureNetwork) ListenUDP(network string, _ *net.UDPAddr) (transport.UDPConn, error) {
	if network == "udp6" {
		return nil, errors.New("fixture is IPv4 only")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, net.ErrClosed
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	owned := &fixtureUDP{UDPConn: conn, owner: n}
	n.packets[owned] = struct{}{}
	n.opened.Add(1)
	return owned, nil
}
func (n *fixtureNetwork) ListenPacket(network, address string) (net.PacketConn, error) {
	return n.ListenUDP(network, nil)
}
func (n *fixtureNetwork) Close(context.Context) error {
	n.mu.Lock()
	n.closed = true
	var sockets []*fixtureUDP
	for socket := range n.packets {
		sockets = append(sockets, socket)
	}
	n.mu.Unlock()
	for _, socket := range sockets {
		_ = socket.Close()
	}
	return nil
}

func startSTUNFixture(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var data [2048]byte
			n, source, err := socket.ReadFromUDP(data[:])
			if err != nil {
				return
			}
			request := &stun.Message{Raw: append([]byte(nil), data[:n]...)}
			if request.Decode() != nil || request.Type != stun.BindingRequest {
				continue
			}
			response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: source.IP, Port: source.Port})
			if err == nil {
				_, _ = socket.WriteToUDP(response.Raw, source)
			}
		}
	}()
	return socket.LocalAddr().(*net.UDPAddr), func() { socket.Close(); <-done }
}

type proxyStream struct {
	reader  *io.PipeReader
	writer  *io.PipeWriter
	channel *webrtc.DataChannel
	once    sync.Once
}

func (s *proxyStream) Read(b []byte) (int, error) { return s.reader.Read(b) }
func (s *proxyStream) Write(b []byte) (int, error) {
	if err := s.channel.Send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (s *proxyStream) Close() error {
	s.once.Do(func() { s.reader.Close(); s.writer.Close() })
	return nil
}

type proxyFixture struct {
	t       *testing.T
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	peers   []*webrtc.PeerConnection
	streams []*proxyStream
	workers sync.WaitGroup
	ids     map[turbotunnel.ClientID]bool
	polls   atomic.Int32
	errors  chan error
}

func newProxyFixture(t *testing.T) *proxyFixture {
	ctx, cancel := context.WithCancel(context.Background())
	return &proxyFixture{t: t, ctx: ctx, cancel: cancel, ids: make(map[turbotunnel.ClientID]bool), errors: make(chan error, 32)}
}
func (f *proxyFixture) report(err error) {
	select {
	case f.errors <- err:
	default:
	}
}
func (f *proxyFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.ServerName != "front.example" || r.Host != "broker.example" || r.URL.RequestURI() != "/client?token=fixture" {
		f.report(errors.New("Snowflake TLS front, Host, or broker path/query changed"))
		w.WriteHeader(400)
		return
	}
	data, err := limitedRead(r.Body, readLimit)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	poll, err := messages.DecodeClientPollRequest(data)
	if err != nil || poll.Fingerprint != "1111111111111111111111111111111111111111" {
		f.report(errors.New("Snowflake did not preserve its bridge fingerprint"))
		w.WriteHeader(400)
		return
	}
	offer, err := util.DeserializeSessionDescription(poll.Offer)
	if err != nil {
		f.report(err)
		w.WriteHeader(400)
		return
	}
	settings := webrtc.SettingEngine{}
	settings.SetIncludeLoopbackCandidate(true)
	settings.SetInterfaceFilter(func(name string) bool { return strings.HasPrefix(name, "lo") })
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	settings.LoggerFactory = quietLoggerFactory{}
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		f.report(err)
		w.WriteHeader(500)
		return
	}
	f.mu.Lock()
	f.peers = append(f.peers, pc)
	f.mu.Unlock()
	pc.OnDataChannel(func(channel *webrtc.DataChannel) {
		read, write := io.Pipe()
		stream := &proxyStream{reader: read, writer: write, channel: channel}
		f.mu.Lock()
		f.streams = append(f.streams, stream)
		f.mu.Unlock()
		channel.OnMessage(func(message webrtc.DataChannelMessage) { _, _ = write.Write(message.Data) })
		channel.OnClose(func() { stream.Close() })
		channel.OnOpen(func() { f.workers.Add(1); go func() { defer f.workers.Done(); f.serveBridge(stream) }() })
	})
	if err = pc.SetRemoteDescription(*offer); err != nil {
		f.report(err)
		w.WriteHeader(400)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		f.report(err)
		w.WriteHeader(500)
		return
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(answer); err != nil {
		f.report(err)
		w.WriteHeader(500)
		return
	}
	select {
	case <-gathered:
	case <-r.Context().Done():
		return
	case <-f.ctx.Done():
		return
	}
	encoded, err := util.SerializeSessionDescription(pc.LocalDescription())
	if err != nil {
		f.report(err)
		w.WriteHeader(500)
		return
	}
	reply, err := (&messages.ClientPollResponse{Answer: encoded}).EncodePollResponse()
	if err != nil {
		f.report(err)
		w.WriteHeader(500)
		return
	}
	f.polls.Add(1)
	w.Write(reply)
}
func (f *proxyFixture) serveBridge(stream *proxyStream) {
	defer stream.Close()
	var token [len(turbotunnel.Token)]byte
	if _, err := io.ReadFull(stream, token[:]); err != nil {
		return
	}
	if !bytes.Equal(token[:], turbotunnel.Token[:]) {
		f.report(errors.New("Snowflake TurboTunnel token is not the pinned wire token"))
		return
	}
	var id turbotunnel.ClientID
	if _, err := io.ReadFull(stream, id[:]); err != nil {
		return
	}
	f.mu.Lock()
	f.ids[id] = true
	f.mu.Unlock()
	packet := newEncapsulationPacketConn(dummyAddr{}, dummyAddr{}, stream)
	listener, err := kcp.ServeConn(nil, 0, 0, packet)
	if err != nil {
		f.report(err)
		return
	}
	defer listener.Close()
	defer packet.Close()
	conn, err := listener.AcceptKCP()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetStreamMode(true)
	conn.SetWindowSize(WindowSize, WindowSize)
	conn.SetNoDelay(0, 0, 0, 1)
	config := smux.DefaultConfig()
	config.Version = 2
	config.KeepAliveTimeout = 4 * time.Minute
	config.MaxStreamBuffer = StreamSize
	session, err := smux.Server(conn, config)
	if err != nil {
		f.report(err)
		return
	}
	defer session.Close()
	app, err := session.AcceptStream()
	if err != nil {
		return
	}
	defer app.Close()
	_, _ = io.Copy(app, app)
}
func (f *proxyFixture) Close() {
	f.cancel()
	f.mu.Lock()
	peers := append([]*webrtc.PeerConnection(nil), f.peers...)
	streams := append([]*proxyStream(nil), f.streams...)
	f.mu.Unlock()
	for _, stream := range streams {
		stream.Close()
	}
	for _, peer := range peers {
		peer.GracefulClose()
	}
	f.workers.Wait()
}

func TestRealSnowflakeTLSWebRTCAndKCPStreamTraffic(t *testing.T) {
	stunAddr, stopSTUN := startSTUNFixture(t)
	defer stopSTUN()
	proxy := newProxyFixture(t)
	defer proxy.Close()
	broker := httptest.NewUnstartedServer(proxy)
	broker.TLS = &tls.Config{Certificates: []tls.Certificate{fixtureCertificate(t, "front.example")}}
	broker.StartTLS()
	defer broker.Close()
	var brokerDials atomic.Int32
	for iteration := 0; iteration < 2; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())

		var livePackets atomic.Int32
		var dnsQueries atomic.Int32
		var opened atomic.Int32
		lower, err := mobiletor.NewNetwork(ctx, func(call context.Context, kind, address string) (net.Conn, error) {
			if kind != "tcp" || address != "192.0.2.42:443" {
				return nil, errors.New("uncaptured Snowflake broker route")
			}
			brokerDials.Add(1)
			return (&net.Dialer{}).DialContext(call, "tcp4", broker.Listener.Addr().String())
		}, func(call context.Context, kind, address string) (net.PacketConn, error) {
			conn, err := (&net.ListenConfig{}).ListenPacket(call, kind, address)
			if err != nil {
				return nil, err
			}
			livePackets.Add(1)
			opened.Add(1)
			return &countedPacket{PacketConn: conn, live: &livePackets}, nil
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		snapshot := newFixtureNetwork(t, stunAddr)
		interfaces, err := snapshot.Interfaces()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		network, err := pionnet.New(ctx, lower, func(call context.Context, family, host string) ([]netip.Addr, error) {
			dnsQueries.Add(1)
			if family == "ip6" {
				return nil, errors.New("fixture DNS is IPv4 only")
			}
			switch host {
			case "stun.example":
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			case "front.example":
				return []netip.Addr{netip.MustParseAddr("192.0.2.42")}, nil
			default:
				return nil, errors.New("unexpected captured DNS name")
			}
		}, interfaces)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		client, err := NewSnowflakeClient(ctx, ClientConfig{BrokerURL: "https://broker.example/?token=fixture", FrontDomains: []string{"front.example"},
			ICEAddresses: []string{"stun:stun.example:" + strconv.Itoa(stunAddr.Port)}, UTLSClientID: "hellochrome_auto", BridgeFingerprint: "1111111111111111111111111111111111111111", KeepLocalAddresses: iteration == 0}, network, network.DialContext)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		conn, err := client.Dial()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		payload := bytes.Repeat([]byte("real Snowflake STUN+DTLS+SCTP+KCP+smux payload;"), 3000)
		sent := make(chan error, 1)
		go func() { _, err := conn.Write(payload); sent <- err }()
		received := make([]byte, len(payload))
		_, err = io.ReadFull(conn, received)
		if err != nil || !bytes.Equal(received, payload) {
			cancel()
			conn.Close()
			select {
			case problem := <-proxy.errors:
				t.Error(problem)
			default:
			}
			t.Fatalf("Snowflake real stream payload failed: %v", err)
		}
		if err = <-sent; err != nil {
			t.Fatal(err)
		}
		cancel()
		closed := make(chan struct{})
		go func() { conn.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Snowflake session did not join its actual WebRTC workers")
		}
		if err := lower.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if livePackets.Load() != 0 || dnsQueries.Load() == 0 || opened.Load() == 0 {
			t.Fatal("Snowflake did not exercise and drain its captured STUN network")
		}
	}
	if brokerDials.Load() < 2 || proxy.polls.Load() < 2 {
		t.Fatal("Snowflake never negotiated actual broker offers")
	}
	proxy.mu.Lock()
	identities := len(proxy.ids)
	proxy.mu.Unlock()
	if identities != 2 {
		t.Fatal("Snowflake reused the prior VPN session's TurboTunnel identity")
	}
	select {
	case err := <-proxy.errors:
		t.Fatal(err)
	default:
	}
}

// This observes actual lower socket closure, independent of Pion's inventory.
type countedPacket struct {
	net.PacketConn
	live *atomic.Int32
	once sync.Once
	err  error
}

func (c *countedPacket) Close() error {
	c.once.Do(func() { c.err = c.PacketConn.Close(); c.live.Add(-1) })
	return c.err
}
