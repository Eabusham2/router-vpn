// This mobile owner adapts the pinned Snowflake client; see UPSTREAM.json.
// The Snowflake broker, WebRTC data channel, TurboTunnel token/client ID,
// encapsulation, KCP and smux wire protocols remain the upstream protocols.
package snowflake_client

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/transport/v4"
	"github.com/pion/webrtc/v4"
	upstream "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/turbotunnel"
	kcp "router-vpn/mobile/torpt/internal/sfkcp"
	smux "router-vpn/mobile/torpt/internal/sfsmux"
	owned "router-vpn/mobile/torpt/internal/sfturbo"
)

const (
	ReconnectTimeout   = 10 * time.Second
	SnowflakeTimeout   = 20 * time.Second
	DataChannelTimeout = 10 * time.Second
	WindowSize         = 65535
	StreamSize         = 1048576
)

type dummyAddr struct{}

func (dummyAddr) Network() string { return "snowflake" }
func (dummyAddr) String() string  { return "snowflake" }

// Network is an explicitly captured VPN network. It has no default fallback.
// Close starts cancellation and joins every owned socket and DNS operation.
type Network interface {
	transport.Net
	Close(context.Context) error
}

type ClientConfig struct {
	BrokerURL         string
	FrontDomains      []string
	ICEAddresses      []string
	UTLSClientID      string
	BridgeFingerprint string
	// Used only by package integration fixtures; shipping bridge profiles never
	// expose this field and always remove local addresses from offers.
	KeepLocalAddresses bool
}

type Transport struct {
	ctx     context.Context
	cancel  context.CancelFunc
	dialer  *WebRTCDialer
	network Network
	broker  *BrokerChannel
	natDone chan struct{}
	mu      sync.Mutex
	dialed  bool
}

func NewSnowflakeClient(ctx context.Context, config ClientConfig, network Network, dial func(context.Context, string, string) (net.Conn, error)) (*Transport, error) {
	if ctx == nil || ctx.Err() != nil || network == nil || dial == nil {
		return nil, errors.New("Snowflake requires an active captured VPN network")
	}
	servers, err := parseIceServers(config.ICEAddresses)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	broker, err := newBrokerChannelFromConfig(lifetime, config, dial)
	if err != nil {
		cancel()
		return nil, err
	}
	t := &Transport{ctx: lifetime, cancel: cancel, network: network, broker: broker, natDone: make(chan struct{})}
	t.dialer = &WebRTCDialer{BrokerChannel: broker, natPolicy: &NATPolicy{}, webrtcConfig: &webrtc.Configuration{ICEServers: servers}, network: network}
	// Constructing an unused client must not start DNS or socket work. The
	// first Dial owns the NAT worker together with its peer/session workers.
	close(t.natDone)
	return t, nil
}

// Dial creates one session with one replaceable proxy peer, the upstream
// default. The shared Router VPN bridge grammar has no max-peer option.
func (t *Transport) Dial() (net.Conn, error) {
	t.mu.Lock()
	if t.dialed || t.ctx.Err() != nil {
		unused := !t.dialed
		t.mu.Unlock()
		if unused {
			t.closeNetwork()
		}
		return nil, net.ErrClosed
	}
	t.dialed = true
	t.natDone = make(chan struct{})
	go func() {
		defer close(t.natDone)
		updateNATType(t.ctx, t.dialer.webrtcConfig.ICEServers, t.broker, t.network)
	}()
	t.mu.Unlock()
	peers, err := NewPeers(t.ctx, t.dialer)
	if err != nil {
		t.closeNetwork()
		return nil, err
	}
	collectionDone := make(chan struct{})
	go func() { defer close(collectionDone); connectLoop(peers) }()
	pconn, kcpConn, sess, err := newSession(peers)
	if err != nil {
		t.cancel()
		peers.End()
		<-collectionDone
		t.closeNetwork()
		return nil, err
	}
	conn := &SnowflakeConn{sess: sess, kcp: kcpConn, pconn: pconn, snowflakes: peers, transport: t, collectionDone: collectionDone, done: make(chan struct{})}
	stream, err := sess.OpenStream()
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.Stream = stream
	return conn, nil
}

func (t *Transport) closeNetwork() {
	t.cancel()
	_ = t.network.Close(context.Background())
	<-t.natDone
	t.broker.Close()
}

type SnowflakeConn struct {
	*smux.Stream
	sess           *smux.Session
	kcp            *kcp.UDPSession
	pconn          net.PacketConn
	snowflakes     *Peers
	transport      *Transport
	collectionDone <-chan struct{}
	once           sync.Once
	done           chan struct{}
	closeErr       error
}

func (c *SnowflakeConn) Close() error {
	c.once.Do(func() {
		c.transport.cancel()
		// Start captured network shutdown before joining Pion: an ignored DNS/dial
		// remains counted and can keep this real close pending until it finishes.
		networkDone := make(chan error, 1)
		go func() { networkDone <- c.transport.network.Close(context.Background()) }()
		if c.Stream != nil {
			_ = c.Stream.Close()
		}
		c.snowflakes.Stop()
		_ = c.sess.Close()
		_ = c.pconn.Close()
		c.kcp.WaitClosed()
		c.sess.WaitClosed()
		c.snowflakes.End()
		<-c.collectionDone
		<-c.transport.natDone
		c.transport.broker.Close()
		if err := <-networkDone; err != nil {
			c.closeErr = errors.New("captured Snowflake network did not close cleanly")
		}
		close(c.done)
	})
	<-c.done
	return c.closeErr
}

func parseIceServers(addresses []string) ([]webrtc.ICEServer, error) {
	if len(addresses) == 0 || len(strings.Join(addresses, ",")) > 4096 {
		return nil, errors.New("Snowflake requires a bounded STUN server list")
	}
	servers := make([]webrtc.ICEServer, 0, len(addresses))
	for _, address := range addresses {
		parsed, err := ice.ParseURL(strings.TrimSpace(address))
		// Pinned Pion gathers UDP server-reflexive candidates with stun: only.
		// Never silently downgrade stuns: or ignore a user-specified TLS server.
		if err != nil || !strings.HasPrefix(address, "stun:") {
			return nil, errors.New("Snowflake native ICE currently requires STUN over captured UDP")
		}
		servers = append(servers, webrtc.ICEServer{URLs: []string{parsed.String()}})
	}
	// Preserve the upstream randomly selected subset, without changing the
	// process-global PRNG or opening sockets for every configured alternative.
	for i := len(servers) - 1; i > 0; i-- {
		choice, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, err
		}
		j := int(choice.Int64())
		servers[i], servers[j] = servers[j], servers[i]
	}
	if len(servers) > 2 {
		servers = servers[:(len(servers)+1)/2]
	}
	return servers, nil
}

func newSession(peers *Peers) (net.PacketConn, *kcp.UDPSession, *smux.Session, error) {
	id := upstream.NewClientID()
	dial := func(ctx context.Context) (net.PacketConn, error) {
		peer := peers.Pop(ctx)
		if peer == nil {
			return nil, net.ErrClosed
		}
		if _, err := peer.Write(upstream.Token[:]); err != nil {
			peer.Close()
			return nil, err
		}
		if _, err := peer.Write(id[:]); err != nil {
			peer.Close()
			return nil, err
		}
		return newEncapsulationPacketConn(dummyAddr{}, dummyAddr{}, peer), nil
	}
	pconn := owned.NewRedialPacketConn(dummyAddr{}, dummyAddr{}, dial)
	conn, err := kcp.NewConn2(dummyAddr{}, nil, 0, 0, pconn)
	if err != nil {
		pconn.Close()
		return nil, nil, nil, err
	}
	conn.SetStreamMode(true)
	conn.SetWindowSize(WindowSize, WindowSize)
	conn.SetNoDelay(0, 0, 0, 1)
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveTimeout = 10 * time.Minute
	cfg.MaxStreamBuffer = StreamSize
	sess, err := smux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		pconn.Close()
		conn.WaitClosed()
		return nil, nil, nil, err
	}
	return pconn, conn, sess, nil
}

func connectLoop(peers *Peers) {
	for peers.ctx.Err() == nil {
		_, _ = peers.Collect()
		timer := time.NewTimer(ReconnectTimeout)
		select {
		case <-timer.C:
		case <-peers.ctx.Done():
			timer.Stop()
			return
		}
	}
}
