package snowflake_client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/transport/v4"
	"github.com/pion/webrtc/v4"
)

// WebRTCPeer owns one pinned Pion connection and its callback/read lifetime.
// The close worker runs outside Pion callbacks so GracefulClose can join them.
type WebRTCPeer struct {
	id          string
	ctx         context.Context
	cancel      context.CancelFunc
	pc          *webrtc.PeerConnection
	channel     *webrtc.DataChannel
	recvPipe    *io.PipeReader
	writePipe   *io.PipeWriter
	mu          sync.Mutex
	lastReceive time.Time
	open        chan struct{}
	openOnce    sync.Once
	closed      chan struct{}
	done        chan struct{}
	setupDone   chan struct{}
	once        sync.Once
	stale       sync.WaitGroup
}

func newWebRTCPeer(ctx context.Context, config *webrtc.Configuration, broker *BrokerChannel, policy *NATPolicy, network transport.Net) (*WebRTCPeer, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	peer := &WebRTCPeer{id: "snowflake-" + hex.EncodeToString(random[:]), ctx: lifetime, cancel: cancel,
		open: make(chan struct{}), closed: make(chan struct{}), done: make(chan struct{}), setupDone: make(chan struct{})}
	peer.recvPipe, peer.writePipe = io.Pipe()
	err := peer.connect(config, broker, policy, network)
	close(peer.setupDone)
	if err != nil {
		peer.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		peer.Close()
		return nil, ctx.Err()
	}
	return peer, nil
}

func (c *WebRTCPeer) Read(b []byte) (int, error) { return c.recvPipe.Read(b) }
func (c *WebRTCPeer) Write(b []byte) (int, error) {
	if c.Closed() {
		return 0, io.ErrClosedPipe
	}
	if err := c.channel.Send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *WebRTCPeer) Closed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}
func (c *WebRTCPeer) beginClose() {
	c.once.Do(func() {
		c.cancel()
		close(c.closed)
		_ = c.recvPipe.Close()
		_ = c.writePipe.Close()
		go func() {
			<-c.setupDone
			if c.pc != nil {
				_ = c.pc.GracefulClose()
			}
			c.stale.Wait()
			close(c.done)
		}()
	})
}
func (c *WebRTCPeer) Close() error { c.beginClose(); <-c.done; return nil }

func (c *WebRTCPeer) checkForStaleness() {
	defer c.stale.Done()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			c.beginClose()
			return
		case <-timer.C:
			c.mu.Lock()
			last := c.lastReceive
			c.mu.Unlock()
			if time.Since(last) > SnowflakeTimeout {
				c.beginClose()
				return
			}
		}
	}
}

func (c *WebRTCPeer) connect(config *webrtc.Configuration, broker *BrokerChannel, policy *NATPolicy, network transport.Net) error {
	attempt, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	settings := webrtc.SettingEngine{}
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settings.SetIncludeLoopbackCandidate(broker.keepLocalAddresses)
	settings.SetNet(network)
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	settings.SetSTUNGatherTimeout(10 * time.Second)
	settings.LoggerFactory = quietLoggerFactory{}
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	pc, err := api.NewPeerConnection(*config)
	if err != nil {
		return errors.New("Snowflake peer construction failed")
	}
	c.pc = pc
	ordered := true
	dc, err := pc.CreateDataChannel(c.id, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return errors.New("Snowflake data channel construction failed")
	}
	c.channel = dc
	dc.OnOpen(func() { c.openOnce.Do(func() { close(c.open) }) })
	dc.OnClose(c.beginClose)
	dc.OnError(func(error) { c.beginClose() })
	dc.OnMessage(func(message webrtc.DataChannelMessage) {
		c.mu.Lock()
		c.lastReceive = time.Now()
		c.mu.Unlock()
		if _, err := c.writePipe.Write(message.Data); err != nil {
			c.beginClose()
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return errors.New("Snowflake offer construction failed")
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(offer); err != nil {
		return errors.New("Snowflake local offer failed")
	}
	select {
	case <-gathered:
	case <-attempt.Done():
		return attempt.Err()
	}
	local := pc.LocalDescription()
	if local == nil {
		return errors.New("Snowflake local offer is missing")
	}
	actual := broker.GetNATType()
	sent := policy.NATTypeToSend(actual)
	answer, err := broker.Negotiate(attempt, local, sent)
	if err != nil {
		policy.Failure(actual, sent)
		return err
	}
	if err = pc.SetRemoteDescription(*answer); err != nil {
		return errors.New("Snowflake remote answer failed")
	}
	timer := time.NewTimer(DataChannelTimeout)
	defer timer.Stop()
	select {
	case <-attempt.Done():
		policy.Failure(actual, sent)
		return attempt.Err()
	case <-timer.C:
		policy.Failure(actual, sent)
		return errors.New("Snowflake data channel did not open")
	case <-c.open:
	}
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	c.mu.Lock()
	c.lastReceive = time.Now()
	c.mu.Unlock()
	c.stale.Add(1)
	go c.checkForStaleness()
	return nil
}

// Pion's internal diagnostics include SDP and network endpoints. Session status
// comes from the native Tor proof; no bridge credentials or endpoints are logged.
type quietLoggerFactory struct{}

func (quietLoggerFactory) NewLogger(string) logging.LeveledLogger { return quietLogger{} }

type quietLogger struct{}

func (quietLogger) Trace(string)                  {}
func (quietLogger) Tracef(string, ...interface{}) {}
func (quietLogger) Debug(string)                  {}
func (quietLogger) Debugf(string, ...interface{}) {}
func (quietLogger) Info(string)                   {}
func (quietLogger) Infof(string, ...interface{})  {}
func (quietLogger) Warn(string)                   {}
func (quietLogger) Warnf(string, ...interface{})  {}
func (quietLogger) Error(string)                  {}
func (quietLogger) Errorf(string, ...interface{}) {}
