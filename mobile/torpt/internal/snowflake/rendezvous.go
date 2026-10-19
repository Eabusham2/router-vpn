package snowflake_client

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pion/transport/v4"
	"github.com/pion/webrtc/v4"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/messages"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/util"
)

const readLimit = 100000
const natUnknown = "unknown"
const natUnrestricted = "unrestricted"

type RendezvousMethod interface {
	Exchange(context.Context, []byte) ([]byte, error)
}
type BrokerChannel struct {
	Rendezvous         RendezvousMethod
	keepLocalAddresses bool
	natType            string
	lock               sync.Mutex
	BridgeFingerprint  string
}

func newBrokerChannelFromConfig(ctx context.Context, config ClientConfig, dial func(context.Context, string, string) (net.Conn, error)) (*BrokerChannel, error) {
	fp, err := hex.DecodeString(config.BridgeFingerprint)
	if err != nil || len(fp) != 20 {
		return nil, errors.New("Snowflake bridge fingerprint is invalid")
	}
	method, err := newHTTPRendezvous(config.BrokerURL, config.FrontDomains, config.UTLSClientID, dial)
	if err != nil {
		return nil, err
	}
	return &BrokerChannel{Rendezvous: method, keepLocalAddresses: config.KeepLocalAddresses, natType: natUnknown, BridgeFingerprint: strings.ToUpper(config.BridgeFingerprint)}, nil
}
func (b *BrokerChannel) Negotiate(ctx context.Context, offer *webrtc.SessionDescription, natType string) (*webrtc.SessionDescription, error) {
	if !b.keepLocalAddresses {
		offer = &webrtc.SessionDescription{Type: offer.Type, SDP: util.StripLocalAddresses(offer.SDP)}
	}
	data, err := preparePollRequest(offer, natType, b.BridgeFingerprint)
	if err != nil {
		return nil, errors.New("Snowflake offer encoding failed")
	}
	encoded, err := b.Rendezvous.Exchange(ctx, data)
	if err != nil {
		return nil, errors.New("Snowflake broker exchange failed")
	}
	response, err := messages.DecodeClientPollResponse(encoded)
	if err != nil || response.Error != "" {
		return nil, errors.New("Snowflake broker returned no valid answer")
	}
	answer, err := util.DeserializeSessionDescription(response.Answer)
	if err != nil {
		return nil, errors.New("Snowflake broker answer is invalid")
	}
	return answer, nil
}
func preparePollRequest(offer *webrtc.SessionDescription, natType, fingerprint string) ([]byte, error) {
	sdp, err := util.SerializeSessionDescription(offer)
	if err != nil {
		return nil, err
	}
	request := &messages.ClientPollRequest{Offer: sdp, NAT: natType, Fingerprint: fingerprint}
	return request.EncodeClientPollRequest()
}
func (b *BrokerChannel) SetNATType(value string) { b.lock.Lock(); b.natType = value; b.lock.Unlock() }
func (b *BrokerChannel) GetNATType() string      { b.lock.Lock(); defer b.lock.Unlock(); return b.natType }
func (b *BrokerChannel) Close() {
	if closer, ok := b.Rendezvous.(interface{ Close() }); ok {
		closer.Close()
	}
}

type NATPolicy struct{ assumedUnrestrictedNATAndFailedToConnect atomic.Bool }

func (p *NATPolicy) NATTypeToSend(actual string) string {
	if actual == natUnknown && !p.assumedUnrestrictedNATAndFailedToConnect.Load() {
		return natUnrestricted
	}
	return actual
}
func (p *NATPolicy) Failure(actual, sent string) {
	if actual == natUnknown && sent == natUnrestricted {
		p.assumedUnrestrictedNATAndFailedToConnect.Store(true)
	}
}

type WebRTCDialer struct {
	*BrokerChannel
	natPolicy    *NATPolicy
	webrtcConfig *webrtc.Configuration
	network      transport.Net
}

func (w *WebRTCDialer) Catch(ctx context.Context) (*WebRTCPeer, error) {
	return newWebRTCPeer(ctx, w.webrtcConfig, w.BrokerChannel, w.natPolicy, w.network)
}
