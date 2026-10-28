package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

var errDesktopLastRelay = errors.New("desktop Tor last-relay comparison lost its exact child, source or isolated SOCKS socket")

// NativeJoined reports only the immutable native process join supplied by the
// standalone child owner. A retired session, closed control connection or PID
// observation does not acknowledge native work or output-reader drainage.
func (s *DesktopBridgeSession) NativeJoined() bool {
	if s == nil || s.nativeJoined == nil {
		return false
	}
	select {
	case <-s.nativeJoined:
		return true
	default:
		return false
	}
}

// LastRelaySOCKS exposes only this authenticated child's captured loopback
// listener and isolation. The Box still owns each actual socket and must prove
// its full native graph, selected DNS and retained external TLS connection.
func (s *DesktopBridgeSession) LastRelaySOCKS() (address, username, password string, failure error) {
	if s == nil || s.nativeJoined == nil || s.NativeJoined() || !s.Current() || s.metadata.Execution != "" {
		return "", "", "", errDesktopLastRelay
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(s.metadata.SocksPort)), s.metadata.SessionID, s.isolation, nil
}

func (s *DesktopBridgeSession) LookupLastRelayAnchor(ctx context.Context, connection net.Conn, target netip.AddrPort) (LastRelayLocatedAnchor, error) {
	address, username, password, err := s.LastRelaySOCKS()
	if err != nil || ctx == nil || ctx.Err() != nil || connection == nil || connection.LocalAddr() == nil || connection.RemoteAddr() == nil || connection.RemoteAddr().String() != address {
		return LastRelayLocatedAnchor{}, errDesktopLastRelay
	}
	client, err := netip.ParseAddrPort(connection.LocalAddr().String())
	if err != nil || client.String() != connection.LocalAddr().String() {
		return LastRelayLocatedAnchor{}, errDesktopLastRelay
	}
	locator := LastRelayAnchorLocator{SessionSHA256: desktopDigest([]byte(s.metadata.SessionID)), SourceSHA256: s.metadata.SourceSHA256,
		SOCKSUsername: username, SOCKSPassword: password, Client: client, Target: target}
	anchor, err := s.owner.control.LookupLastRelayAnchor(ctx, locator)
	if err != nil || ctx.Err() != nil || !s.Current() || s.NativeJoined() {
		return LastRelayLocatedAnchor{}, errDesktopLastRelay
	}
	return anchor, nil
}

// LastRelayProbe cannot borrow another session's declared credentials or join
// claim. Every nonnil probe remains owned through Close even when construction
// returns an error; its adapter must retain the original external anchor.
func (s *DesktopBridgeSession) LastRelayProbe(ctx context.Context, anchor LastRelayAnchor) (*LastRelayProbe, error) {
	if _, _, _, err := s.LastRelaySOCKS(); err != nil || anchor == nil {
		return nil, errDesktopLastRelay
	}
	return NewLastRelayProbe(ctx, s.owner.control, &desktopLastRelayAnchor{session: s, anchor: anchor})
}

type desktopLastRelayAnchor struct {
	session *DesktopBridgeSession
	anchor  LastRelayAnchor
}

func (a *desktopLastRelayAnchor) Capture() (LastRelayAnchorCapture, error) {
	_, username, password, err := a.session.LastRelaySOCKS()
	if err != nil {
		return LastRelayAnchorCapture{}, err
	}
	capture, err := a.anchor.Capture()
	if err != nil || capture.SessionSHA256 != desktopDigest([]byte(a.session.metadata.SessionID)) || capture.SourceSHA256 != a.session.metadata.SourceSHA256 || capture.SOCKSUsername != username || capture.SOCKSPassword != password {
		return LastRelayAnchorCapture{}, errDesktopLastRelay
	}
	return capture, nil
}

func (a *desktopLastRelayAnchor) Retain() (LastRelayAnchorHold, error) {
	if _, err := a.Capture(); err != nil {
		return nil, err
	}
	return a.anchor.Retain()
}

func (a *desktopLastRelayAnchor) DialProbe(ctx context.Context, address string) (net.Conn, error) {
	if _, err := a.Capture(); err != nil {
		return nil, err
	}
	return a.anchor.DialProbe(ctx, address)
}

func (a *desktopLastRelayAnchor) NativeJoined() bool { return a.session.NativeJoined() }
