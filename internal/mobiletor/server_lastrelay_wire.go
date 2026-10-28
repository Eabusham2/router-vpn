package mobiletor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// This is a private command on the existing exact-peer, authenticated lease
// front. It is deliberately not CONNECT: a missing capability must never turn
// a control/probe address into ordinary Tor traffic or a selected-DNS query.
const serverLastRelayCommand byte = 0xf0
const serverLastRelayAddress = "lastrelay.routervpn.invalid:1"
const serverLastRelayFrameLimit = 8192

var errServerLastRelay = errors.New("captured server Tor comparison is unavailable or changed")

type serverLastRelayRequest struct {
	Schema          int    `json:"schema"`
	Action          string `json:"action"`
	OwnerID         string `json:"owner_id"`
	SessionID       string `json:"session_id"`
	SourceSHA256    string `json:"source_sha256"`
	RegistrySHA256  string `json:"registry_sha256"`
	DNSPolicySHA256 string `json:"dns_policy_sha256"`
	Handle          string `json:"handle"`
	Nonce           string `json:"nonce"`
	Target          string `json:"target"`
	Address         string `json:"address"`
}

type serverLastRelayAnchor struct {
	SessionSHA256   string `json:"session_sha256"`
	AnchorStream    uint64 `json:"anchor_stream"`
	Circuit         uint32 `json:"circuit"`
	ExitFingerprint string `json:"exit_fingerprint"`
	PathSHA256      string `json:"path_sha256"`
	SOCKSUsername   string `json:"socks_username"`
	SOCKSPassword   string `json:"socks_password"`
	Client          string `json:"client"`
	Target          string `json:"target"`
	PathCheckedAt   int64  `json:"path_checked_at"`
	DNSCheckedAt    int64  `json:"dns_checked_at"`
}

type serverLastRelayResponse struct {
	Request serverLastRelayRequest `json:"request"`
	Anchor  *serverLastRelayAnchor `json:"anchor"`
	Closed  bool                   `json:"closed"`
}

func serverLastRelayTarget(target string) (netip.AddrPort, error) {
	switch target {
	case "https://1.1.1.1/cdn-cgi/trace":
		return netip.MustParseAddrPort("1.1.1.1:443"), nil
	case "https://1.0.0.1/cdn-cgi/trace":
		return netip.MustParseAddrPort("1.0.0.1:443"), nil
	default:
		return netip.AddrPort{}, errServerLastRelay
	}
}

func serverLastRelayReserved(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "lastrelay.routervpn.invalid" || strings.HasSuffix(host, ".lastrelay.routervpn.invalid")
}

func (r serverLastRelayRequest) validate() error {
	if r.Schema != 1 || !capturedHex(r.OwnerID, 32) || !capturedHex(r.SessionID, 16) ||
		!capturedHex(r.SourceSHA256, 32) || !capturedHex(r.RegistrySHA256, 32) || !capturedHex(r.DNSPolicySHA256, 32) ||
		!capturedHex(r.Handle, 32) || !capturedHex(r.Nonce, 32) {
		return errServerLastRelay
	}
	if _, err := serverLastRelayTarget(r.Target); err != nil {
		return err
	}
	switch r.Action {
	case "open", "control", "verify", "close":
		if r.Address != "" {
			return errServerLastRelay
		}
	case "probe":
		host, port, err := net.SplitHostPort(r.Address)
		if err != nil || port != "1" || !strings.HasSuffix(host, ".lastrelay.routervpn.invalid") || len(host) > 160 || strings.ContainsAny(host, "\r\n\x00 ") {
			return errServerLastRelay
		}
	default:
		return errServerLastRelay
	}
	return nil
}

// Frames are read without a buffered reader. The bytes immediately following
// an open/probe response belong to the retained TLS/HTTP stream and cannot be
// consumed, replayed or accidentally dropped by JSON parsing.
func serverLastRelayRead(reader io.Reader, result any) error {
	var size [4]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return errServerLastRelay
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > serverLastRelayFrameLimit {
		return errServerLastRelay
	}
	raw := make([]byte, n)
	defer clear(raw)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return errServerLastRelay
	}
	if _, err := profileObject(string(raw), serverLastRelayFrameLimit); err != nil {
		return errServerLastRelay
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(result) != nil {
		return errServerLastRelay
	}
	return nil
}

func serverLastRelayWrite(writer io.Writer, value any) error {
	raw, err := json.Marshal(value)
	defer clear(raw)
	if err != nil || len(raw) == 0 || len(raw) > serverLastRelayFrameLimit {
		return errServerLastRelay
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(raw)))
	frame = append(frame, raw...)
	defer clear(frame)
	for len(frame) != 0 {
		n, err := writer.Write(frame)
		if err != nil || n <= 0 || n > len(frame) {
			return errServerLastRelay
		}
		frame = frame[n:]
	}
	return nil
}

func (a serverLastRelayAnchor) capture(owner, source string) LastRelayAnchorCapture {
	return LastRelayAnchorCapture{OwnerID: owner, SourceSHA256: source, SessionSHA256: a.SessionSHA256,
		AnchorStream: a.AnchorStream, Circuit: a.Circuit, ExitFingerprint: a.ExitFingerprint, PathSHA256: a.PathSHA256,
		SOCKSUsername: a.SOCKSUsername, SOCKSPassword: a.SOCKSPassword,
		PathCheckedAt: time.UnixMilli(a.PathCheckedAt), DNSCheckedAt: time.UnixMilli(a.DNSCheckedAt)}
}
