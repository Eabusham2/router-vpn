// Package mtuprobe authenticates bounded bidirectional MTU test datagrams.
// It adds no listener or ordinary network dialer; the private node and retained
// VPN owner provide their existing sockets.
package mtuprobe

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const HeaderBytes = 68
const MaxBytes = 9000
const maxPeers = 128

var magic = []byte{'R', 'V', 'M', 'T', 'U', '0', '2', 0}
var ErrInvalid = errors.New("invalid or unauthenticated private MTU datagram")

func validIdentity(token, node string) bool {
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") || len(node) != 64 {
		return false
	}
	for _, ch := range node {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}
func signature(packet []byte, token, node string) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("router-vpn-mtu-probe-v2\x00" + node + "\x00"))
	mac.Write(packet[:36])
	mac.Write(packet[HeaderBytes:])
	return mac.Sum(nil)
}
func Recognized(packet []byte) bool {
	return len(packet) >= len(magic) && bytes.Equal(packet[:len(magic)], magic)
}
func Request(size int, token, node string, now time.Time) ([]byte, error) {
	if size < HeaderBytes || size > MaxBytes || !validIdentity(token, node) {
		return nil, ErrInvalid
	}
	packet := make([]byte, size)
	if _, err := rand.Read(packet); err != nil {
		return nil, err
	}
	copy(packet, magic)
	packet[8] = 0
	packet[9] = 2
	binary.BigEndian.PutUint16(packet[10:12], uint16(size))
	binary.BigEndian.PutUint64(packet[12:20], uint64(now.Unix()))
	copy(packet[36:68], signature(packet, token, node))
	return packet, nil
}
func Reply(packet []byte, token, node string, now time.Time) ([]byte, error) {
	if !Recognized(packet) || len(packet) < HeaderBytes || len(packet) > MaxBytes || packet[8] != 0 || packet[9] != 2 || int(binary.BigEndian.Uint16(packet[10:12])) != len(packet) || !validIdentity(token, node) {
		return nil, ErrInvalid
	}
	when := int64(binary.BigEndian.Uint64(packet[12:20]))
	stamp := now.Unix()
	if when < stamp-15 || when > stamp+2 || !hmac.Equal(packet[36:68], signature(packet, token, node)) {
		return nil, ErrInvalid
	}
	reply := append([]byte{}, packet...)
	reply[8] = 1
	copy(reply[36:68], signature(reply, token, node))
	return reply, nil
}
func ValidateReply(request, reply []byte, token, node string, now time.Time) error {
	expected, err := Reply(request, token, node, now)
	if err != nil {
		return err
	}
	if len(reply) != len(expected) || !hmac.Equal(reply, expected) {
		return ErrInvalid
	}
	return nil
}

// Limiter is a bounded token bucket without a reaper goroutine. The maximum
// reply size equals the request; neither authenticated probes nor cover traffic
// can become a reflection amplifier.
type Limiter struct {
	mu      sync.Mutex
	entries map[netip.Addr]bucket
}
type bucket struct {
	at      time.Time
	credits float64
}

func (l *Limiter) Allow(peer netip.Addr, now time.Time) bool {
	peer = peer.Unmap()
	if !peer.IsValid() || peer.Zone() != "" || (!peer.IsPrivate() && !peer.IsLoopback()) || peer.IsUnspecified() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[netip.Addr]bucket{}
	}
	value, exists := l.entries[peer]
	if !exists {
		if len(l.entries) >= maxPeers {
			for key, b := range l.entries {
				if now.Sub(b.at) > 30*time.Second {
					delete(l.entries, key)
				}
			}
			if len(l.entries) >= maxPeers {
				return false
			}
		}
		value = bucket{at: now, credits: 64}
	}
	if elapsed := now.Sub(value.at).Seconds(); elapsed > 0 {
		value.credits += elapsed * 32
		if value.credits > 64 {
			value.credits = 64
		}
		value.at = now
	}
	allowed := value.credits >= 1
	if allowed {
		value.credits--
	}
	l.entries[peer] = value
	return allowed
}
