//go:build routervpn_pq_traffic_test

package mobilepq

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestNativeReadbackRequiresOneExactPeerAndRetainsNoKey(t *testing.T) {
	public := strings.Repeat("01", 32)
	raw := "private_key=" + strings.Repeat("ff", 32) + "\npublic_key=" + public + "\npreshared_key=" + strings.Repeat("02", 32) + "\nlast_handshake_time_sec=123\nlast_handshake_time_nsec=456\nallowed_ip=0.0.0.0/0\n"
	got, err := ReadNativePQSnapshot(raw, public)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = 2
	}
	if got.KeyDigest != sha256.Sum256(key) || got.HandshakeNanos != 123000000456 {
		t.Fatal("readback values changed")
	}
	for name, bad := range map[string]string{
		"duplicate": raw + "public_key=" + public + "\n", "duplicate-key": raw + "preshared_key=" + strings.Repeat("02", 32) + "\n",
		"missing":          strings.ReplaceAll(raw, "last_handshake_time_nsec=456\n", ""),
		"wrong-peer":       strings.ReplaceAll(raw, "public_key="+public, "public_key="+strings.Repeat("03", 32)),
		"empty-key":        strings.ReplaceAll(raw, strings.Repeat("02", 32), strings.Repeat("00", 32)),
		"invalid-key":      strings.ReplaceAll(raw, strings.Repeat("02", 32), "invalid"),
		"seconds-overflow": strings.ReplaceAll(raw, "sec=123", "sec=9223372036"),
		"negative-time":    strings.ReplaceAll(raw, "sec=123", "sec=-1"),
		"nanos-overflow":   strings.ReplaceAll(raw, "nsec=456", "nsec=1000000000"),
		"oversized":        strings.Repeat("x", 65537),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadNativePQSnapshot(bad, public); err == nil {
				t.Fatal("invalid native readback accepted")
			}
		})
	}
}
