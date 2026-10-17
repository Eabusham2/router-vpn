//go:build routervpn_pq_traffic_test

package mobilepq

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// NativePQSnapshot is test-only readback from the real peer's configuration API.
// Only a digest is retained; neither disposable private key is logged or returned.
// This file is absent from normal server and mobile builds.
type NativePQSnapshot struct {
	KeyDigest      [32]byte
	HandshakeNanos int64
}

func ReadNativePQSnapshot(raw, public string) (NativePQSnapshot, error) {
	var result NativePQSnapshot
	bad := errors.New("invalid or ambiguous native test peer readback")
	if len(raw) == 0 || len(raw) > 64<<10 || len(public) != 64 {
		return result, bad
	}
	if key, err := hex.DecodeString(public); err != nil || len(key) != 32 {
		return result, bad
	}
	fields := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			if line != "" {
				return result, bad
			}
			continue
		}
		switch name {
		case "public_key", "preshared_key", "last_handshake_time_sec", "last_handshake_time_nsec":
			if _, exists := fields[name]; exists {
				return result, bad
			}
			fields[name] = value
		}
	}
	if len(fields) != 4 || fields["public_key"] != public {
		return result, bad
	}
	key, err := hex.DecodeString(fields["preshared_key"])
	if err != nil || len(key) != 32 {
		return result, bad
	}
	defer clear(key)
	var nonzero byte
	for _, b := range key {
		nonzero |= b
	}
	if nonzero == 0 {
		return result, bad
	}
	seconds, e1 := strconv.ParseInt(fields["last_handshake_time_sec"], 10, 64)
	nanos, e2 := strconv.ParseInt(fields["last_handshake_time_nsec"], 10, 64)
	if e1 != nil || e2 != nil || seconds < 0 || seconds > 9223372035 || nanos < 0 || nanos >= 1e9 {
		return result, bad
	}
	result.KeyDigest = sha256.Sum256(key)
	result.HandshakeNanos = seconds*1e9 + nanos
	return result, nil
}
