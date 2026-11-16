package multihoprelay

import (
	"crypto/ecdh"
	"encoding/base64"
	"sync"
)

const nodeChainPacketPublicCacheLimit = 256

// A successful fixed-scalar X25519 point check is a pure function of these
// public bytes. Repeated capture, request and native-observer validation must
// still check canonical encoding, every owner field and the current session.
// Only this immutable point result is retained, never a proof or lease result.
type nodeChainPacketPublicCache struct {
	mu    sync.Mutex
	valid map[[32]byte]struct{}
	order [nodeChainPacketPublicCacheLimit][32]byte
	next  int
}

var nodeChainPacketPublicPoints nodeChainPacketPublicCache

func nodeChainPacketPublic(value string) bool {
	return nodeChainPacketPublicPoints.check(value)
}

func (c *nodeChainPacketPublicCache) check(value string) bool {
	// Canonical encoding and field/high-bit aliases are checked even on a hit.
	if !canonicalPacketPublic(value) {
		return false
	}
	raw, _ := base64.StdEncoding.Strict().DecodeString(value)
	point := [32]byte(raw)
	c.mu.Lock()
	_, known := c.valid[point]
	c.mu.Unlock()
	if known {
		return true
	}
	// Keep expensive cryptography outside the cache lock. Concurrent misses
	// may repeat this same check, but cannot insert an unchecked point.
	if !nodeChainPacketPublicPoint(raw) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, known := c.valid[point]; known {
		return true
	}
	if c.valid == nil {
		c.valid = make(map[[32]byte]struct{}, nodeChainPacketPublicCacheLimit)
	}
	if len(c.valid) == nodeChainPacketPublicCacheLimit {
		delete(c.valid, c.order[c.next])
	}
	c.valid[point] = struct{}{}
	c.order[c.next] = point
	c.next = (c.next + 1) % nodeChainPacketPublicCacheLimit
	return true
}

// Preserve the original fixed-scalar ECDH test, including low-order refusal.
func nodeChainPacketPublicPoint(raw []byte) bool {
	peer, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return false
	}
	var scalar [32]byte
	scalar[0] = 9
	key, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return false
	}
	shared, err := key.ECDH(peer)
	clear(shared)
	return err == nil
}
