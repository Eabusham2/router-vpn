package multihoprelay

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func originalNodeChainPacketPublic(value string) bool {
	if !canonicalPacketPublic(value) {
		return false
	}
	raw, _ := base64.StdEncoding.Strict().DecodeString(value)
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

func packetPublicMemoFixture(t *testing.T, position int) string {
	t.Helper()
	raw := sha256.Sum256([]byte(fmt.Sprintf("original-public-point-fixture-%d", position)))
	key, err := ecdh.X25519().NewPrivateKey(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func TestNodeChainPacketPublicMemoPreservesOriginalValidation(t *testing.T) {
	var cache nodeChainPacketPublicCache
	cases := []string{"", "invalid", strings.Repeat("A", 43), base64.StdEncoding.EncodeToString(make([]byte, 31))}
	for _, first := range []byte{0, 1, 236, 237, 238, 255} {
		var raw [32]byte
		raw[0] = first
		if first > 1 {
			for i := 1; i < 31; i++ {
				raw[i] = 255
			}
			raw[31] = 127
		}
		cases = append(cases, base64.StdEncoding.EncodeToString(raw[:]))
	}
	for i := 0; i < 64; i++ {
		valid := packetPublicMemoFixture(t, i)
		if !cache.check(valid) {
			t.Fatal("original point refused before warm alias check")
		}
		raw, _ := base64.StdEncoding.DecodeString(valid)
		raw[31] |= 128
		cases = append(cases, valid, valid+"\n", " "+valid, strings.TrimSuffix(valid, "="), base64.StdEncoding.EncodeToString(raw))
	}
	for round := 0; round < 2; round++ {
		for i, value := range cases {
			want := originalNodeChainPacketPublic(value)
			if got := cache.check(value); got != want {
				t.Fatalf("original canonical/ECDH result changed at case %d round %d", i, round)
			}
			if got := nodeChainPacketPublic(value); got != want {
				t.Fatalf("shipping point check changed at case %d round %d", i, round)
			}
		}
	}
	// A rejected point may never acquire a positive cache entry.
	for point := range cache.valid {
		if !originalNodeChainPacketPublic(base64.StdEncoding.EncodeToString(point[:])) {
			t.Fatal("cache retained a rejected point")
		}
	}
}

func TestNodeChainPacketPublicMemoEvictionRetainsOriginalValidation(t *testing.T) {
	var cache nodeChainPacketPublicCache
	values := make([]string, nodeChainPacketPublicCacheLimit+1)
	for i := range values {
		values[i] = packetPublicMemoFixture(t, i)
		if !cache.check(values[i]) || len(cache.valid) > nodeChainPacketPublicCacheLimit {
			t.Fatal("point validation or memory bound changed", i)
		}
	}
	first, _ := base64.StdEncoding.DecodeString(values[0])
	if _, retained := cache.valid[[32]byte(first)]; retained {
		t.Fatal("original oldest point did not leave the bounded cache")
	}
	for _, value := range values {
		if !cache.check(value) || len(cache.valid) != nodeChainPacketPublicCacheLimit {
			t.Fatal("evicted original point could not be revalidated")
		}
	}
}

func TestNodeChainPacketPublicMemoCanonicalCacheHit(t *testing.T) {
	var cache nodeChainPacketPublicCache
	value := packetPublicMemoFixture(t, 19)
	if !cache.check(value) {
		t.Fatal("original canonical point refused")
	}
	// Go's base64 decoder accepts newlines. They must not reach a warm entry
	// for the same bytes and thereby acquire a second public identity spelling.
	if cache.check(value + "\n") {
		t.Fatal("warm point cache accepted a noncanonical public identity")
	}
}

func TestNodeChainPacketPublicMemoConcurrentOwners(t *testing.T) {
	var cache nodeChainPacketPublicCache
	values := make([]string, 32)
	for i := range values {
		values[i] = packetPublicMemoFixture(t, i)
	}
	var work sync.WaitGroup
	for i := 0; i < 16; i++ {
		work.Add(1)
		go func() {
			defer work.Done()
			for round := 0; round < 3; round++ {
				for _, value := range values {
					if !cache.check(value) || cache.check(value+"\n") || cache.check(base64.StdEncoding.EncodeToString(make([]byte, 32))) {
						t.Error("concurrent canonical/low-order validation changed")
						return
					}
				}
			}
		}()
	}
	work.Wait()
	if len(cache.valid) != len(values) {
		t.Fatal("concurrent cache retained a failed point or lost a valid point")
	}
}
