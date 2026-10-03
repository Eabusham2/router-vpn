package multihoprelay

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// X25519 clamps five scalar bits. These 32 distinct, valid private-key
// encodings identify the same client peer and must share one lease owner.
func scalarAlias(t *testing.T, index int) string {
	t.Helper()
	raw := []byte(strings.Repeat("a", 32))
	raw[0] = raw[0]&248 | byte(index&7)
	raw[31] = raw[31]&63 | byte((index>>3)&3)<<6
	return base64.StdEncoding.EncodeToString(raw)
}
func identityExit(t *testing.T, id, mode, private string) Exit {
	t.Helper()
	e := awgExit(t, "awg2-fast")
	e.ID, e.Mode = id, mode
	e.Transport["private_key"] = private
	if mode == "wg" {
		e.Transport["type"] = "wireguard"
		delete(e.Transport, "amnezia")
	}
	return e
}
func identityRequest(id, mode string) Request { q := req(); q.ExitID = id; q.ExitMode = mode; return q }
func TestPrivateKeyAliasesShareRelayOwnership(t *testing.T) {
	for _, first := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, second := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(first+"/"+second, func(t *testing.T) {
				for alias := 1; alias < 32; alias++ {
					c := config()
					c.Exits = []Exit{identityExit(t, "first", first, scalarAlias(t, 0)), identityExit(t, "alias", second, scalarAlias(t, alias))}
					r := &runner{}
					m, err := New(c, req().EntryNodeID, r)
					if err != nil {
						t.Fatal(err)
					}
					a, b := identityRequest("first", first), identityRequest("alias", second)
					owner, other := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
					if _, err = m.Create(context.Background(), owner, a); err != nil {
						t.Fatal(err)
					}
					available := m.Available()
					if available[0]["client_public_key"] != available[1]["client_public_key"] {
						t.Fatal("test scalar encodings are not aliases")
					}
					if _, err = m.Create(context.Background(), other, b); err == nil {
						t.Fatalf("alias %d started another process for one public peer", alias)
					}
					if r.starts != 1 || !r.processes[0].alive {
						t.Fatal("rejection altered original owner")
					}
					if _, err = m.Create(context.Background(), owner, a); err != nil || r.starts != 1 {
						t.Fatal("idempotent renewal stopped working", err)
					}
					if err = m.Delete(context.Background(), owner, a); err != nil {
						t.Fatal(err)
					}
					if _, err = m.Create(context.Background(), other, b); err != nil {
						t.Fatal("verified stop did not release identity", err)
					}
					if err = m.Close(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
func TestDistinctClientsAtSameWireGuardServerRemainIndependent(t *testing.T) {
	c := config()
	other := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	c.Exits = []Exit{identityExit(t, "first", "awg2-fast", scalarAlias(t, 0)), identityExit(t, "second", "awg2-strong", other)}
	r := &runner{}
	m, err := New(c, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range c.Exits {
		ip := netip.MustParseAddr("10.77.0.2")
		if i == 1 {
			ip = ip.Next()
		}
		if _, err = m.Create(context.Background(), ip, identityRequest(e.ID, e.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	if r.starts != 2 {
		t.Fatal("distinct clients were conflated with server identity")
	}
	if err = m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestAliasedIdentityRetainedUntilCleanupConfirmed(t *testing.T) {
	c := config()
	c.Exits = []Exit{identityExit(t, "first", "awg2-fast", scalarAlias(t, 0)), identityExit(t, "alias", "wg", scalarAlias(t, 31))}
	r := &runner{}
	m, err := New(c, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	owner, other := netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
	a, b := identityRequest("first", "awg2-fast"), identityRequest("alias", "wg")
	if _, err = m.Create(context.Background(), owner, a); err != nil {
		t.Fatal(err)
	}
	r.processes[0].stopFail = true
	if err = m.Delete(context.Background(), owner, a); err == nil {
		t.Fatal("failed stop accepted")
	}
	if _, err = m.Create(context.Background(), other, b); err == nil || r.starts != 1 {
		t.Fatal("unconfirmed cleanup released aliased identity")
	}
	r.processes[0].stopFail = false
	m.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err = m.Create(context.Background(), other, b); err != nil || r.starts != 2 {
		t.Fatal("expired and stopped lease did not release identity", err)
	}
	if err = m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestConcurrentAliasesOnlyStartOneRelay(t *testing.T) {
	c := config()
	c.LastPort = c.FirstPort + 31
	for i := 0; i < 32; i++ {
		e := identityExit(t, fmt.Sprintf("alias-%d", i), "awg2-strong", scalarAlias(t, i))
		c.Exits = append(c.Exits, e)
	}
	r := &runner{}
	m, err := New(c, req().EntryNodeID, r)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := m.Create(context.Background(), netip.AddrFrom4([4]byte{10, 77, 0, byte(i + 2)}), identityRequest(c.Exits[i+1].ID, "awg2-strong"))
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 || r.starts != 1 {
		t.Fatalf("concurrent scalar aliases got %d owners and %d processes", success, r.starts)
	}
	if err = m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestIdentityRegressionUsesRealX25519Derivation(t *testing.T) {
	a, _ := base64.StdEncoding.DecodeString(scalarAlias(t, 0))
	b, _ := base64.StdEncoding.DecodeString(scalarAlias(t, 31))
	ka, ea := ecdh.X25519().NewPrivateKey(a)
	kb, eb := ecdh.X25519().NewPrivateKey(b)
	if errors.Join(ea, eb) != nil || ka.Equal(kb) || !ka.PublicKey().Equal(kb.PublicKey()) {
		t.Fatal("invalid alias negative-control fixture")
	}
}
