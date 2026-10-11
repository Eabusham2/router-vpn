package mobilepq

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

type factoryFunc func([]byte, []byte, []byte, int) (Protocol, error)

func (f factoryFunc) Open(a, b, c []byte, v int) (Protocol, error) { return f(a, b, c, v) }
func nativeConfig() Config {
	return Config{Endpoint: "192.0.2.1:51822", Version: 2, Secret: bytes.Repeat([]byte{3}, 64), Public: bytes.Repeat([]byte{4}, 128), Peer: bytes.Repeat([]byte{5}, 128)}
}

func TestFactoryCapturedKeysAreCopiedAndErased(t *testing.T) {
	var registry FactoryRegistry
	config := nativeConfig()
	var seen [][]byte
	var calls int
	if err := registry.Install(factoryFunc(func(s, p, r []byte, v int) (Protocol, error) {
		calls++
		if v != config.Version || !bytes.Equal(s, config.Secret) || !bytes.Equal(p, config.Public) || !bytes.Equal(r, config.Peer) {
			t.Fatal("captured keys changed")
		}
		seen = [][]byte{s, p, r}
		return &testProtocol{}, nil
	})); err != nil {
		t.Fatal(err)
	}
	protocol, err := registry.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer protocol.Close()
	if calls != 1 {
		t.Fatal("wrong factory call count")
	}
	for _, key := range seen {
		if !bytes.Equal(key, make([]byte, len(key))) {
			t.Fatal("temporary native key copy not erased")
		}
	}
	if config.Secret[0] != 3 || config.Public[0] != 4 || config.Peer[0] != 5 {
		t.Fatal("persistent captured configuration mutated")
	}
	config.Erase()
	if config.Secret != nil || config.Public != nil || config.Peer != nil {
		t.Fatal("configuration retained keys")
	}
}
func TestFactoryRejectsMissingReplacementAndPartialOwner(t *testing.T) {
	var registry FactoryRegistry
	if _, err := registry.Open(nativeConfig()); err == nil {
		t.Fatal("uninstalled factory accepted")
	}
	if err := registry.Install(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	protocol := &testProtocol{}
	f := factoryFunc(func([]byte, []byte, []byte, int) (Protocol, error) { return protocol, errors.New("private details") })
	if err := registry.Install(f); err != nil {
		t.Fatal(err)
	}
	if err := registry.Install(f); err == nil {
		t.Fatal("installed factory replaced")
	}
	if _, err := registry.Open(nativeConfig()); err == nil || err.Error() == "private details" {
		t.Fatal("failed construction leaked details or succeeded")
	}
	if protocol.closes != 1 {
		t.Fatal("partial native owner leaked")
	}
}
func TestFactoryConcurrentInstallPublishesOnlyOne(t *testing.T) {
	var registry FactoryRegistry
	var group sync.WaitGroup
	accepted := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			accepted <- registry.Install(factoryFunc(func([]byte, []byte, []byte, int) (Protocol, error) { return &testProtocol{}, nil })) == nil
		}()
	}
	group.Wait()
	close(accepted)
	count := 0
	for v := range accepted {
		if v {
			count++
		}
	}
	if count != 1 {
		t.Fatal("multiple native factories installed", count)
	}
}
func TestNativeConfigurationRejection(t *testing.T) {
	for _, endpoint := range []string{"localhost:51822", "127.0.0.1:51822", "[::1]:51822", "[fe80::1%en0]:51822", "0.0.0.0:1", "[::ffff:192.0.2.1]:1", "192.0.2.1:0", "224.0.0.1:1", "255.255.255.255:1", "0.1.2.3:1"} {
		c := nativeConfig()
		c.Endpoint = endpoint
		if c.Validate() == nil {
			t.Fatal("unowned endpoint accepted", endpoint)
		}
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Version = 1 }, func(c *Config) { c.Secret = nil }, func(c *Config) { c.Peer = c.Public }, func(c *Config) { c.Secret = make([]byte, 64) }, func(c *Config) { c.Peer = c.Peer[:127] }, func(c *Config) { c.Public = make([]byte, 2*1024*1024+1) }} {
		c := nativeConfig()
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("invalid key policy accepted")
		}
	}
	for _, endpoint := range []string{"192.0.2.1:51822", "10.77.0.1:51822", "[2001:db8::1]:51822"} {
		c := nativeConfig()
		c.Endpoint = endpoint
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
