package mobilepq

import (
	"bytes"
	"errors"
	"net/netip"
)

// Config is private configuration, not status data. Its endpoint is captured
// from the selected WG/AWG peer; it must not perform a resolver lookup or choose
// another network. Exact cryptographic key lengths are enforced again by FFI.
type Config struct {
	Endpoint string `json:"endpoint"`
	Version  int    `json:"version"`
	Secret   []byte `json:"secret"`
	Public   []byte `json:"public"`
	Peer     []byte `json:"peer"`
}

func (c Config) Validate() error {
	fail := errors.New("invalid captured native PQ configuration")
	endpoint, err := netip.ParseAddrPort(c.Endpoint)
	if err != nil || endpoint.Port() == 0 {
		return fail
	}
	ip := endpoint.Addr()
	if ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fail
	}
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 0 || b[0] >= 224 {
			return fail
		}
	}
	if c.Version != 2 && c.Version != 3 {
		return fail
	}
	for _, key := range [][]byte{c.Secret, c.Public, c.Peer} {
		if len(key) < 32 || len(key) > 2*1024*1024 {
			return fail
		}
		var nonzero byte
		for _, b := range key {
			nonzero |= b
		}
		if nonzero == 0 {
			return fail
		}
	}
	if len(c.Public) != len(c.Peer) || bytes.Equal(c.Public, c.Peer) {
		return fail
	}
	return nil
}

func (c *Config) Erase() {
	if c == nil {
		return
	}
	erase(c.Secret)
	erase(c.Public)
	erase(c.Peer)
	c.Secret, c.Public, c.Peer = nil, nil, nil
}
