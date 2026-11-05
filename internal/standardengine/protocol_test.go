package standardengine

import (
	"strings"
	"testing"
)

func TestCapturedStandardFramesRejectChangedScope(t *testing.T) {
	c := Capture{1, strings.Repeat("a", 32), strings.Repeat("b", 64), "standard-socks5", 1234, 1, 2, 1, 3, OperationSize, OperationLayout}
	raw, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeCapture(raw, SHA256(raw)); err != nil || got != c {
		t.Fatal(got, err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte { return []byte(strings.Replace(string(b), "{", "{\"schema\":1,", 1)) },
		"extra":     func(b []byte) []byte { return []byte(strings.TrimSuffix(string(b), "}") + ",\"other\":1}") },
		"space":     func(b []byte) []byte { return append(b, ' ') },
		"protocol": func(b []byte) []byte {
			return []byte(strings.ReplaceAll(string(b), "standard-socks5", "standard-openvpn"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := mutate(append([]byte(nil), raw...))
			if _, err := DecodeCapture(changed, SHA256(changed)); err == nil {
				t.Fatal("changed captured standard scope accepted")
			}
		})
	}

	for _, mutate := range []func(*Capture){func(c *Capture) { c.OperationDevice = 0 }, func(c *Capture) { c.OperationInode = 0 }, func(c *Capture) { c.OperationSize-- }, func(c *Capture) { c.OperationLayout++ }} {
		changed := c
		mutate(&changed)
		if _, err := changed.Canonical(); err == nil {
			t.Fatal("capture omitted or changed exact FD11 descriptor layout")
		}
	}
	if _, err := DecodeCapture(raw, strings.Repeat("c", 64)); err == nil {
		t.Fatal("another source accepted")
	}
	ready := Ready{1, SHA256(raw), "{\"real_native_ledger\":true}"}
	body, _ := ready.Canonical()
	if _, err := DecodeReady(body, ready.CaptureSHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReady(body, strings.Repeat("c", 64)); err == nil {
		t.Fatal("another child capture supplied readiness")
	}
}
