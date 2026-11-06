package standardengine

import (
	"bytes"
	"testing"
)

func TestResolvedPolicyWireRejectsReinterpretation(t *testing.T) {
	raw, err := resolvedPolicyFixture().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"duplicate":  bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"unknown":    bytes.Replace(raw, []byte(`"schema":1`), []byte(`"unknown":true,"schema":1`), 1),
		"whitespace": append([]byte(" "), raw...),
		"trailing":   append(append([]byte(nil), raw...), []byte("{}")...),
		"oversized":  bytes.Repeat([]byte(" "), MaxResolvedPolicy+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeResolvedPolicy(changed, SHA256(changed)); err == nil {
				t.Fatal("noncanonical wire interpreted")
			}
		})
	}
}
