package standardengine

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDNSSECCaptureIdentity(t *testing.T) {
	c := DNSSECCapture{Schema: 1, Session: strings.Repeat("a", 32), DeadlineNS: 1, PlanSHA256: strings.Repeat("b", 64), Name: "example.test.", Type: 1, Anchors: []string{". IN DS 1 8 2 ABCD"}}
	raw, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeDNSSECCapture(raw, SHA256(raw)); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*DNSSECCapture){
		"relative": func(v *DNSSECCapture) { v.Name = "example.test" }, "type": func(v *DNSSECCapture) { v.Type = 43 }, "anchor-count": func(v *DNSSECCapture) { v.Anchors = make([]string, 33) }, "anchor-text": func(v *DNSSECCapture) { v.Anchors = []string{"a\nb"} }, "anchor-total": func(v *DNSSECCapture) {
			v.Anchors = make([]string, 9)
			for i := range v.Anchors {
				v.Anchors[i] = strings.Repeat("a", 4096)
			}
		}, "insecure": func(v *DNSSECCapture) { v.Insecure = []string{"EXAMPLE."} },
	} {
		t.Run(name, func(t *testing.T) {
			v := c
			mutate(&v)
			if _, err := v.Canonical(); err == nil {
				t.Fatal("invalid captured input admitted")
			}
		})
	}
	if _, err = DecodeDNSSECCapture(append(raw, ' '), SHA256(append(raw, ' '))); err == nil {
		t.Fatal("noncanonical input admitted")
	}
	if _, err = DecodeDNSSECCapture(raw, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong original digest admitted")
	}
}
func TestDNSSECFrameBoundaries(t *testing.T) {
	capture := strings.Repeat("a", 64)
	for _, size := range []int{12, 8192, 8193, 65535} {
		packet := bytes.Repeat([]byte{0x73}, size)
		original := DNSSECVerdict{State: 3, RCode: 3, NXDomain: 1, TTL: 31, Packet: packet}
		frames, err := BuildDNSSECFrames(capture, 257, "verdict", original)
		if err != nil {
			t.Fatal(err)
		}
		result, err := DecodeDNSSECFrames(frames, capture, 257, "verdict")
		if err != nil || !bytes.Equal(result.Packet, packet) || result.State != 3 || result.TTL != 31 {
			t.Fatalf("roundtrip %d: %#v %v", size, result, err)
		}
	}
	for _, size := range []int{0, 11, 65536} {
		if _, err := BuildDNSSECFrames(capture, 1, "query", DNSSECVerdict{Packet: make([]byte, size)}); err == nil {
			t.Fatalf("unbounded packet %d", size)
		}
	}
	if _, err := BuildDNSSECFrames(capture, 257, "query", DNSSECVerdict{Packet: make([]byte, 12)}); err == nil {
		t.Fatal("query budget renewed")
	}
}
func TestDNSSECFrameTampering(t *testing.T) {
	capture := strings.Repeat("b", 64)
	original, err := BuildDNSSECFrames(capture, 3, "verdict", DNSSECVerdict{State: 1, HaveData: 1, Packet: bytes.Repeat([]byte{7}, 9000)})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([][]byte) [][]byte{
		"missing": func(f [][]byte) [][]byte { return f[:1] }, "reordered": func(f [][]byte) [][]byte { return [][]byte{f[1], f[0]} },
		"metadata": func(f [][]byte) [][]byte {
			var v DNSSECFrame
			json.Unmarshal(f[1], &v)
			v.State = 2
			f[1], _ = json.Marshal(v)
			return f
		},
		"payload": func(f [][]byte) [][]byte {
			var v DNSSECFrame
			json.Unmarshal(f[1], &v)
			v.Data[0] ^= 1
			f[1], _ = json.Marshal(v)
			return f
		},
		"unknown": func(f [][]byte) [][]byte { f[0] = append(f[0][:len(f[0])-1], []byte(",\"unknown\":1}")...); return f },
	} {
		t.Run(name, func(t *testing.T) {
			f := make([][]byte, len(original))
			for i := range f {
				f[i] = bytes.Clone(original[i])
			}
			if _, err := DecodeDNSSECFrames(mutate(f), capture, 3, "verdict"); err == nil {
				t.Fatal("changed original frame admitted")
			}
		})
	}
	if _, err := DecodeDNSSECFrames(original, capture, 2, "verdict"); err == nil {
		t.Fatal("replayed sequence admitted")
	}
	if _, err := DecodeDNSSECFrames(original, strings.Repeat("c", 64), 3, "verdict"); err == nil {
		t.Fatal("other original capture admitted")
	}
}

func TestDNSSECCapturedAliasPurpose(t *testing.T) {
	base := DNSSECCapture{Schema: 1, Session: strings.Repeat("a", 32), DeadlineNS: 1, PlanSHA256: strings.Repeat("b", 64), Name: "alias.signed.example.", Type: 5}
	raw, err := base.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	retained, err := DecodeDNSSECCapture(raw, SHA256(raw))
	if err != nil || retained.Type != 5 {
		t.Fatal("exact alias purpose lost in sealed capture", err)
	}
	for _, kind := range []uint16{1, 28, 5, 39, 43, 48} {
		wire := resolvedDNSSECWire(base.Name, kind, true)
		_, err := retained.Question(wire)
		if (err == nil) != (kind == 5 || kind == 43 || kind == 48) {
			t.Fatal("alias purpose acquired a different query", kind, err)
		}
	}
	changed := retained
	changed.Type = 1
	other, err := changed.Canonical()
	if err != nil || SHA256(other) == SHA256(raw) {
		t.Fatal("address and alias captures share an identity", err)
	}
	if _, err = DecodeDNSSECCapture(other, SHA256(raw)); err == nil {
		t.Fatal("address capture adopted an alias operation digest")
	}
}
