package standardengine

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestResolvedAnchorCommandOriginalWholeFrames(t *testing.T) {
	anchor := resolvedAnchorFixture(48)
	// A bounded large standalone DNSKEY exercises actual multi-frame assembly.
	rr := anchor.Records[0]
	rr = append(rr, make([]byte, 7000)...)
	binary.BigEndian.PutUint16(rr[9:], uint16(len(rr)-11))
	anchor.Records[0] = rr
	raw, err := anchor.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	capture := strings.Repeat("c", 64)
	frames, err := BuildResolvedAnchorFrames(capture, 2, raw)
	if err != nil || len(frames) < 2 {
		t.Fatal("anchor did not span bounded frames", err)
	}
	if _, err = DecodeResolvedAnchorFrames(frames, capture, 2, anchor.PolicySHA256, 0, ".", 48); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([][]byte) [][]byte{
		"missing": func(f [][]byte) [][]byte { return f[:1] },
		"reorder": func(f [][]byte) [][]byte { f[0], f[1] = f[1], f[0]; return f },
		"digest": func(f [][]byte) [][]byte {
			var frame ResolvedFrame
			json.Unmarshal(f[0], &frame)
			frame.SHA256 = strings.Repeat("d", 64)
			f[0], _ = json.Marshal(frame)
			return f
		},
		"sequence": func(f [][]byte) [][]byte {
			var frame ResolvedFrame
			json.Unmarshal(f[0], &frame)
			frame.Sequence++
			f[0], _ = json.Marshal(frame)
			return f
		},
		"unknown": func(f [][]byte) [][]byte { f[0] = append(f[0][:len(f[0])-1], []byte(",\"extra\":true}")...); return f },
	} {
		t.Run(name, func(t *testing.T) {
			copied := make([][]byte, len(frames))
			for i := range frames {
				copied[i] = append([]byte(nil), frames[i]...)
			}
			if _, err := DecodeResolvedAnchorFrames(mutate(copied), capture, 2, anchor.PolicySHA256, 0, ".", 48); err == nil {
				t.Fatal("foreign anchor frame accepted")
			}
		})
	}
	for _, row := range []struct {
		index int32
		name  string
		kind  uint16
	}{{7, ".", 48}, {0, "example", 48}, {0, ".", 43}} {
		if _, err := DecodeResolvedAnchorFrames(frames, capture, 2, anchor.PolicySHA256, row.index, row.name, row.kind); err == nil {
			t.Fatal("anchor result changed exact lookup")
		}
	}
	for _, kind := range []uint16{43, 48} {
		body, err := (ResolvedRequest{Schema: 1, CaptureSHA256: capture, Sequence: 3, Action: "anchor", Name: ".", Type: kind}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeResolvedRequest(body, capture, 3); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = (ResolvedRequest{Schema: 1, CaptureSHA256: capture, Sequence: 3, Action: "anchor", Name: ".", Type: 1}).Canonical(); err == nil {
		t.Fatal("ordinary record escaped trust-anchor-only action")
	}
}
