package standardengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

const DNSSECLibraryFD = 10
const MaxDNSSECCapture = 64 << 10
const MaxDNSSECQueries uint32 = 256
const MaxDNSSECPacket = 65535
const MaxDNSSECExchangeBytes = 8 << 20

type DNSSECCapture struct {
	Schema     int      `json:"schema"`
	Session    string   `json:"session"`
	DeadlineNS int64    `json:"deadline_ns"`
	PlanSHA256 string   `json:"plan_sha256"`
	Name       string   `json:"name"`
	Type       uint16   `json:"type"`
	Anchors    []string `json:"anchors"`
	Insecure   []string `json:"insecure"`
}

func (c DNSSECCapture) Canonical() ([]byte, error) {
	bad := errors.New("DNSSEC capture escaped original bounded immutable inputs")
	if c.Schema != 1 || !resolvedDigest(c.Session, 16) || c.DeadlineNS <= 0 || !resolvedDigest(c.PlanSHA256, 32) || !ResolvedName(c.Name, false) || c.Name != strings.ToLower(c.Name) || !strings.HasSuffix(c.Name, ".") || c.Type != 1 && c.Type != 28 || len(c.Anchors) > 32 || len(c.Insecure) > 32 {
		return nil, bad
	}
	total := 0
	for _, s := range c.Anchors {
		if len(s) == 0 || len(s) > 4096 {
			return nil, bad
		}
		total += len(s)
		if total > 32768 {
			return nil, bad
		}
		for _, b := range []byte(s) {
			if b < 32 && b != '\t' || b > 126 {
				return nil, bad
			}
		}
	}
	for _, s := range c.Insecure {
		if !ResolvedName(s, true) || s != strings.ToLower(s) || !strings.HasSuffix(s, ".") || len(s) > 254 {
			return nil, bad
		}
	}
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > MaxDNSSECCapture {
		return nil, bad
	}
	return raw, nil
}
func DecodeDNSSECCapture(raw []byte, expected string) (DNSSECCapture, error) {
	var c DNSSECCapture
	if len(raw) == 0 || len(raw) > MaxDNSSECCapture || json.Unmarshal(raw, &c) != nil {
		return c, errors.New("invalid DNSSEC sealed capture")
	}
	canonical, err := c.Canonical()
	if err != nil || !bytes.Equal(canonical, raw) || SHA256(raw) != expected {
		return DNSSECCapture{}, errors.New("DNSSEC sealed capture identity changed")
	}
	return c, nil
}

type DNSSECFrame struct {
	Schema        int    `json:"schema"`
	CaptureSHA256 string `json:"capture_sha256"`
	Sequence      uint32 `json:"sequence"`
	Kind          string `json:"kind"`
	State         uint32 `json:"state,omitempty"`
	RCode         uint32 `json:"rcode,omitempty"`
	HaveData      uint32 `json:"have_data,omitempty"`
	NXDomain      uint32 `json:"nxdomain,omitempty"`
	TTL           uint32 `json:"ttl,omitempty"`
	SHA256        string `json:"sha256"`
	Part          uint32 `json:"part"`
	Parts         uint32 `json:"parts"`
	Data          []byte `json:"data"`
}
type DNSSECVerdict struct {
	State, RCode, HaveData, NXDomain, TTL uint32
	Packet                                []byte
}
type DNSSECQuery struct {
	CaptureSHA256, PlanSHA256, Name string
	Type                            uint16
	Sequence                        uint32
	Packet                          []byte
}

func (f DNSSECFrame) valid() bool {
	if f.Schema != 1 || !resolvedDigest(f.CaptureSHA256, 32) || !resolvedDigest(f.SHA256, 32) || f.Sequence < 1 || f.Sequence > MaxDNSSECQueries+1 || f.Parts < 1 || f.Parts > 8 || f.Part >= f.Parts || len(f.Data) == 0 || len(f.Data) > resolvedChunkSize {
		return false
	}
	if f.Kind == "query" || f.Kind == "reply" {
		return f.Sequence <= MaxDNSSECQueries && f.State == 0 && f.RCode == 0 && f.HaveData == 0 && f.NXDomain == 0 && f.TTL == 0
	}
	return f.Kind == "verdict" && f.State >= 1 && f.State <= 3 && (f.RCode == 0 || f.RCode == 3) && f.HaveData <= 1 && f.NXDomain <= 1 && (f.NXDomain == 1) == (f.RCode == 3)
}
func DecodeDNSSECFrame(raw []byte) (DNSSECFrame, error) {
	var f DNSSECFrame
	if len(raw) == 0 || len(raw) > 12<<10 || json.Unmarshal(raw, &f) != nil || !f.valid() {
		return f, errors.New("invalid DNSSEC original frame")
	}
	canonical, err := json.Marshal(f)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DNSSECFrame{}, errors.New("noncanonical DNSSEC original frame")
	}
	return f, nil
}
func BuildDNSSECFrames(capture string, sequence uint32, kind string, verdict DNSSECVerdict) ([][]byte, error) {
	if len(verdict.Packet) < 12 || len(verdict.Packet) > MaxDNSSECPacket {
		return nil, errors.New("DNSSEC message exceeded packet bound")
	}
	sum := SHA256(verdict.Packet)
	parts := (len(verdict.Packet) + resolvedChunkSize - 1) / resolvedChunkSize
	var frames [][]byte
	for i := 0; i < parts; i++ {
		end := (i + 1) * resolvedChunkSize
		if end > len(verdict.Packet) {
			end = len(verdict.Packet)
		}
		f := DNSSECFrame{1, capture, sequence, kind, verdict.State, verdict.RCode, verdict.HaveData, verdict.NXDomain, verdict.TTL, sum, uint32(i), uint32(parts), bytes.Clone(verdict.Packet[i*resolvedChunkSize : end])}
		if !f.valid() {
			return nil, errors.New("DNSSEC frame lost original bounded metadata")
		}
		raw, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		frames = append(frames, raw)
	}
	return frames, nil
}
func DecodeDNSSECFrames(frames [][]byte, capture string, sequence uint32, kind string) (DNSSECVerdict, error) {
	var out DNSSECVerdict
	if len(frames) == 0 || len(frames) > 8 {
		return out, errors.New("DNSSEC message omitted bounded original frames")
	}
	var first DNSSECFrame
	for i, raw := range frames {
		f, err := DecodeDNSSECFrame(raw)
		if err != nil {
			return out, err
		}
		if f.CaptureSHA256 != capture || f.Sequence != sequence || f.Kind != kind || f.Part != uint32(i) || f.Parts != uint32(len(frames)) {
			return out, errors.New("DNSSEC message changed capture, sequence or frame ordering")
		}
		if i == 0 {
			first = f
		} else if f.SHA256 != first.SHA256 || f.State != first.State || f.RCode != first.RCode || f.HaveData != first.HaveData || f.NXDomain != first.NXDomain || f.TTL != first.TTL {
			return out, errors.New("DNSSEC message changed whole verdict metadata")
		}
		if i+1 < len(frames) && len(f.Data) != resolvedChunkSize {
			return out, errors.New("DNSSEC message omitted complete original chunk")
		}
		out.Packet = append(out.Packet, f.Data...)
	}
	if len(out.Packet) < 12 || len(out.Packet) > MaxDNSSECPacket || SHA256(out.Packet) != first.SHA256 {
		return DNSSECVerdict{}, errors.New("DNSSEC message lost whole original packet")
	}
	out.State, out.RCode, out.HaveData, out.NXDomain, out.TTL = first.State, first.RCode, first.HaveData, first.NXDomain, first.TTL
	return out, nil
}

// DNSSECReceipt keeps the child alive until the parent has observed every
// terminal frame under its unchanged authenticated process proof.
type DNSSECReceipt struct {
	CaptureSHA256 string `json:"capture_sha256"`
	Sequence      uint32 `json:"sequence"`
	FramesSHA256  string `json:"frames_sha256"`
}

func DNSSECTerminalReceipt(capture string, sequence uint32, frames [][]byte) ([]byte, error) {
	if _, err := DecodeDNSSECFrames(frames, capture, sequence, "verdict"); err != nil {
		return nil, err
	}
	return json.Marshal(DNSSECReceipt{capture, sequence, SHA256(bytes.Join(frames, nil))})
}
