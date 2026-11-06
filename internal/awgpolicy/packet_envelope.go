package awgpolicy

import (
	"errors"
	"strconv"
)

// PacketEnvelope bounds the complete datagrams carried inside a predecessor
// packet interface. DataOverhead excludes the inner plaintext and its 16-byte
// padding; ControlMax includes handshake, cookie and enabled junk messages.
// These are configuration bounds, never measured PMTU or peer authentication.
type PacketEnvelope struct {
	DataOverhead int
	ControlMax   int
}

// Envelope accepts nil parameters for WireGuard or the complete validated AWG
// parameter set. carrierIPv6 describes the public carrier destination, including
// a Start Layer when present. layerOverhead is its complete bidirectional bound.
func Envelope(parameters map[string]string, carrierIPv6 bool, layerOverhead int) (PacketEnvelope, error) {
	if layerOverhead < 0 || layerOverhead > 2048 {
		return PacketEnvelope{}, errors.New("packet layer envelope outside bound")
	}
	ipUDP := 28
	if carrierIPv6 {
		ipUDP = 48
	}
	padding, control := 0, 148
	if parameters != nil {
		if _, err := ParametersUAPI(parameters); err != nil {
			return PacketEnvelope{}, err
		}
		n := func(key string) int { value, _ := strconv.Atoi(parameters[key]); return value }
		padding = n("s4")
		control = max(148+n("s1"), 92+n("s2"), 64+n("s3"))
		if n("jc") > 0 {
			control = max(control, n("jmax"))
		}
	}
	return PacketEnvelope{DataOverhead: ipUDP + 32 + padding + layerOverhead, ControlMax: ipUDP + control + layerOverhead}, nil
}

// Capacity rejects oversized control packets even when data would fit. The
// returned endpoint cap is rounded down so a padded transport message fits.
// A Fixed request must fit unchanged; Auto may only reduce the requested cap.
func (e PacketEnvelope) Capacity(entryMTU, requested int, fixed bool) (int, error) {
	if entryMTU < 1280 || entryMTU > 9000 || requested < 1280 || requested > 9000 || e.DataOverhead < 60 || e.DataOverhead > 4096 || e.ControlMax < 176 || e.ControlMax > 4096 {
		return 0, errors.New("invalid captured packet capacity")
	}
	if e.ControlMax > entryMTU {
		return 0, errors.New("entry cannot carry captured packet handshake or control envelope")
	}
	limit := (entryMTU - e.DataOverhead) / 16 * 16
	if limit < 1280 || fixed && requested > limit {
		return 0, errors.New("captured nested packet MTU does not fit its entry")
	}
	return min(requested, limit), nil
}
