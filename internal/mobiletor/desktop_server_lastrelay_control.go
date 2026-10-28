package mobiletor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// This bridge accepts only the private last-relay vocabulary, under the lease
// and anchor already captured by open. It is not a general Tor control proxy.
// Native replies are parsed by the same strict Control used locally, then
// serialized without changing their identities, state, expiry or byte counts.
func (h *serverLastRelayHandle) serveControl(ctx context.Context, r serverLastRelayRequest, client net.Conn) error {
	h.mu.Lock()
	if h.controlUsed || !h.ready {
		h.mu.Unlock()
		return errServerLastRelay
	}
	h.controlUsed = true
	anchor, until := h.anchor, h.until
	h.mu.Unlock()
	if err := h.verify(ctx); err != nil {
		return err
	}
	if serverLastRelayWrite(client, serverLastRelayResponse{Request: r, Anchor: &anchor}) != nil || client.SetDeadline(until) != nil {
		return errServerLastRelay
	}
	reader := bufio.NewReaderSize(client, 2048)
	for count := 0; count < 64; count++ {
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) < 2 || len(line) > 2048 || line[len(line)-2] != '\r' {
			return errServerLastRelay
		}
		command := string(line[:len(line)-2])
		clear(line)
		operation, finish := context.WithTimeout(context.Background(), 2*time.Second)
		reply, err := h.command(operation, command)
		finish()
		if err != nil {
			return err
		}
		if _, err := io.WriteString(client, "250 "+reply+"\r\n"); err != nil {
			return errServerLastRelay
		}
	}
	return errServerLastRelay
}

func (h *serverLastRelayHandle) command(ctx context.Context, command string) (string, error) {
	if len(command) > 2046 || strings.ContainsAny(command, "\x00\r\n\t") {
		return "", errServerLastRelay
	}
	parts := strings.Split(command, " ")
	if len(parts) < 2 || parts[0] != "ROUTERVPN_LASTRELAY" {
		return "", errServerLastRelay
	}
	if err := h.lock(ctx); err != nil {
		return "", err
	}
	defer h.unlock()
	if !h.current() {
		return "", errServerLastRelay
	}
	if parts[1] == "INFO" {
		if len(parts) != 2 {
			return "", errServerLastRelay
		}
		capability, err := h.owner.control.LastRelayInfo(ctx)
		if err != nil {
			return "", err
		}
		return "version=1 transport=begindir min_ttl_ms=100 max_ttl_ms=10000 max_response_bytes=8192 generation_highwater=" + strconv.FormatUint(capability.GenerationHighWater, 10), nil
	}
	var identity LastRelayIdentity
	if len(parts) != 6 && len(parts) != 10 {
		return "", errServerLastRelay
	}
	generation, err := lastRelayNumber(parts[4], math.MaxInt64)
	if err != nil {
		return "", err
	}
	identity = LastRelayIdentity{SessionSHA256: parts[2], SourceSHA256: parts[3], Generation: generation, Nonce: parts[len(parts)-1]}
	if _, err := identity.arguments(); err != nil {
		return "", err
	}
	h.mu.Lock()
	anchor, issued, old, until := h.anchor, h.issued, h.identity, h.until
	h.mu.Unlock()
	if identity.SessionSHA256 != anchor.SessionSHA256 || identity.SourceSHA256 != h.request.SourceSHA256 {
		return "", errServerLastRelay
	}
	var status LastRelayStatus
	switch parts[1] {
	case "CAPTURE":
		if len(parts) != 10 || issued || parts[7] != anchor.SOCKSUsername || parts[8] != anchor.SOCKSPassword {
			return "", errServerLastRelay
		}
		ttl, err := lastRelayNumber(parts[5], uint64(LastRelayMaxTTL.Milliseconds()))
		if err != nil {
			return "", err
		}
		stream, err := lastRelayNumber(parts[6], math.MaxInt64)
		if err != nil || stream != anchor.AnchorStream || time.Duration(ttl)*time.Millisecond < LastRelayMinTTL || time.Now().Add(time.Duration(ttl)*time.Millisecond).After(until) {
			return "", errServerLastRelay
		}
		if err := h.verifyLocked(ctx); err != nil {
			return "", err
		}
		// Record before issuing C: a lost response must retain this exact
		// native capability until CLOSE or actual native process join.
		h.mu.Lock()
		h.identity = identity
		h.issued = true
		h.mu.Unlock()
		status, err = h.owner.control.CaptureLastRelay(ctx, identity, time.Duration(ttl)*time.Millisecond, stream, anchor.SOCKSUsername, anchor.SOCKSPassword)
	case "STATUS", "CLOSE":
		if len(parts) != 6 || !issued || identity != old {
			return "", errServerLastRelay
		}
		if parts[1] == "STATUS" {
			status, err = h.owner.control.LastRelayStatus(ctx, identity)
		} else {
			status, err = h.owner.control.CloseLastRelay(ctx, identity)
		}
	default:
		return "", errServerLastRelay
	}
	if err != nil {
		return "", err
	}
	if !h.statusMatches(status) {
		return "", errServerLastRelay
	}
	h.mu.Lock()
	if h.known {
		err = validateLastRelayProgress(h.status, status)
	}
	if err == nil {
		h.status = status
		h.known = true
	}
	h.mu.Unlock()
	if err != nil {
		return "", err
	}
	return serverLastRelayStatusText(status), nil
}

func (h *serverLastRelayHandle) statusMatches(status LastRelayStatus) bool {
	h.mu.Lock()
	identity, anchor := h.identity, h.anchor
	h.mu.Unlock()
	return status.Identity == identity && status.AnchorStream == anchor.AnchorStream && status.Circuit == anchor.Circuit && status.ExitFingerprint == anchor.ExitFingerprint && status.PathSHA256 == anchor.PathSHA256
}

func serverLastRelayStatusText(status LastRelayStatus) string {
	return fmt.Sprintf("version=1 state=%s reason=%s session=%s source=%s generation=%d anchor=%d circuit=%d stream=%d relay_stream=%d end_reason=%d exit=%s path_sha256=%s address=%s port=1 expires_ms=%d request_bytes=%d response_bytes=%d",
		status.State, status.Reason, status.Identity.SessionSHA256, status.Identity.SourceSHA256, status.Identity.Generation, status.AnchorStream, status.Circuit, status.Stream, status.RelayStream, status.EndReason,
		status.ExitFingerprint, status.PathSHA256, status.Address, status.Expires.Milliseconds(), status.RequestBytes, status.ResponseBytes)
}

func (h *serverLastRelayHandle) serveProbe(ctx context.Context, r serverLastRelayRequest, client net.Conn) error {
	h.mu.Lock()
	want, err := lastRelayExpectedAddress(h.identity)
	if err != nil || !h.issued || !h.known || h.status.State != "armed" || h.probeUsed || r.Address != want {
		h.mu.Unlock()
		return errServerLastRelay
	}
	h.probeUsed = true
	anchor := h.anchor
	h.mu.Unlock()
	if err := h.verify(ctx); err != nil {
		return err
	}
	connection, err := h.dial(ctx, r.Address)
	if err != nil || connection == nil {
		return errServerLastRelay
	}
	if serverLastRelayWrite(client, serverLastRelayResponse{Request: r, Anchor: &anchor}) != nil {
		return errServerLastRelay
	}
	return h.pump(client, connection)
}
