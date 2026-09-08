package common

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// NewDNSProbeQuery constructs one ordinary IN A/AAAA question with an
// unpredictable transaction ID. It is deliberately not a general DNS encoder.
func NewDNSProbeQuery(qtype uint16) ([]byte, error) {
	if qtype != 1 && qtype != 28 {
		return nil, errors.New("DNS probe requires an A or AAAA question")
	}
	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 0, 0, 1}
	if _, err := rand.Read(query[:2]); err != nil {
		return nil, fmt.Errorf("DNS probe transaction ID: %w", err)
	}
	binary.BigEndian.PutUint16(query[len(query)-4:len(query)-2], qtype)
	return query, nil
}

// ProbeDNSUDP measures a matching, completely framed response from exactly one
// literal IP/port. It never bootstraps through the OS resolver or substitutes
// another upstream. A matching NXDOMAIN/NODATA proves responsiveness, not a
// usable address, DNSSEC authenticity, or selected VPN route enforcement.
func ProbeDNSUDP(parent context.Context, endpoint string, qtype uint16, timeout time.Duration) (time.Duration, error) {
	if parent == nil || timeout <= 0 {
		return 0, errors.New("DNS probe requires a context and positive timeout")
	}
	if err := context.Cause(parent); err != nil {
		return 0, err
	}
	host, portText, err := net.SplitHostPort(endpoint)
	port, portErr := strconv.Atoi(portText)
	if err != nil || net.ParseIP(host) == nil || portErr != nil || port < 1 || port > 65535 {
		return 0, errors.New("DNS probe requires a literal upstream IP and valid port")
	}
	query, err := NewDNSProbeQuery(qtype)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", endpoint)
	if err != nil {
		return 0, err
	}
	// DialContext covers dialing only. Close the owned socket on cancellation
	// so a stopped benchmark cannot keep waiting out another read deadline.
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); _ = conn.Close() })
	defer func() {
		if !stop() {
			<-done
		}
		_ = conn.Close()
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	started := time.Now()
	if _, err := conn.Write(query); err != nil {
		return 0, dnsProbeIOError(ctx, err)
	}
	// A full-size datagram plus a sentinel avoids accepting a valid prefix of
	// a response truncated by a small receive buffer.
	response := make([]byte, 65536)
	n, err := conn.Read(response)
	if err != nil {
		return 0, dnsProbeIOError(ctx, err)
	}
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	if err := ValidateDNSProbeResponse(query, response[:n]); err != nil {
		return 0, err
	}
	return time.Since(started), nil
}

func dnsProbeIOError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return err
}
