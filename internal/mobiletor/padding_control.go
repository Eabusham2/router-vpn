package mobiletor

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	PaddingMinRateKbps = 32
	PaddingMaxRateKbps = 192
	PaddingMinTTL      = 100 * time.Millisecond
	PaddingMaxTTL      = 10 * time.Second
)

// PaddingIdentity names one authenticated native controller generation. It is
// not a VPN proof: hosts must separately own the selected path and DNS before
// starting cover and while renewing its short lifetime.
type PaddingIdentity struct {
	SessionSHA256 string
	SourceSHA256  string
	Generation    uint64
}

type PaddingCapability struct {
	GenerationHighWater uint64
}

// PaddingStatus reports Tor link-cell accounting, not physical delivery or
// remote replies. Queued cells have already advanced the circuit cipher and
// cannot be removed from an otherwise live circuit to manufacture a Stop.
type PaddingStatus struct {
	Identity                   PaddingIdentity
	State, Reason              string
	RateKbps                   int
	Expires                    time.Duration
	QueuedCells, QueuedBytes   uint64
	ChannelCells, ChannelBytes uint64
	DroppedCells, DroppedBytes uint64
	PendingCells               uint64
	LastCircuit                uint32
}

func paddingHex(value string, sizes ...int) bool {
	for _, size := range sizes {
		if len(value) == size {
			decoded, err := hex.DecodeString(value)
			return err == nil && hex.EncodeToString(decoded) == value
		}
	}
	return false
}

func (identity PaddingIdentity) arguments() (string, error) {
	if !paddingHex(identity.SessionSHA256, 64) || !paddingHex(identity.SourceSHA256, 64) || identity.Generation < 1 || identity.Generation > math.MaxInt64 {
		return "", errors.New("native Tor padding requires canonical captured session, source and generation")
	}
	return identity.SessionSHA256 + " " + identity.SourceSHA256 + " " + strconv.FormatUint(identity.Generation, 10), nil
}

func paddingTTL(ttl time.Duration) (string, error) {
	if ttl < PaddingMinTTL || ttl > PaddingMaxTTL || ttl%time.Millisecond != 0 {
		return "", errors.New("native Tor padding proof lifetime must be 100..10000 whole milliseconds")
	}
	return strconv.FormatInt(ttl.Milliseconds(), 10), nil
}

func paddingFields(reply []string, keys ...string) (map[string]string, error) {
	if len(reply) != 1 {
		return nil, errors.New("native Tor padding reply is missing or ambiguous")
	}
	fields := strings.Split(reply[0], " ")
	if len(fields) != len(keys) {
		return nil, errors.New("native Tor padding reply has unexpected fields")
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	result := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found || !allowed[key] || value == "" || result[key] != "" || strings.ContainsAny(value, "\t\r\n=") {
			return nil, errors.New("native Tor padding reply has noncanonical or repeated fields")
		}
		result[key] = value
	}
	return result, nil
}

func paddingNumber(value string, maximum uint64) (uint64, error) {
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number > maximum || strconv.FormatUint(number, 10) != value {
		return 0, errors.New("native Tor padding reply has an invalid counter")
	}
	return number, nil
}

// Retire the stream on any untrusted reply, including a valid Tor 250 frame
// containing malformed capability or status data. Parsing holds the operation
// lock so another command cannot consume that connection before retirement.
func (c *Control) paddingCommand(ctx context.Context, command string, parse func([]string) error) (failure error) {
	if c == nil || ctx == nil {
		return errors.New("native Tor padding requires its live owning controller")
	}
	c.operation.Lock()
	defer c.operation.Unlock()
	defer func() {
		if failure != nil {
			_ = c.Close()
		}
	}()
	values, err := c.command(ctx, command)
	if err != nil {
		return err
	}
	if err := parse(values); err != nil {
		return err
	}
	return ctx.Err()
}

func (c *Control) PaddingInfo(ctx context.Context) (result PaddingCapability, failure error) {
	failure = c.paddingCommand(ctx, "ROUTERVPN_PADDING INFO", func(reply []string) error {
		fields, err := paddingFields(reply, "version", "direction", "min_rate_kbps", "max_rate_kbps", "default_rate_kbps", "max_ttl_ms", "max_pending_cells", "accounting", "generation_highwater", "username_hex_lengths", "password_hex_length")
		if err != nil {
			return err
		}
		for key, expected := range map[string]string{
			"version": "1", "direction": "outgoing", "min_rate_kbps": "32", "max_rate_kbps": "192", "default_rate_kbps": "192",
			"max_ttl_ms": "10000", "max_pending_cells": "1", "accounting": "tor-link-cell", "username_hex_lengths": "32,64", "password_hex_length": "64",
		} {
			if fields[key] != expected {
				return errors.New("native Tor padding capability differs from the captured implementation contract")
			}
		}
		result.GenerationHighWater, err = paddingNumber(fields["generation_highwater"], math.MaxInt64)
		return err
	})
	if failure != nil {
		return PaddingCapability{}, failure
	}
	return result, nil
}

func parsePaddingStatus(reply []string, identity PaddingIdentity, rate int) (PaddingStatus, error) {
	fields, err := paddingFields(reply, "version", "state", "reason", "session", "source", "generation", "rate_kbps", "expires_ms", "queued_cells", "queued_cell_bytes", "channel_cells", "channel_cell_bytes", "dropped_cells", "dropped_cell_bytes", "pending_cells", "last_circuit")
	if err != nil {
		return PaddingStatus{}, err
	}
	if fields["version"] != "1" || fields["session"] != identity.SessionSHA256 || fields["source"] != identity.SourceSHA256 || fields["generation"] != strconv.FormatUint(identity.Generation, 10) || fields["rate_kbps"] != strconv.Itoa(rate) {
		return PaddingStatus{}, errors.New("native Tor padding receipt belongs to another policy or owner")
	}
	numbers := make(map[string]uint64, 9)
	for _, key := range []string{"expires_ms", "queued_cells", "queued_cell_bytes", "channel_cells", "channel_cell_bytes", "dropped_cells", "dropped_cell_bytes", "pending_cells", "last_circuit"} {
		numbers[key], err = paddingNumber(fields[key], math.MaxUint64)
		if err != nil {
			return PaddingStatus{}, err
		}
	}
	if numbers["expires_ms"] > uint64(PaddingMaxTTL.Milliseconds()) || numbers["pending_cells"] > 1 || numbers["last_circuit"] > math.MaxUint32 {
		return PaddingStatus{}, errors.New("native Tor padding receipt exceeds its lifetime or queue bounds")
	}
	for _, pair := range [][2]string{{"queued_cells", "queued_cell_bytes"}, {"channel_cells", "channel_cell_bytes"}, {"dropped_cells", "dropped_cell_bytes"}} {
		cells, bytes := numbers[pair[0]], numbers[pair[1]]
		if cells > math.MaxUint64/514 || bytes < cells*512 || bytes > cells*514 || bytes%2 != 0 {
			return PaddingStatus{}, errors.New("native Tor padding byte accounting is inconsistent")
		}
	}
	queued, channel, dropped, pending := numbers["queued_cells"], numbers["channel_cells"], numbers["dropped_cells"], numbers["pending_cells"]
	queuedBytes, channelBytes, droppedBytes := numbers["queued_cell_bytes"], numbers["channel_cell_bytes"], numbers["dropped_cell_bytes"]
	if channel > queued || dropped > queued-channel || pending != queued-channel-dropped || channelBytes > queuedBytes || droppedBytes > queuedBytes-channelBytes {
		return PaddingStatus{}, errors.New("native Tor padding cell conservation failed")
	}
	pendingBytes := queuedBytes - channelBytes - droppedBytes
	if pendingBytes != 512*pending && pendingBytes != 514*pending {
		return PaddingStatus{}, errors.New("native Tor padding pending-byte conservation failed")
	}
	state, reason := fields["state"], fields["reason"]
	if state == "running" {
		if reason != "active" || numbers["expires_ms"] == 0 {
			return PaddingStatus{}, errors.New("native Tor padding running receipt has no live proof lifetime")
		}
	} else {
		if state != "stopped" && state != "stopping" || state == "stopped" && pending != 0 || state == "stopping" && pending != 1 || numbers["expires_ms"] != 0 {
			return PaddingStatus{}, errors.New("native Tor padding stop receipt is inconsistent")
		}
		switch reason {
		case "owner", "disabled", "expired", "configuration", "shutdown", "send-error", "controller":
		default:
			return PaddingStatus{}, errors.New("native Tor padding retirement reason is invalid")
		}
	}
	if queued != 0 && numbers["last_circuit"] == 0 {
		return PaddingStatus{}, errors.New("native Tor padding circuit accounting is inconsistent")
	}
	return PaddingStatus{Identity: identity, State: state, Reason: reason, RateKbps: rate,
		Expires: time.Duration(numbers["expires_ms"]) * time.Millisecond, QueuedCells: queued, QueuedBytes: queuedBytes,
		ChannelCells: channel, ChannelBytes: channelBytes, DroppedCells: dropped, DroppedBytes: droppedBytes,
		PendingCells: pending, LastCircuit: uint32(numbers["last_circuit"])}, nil
}

func (c *Control) paddingStatus(ctx context.Context, action string, identity PaddingIdentity, rate int, extra string, ttl time.Duration) (result PaddingStatus, failure error) {
	arguments, err := identity.arguments()
	if err != nil {
		return PaddingStatus{}, err
	}
	if rate < PaddingMinRateKbps || rate > PaddingMaxRateKbps {
		return PaddingStatus{}, errors.New("native Tor padding requires its captured 32..192 kbit/s rate")
	}
	command := "ROUTERVPN_PADDING " + action + " " + arguments
	if extra != "" {
		command += " " + extra
	}
	failure = c.paddingCommand(ctx, command, func(reply []string) error {
		result, err = parsePaddingStatus(reply, identity, rate)
		if err == nil && (action == "START" || action == "RENEW") && result.State != "running" {
			err = errors.New("native Tor padding did not retain its proved running owner")
		}
		if err == nil && ttl > 0 && result.Expires > ttl {
			err = errors.New("native Tor padding reply extended the captured proof lifetime")
		}
		if err == nil && action == "STOP" && result.State == "running" {
			err = errors.New("native Tor padding stop did not revoke generation")
		}
		return err
	})
	if failure != nil {
		return PaddingStatus{}, failure
	}
	return result, nil
}

func (c *Control) StartPadding(ctx context.Context, identity PaddingIdentity, rate int, ttl time.Duration, username, password string) (PaddingStatus, error) {
	lifetime, err := paddingTTL(ttl)
	if err != nil {
		return PaddingStatus{}, err
	}
	if !paddingHex(username, 32, 64) || !paddingHex(password, 64) {
		return PaddingStatus{}, errors.New("native Tor padding requires the exact canonical SOCKS isolation credentials")
	}
	return c.paddingStatus(ctx, "START", identity, rate, strconv.Itoa(rate)+" "+lifetime+" "+username+" "+password, ttl)
}

func (c *Control) RenewPadding(ctx context.Context, identity PaddingIdentity, rate int, ttl time.Duration) (PaddingStatus, error) {
	lifetime, err := paddingTTL(ttl)
	if err != nil {
		return PaddingStatus{}, err
	}
	return c.paddingStatus(ctx, "RENEW", identity, rate, lifetime, ttl)
}

func (c *Control) PaddingStatus(ctx context.Context, identity PaddingIdentity, rate int) (PaddingStatus, error) {
	return c.paddingStatus(ctx, "STATUS", identity, rate, "", 0)
}

func (c *Control) StopPadding(ctx context.Context, identity PaddingIdentity, rate int) (PaddingStatus, error) {
	return c.paddingStatus(ctx, "STOP", identity, rate, "", 0)
}
