package mobiletor

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	LastRelayMinTTL           = 100 * time.Millisecond
	LastRelayMaxTTL           = 10 * time.Second
	LastRelayMaxResponseBytes = 8192
	lastRelayRequest          = "GET /tor/robots.txt HTTP/1.0\r\n\r\n"
	lastRelayRobots           = "User-agent: *\r\nDisallow: /\r\n"
	lastRelayEndDone          = 6
)

// LastRelayIdentity names one authenticated, one-use native capture. These
// caller fields are not proof of a running path: LastRelayProbe separately
// compares the daemon's receipt with its retained native anchor capture.
type LastRelayIdentity struct {
	SessionSHA256, SourceSHA256 string
	Generation                  uint64
	Nonce                       string
}

type LastRelayCapability struct {
	GenerationHighWater uint64
}

// LastRelayStatus contains native identities and byte counts, never a latency
// or a success score. A real response and the captured path must be verified
// independently before any measurement can be retained.
type LastRelayStatus struct {
	Identity                    LastRelayIdentity
	State, Reason               string
	AnchorStream, Stream        uint64
	Circuit                     uint32
	RelayStream                 uint16
	ExitFingerprint             string
	PathSHA256, Address         string
	Expires                     time.Duration
	RequestBytes, ResponseBytes uint32
	EndReason                   uint8
}

func (identity LastRelayIdentity) arguments() (string, error) {
	if !paddingHex(identity.SessionSHA256, 64) || !paddingHex(identity.SourceSHA256, 64) ||
		identity.Generation < 1 || identity.Generation > math.MaxInt64 || !paddingHex(identity.Nonce, 64) {
		return "", errors.New("last-relay probe requires canonical captured source, session, generation and nonce")
	}
	return identity.SessionSHA256 + " " + identity.SourceSHA256 + " " + strconv.FormatUint(identity.Generation, 10), nil
}

func (identity LastRelayIdentity) address() string {
	return strconv.FormatUint(identity.Generation, 10) + "." + identity.Nonce[:32] + "." + identity.Nonce[32:] + ".lastrelay.routervpn.invalid"
}

func lastRelayFields(reply []string, keys ...string) (map[string]string, error) {
	fields, err := paddingFields(reply, keys...)
	if err != nil {
		return nil, errors.New("last-relay control receipt has missing, repeated or noncanonical fields")
	}
	return fields, nil
}

func lastRelayNumber(value string, maximum uint64) (uint64, error) {
	n, err := paddingNumber(value, maximum)
	if err != nil {
		return 0, errors.New("last-relay control receipt has an invalid counter or identity")
	}
	return n, nil
}

// Parsing remains under the same operation lock as the framed command. A bad
// receipt retires only this captured controller, before another operation can
// consume an unread or ambiguous reply.
func (c *Control) lastRelayCommand(ctx context.Context, command string, parse func([]string) error) (failure error) {
	if c == nil || c.conn == nil || ctx == nil {
		return errors.New("last-relay probe requires its authenticated native controller")
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

func (c *Control) LastRelayInfo(ctx context.Context) (capability LastRelayCapability, failure error) {
	failure = c.lastRelayCommand(ctx, "ROUTERVPN_LASTRELAY INFO", func(reply []string) error {
		fields, err := lastRelayFields(reply, "version", "transport", "min_ttl_ms", "max_ttl_ms", "max_response_bytes", "generation_highwater")
		if err != nil {
			return err
		}
		for key, value := range map[string]string{"version": "1", "transport": "begindir", "min_ttl_ms": "100", "max_ttl_ms": "10000", "max_response_bytes": "8192"} {
			if fields[key] != value {
				return errors.New("last-relay native capability differs from its captured protocol")
			}
		}
		capability.GenerationHighWater, err = lastRelayNumber(fields["generation_highwater"], math.MaxInt64)
		return err
	})
	if failure != nil {
		return LastRelayCapability{}, failure
	}
	return capability, nil
}

func parseLastRelayStatus(reply []string, identity LastRelayIdentity) (LastRelayStatus, error) {
	if _, err := identity.arguments(); err != nil {
		return LastRelayStatus{}, err
	}
	fields, err := lastRelayFields(reply, "version", "state", "reason", "session", "source", "generation", "anchor", "circuit", "stream", "relay_stream", "end_reason", "exit", "path_sha256", "address", "port", "expires_ms", "request_bytes", "response_bytes")
	if err != nil {
		return LastRelayStatus{}, err
	}
	if fields["version"] != "1" || fields["session"] != identity.SessionSHA256 || fields["source"] != identity.SourceSHA256 ||
		fields["generation"] != strconv.FormatUint(identity.Generation, 10) || fields["address"] != identity.address() || fields["port"] != "1" ||
		!paddingHex(fields["exit"], 40) || !paddingHex(fields["path_sha256"], 64) {
		return LastRelayStatus{}, errors.New("last-relay native receipt belongs to another captured path or operation")
	}
	numbers := make(map[string]uint64, 8)
	for key, maximum := range map[string]uint64{"anchor": math.MaxInt64, "circuit": math.MaxUint32, "stream": math.MaxInt64, "relay_stream": math.MaxUint16,
		"end_reason": math.MaxUint8, "expires_ms": uint64(LastRelayMaxTTL.Milliseconds()), "request_bytes": uint64(len(lastRelayRequest)), "response_bytes": LastRelayMaxResponseBytes} {
		numbers[key], err = lastRelayNumber(fields[key], maximum)
		if err != nil {
			return LastRelayStatus{}, err
		}
	}
	if numbers["anchor"] == 0 || numbers["circuit"] == 0 || numbers["stream"] != 0 && numbers["stream"] == numbers["anchor"] ||
		(numbers["stream"] == 0) != (numbers["relay_stream"] == 0) ||
		numbers["stream"] == 0 && (numbers["request_bytes"] != 0 || numbers["response_bytes"] != 0 || numbers["end_reason"] != 0) ||
		numbers["response_bytes"] > 0 && numbers["request_bytes"] != uint64(len(lastRelayRequest)) {
		return LastRelayStatus{}, errors.New("last-relay receipt has inconsistent stream ownership or accounting")
	}
	state, reason := fields["state"], fields["reason"]
	switch reason {
	case "captured", "expired-or-path", "attach", "request", "reply-owner", "reply-protocol", "configuration", "owner", "stream", "anchor", "shutdown", "controller", "no-retry", "relay-end":
	default:
		return LastRelayStatus{}, errors.New("last-relay native retirement reason is unknown")
	}
	switch state {
	case "armed":
		if reason != "captured" || numbers["stream"] != 0 || numbers["request_bytes"] != 0 || numbers["response_bytes"] != 0 || numbers["end_reason"] != 0 {
			return LastRelayStatus{}, errors.New("last-relay capture was consumed before its socket was opened")
		}
	case "connecting":
		if reason != "captured" || numbers["stream"] == 0 || numbers["request_bytes"] != 0 || numbers["response_bytes"] != 0 || numbers["end_reason"] != 0 {
			return LastRelayStatus{}, errors.New("last-relay connecting receipt has premature data or an unowned stream")
		}
	case "connected":
		if reason != "captured" || numbers["stream"] == 0 || numbers["end_reason"] != 0 {
			return LastRelayStatus{}, errors.New("last-relay connected receipt lacks its exact live stream")
		}
	case "ended":
		if reason != "relay-end" || numbers["stream"] == 0 || numbers["end_reason"] == 0 {
			return LastRelayStatus{}, errors.New("last-relay ended receipt lacks its actual relay END")
		}
	case "draining", "stopped":
		if reason == "captured" || numbers["expires_ms"] != 0 || state == "draining" && numbers["stream"] == 0 {
			return LastRelayStatus{}, errors.New("last-relay close receipt does not retain its exact retired stream")
		}
	default:
		return LastRelayStatus{}, errors.New("last-relay native state is unknown")
	}
	if state != "stopped" && state != "draining" && numbers["expires_ms"] == 0 {
		return LastRelayStatus{}, errors.New("last-relay live receipt has no remaining captured lifetime")
	}
	return LastRelayStatus{Identity: identity, State: state, Reason: reason, AnchorStream: numbers["anchor"], Circuit: uint32(numbers["circuit"]),
		Stream: numbers["stream"], RelayStream: uint16(numbers["relay_stream"]), EndReason: uint8(numbers["end_reason"]),
		ExitFingerprint: fields["exit"], PathSHA256: fields["path_sha256"], Address: fields["address"],
		Expires: time.Duration(numbers["expires_ms"]) * time.Millisecond, RequestBytes: uint32(numbers["request_bytes"]), ResponseBytes: uint32(numbers["response_bytes"])}, nil
}

func (c *Control) CaptureLastRelay(ctx context.Context, identity LastRelayIdentity, ttl time.Duration, anchor uint64, username, password string) (status LastRelayStatus, failure error) {
	arguments, err := identity.arguments()
	if err != nil {
		return status, err
	}
	if ttl < LastRelayMinTTL || ttl > LastRelayMaxTTL || ttl%time.Millisecond != 0 || anchor < 1 || anchor > math.MaxInt64 ||
		!paddingHex(username, 32, 64) || !paddingHex(password, 64) {
		return status, errors.New("last-relay capture requires its bounded lifetime and exact live SOCKS anchor")
	}
	command := "ROUTERVPN_LASTRELAY CAPTURE " + arguments + " " + strconv.FormatInt(ttl.Milliseconds(), 10) + " " + strconv.FormatUint(anchor, 10) + " " + username + " " + password + " " + identity.Nonce
	failure = c.lastRelayCommand(ctx, command, func(reply []string) error {
		status, err = parseLastRelayStatus(reply, identity)
		if err == nil && (status.State != "armed" || status.AnchorStream != anchor || status.Expires > ttl) {
			err = errors.New("last-relay capture changed its anchor, one-use state or granted lifetime")
		}
		return err
	})
	if failure != nil {
		return LastRelayStatus{}, failure
	}
	return status, nil
}

func (c *Control) lastRelayStatus(ctx context.Context, identity LastRelayIdentity, action string) (status LastRelayStatus, failure error) {
	arguments, err := identity.arguments()
	if err != nil {
		return status, err
	}
	failure = c.lastRelayCommand(ctx, "ROUTERVPN_LASTRELAY "+action+" "+arguments+" "+identity.Nonce, func(reply []string) error {
		status, err = parseLastRelayStatus(reply, identity)
		if err == nil && action == "CLOSE" && status.State != "stopped" && status.State != "draining" {
			err = errors.New("last-relay native close did not revoke its captured capability")
		}
		return err
	})
	if failure != nil {
		return LastRelayStatus{}, failure
	}
	return status, nil
}

func (c *Control) LastRelayStatus(ctx context.Context, identity LastRelayIdentity) (LastRelayStatus, error) {
	return c.lastRelayStatus(ctx, identity, "STATUS")
}

func (c *Control) CloseLastRelay(ctx context.Context, identity LastRelayIdentity) (LastRelayStatus, error) {
	return c.lastRelayStatus(ctx, identity, "CLOSE")
}

func sameLastRelayPath(a, b LastRelayStatus) bool {
	return a.Identity == b.Identity && a.AnchorStream == b.AnchorStream && a.Circuit == b.Circuit &&
		a.ExitFingerprint == b.ExitFingerprint && a.PathSHA256 == b.PathSHA256 && a.Address == b.Address
}

func validateLastRelayProgress(previous, current LastRelayStatus) error {
	if !sameLastRelayPath(previous, current) || previous.Stream != 0 && (previous.Stream != current.Stream || previous.RelayStream != current.RelayStream) ||
		current.RequestBytes < previous.RequestBytes || current.ResponseBytes < previous.ResponseBytes || previous.EndReason != 0 && current.EndReason != previous.EndReason ||
		current.Expires > previous.Expires {
		return errors.New("last-relay receipt regressed or changed its retained source, circuit or stream")
	}
	order := map[string]int{"armed": 0, "connecting": 1, "connected": 2, "ended": 3, "draining": 4, "stopped": 5}
	if order[current.State] < order[previous.State] {
		return errors.New("last-relay receipt revived a retired or completed stream")
	}
	return nil
}

func lastRelayExpectedAddress(identity LastRelayIdentity) (string, error) {
	if _, err := identity.arguments(); err != nil {
		return "", err
	}
	return strings.Join([]string{identity.address(), "1"}, ":"), nil
}
