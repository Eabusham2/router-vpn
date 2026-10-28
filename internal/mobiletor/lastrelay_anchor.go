package mobiletor

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strconv"
)

// LastRelayAnchorLocator is built from the retained SOCKS TCP socket's actual
// local address and the numeric external destination already selected through
// the captured DNS policy. No resolver, circuit enumeration or guessed stream
// identifier is used by this read-only native discovery request.
type LastRelayAnchorLocator struct {
	SessionSHA256, SourceSHA256  string
	SOCKSUsername, SOCKSPassword string
	Client, Target               netip.AddrPort
}

type LastRelayLocatedAnchor struct {
	SessionSHA256, SourceSHA256 string
	AnchorStream                uint64
	Circuit                     uint32
	ExitFingerprint, PathSHA256 string
	Client, Target              netip.AddrPort
}

func (locator LastRelayAnchorLocator) arguments() (string, error) {
	client, target := locator.Client.Addr(), locator.Target.Addr()
	if !paddingHex(locator.SessionSHA256, 64) || !paddingHex(locator.SourceSHA256, 64) ||
		!paddingHex(locator.SOCKSUsername, 32, 64) || !paddingHex(locator.SOCKSPassword, 64) ||
		!locator.Client.IsValid() || !client.IsLoopback() || client.Is4In6() || client.Zone() != "" || locator.Client.Port() == 0 ||
		!locator.Target.IsValid() || !target.IsGlobalUnicast() || target.IsPrivate() || target.IsLoopback() || target.IsLinkLocalUnicast() || target.Is4In6() || target.Zone() != "" || locator.Target.Port() == 0 {
		return "", errors.New("last-relay anchor discovery requires exact canonical SOCKS and captured public target tuples")
	}
	return locator.SessionSHA256 + " " + locator.SourceSHA256 + " " + locator.SOCKSUsername + " " + locator.SOCKSPassword + " " +
		client.String() + " " + strconv.Itoa(int(locator.Client.Port())) + " " + target.String() + " " + strconv.Itoa(int(locator.Target.Port())), nil
}

func (c *Control) LookupLastRelayAnchor(ctx context.Context, locator LastRelayAnchorLocator) (anchor LastRelayLocatedAnchor, failure error) {
	arguments, err := locator.arguments()
	if err != nil {
		return anchor, err
	}
	failure = c.lastRelayCommand(ctx, "ROUTERVPN_LASTRELAY ANCHOR "+arguments, func(reply []string) error {
		fields, err := lastRelayFields(reply, "version", "session", "source", "anchor", "circuit", "exit", "path_sha256", "client_ip", "client_port", "target_ip", "target_port")
		if err != nil {
			return err
		}
		if fields["version"] != "1" || fields["session"] != locator.SessionSHA256 || fields["source"] != locator.SourceSHA256 ||
			fields["client_ip"] != locator.Client.Addr().String() || fields["client_port"] != strconv.Itoa(int(locator.Client.Port())) ||
			fields["target_ip"] != locator.Target.Addr().String() || fields["target_port"] != strconv.Itoa(int(locator.Target.Port())) ||
			!paddingHex(fields["exit"], 40) || !paddingHex(fields["path_sha256"], 64) {
			return errors.New("last-relay anchor discovery belongs to another retained socket or selected destination")
		}
		stream, err := lastRelayNumber(fields["anchor"], math.MaxInt64)
		if err != nil || stream == 0 {
			return errors.New("last-relay anchor discovery lacks its actual native stream")
		}
		circuit, err := lastRelayNumber(fields["circuit"], math.MaxUint32)
		if err != nil || circuit == 0 {
			return errors.New("last-relay anchor discovery lacks its actual native circuit")
		}
		anchor = LastRelayLocatedAnchor{SessionSHA256: locator.SessionSHA256, SourceSHA256: locator.SourceSHA256, AnchorStream: stream, Circuit: uint32(circuit),
			ExitFingerprint: fields["exit"], PathSHA256: fields["path_sha256"], Client: locator.Client, Target: locator.Target}
		return nil
	})
	if failure != nil {
		return LastRelayLocatedAnchor{}, failure
	}
	return anchor, nil
}
