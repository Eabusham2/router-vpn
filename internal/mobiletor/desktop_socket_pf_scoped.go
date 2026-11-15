package mobiletor

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Off retains the original dispatch, but cannot impose a whole-host pass or
// deny. Its exact creator-UID guard lives in the retained slot, independently
// of the mutable generation containing individual tuple permissions.
func desktopPFIsolatedBaseline(session string) string {
	return fmt.Sprintf("anchor \"p%s\" out\n", session)
}

func desktopPFIsolatedPointer(c DesktopSocketCapture, generation string, uid uint32, scope string) string {
	allowed := desktopPFLabel("allowed\x00" + c.SessionID + "\x00" + c.SourceSHA256)
	reset := desktopPFLabel("unproven\x00" + c.SessionID + "\x00" + c.SourceSHA256)
	label := desktopPFLabel("isolated\x00" + c.SessionID + "\x00" + c.SourceSHA256 + "\x00" + c.NetworkID)
	if scope == "" {
		scope = "all"
	}
	lines := []string{}
	for _, network := range []string{"tcp", "udp"} {
		flags := ""
		if network == "tcp" {
			flags = " flags any"
		}
		lines = append(lines, fmt.Sprintf("pass out proto %s %s user %d%s tag \"%s\" no state", network, scope, uid, flags, reset))
	}
	lines = append(lines, fmt.Sprintf("anchor \"/%s\" out all", generation))
	for _, network := range []string{"tcp", "udp"} {
		lines = append(lines, fmt.Sprintf("block drop out quick proto %s %s user %d ! tagged \"%s\" label \"%s\"", network, scope, uid, allowed, label))
	}
	return strings.Join(lines, "\n") + "\n"
}

func desktopPFStateField(field string) (string, error) {
	if strings.HasPrefix(field, "(") && strings.HasSuffix(field, ")") {
		field = field[1 : len(field)-1]
	}
	if field == "" || strings.ContainsAny(field, "()") {
		return "", errors.New("Darwin PF state has an ambiguous translated endpoint")
	}
	return field, nil
}

func desktopPFStateEndpoint(field string) (netip.AddrPort, error) {
	field, fieldErr := desktopPFStateField(field)
	if fieldErr != nil {
		return netip.AddrPort{}, fieldErr
	}
	if endpoint, err := netip.ParseAddrPort(field); err == nil {
		return endpoint, nil
	}
	// Darwin pfctl prints IPv6 ports after the address in brackets.
	if index := strings.LastIndexByte(field, '['); index > 0 && strings.HasSuffix(field, "]") {
		address, addressErr := netip.ParseAddr(field[:index])
		port, portErr := strconv.ParseUint(field[index+1:len(field)-1], 10, 16)
		if addressErr == nil && portErr == nil {
			return netip.AddrPortFrom(address, uint16(port)), nil
		}
	}
	return netip.AddrPort{}, errors.New("Darwin PF state has no exact transport endpoint")
}

// PF looks up states before UID rules and can use endpoint-independent UDP
// keys. Refuse any state containing this pinned local address/port, regardless
// of peer or direction. Unrelated host states are inspected, never flushed.
// The caller must bind and retain this original socket before exposing it.
// XNU pf_test_state_udp tries APD, AD and EI keys before pf_test_rule; the
// lookup key does not include the creator UID. See the pinned native source:
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/net/pf.c
func desktopPFIsolatedStatesAbsent(raw []byte, network string, local netip.AddrPort) error {
	if len(raw) > 2<<20 || network != "tcp" && network != "udp" || !local.IsValid() || local.Port() == 0 || local.Addr().IsUnspecified() || local.Addr().IsMulticast() || local.Addr().Is4In6() || local.Addr().Zone() != "" {
		return errors.New("Darwin isolated state readback lost its exact bound socket")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 6 || !desktopPFFilterInterface.MatchString(fields[0]) {
			return errors.New("Darwin isolated state inventory has an unknown format")
		}
		protocol := fields[1]
		if protocol != "tcp" && protocol != "udp" && protocol != "icmp" && protocol != "icmp6" {
			return errors.New("Darwin isolated state inventory has an unknown protocol")
		}
		endpoints, arrows := 0, 0
		for _, field := range fields[2 : len(fields)-1] {
			if field == "->" || field == "<-" {
				arrows++
				continue
			}
			endpoint, err := desktopPFStateEndpoint(field)
			if err != nil {
				// ICMP state keys can omit a transport port. They cannot match
				// the captured TCP/UDP socket, but still need complete addresses.
				if protocol != "icmp" && protocol != "icmp6" {
					return err
				}
				address, fieldErr := desktopPFStateField(field)
				if fieldErr != nil {
					return fieldErr
				}
				if _, err := netip.ParseAddr(address); err != nil {
					return err
				}
			} else if protocol == network {
				address := endpoint.Addr().Unmap().WithZone("")
				if address.IsUnspecified() || endpoint.Port() == 0 {
					return errors.New("Darwin isolated state inventory has an unresolved wildcard endpoint")
				}
				if address == local.Addr() && endpoint.Port() == local.Port() {
					return errors.New("Darwin PF retains an earlier state matching the original isolated socket")
				}
			}
			endpoints++
		}
		if arrows != 1 || endpoints < 2 || endpoints > 4 || !strings.Contains(fields[len(fields)-1], ":") {
			return errors.New("Darwin isolated state inventory omitted its complete native tuple")
		}
	}
	return nil
}
