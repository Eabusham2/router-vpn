//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
)

type desktopDarwinStateInterface struct {
	Name      string
	Index     int
	Addresses []netip.Addr
}

// Only the tagged kernel fixture sets these to its newly created loopback
// aliases. Shipping code cannot use an argument/environment to change scope.
var desktopDarwinPFTestAddresses []netip.Addr

func desktopDarwinCaptureStateInterfaces() ([]desktopDarwinStateInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var captured []desktopDarwinStateInterface
	addressCount := 0
	for _, iface := range interfaces {
		fixture := desktopDarwinPFTestScope != "" && iface.Name == "lo0"
		if iface.Flags&net.FlagUp == 0 || !fixture && (iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || strings.HasPrefix(iface.Name, "utun") || strings.HasPrefix(iface.Name, "ipsec")) {
			continue
		}
		if desktopDarwinPFTestScope != "" && !fixture {
			continue
		}
		if !desktopDarwinInterfaceName.MatchString(iface.Name) || iface.Index <= 0 {
			return nil, errors.New("Darwin physical state scope has another interface identity")
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		item := desktopDarwinStateInterface{Name: iface.Name, Index: iface.Index}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || !prefix.Addr().IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().Is4In6() {
				return nil, errors.New("Darwin physical interface has an unreadable address")
			}
			value := prefix.Addr().WithZone("")
			if fixture {
				found := false
				for _, owned := range desktopDarwinPFTestAddresses {
					found = found || owned == value
				}
				if !found {
					continue
				}
			}
			item.Addresses = append(item.Addresses, value)
			addressCount++
			if addressCount > 256 {
				return nil, errors.New("Darwin physical state addresses exceed their capture bound")
			}
		}
		if len(item.Addresses) != 0 {
			sort.Slice(item.Addresses, func(i, j int) bool { return item.Addresses[i].Less(item.Addresses[j]) })
			captured = append(captured, item)
		}
	}
	if len(captured) == 0 || len(captured) > 64 {
		return nil, errors.New("Darwin physical state scope is empty or exceeds its bound")
	}
	sort.Slice(captured, func(i, j int) bool { return captured[i].Name < captured[j].Name })
	return captured, nil
}

func desktopDarwinCheckStateInterfaces(captured []desktopDarwinStateInterface) error {
	actual, err := desktopDarwinCaptureStateInterfaces()
	if err != nil || !reflect.DeepEqual(actual, captured) {
		return errors.Join(err, errors.New("Darwin physical state scope changed its interface or address ownership"))
	}
	return nil
}

// PF stores floating states under its all-interface key. An interface-only
// clear therefore cannot prove they are absent. Retire both interface-bound
// states and states using any captured address (including temporary IPv6) in
// either direction. Unrelated tunnel/loopback addresses are never supplied.
func desktopDarwinRetirePhysicalStates(ctx context.Context, captured []desktopDarwinStateInterface) error {
	if err := desktopDarwinCheckStateInterfaces(captured); err != nil {
		return err
	}
	for _, iface := range captured {
		if desktopDarwinPFTestScope == "" {
			if _, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-i", iface.Name, "-F", "states"); err != nil {
				return err
			}
		}
		for _, address := range iface.Addresses {
			any := "::/0"
			if address.Is4() {
				any = "0.0.0.0/0"
			}
			if _, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-k", address.String()); err != nil {
				return err
			}
			if _, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-k", any, "-k", address.String()); err != nil {
				return err
			}
		}
	}
	return desktopDarwinCheckPhysicalStates(ctx, captured)
}

func desktopDarwinStateAddress(field string) (netip.Addr, bool) {
	field = strings.Trim(field, "(){}")
	if endpoint, err := netip.ParseAddrPort(field); err == nil {
		return endpoint.Addr().WithZone(""), true
	}
	// Darwin/BSD pfctl prints an IPv6 port after the address in brackets.
	if index := strings.LastIndexByte(field, '['); index > 0 && strings.HasSuffix(field, "]") {
		field = field[:index]
	}
	address, err := netip.ParseAddr(field)
	return address.WithZone(""), err == nil
}

func desktopDarwinStatesAbsent(raw []byte, captured []desktopDarwinStateInterface) error {
	interfaces := make(map[string]bool)
	addresses := make(map[netip.Addr]bool)
	for _, iface := range captured {
		interfaces[iface.Name] = desktopDarwinPFTestScope == ""
		for _, address := range iface.Addresses {
			addresses[address] = true
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.Contains(line, " -> ") && !strings.Contains(line, " <- ") {
			return errors.New("Darwin PF state readback has an unknown format")
		}
		if interfaces[fields[0]] {
			return errors.New("Darwin PF retains an earlier state on a captured physical interface")
		}
		count := 0
		for _, field := range fields[2:] {
			address, valid := desktopDarwinStateAddress(field)
			if valid {
				count++
				if addresses[address] {
					return errors.New("Darwin PF retains a floating state using a captured physical address")
				}
			}
		}
		if count < 2 {
			return errors.New("Darwin PF state readback omitted its actual address tuple")
		}
	}
	return nil
}

func desktopDarwinCheckPhysicalStates(ctx context.Context, captured []desktopDarwinStateInterface) error {
	if err := desktopDarwinCheckStateInterfaces(captured); err != nil {
		return err
	}
	for _, iface := range captured {
		raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-i", iface.Name, "-v", "-s", "Interfaces")
		fields := strings.Fields(string(raw))
		if err != nil || len(fields) == 0 || strings.TrimSuffix(fields[0], ":") != iface.Name || strings.Contains(strings.ToLower(string(raw)), "skip") {
			return errors.Join(err, errors.New("Darwin physical interface bypasses PF or has no independent filter readback"))
		}
	}
	raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "states")
	if err != nil {
		return err
	}
	return desktopDarwinStatesAbsent(raw, captured)
}
