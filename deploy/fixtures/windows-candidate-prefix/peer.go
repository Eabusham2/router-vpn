//go:build windows && routervpn_windows_candidate_prefix_native

package routervpnamnezia

// Only the platform selection differs from the independently encrypted
// Linux/Darwin reference. The original WG/AWG forwarding, proof handlers and
// final TCP/authentication counters remain their byte-identical source.
import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

func desktopWindowsPrefixReferenceAddress() (netip.Addr, error) {
	logger := log.NewNOPFactory().Logger()
	updates, err := tun.NewNetworkUpdateMonitor(logger)
	if err != nil {
		return netip.Addr{}, err
	}
	defer updates.Close()
	monitor, err := tun.NewDefaultInterfaceMonitor(updates, logger, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: control.NewDefaultInterfaceFinder()})
	if err != nil {
		return netip.Addr{}, err
	}
	defer monitor.Close()
	if err := updates.Start(); err != nil {
		return netip.Addr{}, err
	}
	if err := monitor.Start(); err != nil {
		return netip.Addr{}, err
	}
	selected := monitor.DefaultInterface()
	if selected != nil && selected.Flags&net.FlagUp != 0 && selected.Flags&net.FlagLoopback == 0 {
		for _, prefix := range selected.Addresses {
			if prefix.Addr().Is4() && prefix.Addr().IsPrivate() {
				return prefix.Addr(), nil
			}
		}
	}
	return netip.Addr{}, net.InvalidAddrError("prefix reference has no current selected private IPv4")
}

func desktopWindowsPrefixReferenceAddressPair(address, client string) bool {
	if os.Getenv("ROUTERVPN_WINDOWS_PREFIX_REFERENCE") != "1" || address != client {
		return false
	}
	actual, err := desktopWindowsPrefixReferenceAddress()
	return err == nil && actual.String() == address
}

func TestRouterVPNDesktopWindowsPrefixReferenceProcess(t *testing.T) {
	if os.Getenv("ROUTERVPN_WINDOWS_PREFIX_REFERENCE") != "1" || os.Getenv("ROUTERVPN_NODE_CHAIN_REFERENCE_CHILD") != "1" {
		t.Fatal("Windows prefix reference requires its explicit inherited test invocation")
	}
	address, err := desktopWindowsPrefixReferenceAddress()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "physical_address": address.String()}); err != nil {
		t.Fatal(err)
	}
	TestRouterVPNDesktopNodeChainReferenceProcess(t)
}
