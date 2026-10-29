//go:build windows && routervpn_windows_physical_composition

package box

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/routervpn/desktoppt"
	"github.com/sagernet/sing-box/routervpn/mobiletor"
	M "github.com/sagernet/sing/common/metadata"
)

// This is prospective bootstrap composition evidence. The actual compiler,
// native Box, interface monitor, generated Windows factory, isolated token,
// Winsock imports, WFP filters, PT dependency capture and selected DNS callback
// execute. The existing harmless TUN fixture prevents changes to CI host routes;
// it is never claimed as a real TUN, Connected proof, or device acceptance.
// The explicitly selected custom resolver is a real external DoH service:
// https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/
// No runtime resolver substitution or response fixture is permitted here.
func TestRouterVPNDesktopTorWindowsPhysicalBootstrapComposition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	created := false
	// Registered before the Box: this independent readback runs after the
	// existing Box fixture has joined its real broker and source cleanup.
	t.Cleanup(func() {
		if !created {
			return
		}
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		state, err := mobiletor.DesktopWindowsCompositionSnapshot(bounded)
		if err != nil || !state.Closed || len(state.Grants) != 0 {
			t.Error("native bootstrap cleanup did not retire its exact kernel owner", err, state)
		}
	})
	f := newDesktopTorBoxCapturedFixture(t, func(profile map[string]any) {
		profile["external"] = map[string]any{"protocol": "tor"}
		profile["kill_switch_policy"] = "on-connect"
		profile["dns_mode"], profile["dns_protocol"] = "custom", "https"
		profile["dns_host"], profile["dns_port"] = "1.1.1.1", 443
		profile["dns_server_name"], profile["dns_path"] = "cloudflare-dns.com", "/dns-query"
	}, nil, routervpndesktoppt.RegisterPhysicalOutbound)
	meta := f.policy.Metadata()
	if meta.TargetOS != "windows" || !f.policy.PhysicalBroker() || meta.KillSwitchPolicy != "on-connect" ||
		meta.DNS.Address != "1.1.1.1" || meta.DNS.Port != 443 || meta.DNS.Transport != "https" || meta.HomeLANAccess {
		t.Fatal("actual Windows compiler lost the selected bootstrap policy", meta)
	}
	// A second valid compiler output with another source/resolver cannot bind
	// the existing Box, even though it is independently supported on Windows.
	var foreignProfile map[string]any
	if err := json.Unmarshal([]byte(f.policy.Profile()), &foreignProfile); err != nil {
		t.Fatal(err)
	}
	foreignProfile["dns_port"] = 444
	raw, err := json.Marshal(foreignProfile)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := mobiletor.NewDesktopBridgePolicy(string(raw), meta.SessionID, desktopTorBoxIsolation, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.box.RouterVPNDesktopTorPreparePhysical(foreign); err == nil {
		t.Fatal("a different compiler source acquired this Box's native factory")
	}
	if err := f.box.RouterVPNDesktopTorPreparePhysical(f.policy); err != nil {
		t.Fatal("exact native factory preparation", err)
	}
	if err := f.box.Start(); err != nil {
		t.Fatal("real native manager/factory initialization", err)
	}
	created = true
	state, err := mobiletor.DesktopWindowsCompositionSnapshot(ctx)
	if err != nil || state.Calls != 1 || state.Closed || len(state.Grants) != 0 || state.Owner.Kind != "windows-isolated-token" ||
		state.Capture.SessionID != meta.SessionID || state.Capture.SourceSHA256 != meta.SourceSHA256 || state.Capture.NetworkID == "" ||
		state.Options.KillSwitchPolicy != "on-connect" || state.Options.IPv6Enabled || len(state.Options.Interfaces) != 1 ||
		len(state.Options.PrivateDestinations) != 0 || len(state.Options.LANPrefixes) != 0 {
		t.Fatal("generated factory did not create its exact empty kernel owner", err, state)
	}
	rawObserver, ok := f.box.service.Get(routervpndesktoppt.NetworkOwnerTag)
	observer, typed := rawObserver.(*routervpndesktoppt.NetworkOwner)
	if !ok || !typed || observer == nil {
		t.Fatal("Box lost its concrete captured network service")
	}
	captured, err := observer.Activate(meta.SessionID, meta.SourceSHA256)
	if err != nil {
		t.Fatal("captured bootstrap network activation", err)
	}
	transport, ok := f.box.dnsTransport.Transport(meta.BootstrapDNSTag)
	if !ok || transport.Type() != C.DNSTypeHTTPS {
		t.Fatal("Box lost its selected native HTTPS transport")
	}
	physical, ok := f.box.outbound.Outbound(mobiletor.DesktopPhysicalOutboundTag)
	if !ok {
		t.Fatal("Box lost its mandatory native physical outbound")
	}
	// Ordinary application-token sockets to the exact selected resolver must
	// fail in the kernel. The successful owned query below disqualifies an
	// unavailable external service/network as a false negative explanation.
	ordinary, ordinaryErr := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp4", "1.1.1.1:443")
	if ordinary != nil {
		_ = ordinary.Close()
	}
	if !errors.Is(ordinaryErr, syscall.Errno(10013)) {
		t.Fatal("ordinary selected-resolver socket was not denied by actual WFP", ordinaryErr)
	}
	uncaptured, uncapturedErr := physical.DialContext(ctx, "tcp", M.ParseSocksaddr("1.1.1.1:443"))
	if uncaptured != nil {
		_ = uncaptured.Close()
	}
	if uncapturedErr == nil {
		t.Fatal("uncaptured context acquired the physical native outbound")
	}
	resolver := option.DomainResolveOptions{Server: meta.BootstrapDNSTag, Strategy: option.DomainStrategy(C.DomainStrategyIPv4Only), DisableCache: true}
	owner, err := routervpndesktoppt.NewPlain(captured, resolver, nil, observer.Current)
	if err != nil {
		t.Fatal("actual native PT resolver/dependency capture", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := owner.Close(bounded); err != nil {
			t.Error("captured PT bootstrap owner did not join", err)
		}
	})
	if err := owner.Start(); err != nil {
		t.Fatal("actual native PT start", err)
	}
	query, stop := context.WithTimeout(owner.Context(), 12*time.Second)
	addresses, queryErr := routervpndesktoppt.DesktopWindowsCompositionResolve(owner, query, "ip4", "example.com")
	stop()
	if queryErr != nil || len(addresses) == 0 {
		t.Fatal("selected bootstrap DNS did not traverse the compiled owned native path", queryErr, addresses)
	}
	for _, address := range addresses {
		if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() {
			t.Fatal("selected real DNS reply was not a usable public IPv4 answer", address)
		}
	}
	state, err = mobiletor.DesktopWindowsCompositionSnapshot(ctx)
	if err != nil || len(state.Grants) == 0 {
		t.Fatal("selected DNS succeeded without independently proved connected WFP sockets", err, state)
	}
	remote := netip.MustParseAddrPort("1.1.1.1:443")
	for _, grant := range state.Grants {
		if grant.Capture != state.Capture || grant.Binding.Owner != state.Owner || grant.Network != "tcp" || grant.Remote != remote ||
			grant.Binding.InterfaceIndex != state.Options.Interfaces[0].Index || grant.Local.Addr() != state.Options.Interfaces[0].Address || grant.Local.Port() == 0 {
			t.Fatal("selected DNS used another identity, family, interface or resolver", grant)
		}
	}
	if !owner.Current() || !observer.Current() {
		t.Fatal("successful selected DNS lost its native lifetime")
	}
	// Replace the exact native resolver owner under the same tag. The old
	// captured callback must reject it before an ordinary/new lookup, even if
	// the original HTTP transport has a pooled live connection.
	if err := f.box.dnsTransport.Remove(meta.BootstrapDNSTag); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range f.options.DNS.Servers {
		if candidate.Tag == meta.BootstrapDNSTag {
			if err := f.box.dnsTransport.Create(f.box.ctx, f.box.logger, candidate.Tag, candidate.Type, candidate.Options); err != nil {
				t.Fatal(err)
			}
		}
	}
	replacement, ok := f.box.dnsTransport.Transport(meta.BootstrapDNSTag)
	if !ok || replacement == transport {
		t.Fatal("resolver replacement fixture did not create a new real native object")
	}
	query, stop = context.WithTimeout(captured, 2*time.Second)
	late, lateErr := routervpndesktoppt.DesktopWindowsCompositionResolve(owner, query, "ip4", "example.net")
	stop()
	if lateErr == nil || len(late) != 0 || owner.Current() {
		t.Fatal("old bootstrap capture accepted a replacement native resolver", lateErr, late)
	}
	observer.InterfaceUpdated(context.Background())
	if observer.Current() || captured.Err() == nil {
		t.Fatal("physical network replacement retained the old native capture")
	}
	if _, err := observer.Activate(meta.SessionID, meta.SourceSHA256); err == nil {
		t.Fatal("retired physical generation could be reactivated")
	}
	if result, err := f.box.RouterVPNDesktopTorCreate(f.policy); result != nil || err == nil {
		t.Fatal("bootstrap fixture or retired capture was mistaken for a proved native TUN/connection")
	}
	t.Log("Prospective exact Windows compiler -> Box/native factory -> isolated token/WFP -> selected real HTTPS DNS passed; ordinary/uncaptured/source/replaced-resolver paths reject. No actual TUN or Connected evidence is claimed.")
}
