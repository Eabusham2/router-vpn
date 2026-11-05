//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"strings"
	"testing"
)

// All supported cipher pairs use distinct actual private keys. The additional
// lifecycle cases retain the AES256 pair, never a model entry proof.
var linuxHostTUNExternalSSEntryCases = func() []string {
	var cases []string
	for _, entry := range []string{"128", "256", "chacha"} {
		for _, final := range []string{"128", "256", "chacha"} {
			cases = append(cases, "external-ss"+entry+"ss"+final+"-on-connect")
		}
	}
	for _, action := range []string{"always", "always-off", "public", "cancelled", "source", "entry-source", "replacement", "wrong-entry-public", "wrong-entry-key", "wrong-entry-method", "wrong-key", "wrong-final-method", "dns-failure", "tcp-dns"} {
		cases = append(cases, "external-ss256ss256-"+action)
	}
	return cases
}()

func linuxHostTUNExternalSSEntryCase(scenario string) bool {
	for _, candidate := range linuxHostTUNExternalSSEntryCases {
		if candidate == scenario {
			return true
		}
	}
	return false
}
func linuxHostTUNExternalAnyEntry(scenario string) bool {
	return linuxHostTUNExternalWGEntry(scenario) || linuxHostTUNExternalSSEntryCase(scenario)
}

type linuxExternalTUNSSEntryReceipt struct {
	Method        string `json:"method"`
	Address       string `json:"address"`
	PhysicalTCP   int64  `json:"physical_tcp"`
	PhysicalUDP   int64  `json:"physical_udp"`
	Streams       int64  `json:"streams"`
	Packets       int64  `json:"packets"`
	PublicReplies uint32 `json:"public_replies"`
	AuthTCP       uint32 `json:"auth_tcp"`
	AuthUDP       uint32 `json:"auth_udp"`
}
type linuxExternalTUNSSPair struct {
	entryMethod, entryPassword, finalMethod string
	address                                 netip.AddrPort
}

func linuxHostTUNSSMethod(token string) string {
	switch token {
	case "128":
		return "2022-blake3-aes-128-gcm"
	case "256":
		return "2022-blake3-aes-256-gcm"
	case "chacha":
		return "2022-blake3-chacha20-poly1305"
	}
	return ""
}
func linuxHostTUNSSKey(t *testing.T, method string) string {
	t.Helper()
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	return base64.StdEncoding.EncodeToString(raw)
}
func linuxHostTUNPrepareSSEntryPeer(t *testing.T, peer *linuxExternalTUNPeer, scenario string) {
	t.Helper()
	if !linuxHostTUNExternalSSEntryCase(scenario) {
		return
	}
	token, _, _ := strings.Cut(strings.TrimPrefix(scenario, "external-ss"), "-")
	entry, final, ok := strings.Cut(token, "ss")
	e, f := linuxHostTUNSSMethod(entry), linuxHostTUNSSMethod(final)
	if !ok || e == "" || f == "" {
		t.Fatal("unknown captured SS pair")
	}
	peer.ssEntry = &linuxExternalTUNSSPair{entryMethod: e, entryPassword: linuxHostTUNSSKey(t, e), finalMethod: f}
	peer.password = linuxHostTUNSSKey(t, f)
}
func linuxHostTUNSSEntryRead(t *testing.T, peer *linuxExternalTUNPeer, reply linuxExternalTUNPeerReply) {
	t.Helper()
	if peer.ssEntry == nil {
		if reply.ShadowsocksEntry != nil {
			t.Fatal("ordinary peer acquired unrequested SS entry")
		}
		return
	}
	e := reply.ShadowsocksEntry
	if e == nil || reply.PacketEntry != nil || peer.entry != nil || peer.protocol != "shadowsocks" || e.Method != peer.ssEntry.entryMethod || e.PhysicalTCP < 0 || e.PhysicalUDP < 0 || e.Streams < 0 || e.Packets < 0 {
		t.Fatal("lost independent SS entry receipt")
	}
	address, err := netip.ParseAddrPort(e.Address)
	if err != nil || address.Addr().String() != "11.77.0.2" || address.Port() == 0 || peer.ssEntry.address.IsValid() && peer.ssEntry.address != address || peer.address != netip.MustParseAddrPort("198.51.100.240:8388") {
		t.Fatal("SS entry replaced captured physical/final tuple", err)
	}
	peer.ssEntry.address = address
}
func linuxHostTUNInstallSSEntry(t *testing.T, peer *linuxExternalTUNPeer, scenario string, profile *common.RouterProfile) common.RouterProfile {
	t.Helper()
	s := peer.ssEntry
	action := linuxHostTUNExternalAction(scenario)
	profile.Endpoint = peer.address.Addr().String()
	profile.DNSProtocol = "udp"
	if action == "tcp-dns" {
		profile.DNSProtocol = "tcp"
	}
	profile.External.Shadowsocks.Method = s.finalMethod
	if action == "wrong-key" {
		profile.External.Shadowsocks.Password = linuxHostTUNSSKey(t, s.finalMethod)
	}
	if action == "wrong-final-method" {
		profile.External.Shadowsocks.Method = "2022-blake3-chacha20-poly1305"
	}
	entry := common.RouterProfile{ID: "installed-linux-entry", Name: "Independent captured SS2022 entry", NodeKind: "external", Endpoint: s.address.Addr().String(), StartLayer: common.StartLayerOff, External: &common.ExternalNodeConfig{Protocol: "shadowsocks", ExpectedPublicIP: "203.0.113.77", Shadowsocks: &common.ExternalShadowsocksConfig{Server: s.address.Addr().String(), Port: int(s.address.Port()), Method: s.entryMethod, Password: s.entryPassword}}}
	if action == "wrong-entry-public" {
		entry.External.ExpectedPublicIP = "203.0.113.79"
	}
	if action == "wrong-entry-key" {
		entry.External.Shadowsocks.Password = linuxHostTUNSSKey(t, s.entryMethod)
	}
	if action == "wrong-entry-method" {
		entry.External.Shadowsocks.Method = "2022-blake3-chacha20-poly1305"
	}
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal("SS entry failed original importer", err)
	}
	return entry
}
func linuxHostTUNSSEntryFailure(t *testing.T, peer *linuxExternalTUNPeer, action string, middle linuxExternalTUNResult, observed linuxExternalTUNPeerReply) bool {
	t.Helper()
	if peer.ssEntry == nil {
		return false
	}
	entryFailure := action == "wrong-entry-key" || action == "wrong-entry-method"
	finalFailure := action == "wrong-key" || action == "wrong-final-method"
	if !entryFailure && !finalFailure {
		return false
	}
	if !middle.FailedProof || middle.Proof != nil || observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
		t.Fatal("invalid SS credential reached final inner destination", middle, observed)
	}
	if entryFailure {
		if observed.Connections != 0 || observed.PhysicalUDP != 0 || observed.ShadowsocksEntry == nil || observed.ShadowsocksEntry.AuthTCP == 0 {
			t.Fatal("unauthenticated SS entry reached final sockets", observed)
		}
	} else if observed.PhysicalUDP == 0 || observed.Connections != 0 || observed.AuthFailures == 0 {
		t.Fatal("wrong final SS credential missed actual selected UDP DNS authentication", observed)
	}
	return true
}
func linuxHostTUNSSEntryObserved(t *testing.T, peer *linuxExternalTUNPeer, action string, reply linuxExternalTUNPeerReply) {
	t.Helper()
	if peer.ssEntry == nil {
		return
	}
	e := reply.ShadowsocksEntry
	if e == nil {
		t.Fatal("SS entry observation missing")
	}
	if action == "source" || action == "entry-source" {
		if e.PhysicalTCP != 0 || e.PhysicalUDP != 0 || e.Streams != 0 || e.Packets != 0 || e.PublicReplies != 0 {
			t.Fatal("changed source reached SS entry", reply)
		}
		return
	}
	if action == "wrong-entry-key" || action == "wrong-entry-method" {
		if e.PhysicalTCP == 0 || e.Streams != 0 || e.PhysicalUDP != 0 || e.Packets != 0 || e.PublicReplies != 0 {
			t.Fatal("invalid entry missed real SS authentication", reply)
		}
		return
	}
	if e.PhysicalTCP == 0 || e.Streams == 0 || e.PublicReplies == 0 {
		t.Fatal("SS entry proof bypassed actual independent cipher", reply)
	}
	if action == "wrong-entry-public" {
		if e.PhysicalUDP != 0 || e.Packets != 0 {
			t.Fatal("unproved SS entry reached final datagrams", reply)
		}
		return
	}
	if action == "tcp-dns" {
		if e.PhysicalUDP != 0 || e.Packets != 0 || reply.PhysicalUDP != 0 || reply.Packets != 0 {
			t.Fatal("selected TCP DNS substituted UDP", reply)
		}
	} else if e.PhysicalUDP == 0 || e.Packets == 0 || reply.PhysicalUDP == 0 {
		t.Fatal("selected UDP DNS bypassed one original SS owner", reply)
	}
}
func linuxHostTUNExternalSSAuthority(native *desktopNodeLaunch) error {
	bad := errors.New("Linux SS entry lost exact original TCP/UDP root or independent final policy")
	if native == nil || native.external == nil || !desktopExternalSSEntryOwner(native.external) || !desktopExternalSS2022Profile(native.external.profile) || native.external.physical == nil {
		return bad
	}
	o := native.external
	capture, err := o.physical.Capture()
	if err != nil || capture.EntryID != o.entry.ID || capture.Protocol != "shadowsocks" || capture.StartLayer != "" || len(capture.PhysicalRoots) != 1 || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != mobilemultihop.ExternalFinalTag {
		return bad
	}
	root := capture.PhysicalRoots[0]
	entry := o.entry.External.Shadowsocks
	final := o.profile.External.Shadowsocks
	if root.Type != "shadowsocks" || root.Tag != "external-entry" || len(root.Destinations) != 2 || len(root.Networks) != 2 {
		return bad
	}
	wanted := map[string]bool{"tcp": true, "udp": true}
	for _, dest := range root.Destinations {
		if !wanted[dest.Network] || dest.Host != entry.Server || dest.Port != entry.Port {
			return bad
		}
		delete(wanted, dest.Network)
	}
	if len(wanted) != 0 {
		return bad
	}
	var before, after map[string]any
	if json.Unmarshal([]byte(o.physical.OriginalPolicy().Config()), &before) != nil || json.Unmarshal([]byte(o.physical.Config()), &after) != nil {
		return bad
	}
	old, _ := before["outbounds"].([]any)
	current, _ := after["outbounds"].([]any)
	if len(current) != 3 {
		return bad
	}
	e, f := taggedRuntimeItem(current, "external-entry"), taggedRuntimeItem(current, mobilemultihop.ExternalFinalTag)
	if e == nil || f == nil || e["detour"] != mobilemultihop.DesktopExternalPhysicalTag || f["detour"] != "external-entry" || e["server"] != entry.Server || e["server_port"] != float64(entry.Port) || e["method"] != entry.Method || e["password"] != entry.Password || f["server"] != final.Server || f["server_port"] != float64(final.Port) || f["method"] != final.Method || f["password"] != final.Password || !reflect.DeepEqual(f, taggedRuntimeItem(old, mobilemultihop.ExternalFinalTag)) {
		return bad
	}
	delete(e, "detour")
	if !reflect.DeepEqual(e, taggedRuntimeItem(old, "external-entry")) {
		return bad
	}
	return nil
}

func TestDesktopLinuxInstalledSSEntryFixtureKeepsCompiledAuthority(t *testing.T) {
	for _, entryToken := range []string{"128", "256", "chacha"} {
		for _, finalToken := range []string{"128", "256", "chacha"} {
			t.Run(entryToken+"-"+finalToken, func(t *testing.T) {
				_, _, launch := desktopSSEntryFixture(t, "always", linuxHostTUNSSMethod(entryToken), linuxHostTUNSSMethod(finalToken), "udp")
				if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
					t.Fatal(err)
				}
				if err := linuxHostTUNExternalSSAuthority(launch); err != nil {
					t.Fatal("actual compiled SS pair lost original authority", err)
				}
				originalEntry, originalFinal := launch.external.entry, launch.external.profile
				for _, fault := range []string{"entry-key", "final-key", "entry-port", "entry-server", "final-server", "layer"} {
					launch.external.entry, launch.external.profile = cloneRouterProfile(originalEntry), cloneRouterProfile(originalFinal)
					switch fault {
					case "entry-key":
						launch.external.entry.External.Shadowsocks.Password = desktopSSEntryKey(linuxHostTUNSSMethod(entryToken), 'z')
					case "final-key":
						launch.external.profile.External.Shadowsocks.Password = desktopSSEntryKey(linuxHostTUNSSMethod(finalToken), 'z')
					case "entry-port":
						launch.external.entry.External.Shadowsocks.Port++
					case "entry-server":
						launch.external.entry.External.Shadowsocks.Server = "192.0.2.99"
					case "final-server":
						launch.external.profile.External.Shadowsocks.Server = "192.0.2.99"
					case "layer":
						launch.external.profile.StartLayer = common.StartLayerAES256GCM
					}
					if linuxHostTUNExternalSSAuthority(launch) == nil {
						t.Fatal("SS witness accepted substituted original source", fault)
					}
				}
				launch.external.entry, launch.external.profile = originalEntry, originalFinal
				if err := linuxHostTUNExternalSSAuthority(launch); err != nil {
					t.Fatal("fault mutated original policy", err)
				}
			})
		}
	}
}

// This case retains the actual public SS pair through Disconnect, then releases
// the same creator through the public protection endpoint. The saved final
// profile and entry remain independently captured throughout the Off write.
func linuxHostTUNSSEntryOff(ctx context.Context, a *app, session *desktopLinuxNodeSession, host *desktopLinuxNodeHost) error {
	if host == nil || host.transaction == nil || desktopExternalPathProfileID(host.launch) != "installed-linux-external" || host.transaction.baselineReleased || host.transaction.baseline.ObserveClosed(ctx) != nil {
		return errors.New("SS Off lost its original closed Always creator")
	}
	if err := linuxHostTUNOffNetwork(ctx, false); err != nil {
		return err
	}
	view, err := linuxHostTUNOffSettings(ctx, a)
	if err != nil || view.EffectivePolicy != "always" || view.ProtectionStatus != "retained" || view.ProtectionProfileID != "installed-linux-external" {
		return errors.Join(err, errors.New("SS Off lost original final profile protection"))
	}
	a.mu.Lock()
	before := cloneRouterProfileStore(a.profiles)
	a.mu.Unlock()
	if len(before.Profiles) != 3 || before.SelectedID != "installed-linux-external" || before.Profiles[1].ID != before.SelectedID || before.Profiles[2].ID != "installed-linux-entry" {
		return errors.New("SS Off lost independently saved original sources")
	}
	expected, err := profileProtectionOffResult(before.Profiles[1])
	if err != nil {
		return err
	}
	before.Profiles[1] = expected
	body := linuxHostTUNOffBody(view)
	reply := httptest.NewRecorder()
	a.profileProtectionSettings(reply, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(body)).WithContext(ctx))
	if reply.Code != http.StatusOK {
		return errors.New("SS original public Off failed")
	}
	if err := session.enter(ctx); err != nil {
		return err
	}
	retained := session.active != nil || session.predecessor != nil || session.off != nil
	session.gate <- struct{}{}
	if retained || !host.transaction.baselineReleased || !host.transaction.closed || !host.transaction.released || mobiletor.ReadDesktopLinuxNodeAbsence(ctx, host.selection.SessionID) != nil {
		return errors.New("SS public Off did not join its original creator and exact native absence")
	}
	raw, err := readPrivateRegular(a.cfg.ProfilesFile, 64<<10)
	var saved common.RouterProfileStore
	if err != nil || json.Unmarshal(raw, &saved) != nil || !reflect.DeepEqual(saved, before) {
		return errors.Join(err, errors.New("SS Off changed independent entry or lost exact final profile persistence"))
	}
	replay := httptest.NewRecorder()
	a.profileProtectionSettings(replay, httptest.NewRequest(http.MethodPost, "/api/profile/protection", bytes.NewReader(body)).WithContext(ctx))
	if replay.Code != http.StatusConflict {
		return errors.New("SS Off replay authorized another source")
	}
	return linuxHostTUNOffNetwork(ctx, true)
}
