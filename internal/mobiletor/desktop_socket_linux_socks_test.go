//go:build linux

package mobiletor

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func desktopLinuxSOCKSDestinationFixture() (*desktopLinuxGuardian, desktopLinuxSOCKSAssociation) {
	owner := desktopSocketFixturePolicy().owner
	binding := DesktopSocketBinding{Owner: owner, InterfaceName: "captured", InterfaceIndex: 2, LocalAddress: netip.MustParseAddr("192.168.1.10")}
	control := DesktopSocketGrant{Capture: desktopSocketFixtureCapture(), Binding: binding, SocketID: strings.Repeat("1", 32), Network: "tcp",
		Local: netip.MustParseAddrPort("192.168.1.10:40001"), Remote: netip.MustParseAddrPort("192.168.1.20:1080"), Sequence: 1}
	g := &desktopLinuxGuardian{capture: control.Capture, owner: owner, options: DesktopLinuxSocketOptions{PrivateDestinations: []DesktopLinuxSocketDestination{{Network: "tcp", Address: control.Remote}}}}
	return g, desktopLinuxSOCKSAssociation{Control: control, Binding: binding, Remote: netip.MustParseAddrPort("192.168.1.20:40002"), SocketID: strings.Repeat("2", 32)}
}

func TestDesktopLinuxSOCKSDestinationKeepsExactPrivateException(t *testing.T) {
	g, association := desktopLinuxSOCKSDestinationFixture()
	before := append([]DesktopLinuxSocketDestination(nil), g.options.PrivateDestinations...)
	if !g.socksDestination(association) || g.options.permits("udp", association.Remote) {
		t.Fatal("selected private association did not remain distinct from ordinary UDP admission")
	}
	for _, text := range []string{"192.168.1.21:40002", "127.0.0.1:40002", "169.254.1.2:40002", "[fe80::1]:40002", "0.0.0.0:40002", "224.0.0.1:40002", "192.168.1.20:0"} {
		changed := association
		changed.Remote = netip.MustParseAddrPort(text)
		if g.socksDestination(changed) {
			t.Fatal("private association gained another unselected destination", text)
		}
	}
	for _, fault := range []string{"owner", "capture", "id", "network", "sequence", "control-port", "control-address"} {
		changed := association
		switch fault {
		case "owner":
			changed.Binding.Owner.Generation++
		case "capture":
			changed.Control.Capture.NetworkID = strings.Repeat("e", 32)
		case "id":
			changed.SocketID = association.Control.SocketID
		case "network":
			changed.Control.Network = "udp"
		case "sequence":
			changed.Control.Sequence = 0
		case "control-port":
			changed.Control.Remote = netip.AddrPortFrom(changed.Control.Remote.Addr(), 1081)
		case "control-address":
			changed.Control.Remote = netip.MustParseAddrPort("192.168.1.21:1080")
		}
		if g.socksDestination(changed) {
			t.Fatal("association substituted its original private control", fault)
		}
	}
	if !reflect.DeepEqual(before, g.options.PrivateDestinations) || len(g.options.LANPrefixes) != 0 {
		t.Fatal("association mutated original ordinary policy")
	}
	g.options.LANPrefixes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	association.Remote = netip.MustParseAddrPort("192.168.1.21:40002")
	if !g.socksDestination(association) || !g.options.permits("udp", association.Remote) {
		t.Fatal("association erased an already selected ordinary LAN allowance")
	}
}

func TestDesktopLinuxSOCKSPublicRelayRetainsCapturedFamilies(t *testing.T) {
	g, association := desktopLinuxSOCKSDestinationFixture()
	association.Remote = netip.MustParseAddrPort("1.1.1.1:40002")
	if !g.socksDestination(association) {
		t.Fatal("ordinary public relay was rejected")
	}
	association.Remote = netip.MustParseAddrPort("[2606:4700:4700::1111]:40002")
	association.Binding.LocalAddress = netip.MustParseAddr("fd50::1")
	if !g.socksDestination(association) {
		t.Fatal("ordinary public IPv6 relay lost its separate captured UDP family")
	}
	association.Binding.LocalAddress = association.Control.Local.Addr()
	if g.socksDestination(association) {
		t.Fatal("UDP relay inherited a different socket family")
	}
	association.Binding.LocalAddress = netip.MustParseAddr("fd50::1")
	association.Remote = netip.MustParseAddrPort("[fd50::2]:40002")
	if g.socksDestination(association) {
		t.Fatal("public cross-family path manufactured a private relay exception")
	}
}

func TestDesktopLinuxSOCKSNativeTCPStateRejectsClosedControl(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	file, err := client.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd := int(file.Fd())
	if err := desktopLinuxSOCKSEstablished(fd); err != nil {
		t.Fatal("actual original TCP was not established", err)
	}
	actual, err := desktopLinuxSOCKSPeer(fd)
	if err != nil || actual.String() != client.RemoteAddr().String() {
		t.Fatal("actual original TCP peer did not match", err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for desktopLinuxSOCKSEstablished(fd) == nil {
		if !time.Now().Before(deadline) {
			t.Fatal("remote EOF retained established TCP authority")
		}
		time.Sleep(time.Millisecond)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if desktopLinuxSOCKSEstablished(fd) == nil {
		t.Fatal("closed original TCP descriptor retained authority")
	}
	regular, err := os.CreateTemp(t.TempDir(), "foreign")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if desktopLinuxSOCKSEstablished(int(regular.Fd())) == nil {
		t.Fatal("ordinary file became TCP control authority")
	}
}

func TestDesktopLinuxSOCKSKernelExpiryRequiresExactControl(t *testing.T) {
	n, rows, _ := linuxRunningFixture(t)
	control := DesktopSocketGrant{Capture: n.Capture, Binding: DesktopSocketBinding{InterfaceName: "rvpn-test", InterfaceIndex: 7},
		SocketID: fmt.Sprintf("%032x", 1), Network: "tcp", Local: netip.MustParseAddrPort("198.18.0.1:40000"), Remote: netip.MustParseAddrPort("198.18.0.2:8443"), Sequence: 1}
	started := time.Now()
	until, err := n.socksControlExpiry(rows, control, started)
	if err != nil || !until.Equal(started.Add(8*time.Second)) {
		t.Fatal("exact native control expiry was not retained", err)
	}
	for _, fault := range []string{"comment", "future-sequence", "missing", "expired", "extended", "nan", "infinity", "timeout", "elapsed"} {
		changed := desktopLinuxProtectionCopyRows(t, rows)
		entry := linuxRunningFirst(changed)
		observed := started
		switch fault {
		case "comment":
			entry["comment"] = strings.Repeat("f", 32) + ":1"
		case "future-sequence":
			entry["comment"] = control.SocketID + ":2"
		case "missing":
			delete(entry, "expires")
		case "expired":
			entry["expires"] = float64(0)
		case "extended":
			entry["expires"] = float64(10)
		case "nan":
			entry["expires"] = math.NaN()
		case "infinity":
			entry["expires"] = math.Inf(1)
		case "timeout":
			entry["timeout"] = float64(10)
		case "elapsed":
			observed = time.Now().Add(-10 * time.Second)
		}
		if _, err := n.socksControlExpiry(changed, control, observed); err == nil {
			t.Fatal("native association accepted an invalid control expiry", fault)
		}
	}
}

func TestDesktopLinuxSOCKSChildTimeoutCannotOutliveControl(t *testing.T) {
	now := time.Now()
	for _, budget := range []time.Duration{time.Millisecond, time.Second, 2 * time.Second} {
		deadline := now.Add(budget)
		until := now.Add(8*time.Second + 499*time.Millisecond)
		seconds, err := desktopLinuxSOCKSTimeout(now, deadline, until)
		if err != nil || seconds <= 0 || deadline.Add(time.Duration(seconds)*time.Second).After(until) {
			t.Fatal("derived native expiry outlived original control after worst-case installation", err)
		}
	}
	for _, entry := range [][2]time.Time{{now, now.Add(8 * time.Second)}, {now.Add(3 * time.Second), now.Add(8 * time.Second)}, {now.Add(time.Second), now.Add(time.Second)}, {now.Add(time.Second), now.Add(1500 * time.Millisecond)}, {now.Add(time.Second), now.Add(20 * time.Second)}} {
		if _, err := desktopLinuxSOCKSTimeout(now, entry[0], entry[1]); err == nil {
			t.Fatal("unbounded or unusable native association deadline accepted")
		}
	}
}

func TestDesktopLinuxSOCKSControlRetirementRequiresJoinedChild(t *testing.T) {
	g, association := desktopLinuxSOCKSDestinationFixture()
	control := &desktopLinuxOwnedSocket{socksChild: association.SocketID}
	g.sockets = map[string]*desktopLinuxOwnedSocket{association.Control.SocketID: control, association.SocketID: {}}
	g.socks = map[string]desktopLinuxSOCKSAssociation{association.SocketID: association}
	if g.retireSOCKSControl(association.Control.SocketID) == nil || len(g.socks) != 1 {
		t.Fatal("control retired before its original UDP descriptor was joined")
	}
	delete(g.sockets, association.SocketID)
	if err := g.retireSOCKSControl(association.Control.SocketID); err != nil || len(g.socks) != 0 || control.socksChild != association.SocketID {
		t.Fatal("joined child did not release pending ownership or erased original one-use claim", err)
	}
}
