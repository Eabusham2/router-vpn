//go:build windows

package mobiletor

import (
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func desktopWindowsNetworkFixture() ([]byte, *syscall.IpAdapterInfo, *syscall.IpAdapterInfo) {
	size := int(unsafe.Sizeof(syscall.IpAdapterInfo{}))
	buffer := make([]byte, size*2)
	first := (*syscall.IpAdapterInfo)(unsafe.Pointer(&buffer[0]))
	second := (*syscall.IpAdapterInfo)(unsafe.Pointer(&buffer[size]))
	first.Index, first.DhcpEnabled, first.Next = 17, 1, second
	second.Index, second.DhcpEnabled = 29, 1
	copy(first.DhcpServer.IpAddress.String[:], "192.168.17.1")
	copy(second.DhcpServer.IpAddress.String[:], "192.168.29.1")
	return buffer, first, second
}

func TestDesktopSocketWindowsNetworkSelectedSnapshot(t *testing.T) {
	buffer, _, selected := desktopWindowsNetworkFixture()
	got, err := desktopWindowsDHCPFromSnapshot(buffer, selected.Index)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("192.168.29.1") {
		t.Fatalf("selected physical adapter lease: %v %v", got, err)
	}
	selected.DhcpEnabled = 0
	selected.DhcpServer = syscall.IpAddrString{}
	got, err = desktopWindowsDHCPFromSnapshot(buffer, selected.Index)
	if err != nil || len(got) != 0 {
		t.Fatalf("static IPv4 must not acquire a renewal exception: %v %v", got, err)
	}
	if _, err := desktopWindowsDHCPFromSnapshot(buffer, 999); err == nil {
		t.Fatal("missing selected interface borrowed another adapter's lease")
	}
	runtime.KeepAlive(buffer)
}

func TestDesktopSocketWindowsNetworkRejectsLeaseSubstitution(t *testing.T) {
	for _, text := range []string{"", "0.0.0.0", "255.255.255.255", "127.0.0.1", "224.0.0.1", "::1", "192.168.029.1", "server.local", "192.168.29.1 \t"} {
		t.Run(text, func(t *testing.T) {
			buffer, _, selected := desktopWindowsNetworkFixture()
			selected.DhcpServer.IpAddress.String = [16]byte{}
			copy(selected.DhcpServer.IpAddress.String[:], text)
			if got, err := desktopWindowsDHCPFromSnapshot(buffer, selected.Index); err == nil {
				t.Fatalf("invalid selected lease admitted %v", got)
			}
			runtime.KeepAlive(buffer)
		})
	}
	t.Run("unterminated", func(t *testing.T) {
		buffer, _, selected := desktopWindowsNetworkFixture()
		for index := range selected.DhcpServer.IpAddress.String {
			selected.DhcpServer.IpAddress.String[index] = '1'
		}
		if _, err := desktopWindowsDHCPFromSnapshot(buffer, selected.Index); err == nil {
			t.Fatal("unterminated lease address was admitted")
		}
		runtime.KeepAlive(buffer)
	})
	t.Run("invalid-state", func(t *testing.T) {
		buffer, _, selected := desktopWindowsNetworkFixture()
		selected.DhcpEnabled = 2
		if _, err := desktopWindowsDHCPFromSnapshot(buffer, selected.Index); err == nil {
			t.Fatal("unknown DHCP state was admitted")
		}
		runtime.KeepAlive(buffer)
	})
}

func TestDesktopSocketWindowsNetworkRejectsMalformedSnapshot(t *testing.T) {
	for _, which := range []string{"adapter-outside", "adapter-cycle", "server-outside", "server-cycle", "short-buffer"} {
		t.Run(which, func(t *testing.T) {
			buffer, first, selected := desktopWindowsNetworkFixture()
			foreignAdapter := new(syscall.IpAdapterInfo)
			foreignServer := new(syscall.IpAddrString)
			index := selected.Index
			switch which {
			case "adapter-outside":
				first.Next = foreignAdapter
			case "adapter-cycle":
				selected.Next, index = first, 999
			case "server-outside":
				selected.DhcpServer.Next = foreignServer
			case "server-cycle":
				selected.DhcpServer.Next = &selected.DhcpServer
			case "short-buffer":
				buffer = buffer[:1]
			}
			if _, err := desktopWindowsDHCPFromSnapshot(buffer, index); err == nil {
				t.Fatal("malformed bounded OS snapshot was admitted")
			}
			runtime.KeepAlive(buffer)
			runtime.KeepAlive(foreignAdapter)
			runtime.KeepAlive(foreignServer)
		})
	}
}

// This read-only kernel case uses the actual selected index; no DNS, DHCP
// request, route or firewall operation is performed by the capture API.
func TestDesktopSocketWindowsNetworkActualAdapter(t *testing.T) {
	if _, err := DesktopWindowsPhysicalDHCPServers(0); err == nil {
		t.Fatal("zero interface identity was admitted")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range interfaces {
		if selected.Flags&net.FlagUp == 0 || selected.Flags&net.FlagLoopback != 0 || selected.Index <= 0 {
			continue
		}
		addresses, err := selected.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() {
				continue
			}
			servers, err := DesktopWindowsPhysicalDHCPServers(uint32(selected.Index))
			if err != nil {
				t.Fatalf("capture actual IPv4 adapter %s/%d: %v", selected.Name, selected.Index, err)
			}
			if err := desktopWindowsValidateDHCP(servers); err != nil {
				t.Fatal(err)
			}
			t.Logf("selected actual adapter %s/%d; %d captured renewal servers", selected.Name, selected.Index, len(servers))
			return
		}
	}
	t.Fatal("Windows native fixture has no active IPv4 adapter for read-only lease capture")
}
