//go:build windows

package mobiletor

import (
	"bytes"
	"errors"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"
)

// DesktopWindowsPhysicalDHCPServers captures only the selected physical
// adapter's actual IPv4 lease server. It performs no DNS lookup, route change,
// adapter reconfiguration or fallback to another interface. Static IPv4 has no
// renewal exception; an incomplete DHCP lease is rejected before protection is
// installed. IPv6-only factories do not call this IPv4 API.
// https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersinfo
func DesktopWindowsPhysicalDHCPServers(index uint32) ([]netip.Addr, error) {
	if index == 0 {
		return nil, errors.New("Windows DHCP capture requires its actual physical interface")
	}
	api, err := desktopWFPLoad()
	if err != nil {
		return nil, err
	}
	// The module was loaded from GetSystemDirectoryW, not a search path.
	get, err := api.interfaceLUID.Dll.FindProc("GetAdaptersInfo")
	if err != nil {
		return nil, err
	}
	size := uint32(15 * 1024)
	for attempt := 0; attempt < 3; attempt++ {
		if size < uint32(unsafe.Sizeof(syscall.IpAdapterInfo{})) || size > 1024*1024 {
			return nil, errors.New("Windows DHCP adapter snapshot exceeded its bound")
		}
		buffer := make([]byte, size)
		status, _, _ := get.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
		if status == 111 { // ERROR_BUFFER_OVERFLOW: bounded adapter-list retry.
			continue
		}
		if status != 0 {
			return nil, desktopWFPError("capture selected IPv4 DHCP lease", status)
		}
		result, err := desktopWindowsDHCPFromSnapshot(buffer, index)
		runtime.KeepAlive(buffer)
		return result, err
	}
	return nil, errors.New("Windows DHCP adapter snapshot changed repeatedly")
}

func desktopWindowsDHCPFromSnapshot(buffer []byte, index uint32) ([]netip.Addr, error) {
	if len(buffer) == 0 || len(buffer) > 1024*1024 {
		return nil, errors.New("Windows DHCP snapshot is empty or unbounded")
	}
	base := uintptr(unsafe.Pointer(&buffer[0]))
	inside := func(pointer unsafe.Pointer, size uintptr) bool {
		value := uintptr(pointer)
		return value >= base && size <= uintptr(len(buffer)) && value-base <= uintptr(len(buffer))-size
	}
	seen := make(map[*syscall.IpAdapterInfo]bool)
	for adapter := (*syscall.IpAdapterInfo)(unsafe.Pointer(&buffer[0])); adapter != nil; adapter = adapter.Next {
		if !inside(unsafe.Pointer(adapter), unsafe.Sizeof(*adapter)) || seen[adapter] || len(seen) >= 256 {
			return nil, errors.New("Windows DHCP snapshot contains an invalid adapter chain")
		}
		seen[adapter] = true
		if adapter.Index != index {
			continue
		}
		if adapter.DhcpEnabled == 0 {
			return nil, nil
		}
		if adapter.DhcpEnabled != 1 {
			return nil, errors.New("Windows selected IPv4 adapter has an invalid DHCP state")
		}
		var result []netip.Addr
		servers := make(map[*syscall.IpAddrString]bool)
		for server := &adapter.DhcpServer; server != nil; server = server.Next {
			if !inside(unsafe.Pointer(server), unsafe.Sizeof(*server)) || servers[server] || len(servers) >= 8 {
				return nil, errors.New("Windows DHCP snapshot contains an invalid lease-server chain")
			}
			servers[server] = true
			end := bytes.IndexByte(server.IpAddress.String[:], 0)
			if end <= 0 {
				return nil, errors.New("Windows DHCP lease server is not terminated")
			}
			text := string(server.IpAddress.String[:end])
			address, err := netip.ParseAddr(text)
			if err != nil || address.String() != text {
				return nil, errors.New("Windows DHCP lease server is not a canonical literal")
			}
			result = append(result, address)
		}
		if err := desktopWindowsValidateDHCP(result); err != nil {
			return nil, err
		}
		return result, nil
	}
	return nil, errors.New("Windows selected physical IPv4 interface has no adapter lease snapshot")
}
