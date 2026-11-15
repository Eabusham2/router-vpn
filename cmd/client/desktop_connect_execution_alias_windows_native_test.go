//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"syscall"
	"unsafe"
)

type windowsCONNECTAliasSockaddr struct {
	Family uint16
	Data   [26]byte
}

// MIB_UNICASTIPADDRESS_ROW, with the same amd64/arm64 ABI checked by the
// shipping network observer. Only the two fixture addresses are ever changed.
type windowsCONNECTAliasRow struct {
	Address                                                             windowsCONNECTAliasSockaddr
	LUID                                                                uint64
	Index, PrefixOrigin, SuffixOrigin, ValidLifetime, PreferredLifetime uint32
	PrefixLength, SkipAsSource                                          uint8
	DadState, Scope                                                     uint32
	Created                                                             int64
}

type windowsCONNECTNativeAliases struct {
	initialize, create, remove, get, table, free, luid *syscall.LazyProc
}

func newWindowsCONNECTNativeAliases() (*windowsCONNECTNativeAliases, error) {
	if unsafe.Sizeof(windowsCONNECTAliasRow{}) != 80 || unsafe.Offsetof(windowsCONNECTAliasRow{}.LUID) != 32 || unsafe.Offsetof(windowsCONNECTAliasRow{}.PrefixLength) != 60 {
		return nil, errors.New("CONNECT alias adapter has an incompatible native ABI")
	}
	// Resolve the documented system DLL as an absolute path; the fixture must
	// never load an application-local replacement for IP Helper.
	buffer := make([]uint16, 32768)
	size, _, systemErr := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if size == 0 || size >= uintptr(len(buffer)) {
		return nil, errors.Join(systemErr, errors.New("CONNECT alias system directory unavailable"))
	}
	directory := syscall.UTF16ToString(buffer[:size])
	if !filepath.IsAbs(directory) {
		return nil, errors.New("CONNECT alias system directory is not absolute")
	}
	library := syscall.NewLazyDLL(filepath.Join(directory, "iphlpapi.dll"))
	result := &windowsCONNECTNativeAliases{
		initialize: library.NewProc("InitializeUnicastIpAddressEntry"),
		create:     library.NewProc("CreateUnicastIpAddressEntry"),
		remove:     library.NewProc("DeleteUnicastIpAddressEntry"),
		get:        library.NewProc("GetUnicastIpAddressEntry"),
		table:      library.NewProc("GetUnicastIpAddressTable"),
		free:       library.NewProc("FreeMibTable"),
		luid:       library.NewProc("ConvertInterfaceIndexToLuid"),
	}
	for _, proc := range []*syscall.LazyProc{result.initialize, result.create, result.remove, result.get, result.table, result.free, result.luid} {
		if err := proc.Find(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func windowsCONNECTAliasAddress(row windowsCONNECTAliasRow) netip.Addr {
	if row.Address.Family != syscall.AF_INET {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(row.Address.Data[2:6]))
}

func windowsCONNECTAliasRecordFor(row windowsCONNECTAliasRow) windowsCONNECTAliasRecord {
	return windowsCONNECTAliasRecord{windowsCONNECTAliasIdentity{row.Index, row.LUID}, windowsCONNECTAliasAddress(row), row.PrefixLength, row.SkipAsSource == 1, row.Created}
}

func (k *windowsCONNECTNativeAliases) Inventory(ctx context.Context) (windowsCONNECTAliasIdentity, map[netip.Addr]windowsCONNECTAliasRecord, error) {
	var identity windowsCONNECTAliasIdentity
	if ctx == nil || ctx.Err() != nil {
		return identity, nil, errors.New("CONNECT alias inventory requires its original caller")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return identity, nil, err
	}
	for _, iface := range interfaces {
		if iface.Flags&(net.FlagLoopback|net.FlagUp) != net.FlagLoopback|net.FlagUp {
			continue
		}
		if identity.Index != 0 || iface.Index <= 0 {
			return identity, nil, errors.New("CONNECT alias loopback identity is ambiguous")
		}
		identity.Index = uint32(iface.Index)
		status, _, _ := k.luid.Call(uintptr(identity.Index), uintptr(unsafe.Pointer(&identity.LUID)))
		if status != 0 || identity.LUID == 0 {
			return identity, nil, errors.New("CONNECT alias loopback LUID unavailable")
		}
	}
	if identity.Index == 0 {
		return identity, nil, errors.New("CONNECT alias loopback is absent")
	}
	var pointer uintptr
	status, _, _ := k.table.Call(syscall.AF_INET, uintptr(unsafe.Pointer(&pointer)))
	if status != 0 {
		return identity, nil, syscall.Errno(status)
	}
	if pointer == 0 {
		return identity, nil, errors.New("CONNECT alias inventory omitted its native table")
	}
	defer k.free.Call(pointer)
	count := *(*uint32)(unsafe.Pointer(pointer))
	if count > 65536 {
		return identity, nil, errors.New("CONNECT alias inventory exceeds its bounded native table")
	}
	present := make(map[netip.Addr]windowsCONNECTAliasRecord)
	for index := uint32(0); index < count; index++ {
		row := *(*windowsCONNECTAliasRow)(unsafe.Pointer(pointer + 8 + uintptr(index)*unsafe.Sizeof(windowsCONNECTAliasRow{})))
		address := windowsCONNECTAliasAddress(row)
		if address != windowsCONNECTAliasAddresses[0] && address != windowsCONNECTAliasAddresses[1] {
			continue
		}
		if _, duplicate := present[address]; duplicate {
			return identity, nil, errors.New("CONNECT alias has duplicate native addresses")
		}
		present[address] = windowsCONNECTAliasRecordFor(row)
	}
	return identity, present, ctx.Err()
}

func (k *windowsCONNECTNativeAliases) row(identity windowsCONNECTAliasIdentity, address netip.Addr) windowsCONNECTAliasRow {
	var row windowsCONNECTAliasRow
	k.initialize.Call(uintptr(unsafe.Pointer(&row)))
	row.Address.Family = syscall.AF_INET
	bytes := address.As4()
	copy(row.Address.Data[2:6], bytes[:])
	row.Index, row.LUID = identity.Index, identity.LUID
	row.PrefixLength, row.SkipAsSource = 32, 1
	row.PrefixOrigin, row.SuffixOrigin = 1, 1
	return row
}

func (k *windowsCONNECTNativeAliases) Create(ctx context.Context, identity windowsCONNECTAliasIdentity, address netip.Addr) (*windowsCONNECTAliasRecord, error) {
	if ctx == nil || ctx.Err() != nil || identity.Index == 0 || identity.LUID == 0 || address != windowsCONNECTAliasAddresses[0] && address != windowsCONNECTAliasAddresses[1] {
		return nil, errors.New("CONNECT alias creation lost its exact original request")
	}
	row := k.row(identity, address)
	status, _, _ := k.create.Call(uintptr(unsafe.Pointer(&row)))
	if status != 0 {
		// In particular ERROR_OBJECT_ALREADY_EXISTS grants no ownership. The
		// synchronous IP Helper operation failed without creating our entry.
		return nil, syscall.Errno(status)
	}
	partial := windowsCONNECTAliasRecordFor(row)
	status, _, _ = k.get.Call(uintptr(unsafe.Pointer(&row)))
	if status != 0 {
		return &partial, syscall.Errno(status)
	}
	observed := windowsCONNECTAliasRecordFor(row)
	return &observed, ctx.Err()
}

func (k *windowsCONNECTNativeAliases) Delete(ctx context.Context, record windowsCONNECTAliasRecord) error {
	if ctx == nil || ctx.Err() != nil || record.Created <= 0 || record.Bits != 32 || !record.Skip || record.Address != windowsCONNECTAliasAddresses[0] && record.Address != windowsCONNECTAliasAddresses[1] {
		return errors.New("CONNECT alias removal lost its exact original record")
	}
	row := k.row(record.Interface, record.Address)
	status, _, _ := k.get.Call(uintptr(unsafe.Pointer(&row)))
	if status != 0 {
		return syscall.Errno(status)
	}
	if windowsCONNECTAliasRecordFor(row) != record {
		return errors.New("CONNECT alias changed immediately before native removal")
	}
	status, _, _ = k.remove.Call(uintptr(unsafe.Pointer(&row)))
	if status != 0 {
		return syscall.Errno(status)
	}
	return ctx.Err()
}
