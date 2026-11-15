//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

// Exact Windows SDK MIB_UNICASTIPADDRESS_ROW layout on both supported 64-bit
// targets. CreationTimeStamp and InterfaceLuid distinguish an original address
// from a later same-address/interface-index replacement.
// https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
type windowsCONNECTPhysicalAliasRow struct {
	Address                          syscall.RawSockaddrInet6
	InterfaceLuid                    uint64
	InterfaceIndex                   uint32
	PrefixOrigin, SuffixOrigin       uint32
	ValidLifetime, PreferredLifetime uint32
	OnLinkPrefixLength, SkipAsSource uint8
	DadState, ScopeID                uint32
	CreationTimeStamp                syscall.Filetime
}

var _ [80 - unsafe.Sizeof(windowsCONNECTPhysicalAliasRow{})]byte
var _ [unsafe.Sizeof(windowsCONNECTPhysicalAliasRow{}) - 80]byte
var _ [72 - unsafe.Offsetof(windowsCONNECTPhysicalAliasRow{}.CreationTimeStamp)]byte
var _ [unsafe.Offsetof(windowsCONNECTPhysicalAliasRow{}.CreationTimeStamp) - 72]byte

type windowsCONNECTPhysicalAliasAPI struct {
	dll                              *syscall.DLL
	initialize, create, read, remove *syscall.Proc
}

func windowsCONNECTPhysicalAliasSystemAPI() (*windowsCONNECTPhysicalAliasAPI, error) {
	machine, err := windowscontroller.MachineDirectories()
	if err != nil {
		return nil, err
	}
	dll, err := syscall.LoadDLL(filepath.Join(machine.System, "iphlpapi.dll"))
	if err != nil {
		return nil, err
	}
	a := &windowsCONNECTPhysicalAliasAPI{dll: dll}
	for _, item := range []struct {
		name   string
		target **syscall.Proc
	}{
		{"InitializeUnicastIpAddressEntry", &a.initialize}, {"CreateUnicastIpAddressEntry", &a.create},
		{"GetUnicastIpAddressEntry", &a.read}, {"DeleteUnicastIpAddressEntry", &a.remove},
	} {
		*item.target, err = dll.FindProc(item.name)
		if err != nil {
			dll.Release()
			return nil, err
		}
	}
	return a, nil
}

func windowsCONNECTPhysicalAliasCall(proc *syscall.Proc, row *windowsCONNECTPhysicalAliasRow) error {
	code, _, _ := proc.Call(uintptr(unsafe.Pointer(row)))
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func windowsCONNECTPhysicalAliasAddress(row *windowsCONNECTPhysicalAliasRow, address netip.Addr) {
	row.Address = syscall.RawSockaddrInet6{}
	v4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	v4.Family, v4.Addr = syscall.AF_INET, address.As4()
}

func windowsCONNECTPhysicalAliasIP(row windowsCONNECTPhysicalAliasRow) netip.Addr {
	if row.Address.Family != syscall.AF_INET {
		return netip.Addr{}
	}
	v4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	return netip.AddrFrom4(v4.Addr)
}

func (a *windowsCONNECTPhysicalAliasAPI) current(original windowsCONNECTPhysicalAliasRow) (windowsCONNECTPhysicalAliasRow, error) {
	row := windowsCONNECTPhysicalAliasRow{InterfaceLuid: original.InterfaceLuid, InterfaceIndex: original.InterfaceIndex}
	row.Address = original.Address
	err := windowsCONNECTPhysicalAliasCall(a.read, &row)
	return row, err
}

func windowsCONNECTPhysicalAliasSame(original, current windowsCONNECTPhysicalAliasRow) bool {
	return original.InterfaceLuid != 0 && original.InterfaceIndex != 0 &&
		original.CreationTimeStamp != (syscall.Filetime{}) &&
		original.InterfaceLuid == current.InterfaceLuid && original.InterfaceIndex == current.InterfaceIndex &&
		original.Address == current.Address && original.CreationTimeStamp == current.CreationTimeStamp &&
		original.OnLinkPrefixLength == current.OnLinkPrefixLength && original.SkipAsSource == current.SkipAsSource &&
		original.PrefixOrigin == current.PrefixOrigin && original.SuffixOrigin == current.SuffixOrigin
}

type windowsCONNECTExecutionAliases struct {
	mu                         sync.Mutex
	api                        *windowsCONNECTPhysicalAliasAPI
	physical                   windowsCONNECTPhysicalAliasRow
	rows                       [2]windowsCONNECTPhysicalAliasRow
	created, captured, removed [2]bool
	closed                     bool
}

func windowsCONNECTExecutionOwnAliases(ctx context.Context, physical netip.Addr) (*windowsCONNECTExecutionAliases, error) {
	bad := errors.New("Windows execution requires its original physical address and unused private aliases")
	if ctx == nil || ctx.Err() != nil || !physical.Is4() || !physical.IsPrivate() || physical == netip.MustParseAddr("10.78.0.1") || physical == netip.MustParseAddr("10.78.0.2") {
		return nil, bad
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	index := 0
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, err
			}
			ip := prefix.Addr().Unmap()
			if ip == netip.MustParseAddr("10.78.0.1") || ip == netip.MustParseAddr("10.78.0.2") {
				return nil, bad
			}
			if ip == physical {
				if index != 0 || iface.Index <= 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
					return nil, bad
				}
				index = iface.Index
			}
		}
	}
	if index == 0 {
		return nil, bad
	}
	api, err := windowsCONNECTPhysicalAliasSystemAPI()
	if err != nil {
		return nil, err
	}
	owner := &windowsCONNECTExecutionAliases{api: api}
	owner.physical.InterfaceIndex = uint32(index)
	windowsCONNECTPhysicalAliasAddress(&owner.physical, physical)
	owner.physical, err = api.current(owner.physical)
	if err != nil || owner.physical.DadState != 4 || owner.physical.InterfaceLuid == 0 || owner.physical.CreationTimeStamp == (syscall.Filetime{}) {
		return owner, errors.Join(err, bad)
	}
	for i, address := range []string{"10.78.0.1", "10.78.0.2"} {
		if err := ctx.Err(); err != nil {
			return owner, err
		}
		row := &owner.rows[i]
		api.initialize.Call(uintptr(unsafe.Pointer(row)))
		windowsCONNECTPhysicalAliasAddress(row, netip.MustParseAddr(address))
		row.InterfaceIndex, row.InterfaceLuid = owner.physical.InterfaceIndex, owner.physical.InterfaceLuid
		row.PrefixOrigin, row.SuffixOrigin = 1, 1
		row.OnLinkPrefixLength, row.SkipAsSource = 32, 1
		if err := windowsCONNECTPhysicalAliasCall(api.create, row); err != nil {
			return owner, err
		}
		owner.created[i] = true
		// Read the actual kernel creation identity immediately after successful
		// creation, before caller cancellation can authorize cleanup by tuple.
		actual, err := api.current(*row)
		if err != nil || actual.InterfaceLuid != row.InterfaceLuid || actual.InterfaceIndex != row.InterfaceIndex || windowsCONNECTPhysicalAliasIP(actual) != netip.MustParseAddr(address) || actual.CreationTimeStamp == (syscall.Filetime{}) {
			return owner, errors.Join(err, bad)
		}
		owner.rows[i], owner.captured[i] = actual, true
		for actual.DadState == 1 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return owner, ctx.Err()
			case <-timer.C:
			}
			actual, err = api.current(owner.rows[i])
			if err != nil || !windowsCONNECTPhysicalAliasSame(owner.rows[i], actual) {
				return owner, errors.Join(err, bad)
			}
		}
		if actual.DadState != 4 || actual.OnLinkPrefixLength != 32 || actual.SkipAsSource != 1 {
			return owner, bad
		}
	}
	return owner, owner.Current(ctx)
}

func (a *windowsCONNECTExecutionAliases) Current(ctx context.Context) error {
	if a == nil || ctx == nil {
		return errors.New("missing original Windows alias owner")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.closed || a.api == nil {
		return errors.New("original Windows aliases are retired")
	}
	physical, err := a.api.current(a.physical)
	if err != nil || !windowsCONNECTPhysicalAliasSame(a.physical, physical) || physical.DadState != 4 {
		return errors.Join(err, errors.New("original Windows physical address changed"))
	}
	for i, original := range a.rows {
		if !a.created[i] || !a.captured[i] || a.removed[i] {
			return errors.New("original Windows alias is unavailable")
		}
		current, err := a.api.current(original)
		if err != nil || !windowsCONNECTPhysicalAliasSame(original, current) || current.DadState != 4 {
			return errors.Join(err, errors.New("original Windows alias was replaced"))
		}
	}
	return ctx.Err()
}

func (a *windowsCONNECTExecutionAliases) Close(ctx context.Context, join func(context.Context) error) error {
	if a == nil {
		return nil
	}
	if ctx == nil || join == nil {
		return errors.New("Windows alias retirement requires original joined controller and relay")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := join(ctx); err != nil {
		return err
	}
	for i, original := range a.rows {
		if !a.created[i] {
			continue
		}
		if a.removed[i] {
			if _, err := a.api.current(original); !errors.Is(err, syscall.ERROR_NOT_FOUND) {
				return errors.Join(err, errors.New("retired Windows alias tuple was reoccupied"))
			}
			continue
		}
		if !a.captured[i] {
			return errors.New("created Windows alias lacks original kernel creation identity")
		}
		current, err := a.api.current(original)
		if err != nil || !windowsCONNECTPhysicalAliasSame(original, current) {
			return errors.Join(err, errors.New("Windows alias cleanup refuses a replacement"))
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := windowsCONNECTPhysicalAliasCall(a.api.remove, &current); err != nil {
			return err
		}
		a.removed[i] = true
		if _, err := a.api.current(original); !errors.Is(err, syscall.ERROR_NOT_FOUND) {
			return errors.Join(err, errors.New("original Windows alias remained after deletion"))
		}
	}
	if a.api != nil {
		if err := a.api.dll.Release(); err != nil {
			return err
		}
		a.api = nil
	}
	a.closed = true
	return nil
}

// This pure authority test uses the actual Windows row layout/comparator. It
// does not create an address; the fourteen native cases own that kernel proof.
func TestWindowsCONNECTExecutionAliasOriginalCreation(t *testing.T) {
	original := windowsCONNECTPhysicalAliasRow{InterfaceLuid: 11, InterfaceIndex: 7, CreationTimeStamp: syscall.Filetime{LowDateTime: 9, HighDateTime: 1}, OnLinkPrefixLength: 32, SkipAsSource: 1, PrefixOrigin: 1, SuffixOrigin: 1}
	windowsCONNECTPhysicalAliasAddress(&original, netip.MustParseAddr("10.78.0.1"))
	faults := []struct {
		name   string
		change func(*windowsCONNECTPhysicalAliasRow, *windowsCONNECTPhysicalAliasRow)
	}{
		{"original", func(a, b *windowsCONNECTPhysicalAliasRow) {}},
		{"missing-original-luid", func(a, b *windowsCONNECTPhysicalAliasRow) { a.InterfaceLuid = 0; b.InterfaceLuid = 0 }},
		{"missing-original-index", func(a, b *windowsCONNECTPhysicalAliasRow) { a.InterfaceIndex = 0; b.InterfaceIndex = 0 }},
		{"missing-original-created", func(a, b *windowsCONNECTPhysicalAliasRow) {
			a.CreationTimeStamp = syscall.Filetime{}
			b.CreationTimeStamp = syscall.Filetime{}
		}},
		{"foreign-luid", func(a, b *windowsCONNECTPhysicalAliasRow) { b.InterfaceLuid++ }},
		{"foreign-index", func(a, b *windowsCONNECTPhysicalAliasRow) { b.InterfaceIndex++ }},
		{"foreign-address", func(a, b *windowsCONNECTPhysicalAliasRow) {
			windowsCONNECTPhysicalAliasAddress(b, netip.MustParseAddr("10.78.0.2"))
		}},
		{"recreated-address", func(a, b *windowsCONNECTPhysicalAliasRow) { b.CreationTimeStamp.LowDateTime++ }},
		{"changed-prefix", func(a, b *windowsCONNECTPhysicalAliasRow) { b.OnLinkPrefixLength = 24 }},
		{"changed-skip", func(a, b *windowsCONNECTPhysicalAliasRow) { b.SkipAsSource = 0 }},
		{"changed-prefix-origin", func(a, b *windowsCONNECTPhysicalAliasRow) { b.PrefixOrigin++ }},
		{"changed-suffix-origin", func(a, b *windowsCONNECTPhysicalAliasRow) { b.SuffixOrigin++ }},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			a, b := original, original
			fault.change(&a, &b)
			if windowsCONNECTPhysicalAliasSame(a, b) != (fault.name == "original") {
				t.Fatal("alias creation identity substituted original kernel owner", fault.name)
			}
		})
	}
}
