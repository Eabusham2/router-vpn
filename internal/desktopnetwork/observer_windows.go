//go:build windows

package desktopnetwork

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// The Windows IP Helper ABI below is limited to the documented notification
// keys and bounded table rows. Incomplete callback rows are copied immediately;
// no Windows-owned callback pointer escapes its invocation.
type windowsSockaddr struct {
	Family uint16
	Data   [26]byte
}
type windowsPrefix struct {
	Address windowsSockaddr
	Length  uint8
	_       [2]byte
}
type windowsRoute struct {
	LUID                                               uint64
	Index                                              uint32
	Prefix                                             windowsPrefix
	NextHop                                            windowsSockaddr
	SitePrefixLength                                   uint8
	ValidLifetime, PreferredLifetime, Metric, Protocol uint32
	Loopback, Autoconfigure, Publish, Immortal         uint8
	Age, Origin                                        uint32
}
type windowsInterface struct {
	Family                                                                                                                       uint16
	LUID                                                                                                                         uint64
	Index, MaxReassembly                                                                                                         uint32
	Identifier                                                                                                                   uint64
	MinAdvertisement, MaxAdvertisement                                                                                           uint32
	Advertising, Forwarding, WeakSend, WeakReceive, AutoMetric, NeighbourDetect, ManagedAddress, OtherStateful, AdvertiseDefault uint8
	Discovery, DadTransmits, BaseReachable, Retransmit, PathMTU, LinkLocalBehavior, LinkLocalTimeout                             uint32
	Zones                                                                                                                        [16]uint32
	SitePrefix, Metric, MTU                                                                                                      uint32
	Connected, Wake, Neighbour, DiscoverySupport                                                                                 uint8
	Reachable                                                                                                                    uint32
	TransmitOffload, ReceiveOffload, DisableDefault                                                                              uint8
}
type windowsAddress struct {
	Address                                                             windowsSockaddr
	LUID                                                                uint64
	Index, PrefixOrigin, SuffixOrigin, ValidLifetime, PreferredLifetime uint32
	PrefixLength, SkipAsSource                                          uint8
	DadState, Scope                                                     uint32
	Created                                                             int64
}

func windowsNetworkABI() error {
	if unsafe.Sizeof(windowsRoute{}) != 104 || unsafe.Offsetof(windowsRoute{}.NextHop) != 44 || unsafe.Offsetof(windowsRoute{}.Metric) != 84 ||
		unsafe.Sizeof(windowsInterface{}) != 168 || unsafe.Offsetof(windowsInterface{}.Metric) != 148 || unsafe.Offsetof(windowsInterface{}.MTU) != 152 ||
		unsafe.Sizeof(windowsAddress{}) != 80 || unsafe.Offsetof(windowsAddress{}.LUID) != 32 || unsafe.Offsetof(windowsAddress{}.PrefixLength) != 60 {
		return errors.New("Windows network observer has an incompatible native ABI")
	}
	return nil
}

func windowsNetworkLibrary() (*syscall.DLL, error) {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")
	buffer := make([]uint16, 32768)
	n, _, err := proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || n >= uintptr(len(buffer)) {
		return nil, fmt.Errorf("Windows system directory readback failed: %w", err)
	}
	directory := syscall.UTF16ToString(buffer[:n])
	if !filepath.IsAbs(directory) {
		return nil, errors.New("Windows system directory is not an absolute native path")
	}
	return syscall.LoadDLL(filepath.Join(directory, "iphlpapi.dll"))
}

type windowsObserver struct {
	mu         sync.Mutex
	dll        *syscall.DLL
	procedures map[string]*syscall.Proc
	id         uintptr
	handles    [3]syscall.Handle
	closed     bool
	emit       func(Event, error)
}

var windowsObservers = struct {
	sync.Mutex
	next   uintptr
	owners map[uintptr]*windowsObserver
}{owners: make(map[uintptr]*windowsObserver)}
var windowsRouteCallback = syscall.NewCallback(func(context, row, kind uintptr) uintptr { return windowsNetworkCallback(context, row, kind, "route") })
var windowsInterfaceCallback = syscall.NewCallback(func(context, row, kind uintptr) uintptr { return windowsNetworkCallback(context, row, kind, "link") })
var windowsAddressCallback = syscall.NewCallback(func(context, row, kind uintptr) uintptr { return windowsNetworkCallback(context, row, kind, "address") })

func openNativeObserver(emit func(Event, error)) (nativeObserver, error) {
	if err := windowsNetworkABI(); err != nil {
		return nil, err
	}
	dll, err := windowsNetworkLibrary()
	if err != nil {
		return nil, err
	}
	o := &windowsObserver{dll: dll, procedures: make(map[string]*syscall.Proc), emit: emit}
	for _, name := range []string{"NotifyRouteChange2", "NotifyIpInterfaceChange", "NotifyUnicastIpAddressChange", "CancelMibChangeNotify2", "GetIpForwardTable2", "GetIpInterfaceTable", "GetUnicastIpAddressTable", "ConvertInterfaceIndexToLuid", "FreeMibTable"} {
		proc, find := dll.FindProc(name)
		if find != nil {
			cleanup := o.Close()
			if cleanup != nil {
				return o, errors.Join(find, cleanup)
			}
			return nil, find
		}
		o.procedures[name] = proc
	}
	windowsObservers.Lock()
	if windowsObservers.next == ^uintptr(0) {
		windowsObservers.Unlock()
		cleanup := o.Close()
		if cleanup != nil {
			return o, cleanup
		}
		return nil, errors.New("Windows network callback identity exhausted")
	}
	windowsObservers.next++
	o.id = windowsObservers.next
	windowsObservers.owners[o.id] = o
	windowsObservers.Unlock()
	for i, registration := range []struct {
		name     string
		callback uintptr
	}{{"NotifyRouteChange2", windowsRouteCallback}, {"NotifyIpInterfaceChange", windowsInterfaceCallback}, {"NotifyUnicastIpAddressChange", windowsAddressCallback}} {
		result, _, _ := o.procedures[registration.name].Call(0, registration.callback, o.id, 1, uintptr(unsafe.Pointer(&o.handles[i])))
		if result != 0 || o.handles[i] == 0 {
			err := fmt.Errorf("Windows network callback %s registration failed: %d", registration.name, result)
			if cleanup := o.Close(); cleanup != nil {
				return o, errors.Join(err, cleanup)
			}
			return nil, err
		}
	}
	return o, nil
}

func windowsNetworkCallback(id, row, kind uintptr, which string) uintptr {
	windowsObservers.Lock()
	o := windowsObservers.owners[id]
	windowsObservers.Unlock()
	if o == nil {
		return 0
	}
	if kind == 3 {
		if row != 0 {
			o.emit(Event{}, errors.New("Windows initial network notification unexpectedly contained a mutable row"))
		}
		return 0
	}
	if row == 0 || kind > 2 {
		o.emit(Event{}, errors.New("Windows network notification lost its exact row or type"))
		return 0
	}
	e := Event{Kind: which, Partial: true, Action: "change"}
	if kind == 1 {
		e.Action = "add"
	}
	if kind == 2 {
		e.Action = "delete"
	}
	switch which {
	case "route":
		copy := *(*windowsRoute)(unsafe.Pointer(row))
		object, err := windowsRouteObject(copy)
		if err != nil {
			o.emit(Event{}, err)
			return 0
		}
		object.Priority = 0 // Metric is unspecified in a notification row.
		e.Object, e.Index, e.LUID = object, object.Index, object.LUID
	case "link":
		copy := *(*windowsInterface)(unsafe.Pointer(row))
		e.Index, e.LUID = copy.Index, copy.LUID
		if copy.Family != syscall.AF_INET && copy.Family != syscall.AF_INET6 {
			o.emit(Event{}, errors.New("Windows interface event changed its family"))
			return 0
		}
	case "address":
		copy := *(*windowsAddress)(unsafe.Pointer(row))
		address, err := copy.Address.addr()
		if err != nil {
			o.emit(Event{}, err)
			return 0
		}
		e.Index, e.LUID, e.Address = copy.Index, copy.LUID, address.String()
	}
	if e.Index == 0 || e.LUID == 0 {
		o.emit(Event{}, errors.New("Windows network event has no exact interface identity"))
		return 0
	}
	o.emit(e, nil)
	return 0
}

func (s windowsSockaddr) addr() (netip.Addr, error) {
	switch s.Family {
	case syscall.AF_INET:
		return netip.AddrFrom4([4]byte(s.Data[2:6])), nil
	case syscall.AF_INET6:
		return netip.AddrFrom16([16]byte(s.Data[6:22])), nil
	default:
		return netip.Addr{}, errors.New("Windows network address changed its native family")
	}
}

func windowsRouteObject(row windowsRoute) (DesktopNetworkObject, error) {
	address, err := row.Prefix.Address.addr()
	if err != nil {
		return DesktopNetworkObject{}, err
	}
	gateway, err := row.NextHop.addr()
	if err != nil || gateway.Is4() != address.Is4() {
		return DesktopNetworkObject{}, errors.New("Windows route next hop differs from its native family")
	}
	if int(row.Prefix.Length) > address.BitLen() {
		return DesktopNetworkObject{}, errors.New("Windows route prefix exceeds its native family")
	}
	family := 6
	if address.Is4() {
		family = 4
	}
	o := DesktopNetworkObject{Kind: "route", Family: family, Index: row.Index, LUID: row.LUID, Destination: netip.PrefixFrom(address, int(row.Prefix.Length)).Masked().String(), Priority: row.Metric}
	if !gateway.IsUnspecified() {
		o.Gateway = gateway.String()
	}
	if err := o.Validate("windows"); err != nil {
		return DesktopNetworkObject{}, err
	}
	return o, nil
}

func (o *windowsObserver) table(name string) (uintptr, uint32, error) {
	var pointer uintptr
	result, _, _ := o.procedures[name].Call(0, uintptr(unsafe.Pointer(&pointer)))
	if result != 0 || pointer == 0 {
		return 0, 0, fmt.Errorf("Windows native table %s failed: %d", name, result)
	}
	count := *(*uint32)(unsafe.Pointer(pointer))
	if count > 32768 {
		o.procedures["FreeMibTable"].Call(pointer)
		return 0, 0, errors.New("Windows network table exceeded its bounded inventory")
	}
	return pointer, count, nil
}

func (o *windowsObserver) Snapshot(ctx context.Context) (Snapshot, error) {
	var snapshot Snapshot
	if ctx == nil || ctx.Err() != nil {
		return snapshot, errors.New("Windows network snapshot lost its caller")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.dll == nil {
		return snapshot, errors.New("Windows network snapshot lost its original observer")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return snapshot, err
	}
	for _, iface := range interfaces {
		var luid uint64
		result, _, _ := o.procedures["ConvertInterfaceIndexToLuid"].Call(uintptr(iface.Index), uintptr(unsafe.Pointer(&luid)))
		if result != 0 || luid == 0 {
			return snapshot, errors.New("Windows network snapshot lost a captured interface LUID")
		}
		snapshot.Links = append(snapshot.Links, Link{Index: uint32(iface.Index), LUID: luid, Name: iface.Name, MTU: iface.MTU, Flags: uint32(iface.Flags), Hardware: iface.HardwareAddr.String()})
	}
	ipInterfaces := make(map[uint32][]desktopWindowsIPInterfaceShape)
	for _, name := range []string{"GetIpForwardTable2", "GetUnicastIpAddressTable", "GetIpInterfaceTable"} {
		pointer, count, err := o.table(name)
		if err != nil {
			return snapshot, err
		}
		func() {
			defer o.procedures["FreeMibTable"].Call(pointer)
			for i := uint32(0); i < count; i++ {
				switch name {
				case "GetIpForwardTable2":
					row := *(*windowsRoute)(unsafe.Pointer(pointer + 8 + uintptr(i)*unsafe.Sizeof(windowsRoute{})))
					object, parse := windowsRouteObject(row)
					if parse != nil {
						err = parse
						return
					}
					snapshot.Objects = append(snapshot.Objects, object)
				case "GetUnicastIpAddressTable":
					row := *(*windowsAddress)(unsafe.Pointer(pointer + 8 + uintptr(i)*unsafe.Sizeof(windowsAddress{})))
					address, parse := row.Address.addr()
					if parse != nil || int(row.PrefixLength) > address.BitLen() {
						err = errors.New("Windows unicast table has no complete native prefix")
						return
					}
					snapshot.Addresses = append(snapshot.Addresses, Address{Index: row.Index, LUID: row.LUID, Prefix: netip.PrefixFrom(address, int(row.PrefixLength)).String()})
				case "GetIpInterfaceTable":
					row := *(*windowsInterface)(unsafe.Pointer(pointer + 8 + uintptr(i)*unsafe.Sizeof(windowsInterface{})))
					matched := false
					for n := range snapshot.Links {
						link := &snapshot.Links[n]
						if link.Index == row.Index && link.LUID == row.LUID {
							link.Policy += fmt.Sprintf("%d:%d:%d:%d:%d;", row.Family, row.Metric, row.MTU, row.Connected, row.DisableDefault)
							ipInterfaces[row.Index] = append(ipInterfaces[row.Index], desktopWindowsIPInterfaceShape{Family: row.Family, Index: row.Index, LUID: row.LUID, MTU: row.MTU})
							matched = true
						}
					}
					if !matched {
						err = errors.New("Windows IP interface table contains an unobserved identity")
						return
					}
				}
			}
		}()
		if err != nil {
			return snapshot, err
		}
	}
	for i := range snapshot.Links {
		link, err := desktopWindowsLinkMTU(snapshot.Links[i], ipInterfaces[snapshot.Links[i].Index])
		if err != nil {
			return snapshot, err
		}
		snapshot.Links[i] = link
		parts := strings.Split(snapshot.Links[i].Policy, ";")
		sort.Strings(parts)
		snapshot.Links[i].Policy = strings.Join(parts, ";")
	}
	return snapshot, nil
}

func (o *windowsObserver) Barrier(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Windows network observer lost its bounded caller")
	}
	// IP Helper callbacks deliver independent typed changes. There is no native
	// callback flush API. Their latch is checked under the tracker lock after
	// the full current snapshot; cancelling callbacks is reserved for Close.
	return nil
}

func (o *windowsObserver) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	for i, handle := range o.handles {
		if handle == 0 {
			continue
		}
		proc := o.procedures["CancelMibChangeNotify2"]
		if proc == nil {
			return errors.New("Windows network callback lost its original unregister procedure")
		}
		// Callback dispatch never takes o.mu, and the tracker never holds its
		// mutex while calling Close. The API may join an in-flight callback.
		result, _, _ := proc.Call(uintptr(handle))
		if result != 0 {
			return fmt.Errorf("Windows network callback unregister failed: %d", result)
		}
		o.handles[i] = 0
	}
	windowsObservers.Lock()
	if windowsObservers.owners[o.id] == o {
		delete(windowsObservers.owners, o.id)
	}
	windowsObservers.Unlock()
	if o.dll != nil {
		if err := o.dll.Release(); err != nil {
			return err
		}
		o.dll = nil
	}
	o.closed = true
	return nil
}
