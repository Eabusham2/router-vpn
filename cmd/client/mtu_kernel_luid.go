package main

import (
	"fmt"
	"sync"
)

// MIB_IPINTERFACE_ROW from the Windows SDK (netioapi.h). Keep the complete
// row returned by GetIpInterfaceEntry so changing MTU preserves routing,
// forwarding, neighbor-discovery, metrics and the other interface policy.
// https://learn.microsoft.com/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row
type mtuIPInterfaceRow struct {
	Family                  uint16
	LUID                    uint64
	Index                   uint32
	MaxReassemblySize       uint32
	InterfaceIdentifier     uint64
	MinAdvertisement        uint32
	MaxAdvertisement        uint32
	Advertising             uint8
	Forwarding              uint8
	WeakHostSend            uint8
	WeakHostReceive         uint8
	AutomaticMetric         uint8
	NeighborDetection       uint8
	ManagedAddress          uint8
	OtherConfiguration      uint8
	AdvertiseDefaultRoute   uint8
	RouterDiscovery         uint32
	DadTransmits            uint32
	BaseReachableTime       uint32
	RetransmitTime          uint32
	PathMTUTimeout          uint32
	LinkLocalBehavior       uint32
	LinkLocalTimeout        uint32
	ZoneIndices             [16]uint32
	SitePrefixLength        uint32
	Metric                  uint32
	MTU                     uint32
	Connected               uint8
	WakePatterns            uint8
	NeighborDiscovery       uint8
	SupportsRouterDiscovery uint8
	ReachableTime           uint32
	TransmitOffload         uint8
	ReceiveOffload          uint8
	DisableDefaultRoutes    uint8
}

type mtuLUIDIdentity struct {
	LUID  uint64
	GUID  [16]byte
	Index uint32
	Alias string
}

type mtuLUIDCalls struct {
	identity func(uint64) (mtuLUIDIdentity, error)
	read     func(uint64, uint16) (mtuIPInterfaceRow, error)
	write    func(*mtuIPInterfaceRow) error
}

type mtuLUIDKernelOwner struct {
	mu       sync.Mutex
	calls    mtuLUIDCalls
	identity mtuLUIDIdentity
	state    mtuKernelState
	closed   bool
}

func newMTULUIDKernelOwner(live mtuLiveSnapshot, captured mtuLUIDIdentity, calls mtuLUIDCalls) (*mtuLUIDKernelOwner, error) {
	if !validMTUKernelCapture(live) || captured.LUID == 0 || captured.GUID == ([16]byte{}) || captured.Index == 0 || captured.Alias != live.Interface || calls.identity == nil || calls.read == nil || calls.write == nil {
		return nil, errMTUKernelOwner
	}
	owner := &mtuLUIDKernelOwner{calls: calls, identity: captured, state: mtuKernelState{Interface: live.Interface,
		Family: live.Family, Index: int(captured.Index), MTU: live.OriginalMTU,
		Identity: fmt.Sprintf("windows-luid:%016x:%x", captured.LUID, captured.GUID)}}
	current, _, err := owner.readLocked()
	if err != nil || current != owner.state {
		return nil, errMTUKernelOwner
	}
	return owner, nil
}

func (o *mtuLUIDKernelOwner) readLocked() (mtuKernelState, mtuIPInterfaceRow, error) {
	if o.closed {
		return mtuKernelState{}, mtuIPInterfaceRow{}, errMTUKernelOwner
	}
	identity, err := o.calls.identity(o.identity.LUID)
	if err != nil || identity != o.identity {
		return mtuKernelState{}, mtuIPInterfaceRow{}, errMTUKernelOwner
	}
	family := uint16(2)
	if o.state.Family == 6 {
		family = 23
	}
	row, err := o.calls.read(o.identity.LUID, family)
	if err != nil || row.Family != family || row.LUID != o.identity.LUID || row.Index != o.identity.Index || row.MTU < 576 || row.MTU > 9000 {
		return mtuKernelState{}, mtuIPInterfaceRow{}, errMTUKernelOwner
	}
	state := o.state
	state.MTU = int(row.MTU)
	return state, row, nil
}

func (o *mtuLUIDKernelOwner) Read() (mtuKernelState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	state, _, err := o.readLocked()
	return state, err
}

func (o *mtuLUIDKernelOwner) Change(expected mtuKernelState, mtu int) (mtuKernelState, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	before, row, err := o.readLocked()
	if err != nil || before != expected || mtu < 576 || mtu > 9000 {
		return mtuKernelState{}, errMTUKernelOwner
	}
	row.MTU = uint32(mtu)
	// Windows uses nonzero InterfaceLuid before InterfaceIndex. Clear the
	// latter for the write, so a recycled numeric index cannot retarget it.
	row.LUID, row.Index = o.identity.LUID, 0
	if row.Family == 2 {
		row.SitePrefixLength = 0 // Required by SetIpInterfaceEntry for IPv4.
	}
	if err := o.calls.write(&row); err != nil {
		return mtuKernelState{}, fmt.Errorf("change captured Windows interface MTU: %w", err)
	}
	after, _, err := o.readLocked()
	if err != nil || after.MTU != mtu {
		return mtuKernelState{}, errMTUKernelOwner
	}
	return after, nil
}

func (o *mtuLUIDKernelOwner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	return nil
}
