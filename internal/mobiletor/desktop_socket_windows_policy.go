//go:build windows

package mobiletor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type DesktopWindowsSocketInterface struct {
	Name    string
	Index   uint32
	Address netip.Addr
}
type DesktopWindowsSocketDestination struct {
	Network string
	Address netip.AddrPort
}
type DesktopWindowsSocketOptions struct {
	Interfaces          []DesktopWindowsSocketInterface
	PrivateDestinations []DesktopWindowsSocketDestination
	LANPrefixes         []netip.Prefix
	DHCP4Servers        []netip.Addr
	KillSwitchPolicy    string
	IPv6Enabled         bool
}

type desktopWindowsPolicyInterface struct {
	DesktopWindowsSocketInterface
	LUID uint64
}
type desktopWindowsPolicyPermit struct {
	request DesktopSocketGrant
	rules   []desktopWFPRule
	expires time.Time
}

// DesktopWindowsSocketPolicy combines a genuinely isolated token/socket source
// with its exact WFP drop baseline and dynamic permit session. The native host
// installs this typed owner; a config flag or printed PID cannot construct it.
type DesktopWindowsSocketPolicy struct {
	capture                     DesktopSocketCapture
	options                     DesktopWindowsSocketOptions
	ctx                         context.Context
	cancel                      context.CancelFunc
	gate                        chan struct{}
	identity                    *DesktopWindowsSocketIdentity
	publicIdentity              atomic.Pointer[DesktopWindowsSocketIdentity]
	publicOwner                 atomic.Pointer[DesktopSocketKernelOwner]
	owner                       DesktopSocketKernelOwner
	interfaces                  []desktopWindowsPolicyInterface
	user                        desktopWFPCondition
	baselineEngine, leaseEngine *desktopWFPEngine
	sublayer                    syscall.GUID
	lockKey                     syscall.GUID
	metadata                    []byte
	lockMetadata                []byte
	baseline                    []desktopWFPRule
	tunnel                      []desktopWFPRule
	tunnelName                  string
	tunnelIndex                 uint32
	tunnelLUID                  uint64
	permits                     map[string]*desktopWindowsPolicyPermit
	bindings                    map[string]DesktopSocketCreation
	fixtureScope                []byte
	installed, locked, closed   bool
	baselineRemovalAttempted    bool
	baselineDone, lockVerify    bool
	recoveryMode                bool
	recoveryArmed               atomic.Bool
	retired                     atomic.Bool
	observed                    atomic.Int64
}

var _ DesktopSocketPolicy = (*DesktopWindowsSocketPolicy)(nil)
var _ DesktopSocketSource = (*DesktopWindowsSocketPolicy)(nil)
var _ DesktopSocketSourceRelease = (*DesktopWindowsSocketPolicy)(nil)

func desktopWindowsValidateOptions(options DesktopWindowsSocketOptions, fixture bool) error {
	if options.KillSwitchPolicy != "on-connect" && options.KillSwitchPolicy != "always" || len(options.Interfaces) < 1 || len(options.Interfaces) > 2 || len(options.PrivateDestinations) > 64 || len(options.LANPrefixes) > 32 {
		return errors.New("Windows physical sockets require a bounded captured strict policy")
	}
	families := make(map[bool]bool)
	for _, item := range options.Interfaces {
		address := item.Address
		if item.Name == "" || len(item.Name) > 64 || strings.ContainsAny(item.Name, "\x00\r\n") || item.Index == 0 || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Is4In6() || address.Zone() != "" || families[address.Is4()] || !fixture && address.IsLoopback() || !options.IPv6Enabled && !address.Is4() {
			return errors.New("Windows physical interface lost its exact family or identity")
		}
		families[address.Is4()] = true
	}
	seen := make(map[DesktopWindowsSocketDestination]bool)
	for _, destination := range options.PrivateDestinations {
		address := destination.Address.Addr()
		if destination.Network != "tcp" && destination.Network != "udp" || !destination.Address.IsValid() || destination.Address.Port() == 0 || address.Is4In6() || address.Zone() != "" || address.IsLoopback() || !address.IsPrivate() || seen[destination] {
			return errors.New("Windows physical private exception is not an exact selected private tuple")
		}
		seen[destination] = true
	}
	if err := desktopWindowsValidateLAN(options.LANPrefixes); err != nil {
		return err
	}
	return desktopWindowsValidateDHCP(options.DHCP4Servers)
}
func desktopWindowsValidateLAN(values []netip.Prefix) error {
	if len(values) > 32 {
		return errors.New("Windows Home LAN prefix count exceeds its bound")
	}
	prefixes := make(map[netip.Prefix]bool)
	for _, prefix := range values {
		address := prefix.Addr()
		if !prefix.IsValid() || prefix != prefix.Masked() || address.Is4In6() || address.Zone() != "" || prefixes[prefix] || !address.IsPrivate() && !address.IsLinkLocalUnicast() {
			return errors.New("Windows Home LAN exception lost its captured private prefix")
		}
		// A shorter mask must not escape the actual private/link-local range.
		last := address
		if address.Is4() {
			raw := address.As4()
			mask := ^uint32(0) >> uint(prefix.Bits())
			binary.BigEndian.PutUint32(raw[:], binary.BigEndian.Uint32(raw[:])|mask)
			last = netip.AddrFrom4(raw)
		} else {
			raw := address.As16()
			for bit := prefix.Bits(); bit < 128; bit++ {
				raw[bit/8] |= byte(1 << uint(7-bit%8))
			}
			last = netip.AddrFrom16(raw)
		}
		if !last.IsPrivate() && !last.IsLinkLocalUnicast() {
			return errors.New("Windows Home LAN prefix escapes private addressing")
		}
		prefixes[prefix] = true
	}
	return nil
}
func desktopWindowsValidateDHCP(values []netip.Addr) error {
	if len(values) > 8 {
		return errors.New("Windows captured DHCP server count exceeds its bound")
	}
	seen := make(map[netip.Addr]bool)
	for _, address := range values {
		if !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address == netip.MustParseAddr("255.255.255.255") || seen[address] {
			return errors.New("Windows DHCP renewal has no captured unicast server")
		}
		seen[address] = true
	}
	return nil
}

func desktopWindowsCheckInterface(item DesktopWindowsSocketInterface, fixture bool) (desktopWindowsPolicyInterface, error) {
	actual, err := net.InterfaceByIndex(int(item.Index))
	if err != nil || actual.Name != item.Name || actual.Flags&net.FlagUp == 0 || !fixture && actual.Flags&net.FlagLoopback != 0 {
		return desktopWindowsPolicyInterface{}, errors.Join(err, errors.New("Windows physical interface changed"))
	}
	addresses, err := actual.Addrs()
	if err != nil {
		return desktopWindowsPolicyInterface{}, err
	}
	found := false
	for _, candidate := range addresses {
		prefix, err := netip.ParsePrefix(candidate.String())
		if err == nil && prefix.Addr() == item.Address {
			found = true
			break
		}
	}
	if !found {
		return desktopWindowsPolicyInterface{}, errors.New("Windows physical source address left its captured interface")
	}
	luid, err := desktopWindowsInterfaceLUID(item.Index)
	if err != nil {
		return desktopWindowsPolicyInterface{}, err
	}
	return desktopWindowsPolicyInterface{item, luid}, nil
}

func desktopWindowsInterfaceLUID(index uint32) (uint64, error) {
	api, err := desktopWFPLoad()
	if err != nil {
		return 0, err
	}
	var luid uint64
	status, _, _ := api.interfaceLUID.Call(uintptr(index), uintptr(unsafe.Pointer(&luid)))
	if status != 0 || luid == 0 {
		return 0, errors.Join(desktopWFPError("capture interface LUID", status), errors.New("Windows interface has no LUID"))
	}
	return luid, nil
}

// Calls retain their gate and all resources until the native operation really
// joins, even if a caller times out. Late results remain in this owned policy
// and are removed by its separately bounded/retryable cleanup.
func desktopWindowsPolicyCall[T any](p *DesktopWindowsSocketPolicy, ctx context.Context, cleanup bool, operation func() (T, error)) (T, error) {
	var zero T
	if p == nil || ctx == nil || ctx.Err() != nil || !cleanup && (p.ctx.Err() != nil || p.retired.Load()) {
		return zero, net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-p.gate:
	}
	type result struct {
		value T
		err   error
	}
	finished := make(chan result, 1)
	go func() {
		defer func() { p.gate <- struct{}{} }()
		value, err := operation()
		finished <- result{value, err}
	}()
	select {
	case value := <-finished:
		return value.value, value.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func NewDesktopWindowsSocketPolicy(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions) (*DesktopWindowsSocketPolicy, error) {
	return newDesktopWindowsSocketPolicy(ctx, capture, options, nil)
}

// fixtureScope is a private executable-test seam. Every test filter receives
// the same additional real executable AppID, and its loopback bypass is absent.
// Production callers have no JSON/environment/exported switch for that scope.
func newDesktopWindowsSocketPolicy(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, fixtureScope []byte) (*DesktopWindowsSocketPolicy, error) {
	p, err := newDesktopWindowsPolicyOwner(ctx, capture, options, fixtureScope)
	if err != nil {
		return nil, err
	}
	_, err = desktopWindowsPolicyCall(p, ctx, false, func() (struct{}, error) { return struct{}{}, p.prepare() })
	if err != nil {
		p.Cancel()
		return p, err
	}
	go p.monitor()
	return p, nil
}

func newDesktopWindowsPolicyOwner(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, fixtureScope []byte) (*DesktopWindowsSocketPolicy, error) {
	if ctx == nil || ctx.Err() != nil || !capture.valid() {
		return nil, errors.New("Windows physical policy requires its captured native lifetime")
	}
	if err := desktopWindowsRequireElevation(); err != nil {
		return nil, err
	}
	if err := desktopWindowsValidateOptions(options, len(fixtureScope) > 0); err != nil {
		return nil, err
	}
	if len(fixtureScope) > 65536 || len(fixtureScope)%2 != 0 {
		return nil, errors.New("Windows fixture scope is malformed")
	}
	options.Interfaces = append([]DesktopWindowsSocketInterface(nil), options.Interfaces...)
	options.PrivateDestinations = append([]DesktopWindowsSocketDestination(nil), options.PrivateDestinations...)
	options.LANPrefixes = append([]netip.Prefix(nil), options.LANPrefixes...)
	options.DHCP4Servers = append([]netip.Addr(nil), options.DHCP4Servers...)
	lifetime, cancel := context.WithCancel(ctx)
	p := &DesktopWindowsSocketPolicy{capture: capture, options: options, ctx: lifetime, cancel: cancel, gate: make(chan struct{}, 1), permits: make(map[string]*desktopWindowsPolicyPermit), bindings: make(map[string]DesktopSocketCreation), fixtureScope: append([]byte(nil), fixtureScope...)}
	p.gate <- struct{}{}
	p.sublayer = desktopWindowsManagedKey("baseline", p.fixtureScope)
	var err error
	p.metadata, err = p.baselineMetadata()
	if err != nil {
		p.Cancel()
		return nil, err
	}
	return p, nil
}

func (p *DesktopWindowsSocketPolicy) rule(label string, family int, incoming bool, weight uint64, permit, persistent bool, conditions ...desktopWFPCondition) desktopWFPRule {
	layer := desktopWFPConnect4
	if family == 6 {
		layer = desktopWFPConnect6
	}
	direction := "out"
	if incoming {
		direction = "in"
		layer = desktopWFPAccept4
		if family == 6 {
			layer = desktopWFPAccept6
		}
	}
	name := fmt.Sprintf("%s-%s-v%d", label, direction, family)
	if len(p.fixtureScope) > 0 {
		conditions = append(conditions, desktopWFPCondition{Field: desktopWFPAppID, Type: 12, Bytes: append([]byte(nil), p.fixtureScope...)})
	}
	return desktopWFPRule{Key: desktopWFPDerivedKey(p.capture, name), Name: name, Layer: layer, Sublayer: p.sublayer, Persistent: persistent, Weight: weight, Permit: permit, Metadata: append(append([]byte(nil), p.metadata...), []byte("|"+name)...), Conditions: conditions}
}
func (p *DesktopWindowsSocketPolicy) pair(label string, family int, weight uint64, permit, persistent bool, conditions ...desktopWFPCondition) []desktopWFPRule {
	return []desktopWFPRule{p.rule(label, family, false, weight, permit, persistent, append([]desktopWFPCondition(nil), conditions...)...), p.rule(label, family, true, weight, permit, persistent, append([]desktopWFPCondition(nil), conditions...)...)}
}
func (p *DesktopWindowsSocketPolicy) compileBaseline() []desktopWFPRule {
	var rules []desktopWFPRule
	for _, family := range []int{4, 6} {
		rules = append(rules, p.pair("deny", family, 1, false, true)...)
		if len(p.fixtureScope) == 0 {
			rules = append(rules, p.pair("loopback", family, 60, true, true, desktopWFPCondition{Field: desktopWFPFlags, Type: 3, Match: 6, Number: 1})...)
		}
	}
	// Exact DHCP/NDP maintenance matches the already tested WFP implementation.
	// The production baseline never grants a destination-wide public exception.
	udp := desktopWFPNumber(desktopWFPProtocol, 1, 17)
	dhcp4 := []desktopWFPCondition{udp, desktopWFPNumber(desktopWFPLocalPort, 2, 68), desktopWFPNumber(desktopWFPRemotePort, 2, 67)}
	rules = append(rules, p.rule("dhcp4-reply", 4, true, 30, true, true, dhcp4...))
	rules = append(rules, p.rule("dhcp4-broadcast", 4, false, 30, true, true, append(dhcp4, desktopWFPAddress(desktopWFPRemoteAddress, netip.MustParseAddr("255.255.255.255")))...))
	for index, server := range p.options.DHCP4Servers {
		rules = append(rules, p.rule(fmt.Sprintf("dhcp4-renewal-%d", index), 4, false, 30, true, true, append(append([]desktopWFPCondition(nil), dhcp4...), desktopWFPAddress(desktopWFPRemoteAddress, server))...))
	}
	for i, prefix := range p.options.LANPrefixes {
		family := 6
		if prefix.Addr().Is4() {
			family = 4
		}
		rules = append(rules, p.pair(fmt.Sprintf("lan-%d", i), family, 40, true, true, desktopWFPPrefix(desktopWFPRemoteAddress, prefix))...)
	}
	for _, prefix := range []string{"ff02::1:2/128", "fe80::/10"} {
		rules = append(rules, p.pair("dhcp6-"+strings.ReplaceAll(prefix, "/", "-"), 6, 30, true, true, udp, desktopWFPNumber(desktopWFPLocalPort, 2, 546), desktopWFPNumber(desktopWFPRemotePort, 2, 547), desktopWFPPrefix(desktopWFPRemoteAddress, netip.MustParsePrefix(prefix)))...)
	}
	for _, kind := range []uint64{133, 134, 135, 136} {
		for i, prefix := range []string{"fe80::/10", "ff02::/16"} {
			rules = append(rules, p.pair(fmt.Sprintf("ndp-%d-%d", kind, i), 6, 30, true, true, desktopWFPNumber(desktopWFPProtocol, 1, 58), desktopWFPNumber(desktopWFPLocalPort, 2, kind), desktopWFPPrefix(desktopWFPRemoteAddress, netip.MustParsePrefix(prefix)))...)
		}
	}
	return rules
}
func (p *DesktopWindowsSocketPolicy) prepare() error {
	if err := p.prepareBaseline(); err != nil {
		return err
	}
	var err error
	p.identity, err = NewDesktopWindowsSocketIdentity(p.ctx, p.capture)
	if p.identity != nil {
		p.publicIdentity.Store(p.identity)
	}
	if err != nil {
		return err
	}
	p.owner, err = p.identity.Owner()
	if err != nil {
		return err
	}
	owner := p.owner
	p.publicOwner.Store(&owner)
	sid, err := p.identity.SID()
	if err != nil {
		return err
	}
	p.user, err = desktopWFPUserCondition(p.baselineEngine.api, sid)
	if err != nil {
		return err
	}
	p.observed.Store(time.Now().UnixMilli())
	return nil
}
func (p *DesktopWindowsSocketPolicy) prepareBaseline() error {
	for _, item := range p.options.Interfaces {
		captured, err := desktopWindowsCheckInterface(item, len(p.fixtureScope) > 0)
		if err != nil {
			return err
		}
		p.interfaces = append(p.interfaces, captured)
	}
	var err error
	if err := p.acquireBaselineLock(); err != nil {
		return err
	}
	p.baselineEngine, err = desktopWFPOpen(false)
	if err != nil {
		return err
	}
	p.baseline = p.compileBaseline()
	return p.replaceBaseline()
}
func (p *DesktopWindowsSocketPolicy) expected() []desktopWFPRule {
	rules := append(append([]desktopWFPRule(nil), p.baseline...), p.tunnel...)
	for _, permit := range p.permits {
		rules = append(rules, permit.rules...)
	}
	return rules
}
func (p *DesktopWindowsSocketPolicy) assertBaseline() error {
	if !p.installed || p.baselineEngine == nil {
		return errors.New("Windows physical drop baseline is not installed")
	}
	if err := p.assertBaselineLock(); err != nil {
		return err
	}
	if err := p.baselineEngine.AssertSublayer(p.sublayer, p.metadata); err != nil {
		return err
	}
	return p.baselineEngine.AssertComplete(p.sublayer, p.expected())
}
func (p *DesktopWindowsSocketPolicy) Owner() (DesktopSocketKernelOwner, error) {
	if p == nil {
		return DesktopSocketKernelOwner{}, net.ErrClosed
	}
	owner := p.publicOwner.Load()
	if owner == nil || !p.Current(p.capture, *owner) {
		return DesktopSocketKernelOwner{}, net.ErrClosed
	}
	return *owner, nil
}
func (p *DesktopWindowsSocketPolicy) Current(capture DesktopSocketCapture, owner DesktopSocketKernelOwner) bool {
	if p == nil || p.retired.Load() || p.ctx.Err() != nil || capture != p.capture {
		return false
	}
	identity, captured := p.publicIdentity.Load(), p.publicOwner.Load()
	if identity == nil || captured == nil || owner != *captured || !identity.Current(capture, owner) {
		return false
	}
	observed := p.observed.Load()
	now := time.Now().UnixMilli()
	return observed > 0 && observed <= now && now-observed <= 3000
}

func (p *DesktopWindowsSocketPolicy) Select(ctx context.Context, capture DesktopSocketCapture, network string, remote netip.AddrPort) (DesktopSocketBinding, error) {
	owner, ownerErr := p.Owner()
	if ctx == nil || ctx.Err() != nil || ownerErr != nil || capture != p.capture || network != "tcp" && network != "udp" {
		return DesktopSocketBinding{}, net.ErrClosed
	}
	if err := p.destination(network, remote, true); err != nil {
		return DesktopSocketBinding{}, err
	}
	for _, item := range p.interfaces {
		if item.Address.Is4() == remote.Addr().Is4() {
			return DesktopSocketBinding{Owner: owner, InterfaceName: item.Name, InterfaceIndex: item.Index, LocalAddress: item.Address}, nil
		}
	}
	return DesktopSocketBinding{}, errors.New("Windows physical path has no captured address family")
}
func (p *DesktopWindowsSocketPolicy) destination(network string, remote netip.AddrPort, hint bool) error {
	address := remote.Addr()
	if !remote.IsValid() || address.Is4In6() || address.Zone() != "" || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") || !p.options.IPv6Enabled && !address.Is4() {
		return errors.New("Windows physical destination is not a captured unicast family")
	}
	if hint && network == "udp" && remote.Port() == 0 {
		return nil
	}
	if remote.Port() == 0 || address.IsUnspecified() {
		return errors.New("Windows physical peer has no exact address and port")
	}
	if address.IsLoopback() {
		if len(p.fixtureScope) > 0 {
			return nil
		}
		return errors.New("Windows physical peer cannot bypass protection through loopback")
	}
	if address.IsPrivate() || address.IsLinkLocalUnicast() {
		for _, destination := range p.options.PrivateDestinations {
			if destination.Network == network && destination.Address == remote {
				return nil
			}
		}
		for _, prefix := range p.options.LANPrefixes {
			if prefix.Contains(address) {
				return nil
			}
		}
		return errors.New("Windows physical peer is outside selected private DNS/bridge or Home LAN policy")
	}
	return nil
}
func (p *DesktopWindowsSocketPolicy) binding(binding DesktopSocketBinding) (desktopWindowsPolicyInterface, error) {
	for _, item := range p.interfaces {
		if binding.Owner == p.owner && item.Name == binding.InterfaceName && item.Index == binding.InterfaceIndex && item.Address == binding.LocalAddress {
			return item, nil
		}
	}
	return desktopWindowsPolicyInterface{}, errors.New("Windows physical socket binding changed")
}
func desktopWindowsApplyInterface(raw syscall.RawConn, item desktopWindowsPolicyInterface, set bool) error {
	level, option, value := syscall.IPPROTO_IPV6, 31, int(item.Index) // IPV6_UNICAST_IF, host order.
	if item.Address.Is4() {
		level, option = syscall.IPPROTO_IP, 31
		var index [4]byte
		binary.BigEndian.PutUint32(index[:], item.Index)
		value = int(binary.LittleEndian.Uint32(index[:]))
	}
	var result error
	err := raw.Control(func(handle uintptr) {
		fd := syscall.Handle(handle)
		if set {
			if result = syscall.SetsockoptInt(fd, level, option, value); result != nil {
				return
			}
		}
		actual, err := syscall.GetsockoptInt(fd, level, option)
		if err != nil || uint32(actual) != uint32(value) {
			result = errors.Join(err, errors.New("Windows physical socket lost its captured outgoing interface"))
		}
	})
	return errors.Join(err, result)
}
func (p *DesktopWindowsSocketPolicy) Bind(ctx context.Context, capture DesktopSocketCapture, binding DesktopSocketBinding, network string, raw syscall.RawConn) error {
	if !p.Current(capture, binding.Owner) {
		return net.ErrClosed
	}
	creation, err := p.identity.MatchSocket(ctx, capture, binding, network, raw)
	if err != nil {
		return err
	}
	_, err = desktopWindowsPolicyCall(p, ctx, false, func() (struct{}, error) {
		item, err := p.binding(binding)
		if err != nil {
			return struct{}{}, err
		}
		current, err := desktopWindowsCheckInterface(item.DesktopWindowsSocketInterface, len(p.fixtureScope) > 0)
		if err != nil || current.LUID != item.LUID {
			return struct{}{}, errors.Join(err, errors.New("Windows physical interface identity changed before bind"))
		}
		if err := p.assertBaseline(); err != nil {
			return struct{}{}, err
		}
		if err := desktopWindowsApplyInterface(raw, item, true); err != nil {
			return struct{}{}, err
		}
		if _, duplicate := p.bindings[creation.SocketID]; duplicate {
			return struct{}{}, errors.New("Windows physical socket was rebound")
		}
		p.bindings[creation.SocketID] = creation
		p.observed.Store(time.Now().UnixMilli())
		return struct{}{}, nil
	})
	return err
}
func desktopWindowsPermitKey(q DesktopSocketGrant) string {
	return q.SocketID + "|" + q.Network + "|" + q.Local.String() + "|" + q.Remote.String()
}
func (p *DesktopWindowsSocketPolicy) permitRules(q DesktopSocketGrant, item desktopWindowsPolicyInterface) []desktopWFPRule {
	protocol := uint64(6)
	if q.Network == "udp" {
		protocol = 17
	}
	family := 6
	if q.Local.Addr().Is4() {
		family = 4
	}
	return p.pair("socket-"+desktopWindowsPermitKey(q), family, 50, true, false, p.user, desktopWFPNumber(desktopWFPInterface, 4, item.LUID), desktopWFPNumber(desktopWFPProtocol, 1, protocol), desktopWFPAddress(desktopWFPLocalAddress, q.Local.Addr()), desktopWFPNumber(desktopWFPLocalPort, 2, uint64(q.Local.Port())), desktopWFPAddress(desktopWFPRemoteAddress, q.Remote.Addr()), desktopWFPNumber(desktopWFPRemotePort, 2, uint64(q.Remote.Port())))
}
func (p *DesktopWindowsSocketPolicy) Grant(ctx context.Context, q DesktopSocketGrant) (DesktopSocketReceipt, error) {
	if !p.Current(q.Capture, q.Binding.Owner) || q.Sequence == 0 || !desktopSocketHex(q.SocketID, 32) || q.Network != "tcp" && q.Network != "udp" || !q.Local.IsValid() || q.Local.Port() == 0 || q.Local.Addr() != q.Binding.LocalAddress || q.Local.Addr().Is4() != q.Remote.Addr().Is4() {
		return DesktopSocketReceipt{}, net.ErrClosed
	}
	if err := p.destination(q.Network, q.Remote, false); err != nil {
		return DesktopSocketReceipt{}, err
	}
	return desktopWindowsPolicyCall(p, ctx, false, func() (DesktopSocketReceipt, error) {
		creation, ok := p.bindings[q.SocketID]
		if !ok || creation.Capture != q.Capture || creation.Binding != q.Binding || creation.Network != q.Network {
			return DesktopSocketReceipt{}, errors.New("Windows permit has no exact bound socket owner")
		}
		inspection, err := p.identity.InspectSocket(ctx, creation)
		if err != nil {
			return DesktopSocketReceipt{}, err
		}
		item, err := p.binding(q.Binding)
		if err != nil {
			return DesktopSocketReceipt{}, err
		}
		current, err := desktopWindowsCheckInterface(item.DesktopWindowsSocketInterface, len(p.fixtureScope) > 0)
		if err != nil || current.LUID != item.LUID {
			return DesktopSocketReceipt{}, errors.Join(err, errors.New("Windows physical interface changed before grant"))
		}
		protocol := uint8(6)
		if q.Network == "udp" {
			protocol = 17
		}
		if inspection.Local != q.Local || inspection.Protocol != protocol || inspection.Remote.IsValid() && !inspection.Remote.Addr().IsUnspecified() && inspection.Remote != q.Remote {
			return DesktopSocketReceipt{}, errors.New("Windows permit changed its actual kernel tuple or protocol")
		}
		if err := desktopWindowsApplyInterface(inspection.Raw, item, false); err != nil {
			return DesktopSocketReceipt{}, err
		}
		if err := p.assertBaseline(); err != nil {
			return DesktopSocketReceipt{}, err
		}
		key := desktopWindowsPermitKey(q)
		permit := p.permits[key]
		if permit != nil {
			old := permit.request
			old.Sequence = q.Sequence
			if old != q || q.Sequence <= permit.request.Sequence {
				return DesktopSocketReceipt{}, errors.New("Windows physical grant replayed or replaced another owner")
			}
		} else {
			if len(p.permits) >= DesktopSocketLimit*DesktopSocketPeerLimit {
				return DesktopSocketReceipt{}, errors.New("Windows physical permit count exceeds its bound")
			}
			permit = &desktopWindowsPolicyPermit{request: q, rules: p.permitRules(q, item)}
			// Retain exact keys before beginning the native transaction; even a
			// cancelled/unknown add remains recoverable by immutable identity.
			p.permits[key] = permit
			if err := p.leaseEngine.Begin(); err != nil {
				return DesktopSocketReceipt{}, err
			}
			for i := range permit.rules {
				if err = p.leaseEngine.Add(&permit.rules[i]); err != nil {
					break
				}
			}
			if err == nil {
				err = p.leaseEngine.Commit()
			}
			if err != nil {
				return DesktopSocketReceipt{}, errors.Join(err, p.leaseEngine.Abort())
			}
		}
		if err := p.assertBaseline(); err != nil {
			return DesktopSocketReceipt{}, err
		}
		if !p.Current(q.Capture, q.Binding.Owner) || ctx.Err() != nil {
			return DesktopSocketReceipt{}, net.ErrClosed
		}
		now := time.Now()
		permit.request = q
		permit.expires = now.Add(7 * time.Second)
		p.observed.Store(now.UnixMilli())
		return DesktopSocketReceipt{Grant: q, ObservedAt: now.UnixMilli(), ExpiresAt: permit.expires.UnixMilli()}, nil
	})
}
func (p *DesktopWindowsSocketPolicy) revoke(q DesktopSocketGrant) error {
	key := desktopWindowsPermitKey(q)
	permit := p.permits[key]
	if permit == nil {
		return nil
	}
	old := permit.request
	old.Sequence = q.Sequence
	if old != q || q.Sequence < permit.request.Sequence {
		return errors.New("Windows physical revoke belongs to a replacement owner")
	}
	if err := p.leaseEngine.Abort(); err != nil {
		return err
	}
	if err := p.leaseEngine.Begin(); err != nil {
		return err
	}
	var err error
	for _, rule := range permit.rules {
		if err = p.leaseEngine.Delete(rule.Key); err != nil {
			break
		}
	}
	if err == nil {
		err = p.leaseEngine.Commit()
	}
	if err != nil {
		return errors.Join(err, p.leaseEngine.Abort())
	}
	for _, rule := range permit.rules {
		if err := p.baselineEngine.Absent(rule.Key); err != nil {
			return err
		}
	}
	delete(p.permits, key)
	return nil
}
func (p *DesktopWindowsSocketPolicy) Revoke(ctx context.Context, q DesktopSocketGrant) error {
	if p == nil || p.publicOwner.Load() == nil || q.Capture != p.capture || q.Binding.Owner != *p.publicOwner.Load() || q.Sequence == 0 {
		return errors.New("Windows revoke has no captured physical policy")
	}
	_, err := desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) { return struct{}{}, p.revoke(q) })
	return err
}
func (p *DesktopWindowsSocketPolicy) CreateSocket(ctx context.Context, creation DesktopSocketCreation) (DesktopSocketCreated, error) {
	if !p.Current(creation.Capture, creation.Binding.Owner) {
		return DesktopSocketCreated{}, net.ErrClosed
	}
	return p.publicIdentity.Load().CreateSocket(ctx, creation)
}
func (p *DesktopWindowsSocketPolicy) ReleaseSocket(ctx context.Context, creation DesktopSocketCreation) error {
	_, err := desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) {
		for _, permit := range p.permits {
			if permit.request.SocketID == creation.SocketID {
				return struct{}{}, errors.New("Windows socket source still has a physical permit")
			}
		}
		if p.identity == nil {
			return struct{}{}, errors.New("Windows socket source was not retained")
		}
		if err := p.identity.ReleaseSocket(ctx, creation); err != nil {
			return struct{}{}, err
		}
		delete(p.bindings, creation.SocketID)
		return struct{}{}, nil
	})
	return err
}
func (p *DesktopWindowsSocketPolicy) Cancel() {
	if p == nil {
		return
	}
	p.retired.Store(true)
	p.cancel()
	if identity := p.publicIdentity.Load(); identity != nil {
		identity.Cancel()
	}
}
func (p *DesktopWindowsSocketPolicy) monitor() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(p.ctx, 1500*time.Millisecond)
		_, err := desktopWindowsPolicyCall(p, ctx, false, func() (struct{}, error) {
			now := time.Now()
			for _, permit := range p.permits {
				if permit.expires.IsZero() || !now.Before(permit.expires) {
					if err := p.revoke(permit.request); err != nil {
						return struct{}{}, err
					}
				}
			}
			if err := p.assertBaseline(); err != nil {
				return struct{}{}, err
			}
			if err := p.assertTunnel(); err != nil {
				return struct{}{}, err
			}
			p.observed.Store(time.Now().UnixMilli())
			return struct{}{}, nil
		})
		cancel()
		if err != nil {
			p.Cancel()
			return
		}
	}
}

func (p *DesktopWindowsSocketPolicy) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.Cancel()
	_, err := desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) {
		if p.closed {
			return struct{}{}, nil
		}
		if len(p.permits) != 0 || len(p.bindings) != 0 {
			return struct{}{}, errors.New("Windows physical policy retains unretired sockets or permits")
		}
		if err := p.retireTunnel(); err != nil {
			return struct{}{}, err
		}
		if p.identity != nil {
			if err := p.identity.Close(ctx); err != nil {
				return struct{}{}, err
			}
		}
		if err := p.finishBaseline(); err != nil {
			return struct{}{}, err
		}
		// Release the native lock only after all socket/token ownership and the
		// baseline's final state have been independently acknowledged.
		if err := p.releaseBaselineLock(); err != nil {
			return struct{}{}, err
		}
		if p.baselineEngine != nil {
			if err := p.baselineEngine.Close(); err != nil {
				return struct{}{}, err
			}
		}
		p.closed = true
		return struct{}{}, nil
	})
	return err
}
