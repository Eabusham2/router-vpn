//go:build darwin

package mobiletor

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"syscall"
)

type desktopDarwinOffDescriptor struct {
	creation DesktopSocketCreation
	file     *os.File
	identity desktopDarwinKernelSocket
	local    netip.AddrPort
}

type desktopDarwinPFLocalSocket struct {
	creation DesktopSocketCreation
	local    netip.AddrPort
}

// This seals expected policy text, not a kernel observation. Every use still
// reads the actual slot. The parent reconstructs this seal independently of
// the guardian's serialized metadata before it accepts the native source.
type desktopDarwinPFSlotPolicy struct {
	capture  DesktopSocketCapture
	uid      uint32
	expected string
}

func desktopDarwinIsolatedSlotPolicy(ctx context.Context, capture DesktopSocketCapture, uid uint32) (*desktopDarwinPFSlotPolicy, error) {
	if !capture.valid() || uid < 0x40000000 || uid >= 0x80000000 {
		return nil, errors.New("Darwin Off slot has no captured creator UID")
	}
	source := desktopPFIsolatedPointer(capture, desktopDarwinPFGeneration(capture), uid, desktopDarwinPFTestScope)
	var filters []string
	for _, line := range strings.Split(strings.TrimSpace(source), "\n") {
		if !strings.HasPrefix(line, "anchor ") {
			filters = append(filters, line)
		}
	}
	canonical, err := desktopDarwinPFCanonical(ctx, strings.Join(filters, "\n")+"\n")
	if err != nil {
		return nil, err
	}
	var expected []string
	inserted := false
	for _, line := range strings.Split(canonical, "\n") {
		if strings.HasPrefix(line, "block drop out quick ") {
			if !inserted {
				if len(expected) < 2 {
					return nil, errors.New("Darwin Off slot omitted captured TCP/UDP tag reset")
				}
				expected = append(expected, strings.TrimSpace(desktopDarwinPFPointer(capture)))
				inserted = true
			}
		} else if inserted || !strings.HasPrefix(line, "pass out ") {
			return nil, errors.New("Darwin Off slot canonicalization changed its finite guard order")
		}
		expected = append(expected, line)
	}
	if !inserted || len(expected) < 5 {
		return nil, errors.New("Darwin Off slot omitted its independent creator guard")
	}
	return &desktopDarwinPFSlotPolicy{capture: capture, uid: uid, expected: strings.Join(expected, "\n")}, nil
}

func (p *desktopDarwinPF) pointerValid() bool {
	if !p.HostProtectionOff {
		return p.slotPolicy == nil && p.Pointer == strings.TrimSpace(desktopDarwinPFPointer(p.Capture))
	}
	return p.slotPolicy != nil && p.slotPolicy.capture == p.Capture && p.slotPolicy.uid == p.UID && p.slotPolicy.expected != "" && p.Pointer == p.slotPolicy.expected
}

func (p *desktopDarwinPF) loadPointer(ctx context.Context) error {
	if !p.pointerValid() {
		return errors.New("Darwin PF slot lost its captured policy")
	}
	if !p.HostProtectionOff {
		return desktopDarwinPFLoadPointer(ctx, p.Capture)
	}
	return desktopDarwinPFLoad(ctx, p.Slot, desktopPFIsolatedPointer(p.Capture, p.Anchor, p.UID, desktopDarwinPFTestScope))
}

func (p *desktopDarwinPF) retirePermissions(ctx context.Context) error {
	if !p.valid() {
		return errors.New("Darwin PF permission retirement lost its original capture")
	}
	if err := desktopDarwinPFLoad(ctx, p.Anchor, "\n"); err != nil {
		return err
	}
	if err := p.filtersAbsent(ctx); err != nil {
		return err
	}
	clear(p.permits)
	p.tunnel, p.index = "", 0
	return nil
}

func (g *desktopDarwinGuardian) prepareOffSocket(ctx context.Context, creation DesktopSocketCreation, file *os.File, identity desktopDarwinKernelSocket) error {
	return g.prepareOffSocketWithBind(ctx, creation, file, identity, syscall.Bind)
}

// The shipping caller always uses the native ephemeral bind. Native fixtures
// can select an actual old-state port without changing the host ephemeral range
// or substituting a descriptor, state inventory, identity or successful bind.
func (g *desktopDarwinGuardian) prepareOffSocketWithBind(ctx context.Context, creation DesktopSocketCreation, file *os.File, identity desktopDarwinKernelSocket, bind func(int, syscall.Sockaddr) error) error {
	if g.pf == nil || !g.pf.HostProtectionOff || !g.pf.valid() || g.pf.scopedSockets == nil || identity.uid != g.uid {
		return errors.New("Darwin Off creator has no retained independent UID guard")
	}
	fd := int(file.Fd())
	if err := desktopSocketNoReuse(fd); err != nil {
		return err
	}
	var target syscall.Sockaddr
	if creation.Binding.LocalAddress.Is4() {
		target = &syscall.SockaddrInet4{Addr: creation.Binding.LocalAddress.As4()}
	} else {
		target = &syscall.SockaddrInet6{Addr: creation.Binding.LocalAddress.As16()}
	}
	if bind == nil {
		return errors.New("Darwin Off source has no actual native bind")
	}
	if err := bind(fd, target); err != nil {
		return err
	}
	local, err := desktopSocketLocal(fd)
	if err != nil {
		return err
	}
	if err := desktopDarwinPreboundSocket(file, creation, identity, local); err != nil {
		return err
	}
	if err := desktopDarwinBindInterface(fd, identity.family, creation.Binding.InterfaceIndex); err != nil {
		return err
	}
	g.pf.scopedSockets[creation.SocketID] = desktopDarwinPFLocalSocket{creation: creation, local: local}
	// Only a complete live guard/interface/state inspection can release this
	// bound descriptor from the guardian. No pre-existing tuple is flushed.
	return g.pf.verify(ctx, true)
}

func desktopDarwinPreboundSocket(file *os.File, creation DesktopSocketCreation, identity desktopDarwinKernelSocket, local netip.AddrPort) error {
	actual, err := desktopDarwinSocketIdentity(file)
	if err != nil || actual != identity || actual.network != creation.Network {
		return errors.Join(err, errors.New("Darwin Off prebound source replaced its original kernel socket"))
	}
	bound, err := desktopSocketLocal(int(file.Fd()))
	if err != nil || bound != local || bound.Addr() != creation.Binding.LocalAddress || bound.Port() == 0 {
		return errors.Join(err, errors.New("Darwin Off prebound source replaced its original local endpoint"))
	}
	if _, err := syscall.Getpeername(int(file.Fd())); !errors.Is(err, syscall.ENOTCONN) {
		return errors.New("Darwin Off prebound source connected before its captured permit")
	}
	if creation.Network == "tcp" {
		if err := desktopDarwinTCPUnconnected(int(file.Fd())); err != nil {
			return err
		}
	}
	for _, option := range []int{syscall.SO_REUSEADDR, syscall.SO_REUSEPORT} {
		value, err := syscall.GetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, option)
		if err != nil || value != 0 {
			return errors.Join(err, errors.New("Darwin Off prebound source permits address or port reuse"))
		}
	}
	return nil
}

func (p *DesktopDarwinSocketPolicy) retainOffDescriptor(creation DesktopSocketCreation, file *os.File) (*desktopSocketPrebound, error) {
	if !p.options.HostProtectionOff || file == nil {
		return nil, nil
	}
	p.offMu.Lock()
	defer p.offMu.Unlock()
	fail := func(err error) (*desktopSocketPrebound, error) {
		p.offFailure = errors.Join(p.offFailure, err)
		return nil, err
	}
	if creation.Capture != p.capture || creation.Binding.Owner != p.owner || !desktopSocketHex(creation.SocketID, 32) || p.offSockets[creation.SocketID] != nil {
		return fail(errors.New("Darwin Off source lost its unique original creation"))
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return fail(err)
	}
	var keeper *desktopSocketKeeper
	var duplicateErr error
	if err := raw.Control(func(fd uintptr) { keeper, duplicateErr = desktopSocketDuplicate(int(fd)) }); err != nil || duplicateErr != nil {
		return fail(errors.Join(err, duplicateErr))
	}
	identity, identityErr := desktopDarwinSocketIdentity(keeper.file)
	local, localErr := desktopSocketLocal(int(keeper.file.Fd()))
	if identityErr != nil || localErr != nil || identity.uid != p.uid || identity.network != creation.Network {
		keeper.file.Close()
		return fail(errors.Join(identityErr, localErr, errors.New("Darwin Off transferred socket lost its native creator or bound endpoint")))
	}
	if err := desktopDarwinPreboundSocket(keeper.file, creation, identity, local); err != nil {
		keeper.file.Close()
		return fail(err)
	}
	if p.offSockets == nil {
		p.offSockets = make(map[string]*desktopDarwinOffDescriptor)
	}
	original := &desktopDarwinOffDescriptor{creation: creation, file: keeper.file, identity: identity, local: local}
	p.offSockets[creation.SocketID] = original
	return &desktopSocketPrebound{source: p, creation: creation, local: local, verify: func(file *os.File) error {
		p.offMu.Lock()
		defer p.offMu.Unlock()
		if !p.options.HostProtectionOff || p.offFailure != nil || p.offSockets[creation.SocketID] != original || !p.Current(creation.Capture, creation.Binding.Owner) {
			return errors.New("Darwin Off import lost its retained original source")
		}
		return desktopDarwinPreboundSocket(file, creation, identity, local)
	}}, nil
}

// Close has already cancelled new creation and joined the monitor. A joined
// guardian can nevertheless leave a received FD in an admitted create call,
// before retainOffDescriptor records it. Join that same admission owner before
// inspecting the map, then release it before any finish call or guardian wait.
func (p *DesktopDarwinSocketPolicy) joinOffDescriptorCreation(ctx context.Context) error {
	if !p.options.HostProtectionOff {
		return nil
	}
	if err := p.mu.lockContext(ctx); err != nil {
		return err
	}
	retired := p.offDescriptorsRetired()
	p.mu.Unlock()
	if !retired {
		return errors.New("Darwin Off source still retains an original descriptor or unknown retirement")
	}
	return ctx.Err()
}

func (p *DesktopDarwinSocketPolicy) offDescriptorsRetired() bool {
	p.offMu.Lock()
	defer p.offMu.Unlock()
	return !p.options.HostProtectionOff || len(p.offSockets) == 0 && p.offFailure == nil
}

// The authenticated guardian has already released its copy or joined. Inspect
// only the original engine's complete native FD inventory while our CLOEXEC
// reference pins the socket. The shipping broker exposes neither File nor
// SyscallConn on returned connections and joins its I/O and all private import
// duplicates before invoking ReleaseSocket under the same source admission
// lock. A caller directly using this low-level source must provide that same
// joined ownership; concurrent arbitrary raw-FD duplication is not an authority
// this process can prove absent. No global descriptor-absence claim is made here.
func (p *DesktopDarwinSocketPolicy) releaseOffDescriptor(ctx context.Context, creation DesktopSocketCreation) error {
	return p.checkOffDescriptorRetirement(ctx, creation, true)
}

func (p *DesktopDarwinSocketPolicy) checkOffDescriptorRetirement(ctx context.Context, creation DesktopSocketCreation, retire bool) error {
	if !p.options.HostProtectionOff {
		return nil
	}
	p.offMu.Lock()
	defer p.offMu.Unlock()
	if p.offFailure != nil {
		return p.offFailure
	}
	original := p.offSockets[creation.SocketID]
	if original == nil {
		return nil
	}
	if original.creation != creation || ctx == nil || ctx.Err() != nil {
		return errors.New("Darwin Off retirement lost its original creation or caller")
	}
	identity, err := desktopDarwinSocketIdentity(original.file)
	if err != nil || identity != original.identity {
		return errors.Join(err, errors.New("Darwin Off retained source changed its kernel object"))
	}
	type entry struct {
		device         int32
		inode          uint64
		mode           uint16
		uid, gid, kind uint32
		object         [2]uint64
	}
	observe := func() (map[int]entry, error) {
		fds, err := desktopDarwinFDInventory()
		if err != nil {
			return nil, err
		}
		result := make(map[int]entry, len(fds))
		for _, fd := range fds {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if _, exists := result[fd.number]; exists {
				return nil, errors.New("Darwin original FD inventory duplicated a descriptor")
			}
			var stat syscall.Stat_t
			if err := syscall.Fstat(fd.number, &stat); err != nil {
				return nil, err
			}
			if fd.socket != (stat.Mode&syscall.S_IFMT == syscall.S_IFSOCK) {
				return nil, errors.New("Darwin original FD inventory changed descriptor type")
			}
			value := entry{device: stat.Dev, inode: stat.Ino, mode: stat.Mode, uid: stat.Uid, gid: stat.Gid, kind: fd.kind}
			if fd.socket {
				value.object, err = desktopDarwinSocketObject(fd.number)
				if err != nil {
					return nil, err
				}
				if uintptr(fd.number) != original.file.Fd() && value.object[0] == identity.socket {
					return nil, errors.New("Darwin Off original socket retains a native engine descriptor alias")
				}
			}
			result[fd.number] = value
		}
		if pinned, exists := result[int(original.file.Fd())]; !exists || pinned.object[0] != identity.socket || pinned.object[1] != identity.pcb {
			return nil, errors.New("Darwin original engine FD inventory omitted its retained socket witness")
		}
		return result, nil
	}
	first, err := observe()
	if err != nil {
		return err
	}
	second, err := observe()
	if err != nil {
		return err
	}
	if len(first) != len(second) {
		return errors.New("Darwin original engine FD inventory changed during retirement")
	}
	for fd, value := range first {
		if actual, exists := second[fd]; !exists || actual != value {
			return errors.New("Darwin original engine FD object changed during retirement")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !retire {
		return nil
	}
	if err := original.file.Close(); err != nil {
		return err
	}
	delete(p.offSockets, creation.SocketID)
	return nil
}
