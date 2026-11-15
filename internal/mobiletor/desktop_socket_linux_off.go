//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"syscall"
)

func desktopLinuxChainPolicy(off bool) string {
	if off {
		return "accept"
	}
	return "drop"
}

func (n *desktopLinuxNFT) chainPolicy() string { return desktopLinuxChainPolicy(n.HostProtectionOff) }

func (n *desktopLinuxNFT) denyExpressions() any {
	return []any{
		map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "skuid"}}, "right": float64(n.UID)}},
		map[string]any{"drop": nil},
	}
}

// Off changes the host default only. Its isolated socket UID still needs an
// original expiring tuple permit. Verify the exact deny handle and UID, and
// its position after every permit but before any baseline exemption. A read
// cannot adopt a replacement rule, widen the deny to another UID, or keep a
// late permit below it. required=false permits already-removed original rules
// during joined teardown; every remaining rule must still be the original.
func (n *desktopLinuxNFT) verifyOffDeny(rows []map[string]any, required bool) error {
	if !n.HostProtectionOff {
		if n.DenyHandle != 0 {
			return errors.New("protected Linux owner acquired an unselected UID deny")
		}
		return nil
	}
	if !required && n.UID == 0 && n.DenyHandle == 0 && n.TableName == desktopLinuxNodeTable(n.Capture) {
		return nil
	}
	if n.TableName != desktopLinuxNodeTable(n.Capture) || n.UID == 0 || n.DenyHandle == 0 || n.DenyHandle > 1<<53-1 {
		return errors.New("Linux Off owner lost its exact isolated UID deny")
	}
	deny, baseline := false, false
	for _, row := range rows {
		rule, ok := row["rule"].(map[string]any)
		if !ok {
			continue
		}
		handle := desktopLinuxNumber(rule["handle"])
		if rule["comment"] == n.comment("deny") || handle == n.DenyHandle {
			if deny || baseline || rule["family"] != "inet" || rule["table"] != n.table() || rule["chain"] != "output" || handle != n.DenyHandle || rule["comment"] != n.comment("deny") || !reflect.DeepEqual(rule["expr"], n.denyExpressions()) {
				return errors.New("Linux Off terminal deny changed original UID, handle or ordering")
			}
			deny = true
			continue
		}
		if _, ok := n.Baseline[handle]; ok {
			baseline = true
		}
		for _, transport := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			if rule["comment"] == n.comment(transport) && (deny || baseline) {
				return errors.New("Linux Off tuple permit moved below its original UID deny")
			}
		}
	}
	if required && !deny {
		return errors.New("Linux Off original UID deny disappeared")
	}
	return nil
}

// Each returned Off socket retains a separate CLOEXEC kernel reference. The
// original inode/cookie cannot be recycled while this reference is held.
type desktopLinuxOffDescriptor struct {
	creation DesktopSocketCreation
	file     *os.File
	identity desktopLinuxKernelSocket
}

// Called while the same native-call mutex still owns receipt publication.
func (p *DesktopLinuxSocketPolicy) retainOffDescriptor(c DesktopSocketCreation, returned *os.File) (failure error) {
	defer func() {
		if failure != nil {
			p.offDescriptorFailure = errors.Join(p.offDescriptorFailure, failure)
		}
	}()
	if c.Capture != p.capture || c.Binding.Owner != p.owner || p.offSockets[c.SocketID] != nil {
		return errors.New("Linux Off returned descriptor changed its original creation")
	}
	raw, err := returned.SyscallConn()
	if err != nil {
		return err
	}
	fd := -1
	var duplicateErr error
	controlErr := raw.Control(func(handle uintptr) {
		value, _, errno := syscall.Syscall(syscall.SYS_FCNTL, handle, syscall.F_DUPFD_CLOEXEC, 0)
		if errno != 0 {
			duplicateErr = errno
			return
		}
		fd = int(value)
	})
	if controlErr != nil || duplicateErr != nil || fd < 0 {
		return errors.Join(controlErr, duplicateErr, errors.New("Linux Off could not retain original kernel socket"))
	}
	retained := os.NewFile(uintptr(fd), "routervpn-original-off-socket")
	identity, err := desktopLinuxSocketIdentity(retained)
	if err != nil || identity.uid != p.uid {
		retained.Close()
		return errors.Join(err, errors.New("Linux Off socket has another kernel creator"))
	}
	if p.offSockets == nil {
		p.offSockets = make(map[string]*desktopLinuxOffDescriptor)
	}
	p.offSockets[c.SocketID] = &desktopLinuxOffDescriptor{c, retained, identity}
	return nil
}

// A dead guardian cannot attest caller descriptor retirement. The original
// source keeps the UID deny while any returned creation or unknown retention
// remains. Native Box socket wrappers all live in this original engine.
func (p *DesktopLinuxSocketPolicy) offDescriptorsRetired() bool {
	if !p.options.HostProtectionOff {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.options.HostProtectionOff || len(p.offSockets) == 0 && p.offDescriptorFailure == nil
}

// Closing one Go wrapper is insufficient: net.FileConn and syscall.Dup may
// retain aliases. Inspect the original engine's native fd inventory while our
// reference pins the socket identity. The helper's copy has already joined or
// acknowledged release before this method may close the last retained copy.
func (p *DesktopLinuxSocketPolicy) releaseOffDescriptor(ctx context.Context, c DesktopSocketCreation) error {
	if !p.options.HostProtectionOff {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.options.HostProtectionOff {
		return nil
	}
	if p.offDescriptorFailure != nil {
		return p.offDescriptorFailure
	}
	original, exists := p.offSockets[c.SocketID]
	if !exists {
		return nil
	}
	if original.creation != c {
		return errors.New("Linux Off descriptor retirement changed its original creation")
	}
	identity, err := desktopLinuxSocketIdentity(original.file)
	if err != nil || identity != original.identity {
		return errors.Join(err, errors.New("Linux Off retained descriptor changed kernel identity"))
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux Off descriptor retirement lost original caller")
	}
	// Hold the directory descriptor through both complete observations. A
	// disappeared/reused fd or changed inventory is an unresolved retirement,
	// not absence. Upstream broker retirement has already joined all operations
	// which may duplicate this source's descriptor; this checks native aliases
	// in that original engine, not global absence across arbitrary processes.
	directory, err := os.Open("/proc/self/fd")
	if err != nil {
		return err
	}
	defer directory.Close()
	observe := func() (map[int]syscall.Stat_t, error) {
		if _, err := directory.Seek(0, 0); err != nil {
			return nil, err
		}
		entries, err := directory.ReadDir(-1)
		if err != nil {
			return nil, err
		}
		inventory := make(map[int]syscall.Stat_t, len(entries))
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			fd, err := strconv.Atoi(entry.Name())
			if err != nil {
				return nil, err
			}
			var stat syscall.Stat_t
			if err := syscall.Fstat(fd, &stat); err != nil {
				return nil, err
			}
			inventory[fd] = stat
			if uintptr(fd) != original.file.Fd() && stat.Mode&syscall.S_IFMT == syscall.S_IFSOCK && stat.Ino == identity.inode && stat.Uid == identity.uid {
				return nil, errors.New("Linux Off original socket still has a live native descriptor alias")
			}
		}
		return inventory, nil
	}
	first, err := observe()
	if err != nil {
		return err
	}
	second, err := observe()
	if err != nil {
		return err
	}
	// Descriptor identity/type is stable; access timestamps and unrelated
	// regular-file size changes are not descriptor replacements.
	if len(first) != len(second) {
		return errors.New("Linux Off native fd inventory changed during retirement")
	}
	for fd, before := range first {
		after, exists := second[fd]
		if !exists || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid {
			return errors.New("Linux Off native fd identity changed during retirement")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := original.file.Close(); err != nil {
		return err
	}
	delete(p.offSockets, c.SocketID)
	return nil
}
