//go:build linux

package mobiletor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Linux UAPI nf_tables.h: timeout elements are checked against kernel jiffies,
// independently of userspace timers and wall-clock changes. No dynset/update
// expression is emitted: traffic and receipt retries cannot refresh this grant.
// https://github.com/torvalds/linux/blob/v6.12/include/net/netfilter/nf_tables.h
// https://wiki.netfilter.org/wiki-nftables/index.php/Element_timeouts
const desktopLinuxBootstrapMaxPermit = 2 * time.Second
const (
	desktopLinuxNFTNewRule       = 0x0a06
	desktopLinuxNFTNewSet        = 0x0a09
	desktopLinuxNFTDeleteSet     = 0x0a0b
	desktopLinuxNFTNewSetElement = 0x0a0c
)

func bootstrapBE32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func bootstrapBE64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func bootstrapNative32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}
func bootstrapAttrs(values ...[]byte) []byte    { return bytes.Join(values, nil) }
func bootstrapAttr(k uint16, b []byte) []byte   { return desktopLinuxBaselineAttribute(k, b) }
func bootstrapU32(k uint16, v uint32) []byte    { return bootstrapAttr(k, bootstrapBE32(v)) }
func bootstrapU64(k uint16, v uint64) []byte    { return bootstrapAttr(k, bootstrapBE64(v)) }
func bootstrapString(k uint16, v string) []byte { return bootstrapAttr(k, append([]byte(v), 0)) }
func bootstrapNest(k uint16, values ...[]byte) []byte {
	return bootstrapAttr(k|0x8000, bootstrapAttrs(values...))
}
func bootstrapExpr(name string, data ...[]byte) []byte {
	return bootstrapNest(1, bootstrapString(1, name), bootstrapNest(2, data...))
}
func bootstrapMeta(key uint32) []byte {
	return bootstrapExpr("meta", bootstrapU32(1, 1), bootstrapU32(2, key))
}
func bootstrapCompare(value []byte) []byte {
	return bootstrapExpr("cmp", bootstrapU32(1, 1), bootstrapU32(2, 0), bootstrapNest(3, bootstrapAttr(1, value)))
}
func bootstrapPayload(base, offset, size uint32) []byte {
	return bootstrapExpr("payload", bootstrapU32(1, 1), bootstrapU32(2, base), bootstrapU32(3, offset), bootstrapU32(4, size))
}

// Reserve half the original remaining interval for processing/acknowledgement.
// The fixed cap is also a kernel safety bound if receipt delivery never returns.
// This duration is frozen once; cancellation/recovery never recomputes it.
func desktopLinuxBootstrapPermitDuration(remaining time.Duration) (time.Duration, error) {
	d := remaining / 2
	if d > desktopLinuxBootstrapMaxPermit {
		d = desktopLinuxBootstrapMaxPermit
	}
	d = d.Truncate(20 * time.Millisecond)
	if d < 20*time.Millisecond {
		return 0, errors.New("bootstrap original deadline leaves no bounded kernel permit")
	}
	return d, nil
}

func desktopLinuxBootstrapRuleWire(route desktopLinuxBootstrapRoute, local, remote netip.AddrPort, mark uint32, network, set string) ([]byte, error) {
	if !local.IsValid() || !remote.IsValid() || !local.Addr().IsGlobalUnicast() || !remote.Addr().IsGlobalUnicast() || local.Addr().Is4() != remote.Addr().Is4() || local.Addr().Is4In6() || remote.Addr().Is4In6() || local.Addr().Zone() != "" || remote.Addr().Zone() != "" || local.Port() == 0 || remote.Port() != 53 || mark&0x80000000 == 0 || route.Address != local.Addr() || route.Interface.Index < 1 || len(route.Interface.Name) == 0 || len(route.Interface.Name) >= 16 || strings.ContainsRune(route.Interface.Name, 0) || network != "udp" && network != "tcp" || !desktopLinuxBootstrapSetName(set) {
		return nil, errors.New("bootstrap native rule changed exact socket scope")
	}
	family, src, dst, size := byte(2), uint32(12), uint32(16), uint32(4)
	if !local.Addr().Is4() {
		family, src, dst, size = 10, 8, 24, 16
	}
	protocol := byte(17)
	if network == "tcp" {
		protocol = 6
	}
	iface := make([]byte, 16)
	copy(iface, route.Interface.Name)
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports, local.Port())
	binary.BigEndian.PutUint16(ports[2:], remote.Port())
	expr := bootstrapAttrs(bootstrapMeta(10), bootstrapCompare(bootstrapNative32(0)), bootstrapMeta(3), bootstrapCompare(bootstrapNative32(mark)), bootstrapMeta(7), bootstrapCompare(iface), bootstrapMeta(15), bootstrapCompare([]byte{family}), bootstrapPayload(1, src, size), bootstrapCompare(local.Addr().AsSlice()), bootstrapPayload(1, dst, size), bootstrapCompare(remote.Addr().AsSlice()), bootstrapMeta(16), bootstrapCompare([]byte{protocol}), bootstrapPayload(2, 0, 4), bootstrapCompare(ports), bootstrapMeta(3), bootstrapExpr("lookup", bootstrapString(1, set), bootstrapU32(2, 1), bootstrapU32(4, 1), bootstrapU32(5, 0)), bootstrapExpr("immediate", bootstrapU32(1, 0), bootstrapNest(2, bootstrapNest(2, bootstrapU32(1, 1)))))
	return bootstrapNest(4, expr), nil
}
func desktopLinuxBootstrapSetName(s string) bool {
	if len(s) != 22 || !strings.HasPrefix(s, "rvb_") {
		return false
	}
	for _, c := range s[4:] {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// Exactly one atomic transaction: private timeout set, one element,
// and one tuple-scoped rule. ECHO is requested only for objects with handles;
// BATCH_END ACK independently proves commit. Sequence space is never reused.
func desktopLinuxBootstrapCreateRequests(generation uint32, table, set string, rule []byte, mark uint32, ttl time.Duration, seq, port uint32) ([][]byte, error) {
	if generation == 0 || !desktopLinuxOwnedTableName(table) || !desktopLinuxBootstrapSetName(set) || len(rule) == 0 || len(rule) > 3072 || mark&0x80000000 == 0 || ttl < time.Millisecond || ttl > desktopLinuxBootstrapMaxPermit || ttl%time.Millisecond != 0 || seq == 0 || seq > ^uint32(0)-4 || port == 0 {
		return nil, errors.New("bootstrap creation lacks original bounded transaction")
	}
	flags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL | syscall.NLM_F_ECHO)
	setAttrs := bootstrapAttrs(bootstrapString(1, table), bootstrapString(2, set), bootstrapU32(3, 0x10), bootstrapU32(4, 19), bootstrapU32(5, 4), bootstrapU32(10, 1), bootstrapU64(11, uint64(ttl/time.Millisecond)))
	elem := bootstrapNest(1, bootstrapNest(1, bootstrapAttr(1, bootstrapNative32(mark))), bootstrapU64(4, uint64(ttl/time.Millisecond)))
	elements := bootstrapAttrs(bootstrapString(1, table), bootstrapString(2, set), bootstrapNest(3, elem), bootstrapU32(4, 1))
	return [][]byte{
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchBegin, syscall.NLM_F_REQUEST, seq, port, 0, desktopLinuxNFTSubsystem, bootstrapU32(1, generation)),
		desktopLinuxBaselineMessage(desktopLinuxNFTNewSet, flags, seq+1, port, desktopLinuxNFTInet, 0, setAttrs),
		desktopLinuxBaselineMessage(desktopLinuxNFTNewSetElement, syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, seq+2, port, desktopLinuxNFTInet, 0, elements),
		desktopLinuxBaselineMessage(desktopLinuxNFTNewRule, flags|syscall.NLM_F_APPEND, seq+3, port, desktopLinuxNFTInet, 0, bootstrapAttrs(bootstrapString(1, table), bootstrapString(2, "output"), rule)),
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq+4, port, 0, desktopLinuxNFTSubsystem, nil)}, nil
}

func desktopLinuxBootstrapDeleteGrantRequests(generation uint32, table string, rule, set uint64, seq, port uint32) ([][]byte, error) {
	original, err := desktopLinuxBootstrapDeleteRequests(generation, table, rule, seq, port)
	if err != nil || set == 0 || set > 1<<53-1 || set == rule || seq > ^uint32(0)-3 {
		return nil, errors.Join(err, errors.New("bootstrap deletion lacks both original handles"))
	}
	return [][]byte{original[0], original[1], desktopLinuxBaselineMessage(desktopLinuxNFTDeleteSet, syscall.NLM_F_REQUEST, seq+2, port, desktopLinuxNFTInet, 0, bootstrapAttrs(bootstrapString(1, table), bootstrapU64(16, set))), desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq+3, port, 0, desktopLinuxNFTSubsystem, nil)}, nil
}
