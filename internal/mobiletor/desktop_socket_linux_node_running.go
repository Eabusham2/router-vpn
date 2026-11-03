//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DesktopLinuxNodeRunningSelection is a read-only comparison captured from
// the sealed graph and original physical network before the tunnel starts.
// It creates no socket, guardian, firewall ownership or admission capability.
type DesktopLinuxNodeRunningSelection struct {
	Interfaces    []DesktopLinuxSocketInterface
	Destinations  []DesktopLinuxSocketDestination
	SOCKSControls []DesktopLinuxSocketDestination
}

func (s DesktopLinuxNodeRunningSelection) validate() error {
	if len(s.Interfaces) == 0 || len(s.Interfaces) > 64 || len(s.Destinations) == 0 || len(s.Destinations) > 256 || len(s.SOCKSControls) > 256 {
		return errors.New("Linux running policy lost its bounded original physical selection")
	}
	interfaces := make(map[DesktopLinuxSocketInterface]bool)
	for _, v := range s.Interfaces {
		if !desktopLinuxInterfaceName.MatchString(v.Name) || v.Index == 0 || !v.Address.IsValid() ||
			v.Address.IsUnspecified() || v.Address.IsMulticast() || v.Address.IsLoopback() || v.Address.Is4In6() ||
			v.Address.Zone() != "" || interfaces[v] {
			return errors.New("Linux running policy substituted its physical interface selection")
		}
		interfaces[v] = true
	}
	destinations := make(map[DesktopLinuxSocketDestination]bool)
	for _, v := range s.Destinations {
		if v.Network != "tcp" && v.Network != "udp" || !v.Address.IsValid() || v.Address.Port() == 0 ||
			v.Address.Addr().IsUnspecified() || v.Address.Addr().IsMulticast() || v.Address.Addr().IsLoopback() ||
			v.Address.Addr().Is4In6() || v.Address.Addr().Zone() != "" || destinations[v] {
			return errors.New("Linux running policy substituted its captured outer destination")
		}
		destinations[v] = true
	}
	controls := make(map[DesktopLinuxSocketDestination]bool)
	for _, control := range s.SOCKSControls {
		if control.Network != "tcp" || !destinations[control] || controls[control] || !desktopSocketSOCKSAddress(control.Address.Addr()) {
			return errors.New("Linux running SOCKS control is not an exact selected original TCP destination")
		}
		controls[control] = true
	}
	return nil
}

func desktopLinuxRunningPort(value any) (uint16, bool) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 1 || number > 65535 || number != math.Trunc(number) {
		return 0, false
	}
	return uint16(number), true
}

type desktopLinuxRunningTuple struct {
	socket, comment, tuple, kind, parent string
	sequence, parentSequence             uint64
	local                                netip.Addr
	remote                               netip.AddrPort
	expires                              float64
	static                               bool
}

func desktopLinuxRunningSequence(value string) (uint64, bool) {
	number, err := strconv.ParseUint(value, 10, 64)
	return number, err == nil && number != 0 && value == strconv.FormatUint(number, 10)
}

// Every live element retains its exact native tuple and canonical annotation.
// Linked UDP is checked against the selected TCP owner in a separate pass so
// the kernel dump's set/element ordering cannot grant or remove authority.
func desktopLinuxRunningElement(raw any, kind string, selection DesktopLinuxNodeRunningSelection) (desktopLinuxRunningTuple, error) {
	var result desktopLinuxRunningTuple
	bad := errors.New("Linux running policy contains an uncaptured or malformed live tuple")
	if kind != "tcp4" && kind != "udp4" && kind != "tcp6" && kind != "udp6" {
		return result, bad
	}
	outer, ok := raw.(map[string]any)
	if !ok || len(outer) != 1 {
		return result, bad
	}
	element, ok := outer["elem"].(map[string]any)
	if !ok || !desktopLinuxProtectionKeys(element, "val", "timeout", "expires", "comment") {
		return result, bad
	}
	comment, ok := element["comment"].(string)
	if !ok {
		return result, bad
	}
	parts := strings.Split(comment, ":")
	if len(parts) != 2 && len(parts) != 5 || !desktopSocketHex(parts[0], 32) {
		return result, bad
	}
	sequence, valid := desktopLinuxRunningSequence(parts[1])
	if !valid {
		return result, bad
	}
	result.socket, result.comment, result.sequence, result.kind = parts[0], comment, sequence, kind
	if len(parts) == 5 {
		parentSequence, valid := desktopLinuxRunningSequence(parts[4])
		if kind[:3] != "udp" || parts[2] != "socks" || !desktopSocketHex(parts[3], 32) || parts[3] == parts[0] || !valid {
			return result, bad
		}
		result.parent, result.parentSequence = parts[3], parentSequence
	}
	timeout := float64(9)
	if value, exists := element["timeout"]; exists {
		var valid bool
		timeout, valid = value.(float64)
		if !valid || math.IsNaN(timeout) || math.IsInf(timeout, 0) || timeout < 1 || timeout > 9 || timeout != math.Trunc(timeout) || result.parent == "" && timeout != 9 {
			return result, bad
		}
	}
	expires, ok := element["expires"].(float64)
	if !ok || math.IsNaN(expires) || math.IsInf(expires, 0) || expires <= 0 || expires > timeout {
		return result, bad
	}
	result.expires = expires
	value, ok := element["val"].(map[string]any)
	if !ok || len(value) != 1 {
		return result, bad
	}
	tuple, ok := value["concat"].([]any)
	if !ok || len(tuple) != 5 {
		return result, bad
	}
	name, nameOK := tuple[0].(string)
	localText, localOK := tuple[1].(string)
	remoteText, remoteOK := tuple[3].(string)
	local, localErr := netip.ParseAddr(localText)
	remote, remoteErr := netip.ParseAddr(remoteText)
	_, localPortOK := desktopLinuxRunningPort(tuple[2])
	remotePort, remotePortOK := desktopLinuxRunningPort(tuple[4])
	if !nameOK || !localOK || !remoteOK || localErr != nil || remoteErr != nil || local.String() != localText || remote.String() != remoteText || !localPortOK || !remotePortOK || local.Is4() != (kind[3] == '4') || remote.Is4() != local.Is4() {
		return result, bad
	}
	result.local, result.remote = local, netip.AddrPortFrom(remote, remotePort)
	physical := false
	for _, selected := range selection.Interfaces {
		if selected.Name == name && selected.Address == local {
			physical = true
			break
		}
	}
	for _, selected := range selection.Destinations {
		if selected.Network == kind[:3] && selected.Address == result.remote {
			result.static = true
			break
		}
	}
	if !physical || result.parent == "" && !result.static || result.parent != "" && (!desktopSocketSOCKSAddress(local) || !desktopSocketSOCKSAddress(remote)) {
		return result, bad
	}
	encoded, err := json.Marshal(tuple)
	if err != nil {
		return result, err
	}
	result.tuple = kind + ":" + string(encoded)
	return result, nil
}

func desktopLinuxRunningSOCKS(entries []desktopLinuxRunningTuple, selection DesktopLinuxNodeRunningSelection, homeLAN bool) error {
	sockets := make(map[string][]desktopLinuxRunningTuple)
	controls := make(map[netip.AddrPort]bool)
	for _, control := range selection.SOCKSControls {
		controls[control.Address] = true
	}
	for _, entry := range entries {
		sockets[entry.socket] = append(sockets[entry.socket], entry)
	}
	parents := make(map[string]bool)
	for _, child := range entries {
		if child.parent == "" {
			continue
		}
		original := sockets[child.parent]
		if len(original) != 1 || len(sockets[child.socket]) != 1 || parents[child.parent] {
			return errors.New("Linux running SOCKS relay lost its unique control and child")
		}
		control := original[0]
		if control.kind[:3] != "tcp" || control.parent != "" || !controls[control.remote] || !desktopSocketSOCKSAddress(control.local) || child.parentSequence > control.sequence || child.expires > control.expires {
			return errors.New("Linux running SOCKS relay has no current selected control grant")
		}
		if child.remote.Addr().IsPrivate() && !(control.remote.Addr().IsPrivate() && child.remote.Addr() == control.remote.Addr()) && !homeLAN && !child.static {
			return errors.New("Linux running SOCKS relay escaped selected private destination policy")
		}
		parents[child.parent] = true
	}
	return nil
}

func desktopLinuxRunningRows(n *desktopLinuxNFT, rows []map[string]any, selection DesktopLinuxNodeRunningSelection) error {
	return desktopLinuxRunningRowsWithLAN(n, rows, selection, false)
}

func desktopLinuxRunningRowsWithLAN(n *desktopLinuxNFT, rows []map[string]any, selection DesktopLinuxNodeRunningSelection, homeLAN bool) error {
	if n == nil || selection.validate() != nil {
		return errors.New("Linux running inventory lacks its original native selection")
	}
	// Validate live elements before removing them from a shallow read-only
	// projection. The unchanged strict prepared inventory then proves every
	// table, chain, baseline, UID rule and set, including absence of extras.
	projected := make([]map[string]any, len(rows))
	sockets := make(map[string]int)
	comments, tuples := make(map[string]bool), make(map[string]bool)
	var entries []desktopLinuxRunningTuple
	for i, row := range rows {
		projected[i] = row
		set, isSet := row["set"].(map[string]any)
		if !isSet {
			continue
		}
		kind := ""
		for _, candidate := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			if set["name"] == n.Prefix+"_"+candidate && desktopLinuxNumber(set["handle"]) == n.Sets[candidate] {
				kind = candidate
				break
			}
		}
		if kind == "" || len(row) != 1 {
			return errors.New("Linux running policy contains an unrelated native set")
		}
		if raw, exists := set["elem"]; exists {
			elements, ok := raw.([]any)
			if !ok || len(elements) > 4096 {
				return errors.New("Linux running policy exceeds its actual tuple-set bound")
			}
			for _, raw := range elements {
				entry, err := desktopLinuxRunningElement(raw, kind, selection)
				if err != nil || comments[entry.comment] || tuples[entry.tuple] {
					return errors.Join(err, errors.New("Linux running policy repeats or changes a captured live tuple"))
				}
				comments[entry.comment], tuples[entry.tuple] = true, true
				entries = append(entries, entry)
				sockets[entry.socket]++
				if len(sockets) > DesktopSocketLimit || sockets[entry.socket] > DesktopSocketPeerLimit {
					return errors.New("Linux running policy exceeds its original socket or peer limit")
				}
			}
		}
		copy := make(map[string]any, len(set))
		for key, value := range set {
			copy[key] = value
		}
		copy["elem"] = []any{}
		projected[i] = map[string]any{"set": copy}
	}
	if err := desktopLinuxRunningSOCKS(entries, selection, homeLAN); err != nil {
		return err
	}
	return desktopLinuxProtectionRows(n, projected, true)
}

// ObserveRunning independently reads only this original creator's live native
// inventory. It neither adopts an owner from a record nor mutates policy. A
// stable generation must bracket all reads; DNS, TUN, original child lifetime
// and authenticated Router proof are separate caller responsibilities.
func (b *DesktopLinuxNodeBaseline) ObserveRunning(ctx context.Context, expected DesktopLinuxProtectionRecord,
	selection DesktopLinuxNodeRunningSelection) error {
	if err := b.enter(ctx); err != nil {
		return err
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.complete || b.removed || b.prepared == nil || expected.Validate() != nil || expected != b.preparedRecord ||
		selection.validate() != nil {
		return errors.New("Linux running observation lost its original prepared baseline or selection")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := b.currentNamespace(ctx); err != nil {
		return err
	}
	for _, physical := range selection.Interfaces {
		if err := desktopLinuxCheckInterface(physical); err != nil {
			return err
		}
	}
	before, err := b.netlink.generation(ctx)
	if err != nil {
		return err
	}
	rows, err := desktopLinuxNFTReadTable(ctx, b.nft.table())
	if err != nil {
		return err
	}
	if err := desktopLinuxRunningRowsWithLAN(b.prepared, rows, selection, b.homeLAN); err != nil {
		return err
	}
	after, err := b.netlink.generation(ctx)
	if err != nil || before != after || b.currentNamespace(ctx) != nil {
		return errors.Join(err, errors.New("Linux running protection changed during its native snapshot"))
	}
	for _, physical := range selection.Interfaces {
		if err := desktopLinuxCheckInterface(physical); err != nil {
			return err
		}
	}
	return ctx.Err()
}
