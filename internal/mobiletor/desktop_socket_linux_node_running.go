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
	Interfaces   []DesktopLinuxSocketInterface
	Destinations []DesktopLinuxSocketDestination
}

func (s DesktopLinuxNodeRunningSelection) validate() error {
	if len(s.Interfaces) == 0 || len(s.Interfaces) > 64 || len(s.Destinations) == 0 || len(s.Destinations) > 256 {
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
	return nil
}

func desktopLinuxRunningPort(value any) (uint16, bool) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 1 || number > 65535 || number != math.Trunc(number) {
		return 0, false
	}
	return uint16(number), true
}

// Every live element must retain its original tuple schema, physical source,
// captured outer destination, bounded expiry and socket/sequence annotation.
// This proves the read inventory, not the existence of a corresponding socket;
// the original process/control/guardian and live source remain separate owners.
func desktopLinuxRunningElement(raw any, kind string, selection DesktopLinuxNodeRunningSelection) (string, string, string, error) {
	bad := errors.New("Linux running policy contains an uncaptured or malformed live tuple")
	outer, ok := raw.(map[string]any)
	if !ok || len(outer) != 1 {
		return "", "", "", bad
	}
	element, ok := outer["elem"].(map[string]any)
	if !ok || !desktopLinuxProtectionKeys(element, "val", "timeout", "expires", "comment") {
		return "", "", "", bad
	}
	if timeout, exists := element["timeout"]; exists && timeout != float64(9) {
		return "", "", "", bad
	}
	expires, ok := element["expires"].(float64)
	if !ok || math.IsNaN(expires) || math.IsInf(expires, 0) || expires <= 0 || expires > 9 {
		return "", "", "", bad
	}
	comment, ok := element["comment"].(string)
	if !ok {
		return "", "", "", bad
	}
	socket, sequence, found := strings.Cut(comment, ":")
	number, err := strconv.ParseUint(sequence, 10, 64)
	if !found || !desktopSocketHex(socket, 32) || err != nil || number == 0 || sequence != strconv.FormatUint(number, 10) {
		return "", "", "", bad
	}
	value, ok := element["val"].(map[string]any)
	if !ok || len(value) != 1 {
		return "", "", "", bad
	}
	tuple, ok := value["concat"].([]any)
	if !ok || len(tuple) != 5 {
		return "", "", "", bad
	}
	name, nameOK := tuple[0].(string)
	localText, localOK := tuple[1].(string)
	remoteText, remoteOK := tuple[3].(string)
	local, localErr := netip.ParseAddr(localText)
	remote, remoteErr := netip.ParseAddr(remoteText)
	_, localPortOK := desktopLinuxRunningPort(tuple[2])
	remotePort, remotePortOK := desktopLinuxRunningPort(tuple[4])
	if !nameOK || !localOK || !remoteOK || localErr != nil || remoteErr != nil ||
		local.String() != localText || remote.String() != remoteText || !localPortOK || !remotePortOK ||
		local.Is4() != (kind[3] == '4') || remote.Is4() != local.Is4() {
		return "", "", "", bad
	}
	physical := false
	for _, selected := range selection.Interfaces {
		if selected.Name == name && selected.Address == local {
			physical = true
			break
		}
	}
	allowed := false
	for _, selected := range selection.Destinations {
		if selected.Network == kind[:3] && selected.Address == netip.AddrPortFrom(remote, remotePort) {
			allowed = true
			break
		}
	}
	if !physical || !allowed {
		return "", "", "", bad
	}
	encoded, err := json.Marshal(tuple)
	if err != nil {
		return "", "", "", bad
	}
	return socket, comment, kind + ":" + string(encoded), nil
}

func desktopLinuxRunningRows(n *desktopLinuxNFT, rows []map[string]any, selection DesktopLinuxNodeRunningSelection) error {
	if n == nil || selection.validate() != nil {
		return errors.New("Linux running inventory lacks its original native selection")
	}
	// Validate live elements before removing them from a shallow read-only
	// projection. The unchanged strict prepared inventory then proves every
	// table, chain, baseline, UID rule and set, including absence of extras.
	projected := make([]map[string]any, len(rows))
	sockets := make(map[string]int)
	comments, tuples := make(map[string]bool), make(map[string]bool)
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
				socket, comment, tuple, err := desktopLinuxRunningElement(raw, kind, selection)
				if err != nil || comments[comment] || tuples[tuple] {
					return errors.Join(err, errors.New("Linux running policy repeats or changes a captured live tuple"))
				}
				comments[comment], tuples[tuple] = true, true
				sockets[socket]++
				if len(sockets) > DesktopSocketLimit || sockets[socket] > DesktopSocketPeerLimit {
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
	if err := desktopLinuxRunningRows(b.prepared, rows, selection); err != nil {
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
