//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"router-vpn/internal/desktopnetwork"
	"sync"
	"time"
)

// These two private aliases are a test-only adapter between an authenticated
// userspace WG peer and the real kernel TCP peer check in the shipping relay.
// They never alter the production listener/source-peer policy or default route.
type macOSImportedExecutionAliasState struct{ index, bits int }

var macOSImportedExecutionAliasGate sync.Mutex
var macOSImportedExecutionAliases = []netip.Addr{netip.MustParseAddr("10.78.0.1"), netip.MustParseAddr("10.78.0.2")}

type macOSImportedExecutionAliasOwner struct {
	index  int
	added  []netip.Addr
	unlock bool
	closed bool
}

func macOSImportedExecutionAliasInventory() (int, map[netip.Addr]macOSImportedExecutionAliasState, error) {
	link, err := net.InterfaceByName("lo0")
	if err != nil || link.Flags&net.FlagLoopback == 0 || link.Flags&net.FlagUp == 0 {
		return 0, nil, errors.Join(err, errors.New("original Darwin loopback unavailable"))
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, nil, err
	}
	present := map[netip.Addr]macOSImportedExecutionAliasState{}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return 0, nil, err
		}
		for _, raw := range addresses {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				return 0, nil, err
			}
			address := prefix.Addr().Unmap()
			if address != macOSImportedExecutionAliases[0] && address != macOSImportedExecutionAliases[1] {
				continue
			}
			if _, duplicate := present[address]; duplicate {
				return 0, nil, errors.New("ambiguous private alias inventory")
			}
			present[address] = macOSImportedExecutionAliasState{iface.Index, prefix.Bits()}
		}
	}
	return link.Index, present, nil
}
func macOSImportedExecutionOwnAliases(ctx context.Context) (*macOSImportedExecutionAliasOwner, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("missing original alias caller")
	}
	if err := desktopnetwork.LockContext(ctx, &macOSImportedExecutionAliasGate); err != nil {
		return nil, err
	}
	owner := &macOSImportedExecutionAliasOwner{unlock: true}
	if ctx.Err() != nil {
		owner.release()
		return nil, ctx.Err()
	}
	index, present, err := macOSImportedExecutionAliasInventory()
	if err != nil {
		owner.release()
		return nil, err
	}
	// Check both aliases before ANY mutation. Existing addresses are never ours.
	for _, address := range macOSImportedExecutionAliases {
		if present[address].index != 0 {
			owner.release()
			return nil, errors.New("private execution fixture alias already exists")
		}
	}
	owner.index = index
	for _, address := range macOSImportedExecutionAliases {
		// Retain the exact attempted mutation before running the command: a
		// canceled process can have added its address before reporting failure.
		owner.added = append(owner.added, address)
		if err := exec.CommandContext(ctx, "/sbin/ifconfig", "lo0", "inet", address.String(), "netmask", "255.255.255.255", "alias").Run(); err != nil {
			return owner, err
		}
		actual, current, err := macOSImportedExecutionAliasInventory()
		if err != nil || actual != owner.index || current[address] != (macOSImportedExecutionAliasState{owner.index, 32}) {
			return owner, errors.Join(err, errors.New("original fixture alias readback changed"))
		}
	}
	return owner, nil
}
func (owner *macOSImportedExecutionAliasOwner) release() {
	if owner != nil && owner.unlock {
		owner.unlock = false
		macOSImportedExecutionAliasGate.Unlock()
	}
}
func (owner *macOSImportedExecutionAliasOwner) Close(ctx context.Context, join func(context.Context) error) error {
	if owner == nil {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("alias cleanup requires original caller")
	}
	if owner.closed {
		return nil
	}
	// The caller must join the original Manager, every portable relay worker and
	// encrypted peer before aliases can disappear. Failed joins retain ownership.
	if join == nil {
		return errors.New("alias cleanup lacks original transport joins")
	}
	if err := join(ctx); err != nil {
		return err
	}
	index, _, err := macOSImportedExecutionAliasInventory()
	if err != nil || index != owner.index {
		return errors.Join(err, errors.New("original alias interface changed"))
	}
	for len(owner.added) > 0 {
		address := owner.added[len(owner.added)-1]
		actual, present, err := macOSImportedExecutionAliasInventory()
		if err != nil || actual != owner.index {
			return errors.Join(err, errors.New("original alias interface changed before removal"))
		}
		state, exists := present[address]
		if !exists {
			owner.added = owner.added[:len(owner.added)-1]
			continue
		}
		if state != (macOSImportedExecutionAliasState{owner.index, 32}) {
			return errors.New("original alias address or mask was replaced")
		}
		bounded, stop := context.WithTimeout(ctx, 2*time.Second)
		err = exec.CommandContext(bounded, "/sbin/ifconfig", "lo0", "inet", address.String(), "-alias").Run()
		stop()
		if err != nil {
			return err
		}
		actual, present, err = macOSImportedExecutionAliasInventory()
		if err != nil || actual != owner.index || present[address].index != 0 {
			return errors.Join(err, errors.New("original alias did not retire"))
		}
		owner.added = owner.added[:len(owner.added)-1]
	}
	owner.closed = true
	owner.release()
	return nil
}
