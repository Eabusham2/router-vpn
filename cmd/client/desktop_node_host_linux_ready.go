//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// This is a comparison captured before the child can create a tunnel. The
// original child's native source still selects and owns its physical sockets.
// Private Router proof and selected DNS targets never become outer exceptions.
func captureDesktopLinuxNodeRunningPath(policy *mobilemultihop.DesktopNodePolicy) (mobiletor.DesktopLinuxNodeRunningSelection, error) {
	var selected mobiletor.DesktopLinuxNodeRunningSelection
	if policy == nil || policy.Validate() != nil || policy.Metadata().TargetOS != "linux" {
		return selected, errors.New("Linux running path requires its original sealed policy")
	}
	capture, err := policy.Capture()
	if err != nil {
		return selected, err
	}
	seen := make(map[mobiletor.DesktopLinuxSocketDestination]bool)
	for _, root := range capture.PhysicalRoots {
		if root.DynamicSOCKSUDP {
			return selected, errors.New("Linux running path has no captured dynamic relay owner")
		}
		for _, destination := range root.Destinations {
			ip, err := netip.ParseAddr(destination.Host)
			if err != nil || ip.String() != destination.Host || ip.Zone() != "" || ip.Is4In6() ||
				ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || destination.Port < 1 || destination.Port > 65535 ||
				destination.Network != "tcp" && destination.Network != "udp" {
				return selected, errors.New("Linux running path lost its compiled literal outer destination")
			}
			value := mobiletor.DesktopLinuxSocketDestination{Network: destination.Network, Address: netip.AddrPortFrom(ip, uint16(destination.Port))}
			if !seen[value] {
				seen[value] = true
				selected.Destinations = append(selected.Destinations, value)
			}
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return selected, err
	}
	seenInterfaces := make(map[mobiletor.DesktopLinuxSocketInterface]bool)
	for _, iface := range interfaces {
		name := strings.ToLower(iface.Name)
		if len(iface.HardwareAddr) == 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 ||
			strings.Contains(name, "tun") || strings.Contains(name, "wireguard") || strings.HasPrefix(name, "wg") || strings.Contains(name, "router-vpn") {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil || iface.Index < 1 {
			return selected, errors.Join(err, errors.New("Linux running path lost its original interface inventory"))
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return selected, errors.New("Linux running path has an unreadable original interface address")
			}
			ip := prefix.Addr()
			if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" ||
				!ip.Is4() && capture.IPv6Mode == "off" {
				continue
			}
			value := mobiletor.DesktopLinuxSocketInterface{Name: iface.Name, Index: uint32(iface.Index), Address: ip}
			if !seenInterfaces[value] {
				seenInterfaces[value] = true
				selected.Interfaces = append(selected.Interfaces, value)
			}
		}
	}
	if len(selected.Interfaces) == 0 || len(selected.Interfaces) > 64 || len(selected.Destinations) == 0 || len(selected.Destinations) > 256 {
		return mobiletor.DesktopLinuxNodeRunningSelection{}, errors.New("Linux running path exceeds its bounded original physical selection")
	}
	return selected, nil
}

func (h *desktopLinuxNodeHost) runningPolicyLocked(ctx context.Context) error {
	if err := h.runningLocked(ctx); err != nil {
		return err
	}
	t := h.transaction
	if err := t.enter(ctx); err != nil {
		return err
	}
	defer func() { t.gate <- struct{}{} }()
	if t.baseline == nil || t.prepared == nil || t.retiring || t.retired || t.closed || t.pending != nil {
		return errors.New("Linux running proof lost its original native protection creator")
	}
	return t.baseline.ObserveRunning(ctx, t.prepared.Protection, h.physical)
}

func validateDesktopLinuxNodeReady(record mobilemultihop.DesktopNodeReadyRecord, live desktopNodeMTURecord,
	started, now time.Time, captured *mobilemultihop.DesktopNodeReadyRecord, fresh bool) error {
	if started.IsZero() || record.ProvedAt < started.UnixMilli() || record.ProvedAt > now.UnixMilli() ||
		fresh && now.UnixMilli()-record.ProvedAt > 30000 || !fresh && (captured == nil || *captured != record) {
		return errors.New("Linux Router readiness is stale or belongs to another original start")
	}
	provedExpiry := live.Expired && live.Restored && !live.Active && live.Failure == "captured MTU lease expired; original MTU restored"
	if live.Failure != "" && !provedExpiry || live.Interface != record.InterfaceName ||
		live.Reader == 1 && live.Index != int(record.InterfaceIndex) ||
		fresh && (live.Active || live.Restored || live.Expired || live.Failure != "" || live.Reader != 1 ||
			live.Index != int(record.InterfaceIndex) || live.MTU != record.MTU || live.Generation != 0 || live.Request != "" || live.Lease != "") {
		return errors.New("Linux Router readiness lost its captured initial native TUN reader")
	}
	return nil
}

// The private child receipt is checked against the actual kernel interface.
// The returned record is still not a routed Router proof or Connected state.
func desktopLinuxNodeTUNCurrent(live desktopNodeMTURecord) error {
	if live.Index < 1 || validateMTULiveInterface(live.Interface) != nil || live.MTU < 1280 || live.MTU > 9000 {
		return errors.New("Linux Router proof has no captured native interface")
	}
	iface, err := net.InterfaceByIndex(live.Index)
	if err != nil || iface.Name != live.Interface || iface.Index != live.Index || iface.MTU != live.MTU ||
		iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return errors.Join(err, errors.New("Linux Router proof changed its actual kernel TUN identity or MTU"))
	}
	return nil
}

func (h *desktopLinuxNodeHost) readReadyLocked(ctx context.Context, fresh bool) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error) {
	var empty mobilemultihop.DesktopNodeReadyRecord
	var noLive desktopNodeMTURecord
	if err := h.runningPolicyLocked(ctx); err != nil {
		return empty, noLive, err
	}
	digest, err := h.selection.ControlSHA256()
	if err != nil {
		return empty, noLive, err
	}
	raw, err := readDesktopRuntimeFile(h.launch, "node-ready.json", mobilemultihop.DesktopNodeReadyRecordLimit)
	if err != nil {
		return empty, noLive, err
	}
	record, err := mobilemultihop.ParseDesktopNodeReadyRecord(raw, h.policy, digest)
	if err != nil {
		return empty, noLive, err
	}
	// Ready is published just before the first heartbeat. Preserve only the
	// actual missing-file condition as a bounded wait; malformed/stale reads
	// cannot turn into retries or replacement readiness.
	if _, err := readDesktopRuntimeFile(h.launch, "node-mtu-status.json", 4096); err != nil {
		return empty, noLive, err
	}
	live, err := readDesktopNodeMTU(h.launch)
	if err != nil {
		return empty, noLive, err
	}
	if err := validateDesktopLinuxNodeReady(record, live, h.started, time.Now(), h.ready, fresh); err != nil {
		return empty, noLive, err
	}
	if err := desktopLinuxNodeTUNCurrent(live); err != nil {
		return empty, noLive, err
	}
	if err := h.runningPolicyLocked(ctx); err != nil {
		return empty, noLive, err
	}
	return record, live, nil
}

// A failed readiness/proof cannot leave a naturally retiring child waiting for
// its short original ACK window. Cancellation retains the exact source/process
// and uses the existing joined retirement; it does not relax any frame timeout.
func (h *desktopLinuxNodeHost) failProofLocked(failure error) error {
	h.proof = nil
	if h.process == nil {
		return failure
	}
	h.closing = true
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return errors.Join(failure, h.retireLocked(ctx, false))
}

func (h *desktopLinuxNodeHost) WaitReady(parent context.Context) (record mobilemultihop.DesktopNodeReadyRecord, failure error) {
	if err := h.enter(parent); err != nil {
		return record, err
	}
	defer func() { h.gate <- struct{}{} }()
	defer func() {
		if failure != nil {
			failure = h.failProofLocked(failure)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	if h.operation == nil {
		return record, errors.New("Linux Router readiness has no original startup operation")
	}
	stop := context.AfterFunc(h.operation, cancel)
	defer stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		var err error
		record, _, err = h.readReadyLocked(ctx, h.ready == nil)
		if err == nil {
			copy := record
			h.ready = &copy
			return record, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return mobilemultihop.DesktopNodeReadyRecord{}, err
		}
		select {
		case <-ctx.Done():
			return mobilemultihop.DesktopNodeReadyRecord{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
