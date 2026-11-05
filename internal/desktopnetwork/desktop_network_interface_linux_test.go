//go:build linux

package desktopnetwork

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func interfaceAttribute(kind uint16, value []byte) []byte {
	raw := make([]byte, (len(value)+7)&^3)
	binary.LittleEndian.PutUint16(raw, uint16(4+len(value)))
	binary.LittleEndian.PutUint16(raw[2:], kind)
	copy(raw[4:], value)
	return raw
}

func interfaceLinkBody(name string, mtu uint32) []byte {
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[4:], 7)
	binary.LittleEndian.PutUint32(body[8:], syscall.IFF_UP|syscall.IFF_RUNNING|syscall.IFF_MULTICAST)
	value := make([]byte, 4)
	binary.LittleEndian.PutUint32(value, mtu)
	body = append(body, interfaceAttribute(3, append([]byte(name), 0))...)
	body = append(body, interfaceAttribute(4, value)...)
	return append(body, interfaceAttribute(1, []byte{2, 3, 4, 5, 6, 7})...)
}

func interfaceAddressBody(family, prefix byte, address net.IP) []byte {
	body := make([]byte, 8)
	body[0], body[1] = family, prefix
	binary.LittleEndian.PutUint32(body[4:], 7)
	if family == syscall.AF_INET {
		address = address.To4()
	} else {
		address = address.To16()
	}
	return append(body, interfaceAttribute(2, address)...)
}

func TestNetworkInterfaceOriginalContextAndExactFields(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reads := 0
	dump := func(caller context.Context, request int, response uint16) ([]syscall.NetlinkMessage, error) {
		if caller != ctx {
			t.Fatal("interface dump replaced original caller")
		}
		reads++
		if request == syscall.RTM_GETLINK && response == syscall.RTM_NEWLINK {
			return []syscall.NetlinkMessage{{Data: interfaceLinkBody("eth0", 1500)}}, nil
		}
		if request != syscall.RTM_GETADDR || response != syscall.RTM_NEWADDR {
			t.Fatal("interface read widened native inventory")
		}
		return []syscall.NetlinkMessage{{Data: interfaceAddressBody(syscall.AF_INET, 24, net.ParseIP("192.0.2.17"))}, {Data: interfaceAddressBody(syscall.AF_INET6, 64, net.ParseIP("2001:db8::4"))}}, nil
	}
	current, addresses, err := linuxInterfaceContext(ctx, 7, dump)
	if err != nil || current.Name != "eth0" || current.Index != 7 || current.MTU != 1500 || current.Flags != net.FlagUp|net.FlagRunning|net.FlagMulticast || current.HardwareAddr.String() != "02:03:04:05:06:07" || reads != 3 {
		t.Fatal("bounded native projection changed physical hash fields", current, err, reads)
	}
	if len(addresses) != 2 || addresses[0].String() != "192.0.2.17/24" || addresses[1].String() != "2001:db8::4/64" {
		t.Fatal("native address projection masked original host addresses", addresses)
	}
}

func TestNetworkInterfaceRejectsLateAndChangedRead(t *testing.T) {
	for _, mode := range []string{"first-cancel", "address-cancel", "final-cancel", "changed-name", "changed-mtu", "duplicate-index"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			reads := 0
			dump := func(caller context.Context, request int, response uint16) ([]syscall.NetlinkMessage, error) {
				if caller != ctx {
					t.Fatal("read replaced original caller")
				}
				reads++
				if mode == "first-cancel" && reads == 1 || mode == "address-cancel" && reads == 2 || mode == "final-cancel" && reads == 3 {
					cancel()
				}
				if request == syscall.RTM_GETADDR {
					return []syscall.NetlinkMessage{{Data: interfaceAddressBody(syscall.AF_INET, 24, net.ParseIP("192.0.2.17"))}}, nil
				}
				name, mtu := "eth0", uint32(1500)
				if reads == 3 && mode == "changed-name" {
					name = "replacement"
				}
				if reads == 3 && mode == "changed-mtu" {
					mtu = 1400
				}
				rows := []syscall.NetlinkMessage{{Data: interfaceLinkBody(name, mtu)}}
				if mode == "duplicate-index" {
					rows = append(rows, rows[0])
				}
				return rows, nil
			}
			current, addresses, err := linuxInterfaceContext(ctx, 7, dump)
			if err == nil || current != nil || addresses != nil {
				t.Fatal("late or replaced native interface acquired path authority", err)
			}
			if ctx.Err() != nil && !errors.Is(err, context.Canceled) {
				t.Fatal("native interface discarded cancellation cause", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if current, addresses, err := InterfaceContext(ctx, 7); current != nil || addresses != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("expired native interface entered live inventory", err)
	}
}

func TestNetworkInterfaceInventoryRetainsOriginalObservation(t *testing.T) {
	for _, mode := range []string{"exact-fields", "late-cancel", "duplicate-index"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			dump := func(caller context.Context, request int, response uint16) ([]syscall.NetlinkMessage, error) {
				if caller != ctx || request != syscall.RTM_GETLINK || response != syscall.RTM_NEWLINK {
					t.Fatal("inventory replaced caller or native query")
				}
				rows := []syscall.NetlinkMessage{{Data: interfaceLinkBody("eth0", 1500)}}
				if mode == "late-cancel" {
					cancel()
				}
				if mode == "duplicate-index" {
					rows = append(rows, rows[0])
				}
				return rows, nil
			}
			links, err := linuxInterfacesContext(ctx, dump)
			if mode == "exact-fields" {
				if err != nil || len(links) != 1 || links[0].Name != "eth0" || links[0].Index != 7 || links[0].MTU != 1500 || links[0].HardwareAddr.String() != "02:03:04:05:06:07" || links[0].Flags != net.FlagUp|net.FlagRunning|net.FlagMulticast {
					t.Fatal("inventory altered original native fields", links, err)
				}
			} else if err == nil || links != nil {
				t.Fatal("late or duplicate inventory admitted", links, err)
			}
			if mode == "late-cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}
