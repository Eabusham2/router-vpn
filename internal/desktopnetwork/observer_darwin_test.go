//go:build darwin

package desktopnetwork

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func darwinCloneNativeObject(t *testing.T, object DesktopNetworkObject) (DesktopNetworkObject, []byte) {
	t.Helper()
	prefix, err := netip.ParsePrefix(object.Destination)
	if err != nil {
		t.Fatal(err)
	}
	address := func(value []byte) []byte {
		if object.Family == 4 {
			wire := make([]byte, syscall.SizeofSockaddrInet4)
			wire[0], wire[1] = byte(len(wire)), syscall.AF_INET
			copy(wire[4:8], value)
			return wire
		}
		wire := make([]byte, syscall.SizeofSockaddrInet6)
		wire[0], wire[1] = byte(len(wire)), syscall.AF_INET6
		copy(wire[8:24], value)
		return wire
	}
	data := address(prefix.Addr().AsSlice())
	addrs := int32(syscall.RTA_DST)
	if object.Gateway != "" {
		gateway, err := netip.ParseAddr(object.Gateway)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, address(gateway.AsSlice())...)
		addrs |= syscall.RTA_GATEWAY
	}
	if object.Flags&syscall.RTF_HOST == 0 {
		data = append(data, address(net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()))...)
		addrs |= syscall.RTA_NETMASK
	}
	header := syscall.RtMsghdr{Msglen: uint16(syscall.SizeofRtMsghdr + len(data)), Version: syscall.RTM_VERSION,
		Type: syscall.RTM_GET, Index: uint16(object.Index), Addrs: addrs, Flags: int32(object.Flags) | syscall.RTF_UP | syscall.RTF_DONE,
		Rmx: syscall.RtMetrics{Mtu: object.MTU, Hopcount: object.Priority}}
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	wire.Write(data)
	raw := wire.Bytes()
	original := append([]byte(nil), raw...)
	messages, err := darwinMessages(raw)
	if err != nil || len(messages) != 1 {
		t.Fatal("native clone fixture did not decode one complete route", err)
	}
	route, ok := messages[0].(*syscall.RouteMessage)
	if !ok {
		t.Fatal("native clone fixture changed its message type")
	}
	actual, err := ParseDesktopDarwinNetworkObject(route)
	if err != nil || actual != object || !bytes.Equal(raw, original) {
		t.Fatal("native clone decoding changed its original route identity", actual, err)
	}
	return actual, original
}

func TestDarwinCloneNativeScopeProjectionAndFailure(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			parent, clone := darwinCloneScopeFixture(family)
			parent, parentWire := darwinCloneNativeObject(t, parent)
			clone, cloneWire := darwinCloneNativeObject(t, clone)
			originalParent, originalClone := parent, clone
			snapshot := Snapshot{Links: []Link{{Index: parent.Index, Name: "captured-native-fixture", MTU: 1500}}, Objects: []DesktopNetworkObject{parent, clone}}
			projected, key, err := project(snapshot, nil)
			if err != nil || key == "" || len(projected.Objects) != 1 || projected.Objects[0] != parent ||
				parent != originalParent || clone != originalClone || snapshot.Objects[0] != originalParent || snapshot.Objects[1] != originalClone ||
				len(parentWire) == 0 || len(cloneWire) == 0 {
				t.Fatal("native scope derivation lost its captured parent or changed bytes", err)
			}
			clone.Flags |= 0x40000 // Refcount/expiry are not present in this capture.
			clone, _ = darwinCloneNativeObject(t, clone)
			snapshot.Objects[1] = clone
			if _, _, err := project(snapshot, nil); err == nil || !strings.Contains(err.Error(), "proto3_equal=false") || strings.Contains(err.Error(), clone.Gateway) {
				t.Fatal("native unsupported cache state lost its private failure", err)
			}
			tracker := &Tracker{ctx: context.Background(), physical: Snapshot{Objects: []DesktopNetworkObject{parent}}}
			tracker.observe(Event{Kind: "route", Action: "add", Index: clone.Index, Object: clone}, nil)
			if tracker.failure == nil || !strings.Contains(tracker.failure.Error(), "proto3_equal=false") {
				t.Fatal("native event discarded its original bounded failure")
			}
			failure := tracker.failure
			tracker.observe(Event{Kind: "route", Action: "add", Index: originalClone.Index, Object: originalClone}, nil)
			if tracker.failure != failure {
				t.Fatal("later valid cache event replaced the original failure")
			}
		})
	}
}

func TestDarwinUnusedInterfaceNativeReadbackComposition(t *testing.T) {
	link := Link{Index: 31, Name: "captured-unused", MTU: 0}
	for _, name := range []string{link.Name, "replacement"} {
		payload := darwinUnusedTestPayload(uint16(link.Index), name, 1, nil)
		header := syscall.IfMsghdr{Msglen: uint16(syscall.SizeofIfMsghdr + len(payload)), Version: syscall.RTM_VERSION,
			Type: syscall.RTM_IFINFO, Index: uint16(link.Index), Addrs: syscall.RTA_IFP, Data: syscall.IfData{Type: 1}}
		var wire bytes.Buffer
		if err := binary.Write(&wire, binary.LittleEndian, header); err != nil {
			t.Fatal(err)
		}
		wire.Write(payload)
		calls := 0
		actual, err := desktopDarwinCaptureUnusedInterface(link, func(index uint32) (desktopDarwinInterfaceReadback, error) {
			return darwinInterfaceReadback(index, func(facility, selected int) ([]byte, error) {
				calls++
				if facility != syscall.NET_RT_IFLIST || selected != int(link.Index) {
					t.Fatal("unused native link changed its exact query selector")
				}
				return wire.Bytes(), nil
			})
		})
		if calls != 1 || (err == nil) != (name == link.Name) {
			t.Fatal("native IFINFO and AF_LINK did not require the complete captured identity", err, calls)
		}
		if err == nil {
			clear(wire.Bytes())
			if actual.Name != link.Name || actual.MTU != 0 || !desktopDarwinUnusedInterfaceMatches(actual) {
				t.Fatal("native unused interface lost its owned original bytes")
			}
		}
	}
	// The diagnostic decoder may ignore valid informational frames. They
	// still prevent the stronger claim of one complete native IFINFO record.
	payload := darwinUnusedTestPayload(uint16(link.Index), link.Name, 1, nil)
	header := syscall.IfMsghdr{Msglen: uint16(syscall.SizeofIfMsghdr + len(payload)), Version: syscall.RTM_VERSION,
		Type: syscall.RTM_IFINFO, Index: uint16(link.Index), Addrs: syscall.RTA_IFP, Data: syscall.IfData{Type: 1}}
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	wire.Write(payload)
	extra := make([]byte, syscall.SizeofRtMsghdr)
	binary.LittleEndian.PutUint16(extra, uint16(len(extra)))
	extra[2], extra[3] = syscall.RTM_VERSION, syscall.RTM_MISS
	wire.Write(extra)
	if _, err := desktopDarwinCaptureUnusedInterface(link, func(index uint32) (desktopDarwinInterfaceReadback, error) {
		return darwinInterfaceReadback(index, func(int, int) ([]byte, error) { return wire.Bytes(), nil })
	}); err == nil {
		t.Fatal("extra native records became a complete one-interface observation")
	}
}

func TestDarwinInterfaceReadbackBoundsAndNativeFields(t *testing.T) {
	link, _ := darwinTestFrame(t, syscall.RTM_IFINFO)
	binary.LittleEndian.PutUint32(link[8:12], 0)
	binary.LittleEndian.PutUint16(link[12:14], 5)
	link[16], link[18], link[19] = 1, 8, 6
	binary.LittleEndian.PutUint32(link[24:28], 0)
	address, _ := darwinTestFrame(t, syscall.RTM_NEWADDR)
	binary.LittleEndian.PutUint16(address[12:14], 5)
	wire := append(append([]byte(nil), link...), address...)
	calls := 0
	observed, err := darwinInterfaceReadback(5, func(facility, index int) ([]byte, error) {
		calls++
		if facility != syscall.NET_RT_IFLIST || index != 5 {
			t.Fatal("Darwin diagnostic changed the captured native readback selector")
		}
		return wire, nil
	})
	want := desktopDarwinInterfaceReadback{Bytes: len(wire), Records: 2, Addresses: 1,
		Shapes: []desktopDarwinInterfaceShape{{Index: 5, MTU: 0, Flags: 0, Type: 1, Physical: 8, AddressLength: 6}}}
	if err != nil || calls != 1 || !reflect.DeepEqual(observed, want) {
		t.Fatal("Darwin readback did not preserve the exact numeric native fields", observed, err)
	}
	clear(wire)
	if !reflect.DeepEqual(observed, want) {
		t.Fatal("Darwin readback retained the borrowed native buffer")
	}
	route, _ := darwinTestFrame(t, syscall.RTM_ADD)
	for _, invalid := range [][]byte{link[:10], make([]byte, 64<<10+1), bytes.Repeat(address, 257), bytes.Repeat(link, 5), route} {
		if _, err := darwinInterfaceReadback(5, func(int, int) ([]byte, error) { return invalid, nil }); err == nil {
			t.Fatal("Darwin diagnostic accepted an incomplete or unbounded native readback")
		}
	}
	if _, err := darwinInterfaceReadback(5, func(int, int) ([]byte, error) { return nil, syscall.EPERM }); err != syscall.EPERM {
		t.Fatal("Darwin diagnostic hid a native readback error", err)
	}
	for _, index := range []uint32{0, 65536} {
		if _, err := darwinInterfaceReadback(index, func(int, int) ([]byte, error) {
			t.Fatal("invalid Darwin index became a whole-host readback")
			return nil, nil
		}); err == nil {
			t.Fatal("invalid Darwin readback index was accepted")
		}
	}
}

func darwinTestFrame(t *testing.T, kind byte) ([]byte, syscall.RoutingMessage) {
	t.Helper()
	var header any
	var expected syscall.RoutingMessage
	payload := []byte{16, syscall.AF_INET, 0, 0, 203, 0, 113, 9, 0, 0, 0, 0, 0, 0, 0, 0}
	switch kind {
	case syscall.RTM_ADD, syscall.RTM_DELETE, syscall.RTM_CHANGE, syscall.RTM_GET,
		syscall.RTM_LOSING, syscall.RTM_REDIRECT, syscall.RTM_LOCK:
		value := &syscall.RouteMessage{Header: syscall.RtMsghdr{
			Msglen: uint16(syscall.SizeofRtMsghdr + len(payload)), Version: syscall.RTM_VERSION,
			Type: kind, Index: 9, Flags: syscall.RTF_HOST | syscall.RTF_UP,
			Addrs: syscall.RTA_DST, Pid: 71, Seq: 53,
			Rmx: syscall.RtMetrics{Mtu: 1400, Hopcount: 3}}, Data: payload}
		header, expected = value.Header, value
	case syscall.RTM_IFINFO:
		value := &syscall.InterfaceMessage{Header: syscall.IfMsghdr{
			Msglen: uint16(syscall.SizeofIfMsghdr + len(payload)), Version: syscall.RTM_VERSION,
			Type: kind, Index: 9, Flags: syscall.IFF_UP, Addrs: syscall.RTA_IFP,
			Data: syscall.IfData{Mtu: 1400, Metric: 3}}, Data: payload}
		header, expected = value.Header, value
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
		value := &syscall.InterfaceAddrMessage{Header: syscall.IfaMsghdr{
			Msglen: uint16(syscall.SizeofIfaMsghdr + len(payload)), Version: syscall.RTM_VERSION,
			Type: kind, Index: 9, Addrs: syscall.RTA_IFA, Metric: 3}, Data: payload}
		header, expected = value.Header, value
	default:
		t.Fatal("unknown native fixture kind", kind)
	}
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	wire.Write(payload)
	return wire.Bytes(), expected
}

func TestDarwinNetworkMessageAlignmentAndOwnership(t *testing.T) {
	kinds := []byte{syscall.RTM_ADD, syscall.RTM_DELETE, syscall.RTM_CHANGE, syscall.RTM_GET,
		syscall.RTM_LOSING, syscall.RTM_REDIRECT, syscall.RTM_LOCK,
		syscall.RTM_IFINFO, syscall.RTM_NEWADDR, syscall.RTM_DELADDR}
	for offset := 0; offset < 8; offset++ {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			wire := make([]byte, offset)
			var expected []syscall.RoutingMessage
			for _, kind := range kinds {
				frame, value := darwinTestFrame(t, kind)
				wire = append(wire, frame...)
				expected = append(expected, value)
			}
			actual, err := darwinMessages(wire[offset:])
			if err != nil || !reflect.DeepEqual(actual, expected) {
				t.Fatal("valid unaligned native records lost their exact header/payload", err)
			}
			for _, message := range actual[:7] {
				route := message.(*syscall.RouteMessage)
				if len(route.Data) != 16 || cap(route.Data) != 16 {
					t.Fatal("native sockaddr payload lost its exact wire length")
				}
				object, err := ParseDesktopDarwinNetworkObject(route)
				if err != nil || object.Destination != "203.0.113.9/32" || object.Index != 9 || object.MTU != 1400 {
					t.Fatal("decoded native route lost its captured identity", object, err)
				}
			}
			clear(wire)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("reused receive buffer mutated a captured native message")
			}
		})
	}
}

func TestDarwinNetworkMessageSocketAddressBounds(t *testing.T) {
	for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			length, expected := syscall.SizeofSockaddrInet4, "203.0.113.9/32"
			if family == syscall.AF_INET6 {
				length, expected = syscall.SizeofSockaddrInet6, "2001:db8::9/128"
			}
			payload := make([]byte, length)
			payload[0], payload[1] = byte(length), family
			if family == syscall.AF_INET {
				copy(payload[4:8], []byte{203, 0, 113, 9})
			} else {
				copy(payload[8:24], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9})
			}
			for _, truncate := range []bool{false, true} {
				data := payload
				if truncate {
					data = payload[:length-1]
				}
				header := syscall.RtMsghdr{Msglen: uint16(syscall.SizeofRtMsghdr + len(data)),
					Version: syscall.RTM_VERSION, Type: syscall.RTM_GET, Index: 9,
					Flags: syscall.RTF_HOST, Addrs: syscall.RTA_DST}
				var frame bytes.Buffer
				if err := binary.Write(&frame, binary.LittleEndian, header); err != nil {
					t.Fatal(err)
				}
				frame.Write(data)
				messages, err := darwinMessages(frame.Bytes())
				if err != nil || len(messages) != 1 {
					t.Fatal("valid route header rejected", err)
				}
				route := messages[0].(*syscall.RouteMessage)
				if len(route.Data) != len(data) || cap(route.Data) != len(data) {
					t.Fatal("owned allocation changed the exact native payload")
				}
				object, err := ParseDesktopDarwinNetworkObject(route)
				if truncate {
					if err == nil {
						t.Fatal("owned allocation completed a truncated wire address")
					}
				} else if err != nil || object.Destination != expected {
					t.Fatal("minimal native sockaddr lost its exact identity", object, err)
				}
			}
		})
	}
}

func TestDarwinNetworkMessageRejectsIncompleteHeaders(t *testing.T) {
	for _, kind := range []byte{syscall.RTM_ADD, syscall.RTM_IFINFO, syscall.RTM_NEWADDR} {
		frame, _ := darwinTestFrame(t, kind)
		size := map[byte]int{syscall.RTM_ADD: syscall.SizeofRtMsghdr,
			syscall.RTM_IFINFO: syscall.SizeofIfMsghdr, syscall.RTM_NEWADDR: syscall.SizeofIfaMsghdr}[kind]
		for length := 4; length < size; length++ {
			t.Run(fmt.Sprintf("%d/%d", kind, length), func(t *testing.T) {
				truncated := append([]byte(nil), frame[:length]...)
				binary.LittleEndian.PutUint16(truncated, uint16(length))
				if messages, err := darwinMessages(truncated); err == nil || messages != nil {
					t.Fatal("truncated native header reached routing policy", length)
				}
			})
		}
	}
	frame, _ := darwinTestFrame(t, syscall.RTM_GET)
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b, 0) },
		func(b []byte) { binary.LittleEndian.PutUint16(b, uint16(len(b)+1)) },
		func(b []byte) { b[2]++ },
		func(b []byte) { b[3] = 255 },
	} {
		bad := append([]byte(nil), frame...)
		mutate(bad)
		if messages, err := darwinMessages(bad); err == nil || messages != nil {
			t.Fatal("malformed native record was admitted")
		}
	}
	if messages, err := darwinMessages(append(frame, 1, 2, 3)); err == nil || messages != nil {
		t.Fatal("trailing partial record was admitted")
	}
	if _, err := darwinMessageHeader(frame, syscall.SizeofRtMsghdr, new(uint32)); err == nil {
		t.Fatal("native header ABI size mismatch was admitted")
	}
}

func TestDarwinInformationalMessageFraming(t *testing.T) {
	for _, kind := range []byte{syscall.RTM_MISS, syscall.RTM_RESOLVE, syscall.RTM_NEWMADDR,
		syscall.RTM_DELMADDR, syscall.RTM_NEWMADDR2} {
		size := syscall.SizeofIfmaMsghdr
		if kind == syscall.RTM_MISS || kind == syscall.RTM_RESOLVE {
			size = syscall.SizeofRtMsghdr
		} else if kind == syscall.RTM_NEWMADDR2 {
			size = syscall.SizeofIfmaMsghdr2
		}
		for _, length := range []int{size - 1, size} {
			frame := make([]byte, length)
			binary.LittleEndian.PutUint16(frame, uint16(length))
			frame[2], frame[3] = syscall.RTM_VERSION, kind
			messages, err := darwinMessages(frame)
			if (length < size) != (err != nil) || len(messages) != 0 {
				t.Fatal("informational record bypassed exact native framing", kind, length, err)
			}
		}
	}
}

func darwinTestNotificationSocket(t *testing.T) (*os.File, int) {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal("native notification fixture socket failed", err)
	}
	var receiver *os.File
	t.Cleanup(func() {
		if receiver != nil {
			receiver.Close()
		} else {
			syscall.Close(pair[0])
		}
		syscall.Close(pair[1])
	})
	for _, fd := range pair {
		syscall.CloseOnExec(fd)
		if err := syscall.SetNonblock(fd, true); err != nil {
			t.Fatal("native fixture lost nonblocking socket", err)
		}
	}
	receiver = os.NewFile(uintptr(pair[0]), "owned-darwin-notification-fixture")
	if receiver == nil {
		t.Fatal("native notification fixture has no original descriptor")
	}
	return receiver, pair[1]
}

func TestDarwinNetworkReceiveNativeSocket(t *testing.T) {
	for _, name := range []string{"payload", "payload-truncated", "empty-buffer", "would-block"} {
		t.Run(name, func(t *testing.T) {
			receiver, sender := darwinTestNotificationSocket(t)
			raw, err := receiver.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			read := func(buffer []byte) (size, flags int, received error) {
				if err := raw.Control(func(fd uintptr) {
					size, flags, received = darwinReceiveNotification(fd, buffer)
				}); err != nil {
					t.Fatal("native read lost its original socket", err)
				}
				return
			}
			payload := []byte("captured native datagram")
			buffer := make([]byte, 64)
			if name == "would-block" {
				if size, flags, err := read(buffer); size != 0 || flags != 0 || (!errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK)) {
					t.Fatal("empty nonblocking socket did not retain its kernel retry result", size, flags, err)
				}
				return
			}
			if n, err := syscall.Write(sender, payload); err != nil || n != len(payload) {
				t.Fatal("native fixture datagram was not delivered completely", n, err)
			}
			if name == "empty-buffer" {
				if size, flags, err := read(nil); err == nil || size != 0 || flags != 0 {
					t.Fatal("absent receive storage consumed or admitted a native message", size, flags, err)
				}
			}
			if name == "payload-truncated" {
				buffer = buffer[:4]
			}
			size, flags, err := read(buffer)
			if name == "payload-truncated" {
				if err != nil || size != len(buffer) || flags&syscall.MSG_TRUNC == 0 || !bytes.Equal(buffer, payload[:len(buffer)]) {
					t.Fatal("native recvmsg lost its actual datagram truncation witness", size, flags, err)
				}
			} else if err != nil || size != len(payload) || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || !bytes.Equal(buffer[:size], payload) {
				t.Fatal("native recvmsg changed its complete owned payload", size, flags, err)
			}
		})
	}
	t.Run("invalid-descriptor", func(t *testing.T) {
		if size, flags, err := darwinReceiveNotification(^uintptr(0), make([]byte, 8)); !errors.Is(err, syscall.EBADF) || size != 0 || flags != 0 {
			t.Fatal("native receive concealed an invalid original descriptor", size, flags, err)
		}
	})
}

func TestDarwinNetworkReceiveLoopAndJoinedClose(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned-notification", true: "empty-notification"}[empty], func(t *testing.T) {
			receiver, sender := darwinTestNotificationSocket(t)
			type observation struct {
				event Event
				err   error
			}
			observed := make(chan observation, 2)
			owner := &darwinObserver{file: receiver, joined: make(chan struct{}), waiters: make(map[int32]chan error),
				emit: func(event Event, err error) { observed <- observation{event, err} }}
			go owner.run()
			t.Cleanup(func() {
				receiver.Close()
				select {
				case <-owner.joined:
				case <-time.After(2 * time.Second):
					t.Error("native fixture retained its receive goroutine")
				}
			})
			frame, _ := darwinTestFrame(t, syscall.RTM_IFINFO)
			if empty {
				frame = nil
			}
			if n, err := syscall.SendmsgN(sender, frame, nil, nil, 0); err != nil || n != len(frame) {
				t.Fatal("native fixture notification was not delivered completely", n, err)
			}
			select {
			case result := <-observed:
				if empty {
					if result.err == nil || result.err.Error() != "Darwin network notification was dropped or truncated" || result.event.Kind != "" {
						t.Fatal("empty native message became network state", result)
					}
				} else if result.err != nil || result.event.Kind != "link" || result.event.Action != "change" || result.event.Index != 9 {
					t.Fatal("actual receive loop lost its original native notification", result)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("actual receive loop did not observe its owned datagram")
			}
			closed := make(chan error, 1)
			go func() { closed <- owner.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal("original native socket close failed", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("original native receive loop did not join on close")
			}
			select {
			case <-owner.joined:
			default:
				t.Fatal("native socket close returned before its receive loop joined")
			}
			if err := owner.Close(); err != nil {
				t.Fatal("joined native socket could not close idempotently", err)
			}
		})
	}
}

func darwinDump2WireFixture(t *testing.T, object DesktopNetworkObject, parentFlags uint32, references, expires int32) []byte {
	t.Helper()
	object.darwinCache = nil
	_, old := darwinCloneNativeObject(t, object)
	var original syscall.RtMsghdr
	if _, err := binary.Decode(old[:syscall.SizeofRtMsghdr], binary.LittleEndian, &original); err != nil {
		t.Fatal(err)
	}
	header := desktopDarwinRouteHeader2{Msglen: original.Msglen, Version: syscall.RTM_VERSION, Type: syscall.RTM_GET2, Index: original.Index,
		Flags: int32(object.Flags) | syscall.RTF_UP, Addrs: original.Addrs, References: references, ParentFlags: int32(parentFlags), Rmx: original.Rmx}
	header.Rmx.Expire = expires
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if wire.Len() != syscall.SizeofRtMsghdr {
		t.Fatal("DUMP2 fixture does not match the actual Darwin header ABI", wire.Len())
	}
	wire.Write(old[syscall.SizeofRtMsghdr:])
	return wire.Bytes()
}

func TestDarwinRouteDump2OriginalIdleCapture(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			parent, child := darwinIdleCacheFixture(family)
			child.darwinCache = nil
			parentWire := darwinDump2WireFixture(t, parent, 0, 8, 0)
			childWire := darwinDump2WireFixture(t, child, parent.Flags|syscall.RTF_UP, 0, 1700000000)
			if family == 4 && len(parentWire)%8 != 4 {
				t.Fatal("native DUMP2 fixture lost its four-byte second-header boundary")
			}
			input := append(append([]byte(nil), parentWire...), childWire...)
			original := append([]byte(nil), input...)
			calls := 0
			objects, err := desktopDarwinReadRouteDump2(func(kind, parameter int) ([]byte, error) {
				calls++
				if kind != syscall.NET_RT_DUMP2 || parameter != 0 || calls != 1 {
					return nil, errors.New("original native route inventory changed its ABI or retried")
				}
				return input, nil
			})
			if err != nil || calls != 1 || len(objects) != 2 || objects[0] != parent || objects[1].Key() != child.Key() || objects[1].darwinCache == nil || !bytes.Equal(input, original) {
				t.Fatal("DUMP2 changed its original route or lost private native fields", err)
			}
			if derived, err := DesktopDarwinDerivedRoute(objects[1], objects[:1]); !derived || err != nil {
				t.Fatal("actual DUMP2 idle row was not proved", err)
			}
			snapshot := Snapshot{Links: []Link{{Index: parent.Index, Name: "captured-native-fixture", MTU: 1500}}, Objects: objects}
			projected, key, err := project(snapshot, nil)
			if err != nil || len(projected.Objects) != 1 || projected.Objects[0] != parent || key == "" {
				t.Fatal("DUMP2 cache changed original physical projection", err)
			}
			withoutCache := snapshot
			withoutCache.Objects = []DesktopNetworkObject{parent}
			_, plainKey, err := project(withoutCache, nil)
			if err != nil || plainKey != key {
				t.Fatal("volatile native refs/expiry entered a stable physical key", err)
			}
			clear(input)
			if derived, err := DesktopDarwinDerivedRoute(objects[1], objects[:1]); !derived || err != nil {
				t.Fatal("DUMP2 proof borrowed the reused native receive buffer", err)
			}
			// A native routing notification has no refcount/parent witness. Even the
			// same public fields and expiry cannot borrow the DUMP2-only authority.
			_, notificationWire := darwinCloneNativeObject(t, child)
			messages, err := darwinMessages(notificationWire)
			if err != nil {
				t.Fatal(err)
			}
			message := messages[0].(*syscall.RouteMessage)
			message.Header.Type = syscall.RTM_DELETE
			message.Header.Flags &^= syscall.RTF_UP
			message.Header.Rmx.Expire = 1700000000
			event, err := parseDarwinEvent(message)
			if err != nil || event.Object.darwinCache != nil {
				t.Fatal("ordinary delete invented private DUMP2 fields", err)
			}
			if derived, err := DesktopDarwinDerivedRoute(event.Object, objects[:1]); derived || err == nil {
				t.Fatal("unproved deletion reused an original native idle snapshot", err)
			}
			// The conventional empty default-route mask is a four-byte native record,
			// not a missing address and not a manufactured full sockaddr.
			shortMask := append([]byte(nil), parentWire[:len(parentWire)-map[int]int{4: syscall.SizeofSockaddrInet4, 6: syscall.SizeofSockaddrInet6}[family]]...)
			shortMask = append(shortMask, 0, 0, 0, 0)
			binary.LittleEndian.PutUint16(shortMask, uint16(len(shortMask)))
			normalized, err := darwinRouteDump2(shortMask)
			if err != nil || len(normalized) != 1 || normalized[0] != parent {
				t.Fatal("DUMP2 lost a complete native empty default mask", err)
			}
		})
	}
	parent, child := darwinIdleCacheFixture(4)
	child.darwinCache = nil
	original := darwinDump2WireFixture(t, child, parent.Flags|1, 0, 1700000000)
	for name, change := range map[string]func([]byte) []byte{
		"short-header":          func(b []byte) []byte { return b[:syscall.SizeofRtMsghdr-1] },
		"truncated-address":     func(b []byte) []byte { return b[:len(b)-1] },
		"short-declared-length": func(b []byte) []byte { binary.LittleEndian.PutUint16(b, 4); return b },
		"version":               func(b []byte) []byte { b[2]++; return b },
		"ordinary-dump-type":    func(b []byte) []byte { b[3] = syscall.RTM_GET; return b },
		"foreign-event-type":    func(b []byte) []byte { b[3] = syscall.RTM_DELETE; return b },
		"reserved":              func(b []byte) []byte { binary.LittleEndian.PutUint32(b[24:], 1); return b },
		"no-interface":          func(b []byte) []byte { binary.LittleEndian.PutUint16(b[4:], 0); return b },
		"unknown-address-bit":   func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], 1<<20|syscall.RTA_DST); return b },
		"missing-declared-address": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[12:], binary.LittleEndian.Uint32(b[12:])|syscall.RTA_BRD)
			return b
		},
		"short-ip-record":            func(b []byte) []byte { b[syscall.SizeofRtMsghdr] = 4; return b },
		"unknown-destination-family": func(b []byte) []byte { b[syscall.SizeofRtMsghdr+1] = 0; return b },
		"unclaimed-tail": func(b []byte) []byte {
			b = append(b, 0, 0, 0, 0)
			binary.LittleEndian.PutUint16(b, uint16(len(b)))
			return b
		},
	} {
		t.Run("wire-"+name, func(t *testing.T) {
			bad := change(append([]byte(nil), original...))
			if objects, err := darwinRouteDump2(bad); err == nil || objects != nil {
				t.Fatal("incomplete or foreign native wire minted DUMP2 proof", objects, err)
			}
		})
	}
	for name, change := range map[string]func([]byte){
		"referenced":                 func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 1) },
		"negative-references":        func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xffffffff) },
		"absent-parent":              func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 0) },
		"different-parent":           func(b []byte) { binary.LittleEndian.PutUint32(b[20:], parent.Flags|1|0x4000) },
		"no-expiry":                  func(b []byte) { binary.LittleEndian.PutUint32(b[48:], 0) },
		"down":                       func(b []byte) { binary.LittleEndian.PutUint32(b[8:], child.Flags) },
		"still-interface-referenced": func(b []byte) { binary.LittleEndian.PutUint32(b[8:], child.Flags|1|0x4000000) },
	} {
		t.Run("native-"+name, func(t *testing.T) {
			bad := append([]byte(nil), original...)
			change(bad)
			objects, err := darwinRouteDump2(bad)
			if err != nil || len(objects) != 1 {
				t.Fatal("native negative fixture lost its well-framed original observation", err)
			}
			if derived, err := DesktopDarwinDerivedRoute(objects[0], []DesktopNetworkObject{parent}); derived || err == nil {
				t.Fatal("unproved original native fields admitted idle cache", err)
			}
		})
	}
	if objects, err := darwinRouteDump2(nil); err != nil || len(objects) != 0 {
		t.Fatal("empty native inventory manufactured a route", err)
	}
}
