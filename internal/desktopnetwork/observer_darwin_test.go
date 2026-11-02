//go:build darwin

package desktopnetwork

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"syscall"
	"testing"
)

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
