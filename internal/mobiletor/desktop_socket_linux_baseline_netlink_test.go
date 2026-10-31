//go:build linux

package mobiletor

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"testing"
)

func linuxBaselineTestACK(request []byte, code int32) *syscall.NetlinkMessage {
	data := make([]byte, 20)
	binary.NativeEndian.PutUint32(data[:4], uint32(code))
	copy(data[4:], request[:16])
	return &syscall.NetlinkMessage{Header: syscall.NlMsghdr{Len: 36, Type: syscall.NLMSG_ERROR,
		Seq: binary.NativeEndian.Uint32(request[8:12]), Pid: binary.NativeEndian.Uint32(request[12:16])}, Data: data}
}

func TestLinuxBaselineRequiresCommittedBatchReceipt(t *testing.T) {
	requests := [3][]byte{
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchBegin, syscall.NLM_F_REQUEST, 101, 503, 0, 10, nil),
		desktopLinuxBaselineMessage(desktopLinuxNFTDeleteTable, syscall.NLM_F_REQUEST, 102, 503, 1, 0, nil),
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, 103, 503, 0, 10, nil),
	}
	for index, request := range requests {
		ack, err := desktopLinuxBaselineDeleteReceipt(linuxBaselineTestACK(request, 0), requests)
		if ack != (index == 2) || (err == nil) != ack {
			t.Fatalf("command %d substituted for committed batch receipt: %v %v", index, ack, err)
		}
		for _, code := range []syscall.Errno{syscall.ERESTART, syscall.ENOENT, syscall.EPERM} {
			ack, err := desktopLinuxBaselineDeleteReceipt(linuxBaselineTestACK(request, -int32(code)), requests)
			if ack || !errors.Is(err, code) {
				t.Fatalf("native failure was not attributed to its exact transaction: %v %v", ack, err)
			}
		}
	}
	for name, change := range map[string]func(*syscall.NetlinkMessage){
		"foreign-sequence":       func(m *syscall.NetlinkMessage) { m.Header.Seq++ },
		"foreign-port":           func(m *syscall.NetlinkMessage) { m.Header.Pid++ },
		"foreign-request":        func(m *syscall.NetlinkMessage) { m.Data[8]++ },
		"foreign-request-flags":  func(m *syscall.NetlinkMessage) { m.Data[10]++ },
		"foreign-request-length": func(m *syscall.NetlinkMessage) { m.Data[4]++ },
		"truncated":              func(m *syscall.NetlinkMessage) { m.Data = m.Data[:19] },
		"positive-error":         func(m *syscall.NetlinkMessage) { binary.NativeEndian.PutUint32(m.Data[:4], 1) },
		"invalid-negative":       func(m *syscall.NetlinkMessage) { binary.NativeEndian.PutUint32(m.Data[:4], 0x80000000) },
		"ordinary-message":       func(m *syscall.NetlinkMessage) { m.Header.Type = desktopLinuxNFTNewGeneration },
	} {
		t.Run(name, func(t *testing.T) {
			reply := linuxBaselineTestACK(requests[2], 0)
			change(reply)
			if ack, err := desktopLinuxBaselineDeleteReceipt(reply, requests); ack || err == nil {
				t.Fatal("unrelated or malformed native receipt authorized deletion", ack, err)
			}
		})
	}
}

func TestLinuxBaselineReplyRejectsUnrelatedDatagrams(t *testing.T) {
	packet := desktopLinuxBaselineMessage(desktopLinuxNFTNewGeneration, 0, 31, 409, 0, 0, nil)
	kernel := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if _, err := desktopLinuxBaselineReply(packet, kernel, 0, 409, 31); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func([]byte) []byte{
		"short":               func(b []byte) []byte { return b[:15] },
		"second-message":      func(b []byte) []byte { return append(b, b...) },
		"trailing-byte":       func(b []byte) []byte { return append(b, 0) },
		"truncated-body":      func(b []byte) []byte { return b[:len(b)-1] },
		"multipart":           func(b []byte) []byte { binary.NativeEndian.PutUint16(b[6:8], syscall.NLM_F_MULTI); return b },
		"wrong-sequence":      func(b []byte) []byte { binary.NativeEndian.PutUint32(b[8:12], 32); return b },
		"wrong-port":          func(b []byte) []byte { binary.NativeEndian.PutUint32(b[12:16], 410); return b },
		"short-header-length": func(b []byte) []byte { binary.NativeEndian.PutUint32(b[:4], 12); return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := desktopLinuxBaselineReply(change(append([]byte{}, packet...)), kernel, 0, 409, 31); err == nil {
				t.Fatal("ambiguous native datagram was accepted")
			}
		})
	}
	for _, source := range []syscall.Sockaddr{nil, &syscall.SockaddrInet4{}, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: 50}, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}, &syscall.SockaddrNetlink{}} {
		if _, err := desktopLinuxBaselineReply(packet, source, 0, 409, 31); err == nil {
			t.Fatal("non-kernel source was accepted")
		}
	}
	for _, flags := range []int{syscall.MSG_TRUNC, syscall.MSG_CTRUNC, syscall.MSG_PEEK} {
		if _, err := desktopLinuxBaselineReply(packet, kernel, flags, 409, 31); err == nil {
			t.Fatal("incomplete native datagram was accepted")
		}
	}
}

func TestLinuxBaselineGenerationRejectsMissingOrAmbiguousIdentity(t *testing.T) {
	var number [4]byte
	binary.BigEndian.PutUint32(number[:], 0x10002)
	packet := desktopLinuxBaselineMessage(desktopLinuxNFTNewGeneration, 0, 31, 409, 0, 2, desktopLinuxBaselineAttribute(1, number[:]))
	message := &syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: desktopLinuxNFTNewGeneration}, Data: packet[16:]}
	if got, err := desktopLinuxBaselineGeneration(message); err != nil || got != 0x10002 {
		t.Fatal(got, err)
	}
	for name, change := range map[string]func(*syscall.NetlinkMessage){
		"zero": func(m *syscall.NetlinkMessage) {
			for i := 8; i < 12; i++ {
				m.Data[i] = 0
			}
			m.Data[3] = 0
		},
		"wrong-family":        func(m *syscall.NetlinkMessage) { m.Data[0] = 1 },
		"wrong-version":       func(m *syscall.NetlinkMessage) { m.Data[1] = 1 },
		"inconsistent-res-id": func(m *syscall.NetlinkMessage) { m.Data[3]++ },
		"wrong-message":       func(m *syscall.NetlinkMessage) { m.Header.Type = desktopLinuxNFTGetGeneration },
		"missing":             func(m *syscall.NetlinkMessage) { m.Data = m.Data[:4] },
		"truncated":           func(m *syscall.NetlinkMessage) { m.Data = m.Data[:11] },
		"duplicate":           func(m *syscall.NetlinkMessage) { m.Data = append(m.Data, m.Data[4:]...) },
		"nested":              func(m *syscall.NetlinkMessage) { binary.NativeEndian.PutUint16(m.Data[6:8], 0x8001) },
		"unknown":             func(m *syscall.NetlinkMessage) { binary.NativeEndian.PutUint16(m.Data[6:8], 4) },
		"integer-width":       func(m *syscall.NetlinkMessage) { binary.NativeEndian.PutUint16(m.Data[4:6], 7) },
		"pid-width": func(m *syscall.NetlinkMessage) {
			m.Data = append(m.Data, desktopLinuxBaselineAttribute(2, []byte{0})...)
		},
		"unterminated-name": func(m *syscall.NetlinkMessage) {
			m.Data = append(m.Data, desktopLinuxBaselineAttribute(3, []byte("nft"))...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := *message
			changed.Data = append([]byte{}, message.Data...)
			change(&changed)
			if generation, err := desktopLinuxBaselineGeneration(&changed); err == nil || generation != 0 {
				t.Fatal("invalid generation acquired native authority", generation, err)
			}
		})
	}
}

func TestLinuxBaselineEndpointRequiresRetainedOwner(t *testing.T) {
	for _, n := range []*desktopLinuxBaselineNetlink{nil, {}, {seq: ^uint32(0) - 3}, {uncertain: errors.New("unknown receipt")}} {
		if generation, err := n.generation(context.Background()); generation != 0 || err == nil {
			t.Fatal("missing original endpoint produced generation", generation, err)
		}
		for _, invalid := range []struct {
			generation uint32
			handle     uint64
		}{{0, 1}, {1, 0}, {1, 1 << 53}, {1, 1}} {
			if ack, sent, err := n.delete(context.Background(), invalid.generation, invalid.handle); ack || sent || err == nil {
				t.Fatal("invalid owner/identity sent or acknowledged deletion", ack, sent, err)
			}
		}
		if err := n.close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLinuxBaselineSemanticFailureRetiresOriginalEndpoint(t *testing.T) {
	requests := [3][]byte{
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchBegin, syscall.NLM_F_REQUEST, 101, 503, 0, 10, nil),
		desktopLinuxBaselineMessage(desktopLinuxNFTDeleteTable, syscall.NLM_F_REQUEST, 102, 503, 1, 0, nil),
		desktopLinuxBaselineMessage(desktopLinuxNFTBatchEnd, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, 103, 503, 0, 10, nil),
	}
	for _, fault := range []string{"foreign-ack-body", "command-only-ack", "invalid-negative", "truncated-ack", "malformed-generation", "generation-ack-without-identity"} {
		t.Run(fault, func(t *testing.T) {
			// A harmless descriptor makes the subsequent operation's endpoint
			// guard real without granting this parser test any firewall access.
			file, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			n := &desktopLinuxBaselineNetlink{file: file, port: 503, seq: 100}
			defer n.close()
			reply := linuxBaselineTestACK(requests[2], 0)
			switch fault {
			case "foreign-ack-body":
				reply.Data[8]++
			case "command-only-ack":
				reply = linuxBaselineTestACK(requests[1], 0)
			case "invalid-negative":
				binary.NativeEndian.PutUint32(reply.Data[:4], 0x80000000)
			case "truncated-ack":
				reply.Data = reply.Data[:19]
			case "malformed-generation":
				reply.Header.Type = desktopLinuxNFTNewGeneration
				reply.Data = []byte{0, 0, 0, 1}
			}
			if fault == "malformed-generation" || fault == "generation-ack-without-identity" {
				if generation, err := n.generationReceipt(reply, requests[2]); generation != 0 || err == nil {
					t.Fatal("malformed generation produced an identity", generation, err)
				}
			} else if ack, err := n.deleteReceipt(reply, requests); ack || err == nil {
				t.Fatal("malformed receipt acknowledged a mutation", ack, err)
			}
			failure := n.uncertain
			if failure == nil {
				t.Fatal("semantic receipt failure left its original endpoint reusable")
			}
			if ack, sent, err := n.delete(context.Background(), 1, 1); ack || sent || !errors.Is(err, failure) {
				t.Fatal("unknown committed operation was replayed through its retired endpoint", ack, sent, err)
			}
			if generation, err := n.generation(context.Background()); generation != 0 || !errors.Is(err, failure) {
				t.Fatal("unknown receipt was laundered through a later generation read", generation, err)
			}
		})
	}
	for _, code := range []syscall.Errno{syscall.ERESTART, syscall.ENOENT, syscall.EPERM} {
		n := &desktopLinuxBaselineNetlink{}
		if ack, err := n.deleteReceipt(linuxBaselineTestACK(requests[0], -int32(code)), requests); ack || !errors.Is(err, code) || n.uncertain != nil {
			t.Fatal("exact negative receipt was mislabeled as an unknown commit", ack, err)
		}
	}
}
