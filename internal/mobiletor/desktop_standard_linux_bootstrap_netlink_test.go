//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func linuxBootstrapTransactionTable() string {
	return desktopLinuxStandardTablePrefix + strings.Repeat("a", 32)
}

// Decode the emitted native datagrams independently of the request builder.
// These assertions bind the native operation to a generation and single exact
// output-rule handle; a table flush or name-only delete is not equivalent.
func TestLinuxStandardBootstrapConditionalDeleteWire(t *testing.T) {
	table := linuxBootstrapTransactionTable()
	requests, err := desktopLinuxBootstrapDeleteRequests(0x10203040, table, 0x123456789, 901, 411)
	if err != nil {
		t.Fatal(err)
	}
	packet := append(append(append([]byte{}, requests[0]...), requests[1]...), requests[2]...)
	messages, err := syscall.ParseNetlinkMessage(packet)
	if err != nil || len(messages) != 3 {
		t.Fatal("conditional removal is not one complete native batch", len(messages), err)
	}
	for i, m := range messages {
		if m.Header.Seq != 901+uint32(i) || m.Header.Pid != 411 {
			t.Fatal("conditional removal changed original sequence or endpoint")
		}
		wantType, wantFlags := uint16(0x10), uint16(syscall.NLM_F_REQUEST)
		if i == 1 {
			wantType = 0x0a08
		} else if i == 2 {
			wantType, wantFlags = 0x11, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK
		}
		if m.Header.Type != wantType || m.Header.Flags != wantFlags || len(m.Data) < 4 || m.Data[1] != 0 {
			t.Fatal("conditional removal changed native operation or commit receipt")
		}
	}
	begin := messages[0].Data
	if len(begin) != 12 || !bytes.Equal(begin[:4], []byte{0, 0, 0, 10}) || binary.NativeEndian.Uint16(begin[4:6]) != 8 || binary.NativeEndian.Uint16(begin[6:8]) != 1 || binary.BigEndian.Uint32(begin[8:]) != 0x10203040 {
		t.Fatal("native removal lost its original generation condition")
	}
	if !bytes.Equal(messages[2].Data, []byte{0, 0, 0, 10}) || !bytes.Equal(messages[1].Data[:4], []byte{1, 0, 0, 0}) {
		t.Fatal("native removal changed its fixed family or batch boundary")
	}
	attrs := map[uint16][]byte{}
	for data := messages[1].Data[4:]; len(data) != 0; {
		if len(data) < 4 {
			t.Fatal("truncated removal attribute")
		}
		n, kind := int(binary.NativeEndian.Uint16(data[:2])), binary.NativeEndian.Uint16(data[2:4])
		if n < 4 || (n+3)&^3 > len(data) || attrs[kind] != nil {
			t.Fatal("ambiguous removal attribute")
		}
		attrs[kind] = append([]byte{}, data[4:n]...)
		data = data[(n+3)&^3:]
	}
	if len(attrs) != 3 || string(attrs[1]) != table+"\x00" || string(attrs[2]) != "output\x00" || len(attrs[3]) != 8 || binary.BigEndian.Uint64(attrs[3]) != 0x123456789 {
		t.Fatal("native removal is not bound to the original single rule", attrs)
	}
}

func TestLinuxStandardBootstrapConditionalDeleteRejectsInvalidScope(t *testing.T) {
	for _, test := range []struct {
		name, table string
		generation  uint32
		handle      uint64
		seq, port   uint32
	}{
		{"generation", linuxBootstrapTransactionTable(), 0, 41, 901, 411},
		{"handle", linuxBootstrapTransactionTable(), 7, 0, 901, 411},
		{"imprecise-handle", linuxBootstrapTransactionTable(), 7, 1 << 53, 901, 411},
		{"unowned-table", "household_policy", 7, 41, 901, 411},
		{"table-suffix", linuxBootstrapTransactionTable() + "_replacement", 7, 41, 901, 411},
		{"table-nul", linuxBootstrapTransactionTable() + "\x00foreign", 7, 41, 901, 411},
		{"zero-sequence", linuxBootstrapTransactionTable(), 7, 41, 0, 411},
		{"sequence-wrap", linuxBootstrapTransactionTable(), 7, 41, ^uint32(0) - 1, 411},
		{"missing-endpoint", linuxBootstrapTransactionTable(), 7, 41, 901, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if requests, err := desktopLinuxBootstrapDeleteRequests(test.generation, test.table, test.handle, test.seq, test.port); err == nil || requests[0] != nil || requests[1] != nil || requests[2] != nil {
				t.Fatal("invalid scope acquired a deletion batch", err)
			}
		})
	}
}

func TestLinuxStandardBootstrapConditionalDeleteRetainsUnknownCommit(t *testing.T) {
	for _, stage := range []string{"begin", "command", "foreign-commit", "original-commit"} {
		t.Run(stage, func(t *testing.T) {
			file, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			n := &desktopLinuxBaselineNetlink{file: file, port: 411, seq: 901}
			defer n.close()
			requests, err := desktopLinuxBootstrapDeleteRequests(7, linuxBootstrapTransactionTable(), 41, 901, 411)
			if err != nil {
				t.Fatal(err)
			}
			index := 2
			if stage == "begin" {
				index = 0
			} else if stage == "command" {
				index = 1
			}
			reply := linuxBaselineTestACK(requests[index], 0)
			if stage == "foreign-commit" {
				reply.Data[8]++
			}
			ack, err := n.deleteReceipt(reply, requests)
			if stage == "original-commit" {
				if !ack || err != nil || n.uncertain != nil {
					t.Fatal("original committed receipt was lost", ack, err)
				}
				return
			}
			if ack || err == nil || n.uncertain == nil {
				t.Fatal("incomplete receipt acquired cleanup authority", ack, err)
			}
			original := n.uncertain
			if ack, sent, err := n.deleteBootstrapRule(context.Background(), 7, linuxBootstrapTransactionTable(), 41); ack || sent || !errors.Is(err, original) {
				t.Fatal("unknown commit was replayed or rebound to a new owner", ack, sent, err)
			}
		})
	}
}
