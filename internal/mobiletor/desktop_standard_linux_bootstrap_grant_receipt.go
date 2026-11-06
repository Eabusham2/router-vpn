//go:build linux

package mobiletor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"syscall"
	"time"
)

type desktopLinuxBootstrapAttribute struct {
	kind  uint16
	value []byte
}

func desktopLinuxBootstrapAttributes(data []byte) ([]desktopLinuxBootstrapAttribute, error) {
	var result []desktopLinuxBootstrapAttribute
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("truncated bootstrap native attribute")
		}
		length := int(binary.NativeEndian.Uint16(data))
		kind := binary.NativeEndian.Uint16(data[2:])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(data) || kind&0x3fff == 0 || !bytes.Equal(data[length:aligned], make([]byte, aligned-length)) {
			return nil, errors.New("ambiguous bootstrap native attribute")
		}
		result = append(result, desktopLinuxBootstrapAttribute{kind & 0x3fff, bytes.Clone(data[4:length])})
		data = data[aligned:]
	}
	return result, nil
}
func desktopLinuxBootstrapAttributeMap(data []byte, pad uint16) (map[uint16][]byte, error) {
	fields, err := desktopLinuxBootstrapAttributes(data)
	if err != nil {
		return nil, err
	}
	result := map[uint16][]byte{}
	for _, f := range fields {
		if f.kind == pad && len(f.value) == 0 {
			continue
		}
		if _, ok := result[f.kind]; ok {
			return nil, errors.New("duplicate bootstrap native field")
		}
		result[f.kind] = f.value
	}
	return result, nil
}

// Kernel expression dumps omit the transaction-only set ID. They preserve all
// actual match/value/verdict semantics. Nested-attribute flags and ordering of
// distinct attributes are wire framing, not scope; duplicate fields are refused.
func desktopLinuxBootstrapExpressionShape(data []byte) ([]any, error) {
	list, err := desktopLinuxBootstrapAttributes(data)
	if err != nil {
		return nil, err
	}
	var result []any
	for _, item := range list {
		if item.kind != 1 {
			return nil, errors.New("unexpected bootstrap expression list member")
		}
		expr, err := desktopLinuxBootstrapAttributeMap(item.value, 0)
		if err != nil || len(expr) != 2 || len(expr[1]) < 2 || expr[1][len(expr[1])-1] != 0 {
			return nil, errors.Join(err, errors.New("malformed bootstrap expression"))
		}
		name := string(expr[1][:len(expr[1])-1])
		fields, err := desktopLinuxBootstrapAttributeMap(expr[2], 0)
		if err != nil {
			return nil, err
		}
		switch name {
		case "meta", "payload":
		case "lookup":
			if id, ok := fields[4]; ok {
				if !bytes.Equal(id, bootstrapBE32(1)) {
					return nil, errors.New("foreign bootstrap transaction set ID")
				}
				delete(fields, 4)
			}
		case "cmp":
			f, e := desktopLinuxBootstrapAttributeMap(fields[3], 0)
			if e != nil || len(f) != 1 || f[1] == nil {
				return nil, errors.New("invalid bootstrap comparison data")
			}
			fields[3] = f[1]
		case "immediate":
			f, e := desktopLinuxBootstrapAttributeMap(fields[2], 0)
			if e != nil || len(f) != 1 || f[2] == nil {
				return nil, errors.New("invalid bootstrap immediate data")
			}
			v, e := desktopLinuxBootstrapAttributeMap(f[2], 0)
			if e != nil || len(v) != 1 || !bytes.Equal(v[1], bootstrapBE32(1)) {
				return nil, errors.New("bootstrap verdict changed")
			}
			fields[2] = v[1]
		default:
			return nil, fmt.Errorf("unowned bootstrap expression %q", name)
		}
		result = append(result, []any{name, fields})
	}
	return result, nil
}

type desktopLinuxBootstrapGrant struct {
	owner                     *desktopLinuxBaselineNetlink
	file                      *os.File
	port                      uint32
	requests                  [][]byte
	table, set                string
	duration                  time.Duration
	originalDeadline          time.Time
	sent, committed, rejected bool
	ruleHandle, setHandle     uint64
	poison                    error
}

func (g *desktopLinuxBootstrapGrant) complete() bool {
	return g != nil && g.poison == nil && (g.rejected || g.committed && (len(g.requests) != 5 || g.ruleHandle != 0 && g.setHandle != 0))
}
func (g *desktopLinuxBootstrapGrant) receipt(message *syscall.NetlinkMessage) error {
	if g == nil || g.poison != nil || g.complete() || message == nil {
		return errors.New("bootstrap receipt has no pending original transaction")
	}
	index := -1
	for i, r := range g.requests {
		if message.Header.Seq == binary.NativeEndian.Uint32(r[8:12]) && message.Header.Pid == binary.NativeEndian.Uint32(r[12:16]) {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("bootstrap receipt belongs to another transaction")
	}
	if message.Header.Type == syscall.NLMSG_ERROR {
		err := desktopLinuxBaselineKernelError(message, g.requests[index])
		var rejected syscall.Errno
		if errors.As(err, &rejected) {
			if g.committed || len(g.requests) == 5 && (g.ruleHandle != 0 || g.setHandle != 0) {
				return errors.New("bootstrap rejection contradicts original object receipts")
			}
			g.rejected = true
			return err
		}
		if err != nil {
			return err
		}
		if index != len(g.requests)-1 || g.committed {
			return errors.New("bootstrap command acknowledgement is not commit")
		}
		g.committed = true
		return nil
	}
	if len(g.requests) != 5 || index != 1 && index != 3 || message.Header.Type != binary.NativeEndian.Uint16(g.requests[index][4:6]) || len(message.Data) < 4 || message.Data[0] != desktopLinuxNFTInet || message.Data[1] != 0 {
		return errors.New("bootstrap echo changed original object type")
	}
	pad := uint16(14)
	if index == 3 {
		pad = 8
	}
	fields, err := desktopLinuxBootstrapAttributeMap(message.Data[4:], pad)
	if err != nil {
		return err
	}
	if !bytes.Equal(fields[1], append([]byte(g.table), 0)) {
		return errors.New("bootstrap echo changed original table")
	}
	if index == 1 {
		if g.setHandle != 0 || len(fields[16]) != 8 || !bytes.Equal(fields[2], append([]byte(g.set), 0)) || !bytes.Equal(fields[3], bootstrapBE32(0x10)) || !bytes.Equal(fields[4], bootstrapBE32(19)) || !bytes.Equal(fields[5], bootstrapBE32(4)) || !bytes.Equal(fields[11], bootstrapBE64(uint64(g.duration/time.Millisecond))) {
			return errors.New("bootstrap set echo changed original finite permit")
		}
		for k, v := range fields {
			switch k {
			case 1, 2, 3, 4, 5, 11, 16:
			case 9:
				if len(v) != 0 {
					return errors.New("bootstrap set acquired a different descriptor")
				}
			default:
				return errors.New("bootstrap set acquired foreign metadata")
			}
		}
		h := binary.BigEndian.Uint64(fields[16])
		if h == 0 || h > 1<<53-1 {
			return errors.New("invalid original bootstrap set handle")
		}
		g.setHandle = h
	} else {
		if g.ruleHandle != 0 || len(fields) != 4 || !bytes.Equal(fields[2], []byte("output\x00")) || len(fields[3]) != 8 || fields[4] == nil {
			return errors.New("bootstrap rule echo changed original scope")
		}
		request, err := desktopLinuxBootstrapAttributeMap(g.requests[3][20:], 0)
		if err != nil {
			return err
		}
		want, err := desktopLinuxBootstrapExpressionShape(request[4])
		if err != nil {
			return err
		}
		got, err := desktopLinuxBootstrapExpressionShape(fields[4])
		if err != nil || !reflect.DeepEqual(want, got) {
			return errors.Join(err, errors.New("bootstrap rule echo changed exact socket or expiry lookup"))
		}
		h := binary.BigEndian.Uint64(fields[3])
		if h == 0 || h > 1<<53-1 {
			return errors.New("invalid original bootstrap rule handle")
		}
		g.ruleHandle = h
	}
	if g.ruleHandle != 0 && g.ruleHandle == g.setHandle {
		return errors.New("bootstrap object receipts reused a handle")
	}
	return nil
}

func (g *desktopLinuxBootstrapGrant) owns(n *desktopLinuxBaselineNetlink) bool {
	return g != nil && n != nil && g.owner == n && g.file != nil && g.file == n.file && g.port != 0 && g.port == n.port
}
