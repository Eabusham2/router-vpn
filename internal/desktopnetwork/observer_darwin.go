//go:build darwin

package desktopnetwork

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type darwinObserver struct {
	mu              sync.Mutex
	file            *os.File
	joined          chan struct{}
	closing, closed bool
	sequence        int32
	waiters         map[int32]chan error
	emit            func(Event, error)
}

func openNativeObserver(emit func(Event, error)) (nativeObserver, error) {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "router-vpn-network-observer")
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("Darwin network observer has no original route socket")
	}
	o := &darwinObserver{file: file, joined: make(chan struct{}), waiters: make(map[int32]chan error), emit: emit}
	go o.run()
	return o, nil
}

func darwinMessages(raw []byte) ([]syscall.RoutingMessage, error) {
	var result []syscall.RoutingMessage
	for len(raw) > 0 {
		if len(raw) < 4 {
			return nil, errors.New("Darwin network message is truncated")
		}
		length := int(binary.LittleEndian.Uint16(raw))
		kind := raw[3]
		if length < 4 || length > len(raw) || raw[2] != syscall.RTM_VERSION {
			return nil, errors.New("Darwin network message has invalid framing or version")
		}
		frame := raw[:length]
		raw = raw[length:]
		// These typed records are observations/queries or multicast membership,
		// not changes to unicast interface addresses or routing policy.
		if kind == syscall.RTM_MISS || kind == syscall.RTM_RESOLVE || kind == syscall.RTM_NEWMADDR || kind == syscall.RTM_DELMADDR || kind == syscall.RTM_NEWMADDR2 {
			minimum := syscall.SizeofIfmaMsghdr
			if kind == syscall.RTM_MISS || kind == syscall.RTM_RESOLVE {
				minimum = syscall.SizeofRtMsghdr
			} else if kind == syscall.RTM_NEWMADDR2 {
				minimum = syscall.SizeofIfmaMsghdr2
			}
			if len(frame) < minimum {
				return nil, errors.New("Darwin informational network message is truncated")
			}
			continue
		}
		// Darwin frames are aligned for their wire headers, not for the Go
		// RoutingMessage structs (which also contain a pointer-bearing slice).
		// The deprecated syscall parser casts the input to those larger structs;
		// a valid second route at a four-byte boundary trips checkptr on arm64.
		// Decode the actual native header into its own value and retain the
		// payload independently of the reusable route-socket receive buffer.
		var message syscall.RoutingMessage
		var err error
		switch kind {
		case syscall.RTM_ADD, syscall.RTM_DELETE, syscall.RTM_CHANGE, syscall.RTM_GET,
			syscall.RTM_LOSING, syscall.RTM_REDIRECT, syscall.RTM_LOCK:
			value := new(syscall.RouteMessage)
			value.Data, err = darwinMessageHeader(frame, syscall.SizeofRtMsghdr, &value.Header)
			message = value
		case syscall.RTM_IFINFO:
			value := new(syscall.InterfaceMessage)
			value.Data, err = darwinMessageHeader(frame, syscall.SizeofIfMsghdr, &value.Header)
			message = value
		case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
			value := new(syscall.InterfaceAddrMessage)
			value.Data, err = darwinMessageHeader(frame, syscall.SizeofIfaMsghdr, &value.Header)
			message = value
		default:
			err = errors.New("unknown Darwin network record")
		}
		if err != nil {
			return nil, errors.New("Darwin network record is unrecognized or incomplete")
		}
		result = append(result, message)
	}
	return result, nil
}

func darwinMessageHeader(frame []byte, size int, header any) ([]byte, error) {
	if len(frame) < size || binary.Size(header) != size {
		return nil, errors.New("Darwin network header does not match its native size")
	}
	if count, err := binary.Decode(frame[:size], binary.LittleEndian, header); err != nil || count != size {
		return nil, errors.New("Darwin network header could not be decoded completely")
	}
	length := len(frame) - size
	payload := make([]byte, length)
	copy(payload, frame[size:])
	return payload, nil
}

func (o *darwinObserver) run() {
	defer close(o.joined)
	raw, err := o.file.SyscallConn()
	if err != nil {
		o.emit(Event{}, err)
		return
	}
	buffer := make([]byte, 256<<10)
	for {
		var size, flags int
		var received error
		err = raw.Read(func(fd uintptr) bool {
			size, _, flags, _, received = syscall.Recvmsg(int(fd), buffer, nil, syscall.MSG_DONTWAIT)
			return received != syscall.EAGAIN && received != syscall.EWOULDBLOCK
		})
		if err == nil {
			err = received
		}
		o.mu.Lock()
		closing := o.closing
		o.mu.Unlock()
		if closing {
			return
		}
		if err != nil {
			o.emit(Event{}, err)
			return
		}
		if size == 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
			o.emit(Event{}, errors.New("Darwin network notification was dropped or truncated"))
			return
		}
		messages, parse := darwinMessages(buffer[:size])
		if parse != nil {
			o.emit(Event{}, parse)
			return
		}
		for _, message := range messages {
			if route, ok := message.(*syscall.RouteMessage); ok && route.Header.Type == syscall.RTM_GET {
				o.mu.Lock()
				waiter := o.waiters[route.Header.Seq]
				if waiter != nil && route.Header.Pid == int32(os.Getpid()) {
					delete(o.waiters, route.Header.Seq)
				} else {
					waiter = nil
				}
				o.mu.Unlock()
				if waiter != nil {
					var result error
					if route.Header.Errno != 0 && route.Header.Errno != int32(syscall.ESRCH) {
						result = syscall.Errno(route.Header.Errno)
					}
					waiter <- result
				}
				continue
			}
			event, parse := parseDarwinEvent(message)
			if parse != nil {
				o.emit(Event{}, parse)
				return
			}
			o.emit(event, nil)
		}
	}
}

func parseDarwinEvent(message syscall.RoutingMessage) (Event, error) {
	switch value := message.(type) {
	case *syscall.InterfaceMessage:
		if value.Header.Version != syscall.RTM_VERSION || value.Header.Index == 0 {
			return Event{}, errors.New("Darwin interface event has no native identity")
		}
		return Event{Kind: "link", Action: "change", Index: uint32(value.Header.Index)}, nil
	case *syscall.InterfaceAddrMessage:
		addresses, err := syscall.ParseRoutingSockaddr(value)
		if err != nil || len(addresses) <= syscall.RTAX_IFA {
			return Event{}, errors.New("Darwin address event is incomplete")
		}
		address := DesktopDarwinNetworkAddress(addresses[syscall.RTAX_IFA])
		mask := DesktopDarwinNetworkAddress(addresses[syscall.RTAX_NETMASK])
		if !address.IsValid() || !mask.IsValid() || address.BitLen() != mask.BitLen() {
			return Event{}, errors.New("Darwin address event changed its family")
		}
		bits, size := net.IPMask(mask.AsSlice()).Size()
		if size != address.BitLen() {
			return Event{}, errors.New("Darwin address event has an invalid mask")
		}
		action := "add"
		if value.Header.Type == syscall.RTM_DELADDR {
			action = "delete"
		} else if value.Header.Type != syscall.RTM_NEWADDR {
			return Event{}, errors.New("Darwin address event has another mutation type")
		}
		return Event{Kind: "address", Action: action, Index: uint32(value.Header.Index), Address: netip.PrefixFrom(address, bits).String()}, nil
	case *syscall.RouteMessage:
		action := "change"
		switch value.Header.Type {
		case syscall.RTM_ADD, syscall.RTM_OLDADD:
			action = "add"
		case syscall.RTM_DELETE, syscall.RTM_OLDDEL:
			action = "delete"
		case syscall.RTM_CHANGE, syscall.RTM_REDIRECT, syscall.RTM_LOCK:
		default:
			return Event{}, fmt.Errorf("Darwin routing event %d is not a tracked policy mutation", value.Header.Type)
		}
		object, err := ParseDesktopDarwinNetworkObject(value)
		if err != nil {
			return Event{}, err
		}
		return Event{Kind: "route", Action: action, Index: object.Index, Object: object}, nil
	default:
		return Event{}, errors.New("Darwin network notification has another record type")
	}
}

func (o *darwinObserver) Barrier(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Darwin network barrier lost its caller")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	o.mu.Lock()
	if o.closing || o.closed || o.sequence == 0x7fffffff {
		o.mu.Unlock()
		return errors.New("Darwin network barrier lost its original socket")
	}
	o.sequence++
	seq := o.sequence
	waiter := make(chan error, 1)
	o.waiters[seq] = waiter
	o.mu.Unlock()
	header := syscall.RtMsghdr{Msglen: uint16(unsafe.Sizeof(syscall.RtMsghdr{}) + 16), Version: syscall.RTM_VERSION, Type: syscall.RTM_GET, Flags: syscall.RTF_HOST, Addrs: syscall.RTA_DST, Pid: int32(os.Getpid()), Seq: seq}
	request := make([]byte, int(header.Msglen))
	copy(request, unsafe.Slice((*byte)(unsafe.Pointer(&header)), int(unsafe.Sizeof(header))))
	sockaddr := request[int(unsafe.Sizeof(header)):]
	sockaddr[0], sockaddr[1], sockaddr[4], sockaddr[7] = 16, syscall.AF_INET, 127, 1
	n, err := o.file.Write(request)
	if err != nil || n != len(request) {
		return errors.Join(errors.New("Darwin network barrier request was not delivered completely"), err)
	}
	select {
	case err := <-waiter:
		return err
	case <-o.joined:
		return errors.New("Darwin network observer exited before its barrier")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *darwinObserver) Snapshot(ctx context.Context) (Snapshot, error) {
	var snapshot Snapshot
	if ctx == nil || ctx.Err() != nil {
		return snapshot, errors.New("Darwin network snapshot lost its caller")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return snapshot, err
	}
	for _, iface := range interfaces {
		snapshot.Links = append(snapshot.Links, Link{Index: uint32(iface.Index), Name: iface.Name, MTU: iface.MTU, Flags: uint32(iface.Flags), Hardware: iface.HardwareAddr.String()})
		addresses, err := iface.Addrs()
		if err != nil {
			return snapshot, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return snapshot, err
			}
			snapshot.Addresses = append(snapshot.Addresses, Address{Index: uint32(iface.Index), Prefix: prefix.String()})
		}
	}
	raw, err := syscall.RouteRIB(syscall.NET_RT_DUMP, 0)
	if err != nil || len(raw) > 4<<20 {
		return snapshot, errors.Join(errors.New("Darwin network inventory is unavailable or unbounded"), err)
	}
	messages, err := darwinMessages(raw)
	if err != nil {
		return snapshot, err
	}
	for _, message := range messages {
		route, ok := message.(*syscall.RouteMessage)
		if !ok {
			return snapshot, errors.New("Darwin route dump contains another record type")
		}
		object, err := ParseDesktopDarwinNetworkObject(route)
		if err != nil {
			return snapshot, err
		}
		snapshot.Objects = append(snapshot.Objects, object)
	}
	return snapshot, nil
}

func (o *darwinObserver) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	if o.closing {
		o.mu.Unlock()
		<-o.joined
		o.mu.Lock()
		closed := o.closed
		o.mu.Unlock()
		if closed {
			return nil
		}
		return errors.New("Darwin network socket close was not acknowledged")
	}
	o.closing = true
	o.mu.Unlock()
	err := o.file.Close()
	<-o.joined
	if err != nil {
		return err
	}
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
	return nil
}
