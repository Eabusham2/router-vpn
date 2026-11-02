//go:build linux

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
)

type linuxObserver struct {
	mu              sync.Mutex
	file            *os.File
	joined          chan struct{}
	closing, closed bool
	sequence        uint32
	waiters         map[uint32]chan error
	emit            func(Event, error)
}

func openNativeObserver(emit func(Event, error)) (nativeObserver, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	// RTMGRP_LINK, IFADDR4/6, ROUTE4/6, RULE4/6. Rule events have no
	// interface key and are matched against exact successful native installs.
	groups := uint32(1 | 0x10 | 0x100 | 0x40 | 0x400 | 0x80 | 0x80000)
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}); err != nil {
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
		return nil, errors.New("native network observer has no original socket")
	}
	o := &linuxObserver{file: file, joined: make(chan struct{}), waiters: make(map[uint32]chan error), emit: emit}
	go o.run()
	return o, nil
}

func (o *linuxObserver) run() {
	defer close(o.joined)
	raw, err := o.file.SyscallConn()
	if err != nil {
		o.emit(Event{}, err)
		return
	}
	buffer := make([]byte, 256<<10)
	for {
		var size, flags int
		var sender syscall.Sockaddr
		var received error
		err = raw.Read(func(fd uintptr) bool {
			size, _, flags, sender, received = syscall.Recvmsg(int(fd), buffer, nil, syscall.MSG_DONTWAIT)
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
		from, ok := sender.(*syscall.SockaddrNetlink)
		if !ok || from.Pid != 0 || size == 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
			o.emit(Event{}, errors.New("Linux network notification is truncated or has no kernel sender"))
			return
		}
		messages, parse := syscall.ParseNetlinkMessage(buffer[:size])
		if parse != nil {
			o.emit(Event{}, parse)
			return
		}
		for _, message := range messages {
			if message.Header.Flags&0x10 != 0 || message.Header.Type == syscall.NLMSG_OVERRUN {
				o.emit(Event{}, errors.New("Linux network notification lost messages"))
				return
			}
			o.mu.Lock()
			waiter := o.waiters[message.Header.Seq]
			o.mu.Unlock()
			if waiter != nil {
				// Only responses to this observer's exact GETLINK request are
				// exempt from mutation notifications. The final ACK drains all
				// earlier datagrams on this same subscribed socket.
				if message.Header.Type == syscall.NLMSG_ERROR {
					var ack error
					if len(message.Data) < 20 || binary.LittleEndian.Uint32(message.Data[12:]) != message.Header.Seq {
						ack = errors.New("Linux network barrier acknowledgement changed its request")
					} else if code := int32(binary.LittleEndian.Uint32(message.Data)); code != 0 {
						ack = syscall.Errno(-code)
					}
					o.mu.Lock()
					delete(o.waiters, message.Header.Seq)
					o.mu.Unlock()
					waiter <- ack
					continue
				}
				if message.Header.Type == syscall.RTM_NEWLINK {
					continue
				}
				o.emit(Event{}, errors.New("Linux network barrier received another message type"))
				return
			}
			event, parse := parseLinuxEvent(message)
			if parse != nil {
				o.emit(Event{}, parse)
				return
			}
			o.emit(event, nil)
		}
	}
}

func (o *linuxObserver) Barrier(ctx context.Context) error {
	if ctx != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("Linux network barrier lost its caller")
	}
	o.mu.Lock()
	if o.closing || o.closed || o.sequence == ^uint32(0) {
		o.mu.Unlock()
		return errors.New("Linux network barrier lost its original socket")
	}
	o.sequence++
	seq := o.sequence
	waiter := make(chan error, 1)
	o.waiters[seq] = waiter
	o.mu.Unlock()
	request := make([]byte, 32)
	binary.LittleEndian.PutUint32(request, uint32(len(request)))
	binary.LittleEndian.PutUint16(request[4:], syscall.RTM_GETLINK)
	binary.LittleEndian.PutUint16(request[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.LittleEndian.PutUint32(request[8:], seq)
	binary.LittleEndian.PutUint32(request[20:], 1) // loopback's original namespace index
	raw, err := o.file.SyscallConn()
	if err == nil {
		var sendErr error
		err = raw.Write(func(fd uintptr) bool {
			sendErr = syscall.Sendto(int(fd), request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
			return sendErr != syscall.EAGAIN && sendErr != syscall.EWOULDBLOCK
		})
		if err == nil {
			err = sendErr
		}
	}
	if err != nil {
		o.mu.Lock()
		delete(o.waiters, seq)
		o.mu.Unlock()
		return err
	}
	select {
	case err := <-waiter:
		return err
	case <-o.joined:
		return errors.New("Linux network observer exited before its barrier")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *linuxObserver) Close() error {
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
		return errors.New("Linux network socket close was not acknowledged")
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

func linuxAttributes(body []byte, offset int) (map[uint16][]byte, error) {
	attributes := make(map[uint16][]byte)
	for offset < len(body) {
		if len(body)-offset < 4 {
			return nil, errors.New("Linux network attribute is truncated")
		}
		length := int(binary.LittleEndian.Uint16(body[offset:]))
		kind := binary.LittleEndian.Uint16(body[offset+2:])
		aligned := (length + 3) &^ 3
		if length < 4 || aligned > len(body)-offset || attributes[kind] != nil {
			return nil, errors.New("Linux network attribute has invalid size or duplicate identity")
		}
		attributes[kind] = append([]byte(nil), body[offset+4:offset+length]...)
		offset += aligned
	}
	return attributes, nil
}

func linuxLink(body []byte) (Link, error) {
	if len(body) < 16 {
		return Link{}, errors.New("Linux link notification is incomplete")
	}
	attrs, err := linuxAttributes(body, 16)
	if err != nil {
		return Link{}, err
	}
	name := attrs[3]
	if len(name) < 2 || name[len(name)-1] != 0 || len(attrs[4]) != 4 {
		return Link{}, errors.New("Linux link notification lost its name or MTU")
	}
	for _, b := range name[:len(name)-1] {
		if b == 0 {
			return Link{}, errors.New("Linux link name is not canonical")
		}
	}
	return Link{Index: binary.LittleEndian.Uint32(body[4:]), Name: string(name[:len(name)-1]), MTU: int(binary.LittleEndian.Uint32(attrs[4])), Flags: binary.LittleEndian.Uint32(body[8:]), Hardware: net.HardwareAddr(attrs[1]).String()}, nil
}

func linuxAddress(body []byte) (Address, error) {
	if len(body) < 8 {
		return Address{}, errors.New("Linux address notification is incomplete")
	}
	attrs, err := linuxAttributes(body, 8)
	if err != nil {
		return Address{}, err
	}
	address := attrs[2] // IFA_LOCAL, or IFA_ADDRESS for IPv6
	if address == nil {
		address = attrs[1]
	}
	ip, ok := netip.AddrFromSlice(address)
	if !ok || body[0] != syscall.AF_INET && body[0] != syscall.AF_INET6 || ip.Is4() != (body[0] == syscall.AF_INET) || int(body[1]) > ip.BitLen() {
		return Address{}, errors.New("Linux address notification changed its family or prefix")
	}
	return Address{Index: binary.LittleEndian.Uint32(body[4:]), Prefix: netip.PrefixFrom(ip, int(body[1])).String()}, nil
}

func parseLinuxEvent(message syscall.NetlinkMessage) (Event, error) {
	e := Event{}
	switch message.Header.Type {
	case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
		link, err := linuxLink(message.Data)
		if err != nil {
			return e, err
		}
		e.Kind, e.Index, e.Name = "link", link.Index, link.Name
		e.Action = "add"
		if message.Header.Type == syscall.RTM_DELLINK {
			e.Action = "delete"
		}
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
		address, err := linuxAddress(message.Data)
		if err != nil {
			return e, err
		}
		e.Kind, e.Index, e.Address = "address", address.Index, address.Prefix
		e.Action = "add"
		if message.Header.Type == syscall.RTM_DELADDR {
			e.Action = "delete"
		}
	case syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWRULE, syscall.RTM_DELRULE:
		e.Kind = "route"
		if message.Header.Type == syscall.RTM_NEWRULE || message.Header.Type == syscall.RTM_DELRULE {
			e.Kind = "rule"
		}
		object, err := ParseDesktopLinuxNetworkObject(e.Kind, message.Data)
		if err != nil {
			return e, err
		}
		e.Object, e.Index = object, object.Index
		e.Action = "add"
		if message.Header.Type == syscall.RTM_DELROUTE || message.Header.Type == syscall.RTM_DELRULE {
			e.Action = "delete"
		}
	default:
		return e, fmt.Errorf("Linux network notification type %d is not a complete tracked mutation", message.Header.Type)
	}
	return e, nil
}

func linuxDump(request int, response uint16) ([]syscall.NetlinkMessage, error) {
	raw, err := syscall.NetlinkRIB(request, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, errors.New("Linux network dump is empty or exceeds its bound")
	}
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, err
	}
	var rows []syscall.NetlinkMessage
	done := false
	for _, message := range messages {
		if done || message.Header.Flags&0x10 != 0 {
			return nil, errors.New("Linux network dump is interrupted or has trailing records")
		}
		if message.Header.Type == syscall.NLMSG_DONE {
			done = true
			continue
		}
		if message.Header.Type != response {
			return nil, errors.New("Linux network dump returned an unrequested record")
		}
		rows = append(rows, message)
	}
	if !done {
		return nil, errors.New("Linux network dump has no complete ending")
	}
	return rows, nil
}

func (o *linuxObserver) Snapshot(ctx context.Context) (Snapshot, error) {
	var snapshot Snapshot
	for _, kind := range []struct {
		request  int
		response uint16
		name     string
	}{{syscall.RTM_GETLINK, syscall.RTM_NEWLINK, "link"}, {syscall.RTM_GETADDR, syscall.RTM_NEWADDR, "address"}, {syscall.RTM_GETROUTE, syscall.RTM_NEWROUTE, "route"}, {syscall.RTM_GETRULE, syscall.RTM_NEWRULE, "rule"}} {
		if ctx == nil || ctx.Err() != nil {
			return snapshot, errors.New("Linux network snapshot lost its caller")
		}
		rows, err := linuxDump(kind.request, kind.response)
		if err != nil {
			return snapshot, err
		}
		for _, row := range rows {
			switch kind.name {
			case "link":
				v, err := linuxLink(row.Data)
				if err != nil {
					return snapshot, err
				}
				snapshot.Links = append(snapshot.Links, v)
			case "address":
				v, err := linuxAddress(row.Data)
				if err != nil {
					return snapshot, err
				}
				snapshot.Addresses = append(snapshot.Addresses, v)
			default:
				v, err := ParseDesktopLinuxNetworkObject(kind.name, row.Data)
				if err != nil {
					return snapshot, err
				}
				snapshot.Objects = append(snapshot.Objects, v)
			}
		}
	}
	return snapshot, nil
}
