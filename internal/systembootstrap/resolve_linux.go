//go:build linux

package systembootstrap

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"router-vpn/internal/common"
)

// Authority is the retained original network owner. A successful earlier answer
// cannot hide owner replacement, a lost native grant, or unresolved cleanup.
type Authority interface {
	Exchange(context.Context, string, netip.AddrPort, []byte) ([]byte, error)
	Current(context.Context) error
}
type Result struct {
	Addresses    []netip.Addr
	Hosts        bool
	SourceSHA256 string
}

// Resolve performs only the original endpoint's captured NSS/search policy.
// Every physical connection comes from the original service-owned grant factory.
func (c *Capture) Resolve(ctx context.Context, owner Authority) (Result, error) {
	return c.ResolveIPv6(ctx, owner, true)
}
func (c *Capture) ResolveIPv6(ctx context.Context, owner Authority, ipv6 bool) (Result, error) {
	empty := Result{}
	if ctx == nil {
		return empty, errors.New("system bootstrap omitted caller")
	}
	if _, ok := ctx.Deadline(); !ok {
		return empty, errors.New("system bootstrap requires original absolute deadline")
	}
	if err := c.Current(ctx); err != nil {
		return empty, err
	}
	var failure error
	for _, method := range c.order {
		if method == "files" {
			if c.hostsErr != nil {
				return empty, c.hostsErr
			}
			if len(c.hosts) > 0 {
				if err := c.Current(ctx); err != nil {
					return empty, err
				}
				var addresses []netip.Addr
				for _, address := range c.hosts {
					if ipv6 || address.Is4() {
						addresses = append(addresses, address)
					}
				}
				if len(addresses) == 0 {
					return empty, errors.New("captured hosts answer has no enabled address family")
				}
				return Result{Addresses: addresses, Hosts: true, SourceSHA256: c.digest}, nil
			}
			continue
		}
		if owner == nil {
			return empty, errors.New("system bootstrap has no original socket grant")
		}
		for _, name := range c.names() {
			addresses, err := c.resolveName(ctx, name, owner, ipv6)
			if currentErr := owner.Current(ctx); currentErr != nil {
				return empty, errors.Join(err, currentErr)
			}
			if currentErr := c.Current(ctx); currentErr != nil {
				return empty, errors.Join(err, currentErr)
			}
			if err == nil && len(addresses) > 0 {
				if err = c.Current(ctx); err != nil {
					return empty, err
				}
				return Result{Addresses: addresses, SourceSHA256: c.digest}, nil
			}
			failure = errors.Join(failure, err)
			if ctx.Err() != nil {
				return empty, errors.Join(failure, ctx.Err())
			}
		}
	}
	return empty, errors.Join(failure, errors.New("captured system resolver returned no endpoint address"))
}
func (c *Capture) resolveName(ctx context.Context, name string, owner Authority, ipv6 bool) ([]netip.Addr, error) {
	var addresses []netip.Addr
	var failure error
	types := []uint16{1, 28}
	if c.noAAAA || !ipv6 {
		types = types[:1]
	}
	var rotation [1]byte
	if c.rotate {
		if _, err := rand.Read(rotation[:]); err != nil {
			return nil, err
		}
	}
	for _, qtype := range types {
		query, err := queryFor(name, qtype, c.trustAD, c.edns)
		if err != nil {
			return nil, err
		}
		answered := false
		for attempt := 0; attempt < c.attempts && !answered; attempt++ {
			for index := range c.servers {
				if err := c.Current(ctx); err != nil {
					return nil, err
				}
				server := c.servers[(index+int(rotation[0]))%len(c.servers)]
				call, cancel := context.WithTimeout(ctx, c.timeout)
				network := "udp"
				if c.tcp {
					network = "tcp"
				}
				if err = owner.Current(ctx); err != nil {
					cancel()
					return nil, err
				}
				response, err := exchange(call, network, server, query, owner)
				if err == nil && response[2]&2 != 0 && network == "udp" {
					response, err = exchange(call, "tcp", server, query, owner)
				}
				cancel()
				if currentErr := owner.Current(ctx); currentErr != nil {
					return nil, errors.Join(err, currentErr)
				}
				if err == nil {
					var values []netip.Addr
					values, err = addressesFor(query, response)
					if err == nil {
						addresses = append(addresses, values...)
						answered = true
						break
					}
				}
				failure = errors.Join(failure, err)
				if ctx.Err() != nil {
					return nil, errors.Join(failure, ctx.Err())
				}
			}
		}
	}
	if len(addresses) > 32 {
		return nil, errors.New("captured DNS answer exceeds endpoint bound")
	}
	if len(addresses) > 0 {
		if err := owner.Current(ctx); err != nil {
			return nil, err
		}
		if err := c.Current(ctx); err != nil {
			return nil, err
		}
		return addresses, nil
	}
	return nil, errors.Join(failure, errors.New("captured DNS has no usable A or AAAA answer"))
}
func exchange(ctx context.Context, network string, server netip.AddrPort, query []byte, owner Authority) ([]byte, error) {
	response, err := owner.Exchange(ctx, network, server, query)
	if err != nil {
		return nil, err
	}
	if err = common.ValidateDNSForwardResponse(query, response); err != nil {
		return nil, err
	}
	return response, ctx.Err()
}
func queryFor(name string, qtype uint16, trustAD, edns bool) ([]byte, error) {
	if !validName(name) || qtype != 1 && qtype != 28 {
		return nil, errors.New("endpoint DNS requires one A/AAAA name")
	}
	q := make([]byte, 12)
	if _, err := rand.Read(q[:2]); err != nil {
		return nil, err
	}
	q[2] = 1
	q[5] = 1
	if trustAD {
		q[3] = 0x20
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	if edns {
		q[11] = 1
		q = append(q, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0)
	}
	return q, nil
}
func dnsName(packet []byte, offset int) (string, int, error) {
	var labels []string
	next := -1
	length := 0
	for steps := 0; steps < 256; steps++ {
		if offset < 12 || offset >= len(packet) {
			break
		}
		size := int(packet[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				break
			}
			pointer := (size&63)<<8 | int(packet[offset+1])
			if pointer < 12 || pointer >= offset {
				break
			}
			if next < 0 {
				next = offset + 2
			}
			offset = pointer
			continue
		}
		if size > 63 || offset+1+size > len(packet) {
			break
		}
		offset++
		length += size + 1
		if length > 255 {
			break
		}
		if size == 0 {
			if next < 0 {
				next = offset
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		}
		label := string(packet[offset : offset+size])
		// Hostname lookups cannot flatten embedded dots or arbitrary wire bytes
		// into a different label sequence used as an answer-owner map key.
		if strings.Contains(label, ".") || !validName(label) {
			break
		}
		labels = append(labels, label)
		offset += size
	}
	return "", 0, errors.New("malformed captured DNS name")
}
func addressesFor(query, response []byte) ([]netip.Addr, error) {
	if err := common.ValidateDNSProbeResponse(query, response); err != nil {
		return nil, err
	}
	if response[3]&15 == 3 {
		return nil, nil
	}
	name, end, err := dnsName(query, 12)
	if err != nil {
		return nil, err
	}
	qtype := binary.BigEndian.Uint16(query[end : end+2])
	_, offset, err := dnsName(response, 12)
	if err != nil {
		return nil, err
	}
	offset += 4
	aliases := map[string]string{}
	values := map[string][]netip.Addr{}
	for count := int(binary.BigEndian.Uint16(response[6:8])); count > 0; count-- {
		owner, end, err := dnsName(response, offset)
		if err != nil {
			return nil, err
		}
		kind, class := binary.BigEndian.Uint16(response[end:end+2]), binary.BigEndian.Uint16(response[end+2:end+4])
		size := int(binary.BigEndian.Uint16(response[end+8 : end+10]))
		data := response[end+10 : end+10+size]
		offset = end + 10 + size
		if class != 1 {
			continue
		}
		if kind == 5 {
			alias, next, err := dnsName(response, end+10)
			if err != nil || next != offset || !validName(alias) {
				return nil, errors.New("captured DNS alias is malformed")
			}
			if prior, ok := aliases[owner]; ok && prior != alias {
				return nil, errors.New("captured DNS alias is ambiguous")
			}
			aliases[owner] = alias
		}
		if kind == qtype && (kind == 1 && size == 4 || kind == 28 && size == 16) {
			ip, ok := netip.AddrFromSlice(data)
			if ok && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.Is4In6() {
				values[owner] = append(values[owner], ip)
			}
		}
	}
	seen := map[string]bool{}
	for links := 0; links < 16; links++ {
		if seen[name] {
			return nil, errors.New("captured DNS alias cycle")
		}
		seen[name] = true
		if addresses := values[name]; len(addresses) > 0 {
			if _, exists := aliases[name]; exists {
				return nil, errors.New("captured DNS owner has both address and alias")
			}
			unique := make(map[netip.Addr]bool)
			var result []netip.Addr
			for _, address := range addresses {
				if !unique[address] {
					unique[address] = true
					result = append(result, address)
				}
			}
			return result, nil
		}
		next, ok := aliases[name]
		if !ok {
			return nil, nil
		}
		name = next
	}
	return nil, errors.New("captured DNS alias chain exceeds bound")
}
