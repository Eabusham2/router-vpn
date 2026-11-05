//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// The original standard creator owns this socket and every acknowledged rule.
// It is deliberately not reconstructible from a reply, tuple, or rule label.
type desktopLinuxStandardBootstrap struct {
	conn       *net.UDPConn
	file       *os.File
	socket     desktopLinuxKernelSocket
	route      desktopLinuxBootstrapRoute
	remote     netip.AddrPort
	mark       uint32
	expression []any
	handle     uint64
	attempted  bool
}
type desktopLinuxBootstrapRoute struct {
	Interface net.Interface
	Address   netip.Addr
	Decision  string
}

func desktopLinuxBootstrapRouteFor(ctx context.Context, remote netip.Addr, mark uint32, local netip.AddrPort) (desktopLinuxBootstrapRoute, error) {
	var zero desktopLinuxBootstrapRoute
	args := []string{"-j", "route", "get", remote.String()}
	if mark != 0 {
		args = append(args, "mark", fmt.Sprint(mark))
	}
	if local.IsValid() {
		args = append(args, "from", local.Addr().String(), "ipproto", "udp", "sport", fmt.Sprint(local.Port()), "dport", "53")
	}
	raw, e := desktopLinuxCommand(ctx, "/usr/sbin/ip", args...)
	if e != nil {
		return zero, e
	}
	var rows []struct{ Dst, Dev, Prefsrc, From string }
	if e = json.Unmarshal(raw, &rows); e != nil || len(rows) != 1 || rows[0].Dst != remote.String() {
		return zero, errors.Join(e, errors.New("bootstrap route is not its exact original destination"))
	}
	var rawRows []map[string]json.RawMessage
	if e = json.Unmarshal(raw, &rawRows); e != nil || len(rawRows) != 1 {
		return zero, errors.Join(e, errors.New("bootstrap route decision is malformed"))
	}
	decision := map[string]json.RawMessage{}
	for _, key := range []string{"gateway", "via", "table", "nhid", "flags", "encap", "multipath"} {
		if value, ok := rawRows[0][key]; ok {
			decision[key] = value
		}
	}
	encoded, e := json.Marshal(decision)
	if e != nil {
		return zero, e
	}
	source := rows[0].Prefsrc
	if source == "" && local.IsValid() && rows[0].From == local.Addr().String() {
		source = local.Addr().String()
	}
	ip, e := netip.ParseAddr(source)
	if e != nil || ip.Is4() != remote.Is4() || !ip.IsGlobalUnicast() {
		return zero, errors.New("bootstrap route lacks a usable original source")
	}
	interfaces, e := desktopnetwork.InterfacesContext(ctx)
	if e != nil {
		return zero, e
	}
	for _, in := range interfaces {
		if in.Name != rows[0].Dev {
			continue
		}
		name := strings.ToLower(in.Name)
		if in.Index < 1 || in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 || len(in.HardwareAddr) == 0 || strings.Contains(name, "tun") || strings.Contains(name, "wireguard") || strings.HasPrefix(name, "wg") || strings.Contains(name, "router-vpn") {
			return zero, errors.New("bootstrap route is not a captured physical interface")
		}
		actual, addresses, e := desktopnetwork.InterfaceContext(ctx, in.Index)
		if e != nil {
			return zero, e
		}
		if !reflect.DeepEqual(*actual, in) {
			return zero, errors.New("bootstrap interface changed during route capture")
		}
		for _, a := range addresses {
			prefix, e := netip.ParsePrefix(a.String())
			if e == nil && prefix.Addr() == ip {
				return desktopLinuxBootstrapRoute{Interface: in, Address: ip, Decision: string(encoded)}, ctx.Err()
			}
		}
	}
	return zero, errors.New("bootstrap route source disappeared")
}
func desktopLinuxBootstrapExpressions(route desktopLinuxBootstrapRoute, local, remote netip.AddrPort, mark uint32) []any {
	match := func(left, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	meta := func(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
	payload := func(protocol, field string) any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	family := "ip6"
	if local.Addr().Is4() {
		family = "ip"
	}
	return []any{match(meta("skuid"), float64(0)), match(meta("mark"), float64(mark)), match(meta("oifname"), route.Interface.Name), match(payload(family, "saddr"), local.Addr().String()), match(payload(family, "daddr"), remote.Addr().String()), match(meta("l4proto"), "udp"), match(payload("udp", "sport"), float64(local.Port())), match(payload("udp", "dport"), float64(remote.Port())), map[string]any{"accept": nil}}
}
func desktopLinuxBootstrapEcho(raw []byte, request map[string]any) (uint64, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return 0, errors.New("bootstrap echo exceeded its bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	value, e := profileValue(d, 0)
	got, ok := value.(map[string]any)
	if e != nil || !ok {
		return 0, errors.Join(e, errors.New("bootstrap echo is ambiguous"))
	}
	if _, e = d.Token(); e != io.EOF {
		return 0, errors.New("bootstrap echo contains trailing data")
	}
	var canonical any
	encoded, _ := json.Marshal(request)
	_ = json.Unmarshal(encoded, &canonical)
	rows, ok := got["nftables"].([]any)
	if !ok || len(got) != 1 || len(rows) != 1 {
		return 0, errors.New("bootstrap creation omitted its original rule echo")
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		return 0, errors.New("invalid bootstrap rule echo")
	}
	op, _ := row["add"].(map[string]any)
	rule, _ := op["rule"].(map[string]any)
	handle := desktopLinuxNumber(rule["handle"])
	if handle == 0 || handle > 1<<53-1 {
		return 0, errors.New("bootstrap rule lacks its original handle")
	}
	delete(rule, "handle")
	if !reflect.DeepEqual(got, canonical) {
		return 0, errors.New("bootstrap rule echo changed its exact socket scope")
	}
	return handle, nil
}
func (t *desktopLinuxStandardBootstrap) currentSocket(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	identity, e := desktopLinuxSocketIdentity(t.file)
	if e != nil || identity != t.socket {
		return errors.Join(e, errors.New("bootstrap socket identity changed"))
	}
	mark, e := syscall.GetsockoptInt(int(t.file.Fd()), syscall.SOL_SOCKET, syscall.SO_MARK)
	if e != nil || uint32(mark) != t.mark {
		return errors.Join(e, errors.New("bootstrap socket mark changed"))
	}
	device, e := desktopLinuxBoundDevice(int(t.file.Fd()))
	if e != nil || device != t.route.Interface.Name {
		return errors.Join(e, errors.New("bootstrap socket physical binding changed"))
	}
	route, e := desktopLinuxBootstrapRouteFor(ctx, t.remote.Addr(), t.mark, t.conn.LocalAddr().(*net.UDPAddr).AddrPort())
	if e != nil || !reflect.DeepEqual(route, t.route) {
		return errors.Join(e, errors.New("bootstrap physical route changed"))
	}
	return ctx.Err()
}

// inventory accepts only the original acknowledged additional handle, never a
// later lookalike. Its removal must leave the original complete baseline.
func (t *desktopLinuxStandardBootstrap) inventory(b *DesktopLinuxNodeBaseline, rows []map[string]any) (bool, error) {
	var filtered []map[string]any
	present := false
	for _, row := range rows {
		rule, _ := row["rule"].(map[string]any)
		if desktopLinuxNumber(rule["handle"]) == t.handle && t.handle != 0 {
			if present || !desktopLinuxProtectionKeys(rule, "family", "table", "chain", "handle", "expr") || rule["family"] != "inet" || rule["table"] != b.nft.table() || rule["chain"] != "output" || !reflect.DeepEqual(desktopLinuxSetNormalized(rule["expr"]), desktopLinuxSetNormalized(t.expression)) {
				return false, errors.New("bootstrap grant was replaced")
			}
			present = true
			continue
		}
		filtered = append(filtered, desktopLinuxSetNormalized(row).(map[string]any))
	}
	n := *b.nft
	n.Baseline = map[uint64]any{}
	for h, expr := range b.nft.Baseline {
		n.Baseline[h] = desktopLinuxSetNormalized(expr)
	}
	return present, desktopLinuxProtectionInventoryRows(&n, filtered, false)
}
func (t *desktopLinuxStandardBootstrap) observe(ctx context.Context, b *DesktopLinuxNodeBaseline) (bool, error) {
	if e := b.currentNamespace(ctx); e != nil {
		return false, e
	}
	before, e := b.netlink.generation(ctx)
	if e != nil {
		return false, e
	}
	rows, e := desktopLinuxNFTReadTable(ctx, b.nft.table())
	if e != nil {
		return false, e
	}
	present, e := t.inventory(b, rows)
	if e != nil {
		return false, e
	}
	after, e := b.netlink.generation(ctx)
	if e != nil || before != after {
		return false, errors.Join(e, errors.New("bootstrap policy changed during its native snapshot"))
	}
	return present, b.currentNamespace(ctx)
}
func (p *DesktopLinuxStandardProtection) cleanupBootstrapLocked(ctx context.Context, lease *os.File) error {
	t, b := p.bootstrap, p.baseline
	if t == nil {
		return nil
	}
	if b.crossTransfer != "bootstrap" {
		return errors.New("bootstrap cleanup lost its original reservation")
	}
	if e := desktopLinuxStandardLease(lease); e != nil {
		return e
	}
	if t.attempted && t.handle == 0 {
		return errors.New("bootstrap retains an unacknowledged grant and original socket")
	}
	if t.handle != 0 {
		present, e := t.observe(ctx, b)
		if e != nil {
			return e
		}
		if present {
			body, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"delete": map[string]any{"rule": map[string]any{"family": "inet", "table": b.nft.table(), "chain": "output", "handle": t.handle}}}}})
			_, commandErr := desktopLinuxNFTCommandFiles(ctx, []string{"-j", "-f", "-"}, string(body), []*os.File{lease})
			present, e = t.observe(ctx, b)
			if e != nil || present {
				return errors.Join(commandErr, e, errors.New("bootstrap original grant removal is not proved"))
			}
		}
	}
	if e := t.closeSocket(); e != nil {
		return e
	}
	p.bootstrap = nil
	b.crossTransfer = ""
	return ctx.Err()
}

// The source port/cookie stays retained until exact removal and baseline
// readback. Only that caller may invoke this descriptor finalizer. ErrClosed
// refers to these same retained Go objects, never a reopened descriptor number.
func (t *desktopLinuxStandardBootstrap) closeSocket() error {
	if t.conn != nil {
		if e := t.conn.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
			return e
		}
		t.conn = nil
	}
	if t.file != nil {
		if e := t.file.Close(); e != nil && !errors.Is(e, os.ErrClosed) {
			return e
		}
		t.file = nil
	}
	return nil
}

// CleanupBootstrap retires only a pending transaction already owned by this
// original creator. It cannot start a lookup or create a replacement socket.
func (p *DesktopLinuxStandardProtection) CleanupBootstrap(ctx context.Context, lease *os.File) error {
	if p == nil || p.baseline == nil {
		return errors.New("bootstrap lost its original creator")
	}
	b := p.baseline
	if e := b.enter(ctx); e != nil {
		return e
	}
	defer func() { b.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return p.cleanupBootstrapLocked(ctx, lease)
}

// BootstrapDNSExchange admits one exact UDP socket to a captured literal
// machine resolver. Only the authenticated service supplies the already
// validated profile question. No socket or permit is returned to its caller.
func (p *DesktopLinuxStandardProtection) BootstrapDNSExchange(ctx context.Context, lease *os.File, resolver netip.Addr, question []byte) (answer []byte, failure error) {
	if ctx == nil {
		return nil, errors.New("bootstrap has no original caller")
	}
	defer func() {
		failure = errors.Join(failure, ctx.Err())
		if failure != nil {
			answer = nil
		}
	}()
	deadline, bounded := ctx.Deadline()
	if !bounded || ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), errors.New("bootstrap requires its original deadline"))
	}
	if desktopLinuxBootstrapQuestion(question) != nil {
		return nil, errors.New("bootstrap question is not a sole exact hostname A/AAAA lookup")
	}
	if !resolver.IsGlobalUnicast() || resolver.IsLoopback() || resolver.Is4In6() || resolver.Zone() != "" || len(question) < 17 || len(question) > 267 {
		return nil, errors.New("bootstrap destination/question is outside captured bounds")
	}
	if e := p.Current(ctx, lease); e != nil {
		return nil, e
	}
	b := p.baseline
	if e := b.enter(ctx); e != nil {
		return nil, e
	}
	defer func() { b.gate <- struct{}{} }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if p.bootstrap != nil || b.crossTransfer != "" || b.successor != nil || b.removed {
		return nil, errors.New("bootstrap creator already has pending work")
	}
	route, e := desktopLinuxBootstrapRouteFor(ctx, resolver, 0, netip.AddrPort{})
	if e != nil {
		return nil, e
	}
	conn, e := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(route.Address, 0)))
	if e != nil {
		return nil, e
	}
	file, e := conn.File()
	if e != nil {
		conn.Close()
		return nil, e
	}
	t := &desktopLinuxStandardBootstrap{conn: conn, file: file, route: route, remote: netip.AddrPortFrom(resolver, 53)}
	p.bootstrap = t
	b.crossTransfer = "bootstrap"
	defer func() {
		cleanup, stop := context.WithDeadline(context.WithoutCancel(ctx), deadline)
		defer stop()
		failure = errors.Join(failure, ctx.Err(), p.cleanupBootstrapLocked(cleanup, lease))
		if failure != nil {
			answer = nil
		}
	}()
	var random [4]byte
	if _, e = rand.Read(random[:]); e != nil {
		return nil, e
	}
	t.mark = binary.BigEndian.Uint32(random[:]) | 0x80000000
	if e = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_MARK, int(t.mark)); e != nil {
		return nil, e
	}
	if e = syscall.SetsockoptString(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, route.Interface.Name); e != nil {
		return nil, e
	}
	t.socket, e = desktopLinuxSocketIdentity(file)
	if e != nil {
		return nil, e
	}
	t.expression = desktopLinuxBootstrapExpressions(route, conn.LocalAddr().(*net.UDPAddr).AddrPort(), t.remote, t.mark)
	if _, e = b.observe(ctx, false); e != nil {
		return nil, e
	}
	if e = t.currentSocket(ctx); e != nil {
		return nil, e
	}
	request := map[string]any{"nftables": []any{map[string]any{"add": map[string]any{"rule": map[string]any{"family": "inet", "table": b.nft.table(), "chain": "output", "expr": t.expression}}}}}
	body, _ := json.Marshal(request)
	t.attempted = true
	raw, e := desktopLinuxNFTCommandFiles(ctx, []string{"-a", "-e", "-j", "-f", "-"}, string(body), []*os.File{lease})
	if e != nil {
		return nil, e
	}
	t.handle, e = desktopLinuxBootstrapEcho(raw, request)
	if e != nil {
		return nil, e
	}
	if b.nft.Baseline[t.handle] != nil || t.handle == b.nft.ChainHandle {
		return nil, errors.New("bootstrap echo reused an original handle")
	}
	present, e := t.observe(ctx, b)
	if e != nil || !present {
		return nil, errors.Join(e, errors.New("bootstrap grant lacks exact readback"))
	}
	if e = t.currentSocket(ctx); e != nil {
		return nil, e
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, e
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if _, e = conn.WriteToUDPAddrPort(question, t.remote); e != nil {
		return nil, e
	}
	buffer := make([]byte, (16<<10)+1)
	n, from, e := conn.ReadFromUDPAddrPort(buffer)
	if e != nil || from != t.remote || n > 16<<10 {
		return nil, errors.Join(e, fmt.Errorf("bootstrap response does not belong to original resolver"))
	}
	if e = t.currentSocket(ctx); e != nil {
		return nil, e
	}
	present, e = t.observe(ctx, b)
	if e != nil || !present {
		return nil, errors.Join(e, errors.New("bootstrap grant changed before response adoption"))
	}
	return buffer[:n], ctx.Err()
}

// No compression, search expansion, additional queries or EDNS payload can
// turn this temporary resolver socket into an arbitrary query/proxy channel.
func desktopLinuxBootstrapQuestion(q []byte) error {
	bad := errors.New("invalid bootstrap question")
	if len(q) < 17 || len(q) > 267 || q[2] != 1 || q[3] != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return bad
	}
	for _, v := range q[6:12] {
		if v != 0 {
			return bad
		}
	}
	i := 12
	labels := 0
	for {
		if i >= len(q) {
			return bad
		}
		n := int(q[i])
		i++
		if n == 0 {
			break
		}
		if n > 63 || i+n >= len(q) || q[i] == '-' || q[i+n-1] == '-' {
			return bad
		}
		for _, c := range q[i : i+n] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return bad
			}
		}
		i += n
		labels++
	}
	if labels == 0 || i+4 != len(q) || binary.BigEndian.Uint16(q[i+2:]) != 1 {
		return bad
	}
	kind := binary.BigEndian.Uint16(q[i : i+2])
	if kind != 1 && kind != 28 {
		return bad
	}
	return nil
}
