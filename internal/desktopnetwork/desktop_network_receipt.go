package desktopnetwork

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const DesktopNetworkReceiptLimit = 16 << 10

// DesktopNetworkObject describes one observed kernel route or policy rule.
// Linux Native is its canonical complete rtnetlink body, including otherwise
// unknown attributes. The other platforms use the native notification keys.
// None of these values grants permission to install, remove or adopt policy.
type DesktopNetworkObject struct {
	Kind        string `json:"kind"`
	Family      int    `json:"family"`
	Index       uint32 `json:"index,omitempty"`
	LUID        uint64 `json:"luid,omitempty"`
	Table       uint32 `json:"table,omitempty"`
	Priority    uint32 `json:"priority,omitempty"`
	Destination string `json:"destination,omitempty"`
	Gateway     string `json:"gateway,omitempty"`
	Flags       uint32 `json:"flags,omitempty"`
	MTU         uint32 `json:"mtu,omitempty"`
	Native      string `json:"native,omitempty"`
	darwinCache *desktopDarwinCacheObservation
}

func (o DesktopNetworkObject) Key() string {
	raw, _ := json.Marshal(o)
	return string(raw)
}

func (o DesktopNetworkObject) Validate(target string) error {
	bad := errors.New("desktop network object lost its complete native identity")
	if o.darwinCache != nil && (target != "darwin" || !o.darwinCache.binds(o)) {
		return bad
	}
	if o.Kind != "route" && o.Kind != "rule" || o.Family != 4 && o.Family != 6 &&
		!(target == "linux" && (o.Family == 128 || o.Family == 129)) {
		return bad
	}
	if target == "linux" {
		body, err := base64.StdEncoding.Strict().DecodeString(o.Native)
		if err != nil || len(body) > 8192 || base64.StdEncoding.EncodeToString(body) != o.Native {
			return bad
		}
		actual, err := ParseDesktopLinuxNetworkObject(o.Kind, body)
		if err != nil || actual != o {
			return bad
		}
		return nil
	}
	if target != "windows" && target != "darwin" || o.Kind != "route" || o.Native != "" || o.Table != 0 || o.Index == 0 ||
		target == "windows" && o.LUID == 0 || target == "darwin" && o.LUID != 0 {
		return bad
	}
	prefix, err := netip.ParsePrefix(o.Destination)
	if err != nil || prefix.String() != o.Destination || prefix != prefix.Masked() || (prefix.Addr().Is4()) != (o.Family == 4) {
		return bad
	}
	if o.Gateway != "" {
		gateway, err := netip.ParseAddr(o.Gateway)
		if err != nil || gateway.String() != o.Gateway || gateway.Is4() != (o.Family == 4) || gateway.Zone() != "" {
			return bad
		}
	}
	return nil
}

// DesktopNetworkReceipt is emitted only by the original native TUN after its
// successful construction and routing calls. Its containing source/session
// proof supplies authority; decoding a saved receipt cannot create it. A batch
// may use it only to classify that owner's bounded startup/teardown events.
type DesktopNetworkReceipt struct {
	Schema      int                    `json:"schema"`
	TargetOS    string                 `json:"target_os"`
	Incarnation string                 `json:"incarnation"`
	Name        string                 `json:"name"`
	Index       uint32                 `json:"index"`
	LUID        uint64                 `json:"luid,omitempty"`
	MTU         int                    `json:"mtu"`
	Addresses   []string               `json:"addresses"`
	Objects     []DesktopNetworkObject `json:"objects"`
}

func (r DesktopNetworkReceipt) Validate() error {
	bad := errors.New("desktop network receipt is not an exact bounded native TUN capture")
	nonce, err := hex.DecodeString(r.Incarnation)
	if r.Schema != 1 || (r.TargetOS != "linux" && r.TargetOS != "windows" && r.TargetOS != "darwin") ||
		err != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != r.Incarnation || bytes.Equal(nonce, make([]byte, 16)) ||
		r.Name == "" || len(r.Name) > 64 || strings.IndexFunc(r.Name, func(v rune) bool { return v <= 0x20 || v == 0x7f }) >= 0 ||
		r.Index == 0 || r.MTU < 576 || r.MTU > 9000 || r.TargetOS == "windows" && r.LUID == 0 || r.TargetOS != "windows" && r.LUID != 0 ||
		len(r.Addresses) == 0 || len(r.Addresses) > 32 || len(r.Objects) > 256 {
		return bad
	}
	previous := ""
	for _, address := range r.Addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil || prefix.String() != address || !prefix.Addr().IsValid() || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().Zone() != "" || address <= previous || prefix.Addr().Is6() && r.MTU < 1280 {
			return bad
		}
		previous = address
	}
	previous = ""
	for _, object := range r.Objects {
		key := object.Key()
		// Multicast FIBs are retained in the ambient snapshot but these native
		// TUN constructors install only unicast IPv4/IPv6 policy. They cannot
		// claim an ambient multicast rule as an owned transition.
		if object.darwinCache != nil || object.Validate(r.TargetOS) != nil || key <= previous || object.Family != 4 && object.Family != 6 ||
			object.Kind == "route" && (object.Index != r.Index || object.LUID != r.LUID) ||
			object.Kind == "rule" && (r.TargetOS != "linux" || object.Index != 0 || object.LUID != 0) {
			return bad
		}
		previous = key
	}
	return nil
}

func CanonicalDesktopNetworkReceipt(r DesktopNetworkReceipt) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > DesktopNetworkReceiptLimit {
		return "", errors.New("desktop network receipt exceeded its native bound")
	}
	return string(raw), nil
}

func ParseDesktopNetworkReceipt(raw string) (DesktopNetworkReceipt, error) {
	var r DesktopNetworkReceipt
	if len(raw) == 0 || len(raw) > DesktopNetworkReceiptLimit || json.Unmarshal([]byte(raw), &r) != nil {
		return r, errors.New("desktop network receipt is unavailable or malformed")
	}
	canonical, err := CanonicalDesktopNetworkReceipt(r)
	if err != nil || canonical != raw {
		return DesktopNetworkReceipt{}, errors.New("desktop network receipt is not canonical and complete")
	}
	return r, nil
}

func SortDesktopNetworkObjects(objects []DesktopNetworkObject) {
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key() < objects[j].Key() })
}

// This private observation exists only on a decoded original NET_RT_DUMP2
// cache row. It is never serialized, accepted from a connection receipt, or
// included in stable route keys. Counts and expiry are live kernel bookkeeping,
// not an additional routing policy or authority to mutate one.
type desktopDarwinCacheObservation struct {
	original    DesktopNetworkObject
	rawFlags    uint32
	parentFlags uint32
	references  int32
	expires     int32
}

func desktopDarwinCaptureCacheObservation(object DesktopNetworkObject, rawFlags, parentFlags uint32, references, expires int32) DesktopNetworkObject {
	const wasCloned, proto3 = uint32(0x20000), uint32(0x40000)
	if object.Flags&(wasCloned|proto3) == wasCloned|proto3 {
		object.darwinCache = &desktopDarwinCacheObservation{original: object, rawFlags: rawFlags,
			parentFlags: parentFlags, references: references, expires: expires}
	}
	return object
}

func (p *desktopDarwinCacheObservation) binds(object DesktopNetworkObject) bool {
	if p == nil || p.original.darwinCache != nil {
		return false
	}
	object.darwinCache = nil
	return object == p.original && p.rawFlags&^uint32(0x1|0x40) == object.Flags
}

func desktopDarwinCloneProtocolMatches(object, parent DesktopNetworkObject) bool {
	const up, done, proto3 = uint32(0x1), uint32(0x40), uint32(0x40000)
	const copied = uint32(0x2 | 0x4000 | 0x8000 | 0x40000)
	if parent.Flags&copied == object.Flags&copied {
		return true
	}
	// Only the observed idle-cache addition is justified. A cleared PROTO3,
	// changed gateway/protocol flag or unobserved route remains unclassified.
	if parent.Flags&proto3 != 0 || object.Flags&proto3 == 0 ||
		parent.Flags&(copied&^proto3) != object.Flags&(copied&^proto3) || parent.Flags&(up|done) != 0 {
		return false
	}
	p := object.darwinCache
	// XNU rtfree requires zero references and no IFREF before in_clsroute /
	// in6_clsroute mark an UP, HOST, non-LLINFO cache with RTPRF_OURS and an
	// expiry. DELCLONE is deleted immediately instead. Redirect/static/deny/
	// proxy/defunct entries are never accepted by this proof.
	const required = uint32(0x1 | 0x4 | 0x20000 | 0x40000)
	const forbidden = uint32(0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x400 | 0x800 | 0x1000 | 0x2000000 | 0x4000000 | 0x8000000 | 0x20000000)
	// A positive native expiry classifies this original cache state; it is not
	// a fresh-path lease. An already-due idle row may await the kernel sweep.
	return p.binds(object) && p.references == 0 && p.expires > 0 &&
		p.rawFlags&required == required && p.rawFlags&forbidden == 0 &&
		p.parentFlags == parent.Flags|up
}

// DesktopDarwinDerivedRoute recognizes a kernel-generated host cache only by
// an exact already captured parent route. RTF_WASCLONED by itself is not a
// permission to ignore a route. Redirects, static entries, differing gateways,
// and multiple equally specific parents remain unclassified.
func DesktopDarwinDerivedRoute(object DesktopNetworkObject, parents []DesktopNetworkObject) (bool, error) {
	const host, wasCloned, forbidden = uint32(0x4), uint32(0x20000), uint32(0x8 | 0x10 | 0x20 | 0x800 | 0x1000 | 0x8000000)
	if object.Flags&wasCloned == 0 {
		return false, nil
	}
	if object.Validate("darwin") != nil || object.Flags&host == 0 || object.Flags&forbidden != 0 {
		return false, desktopDarwinCloneFailure("object-shape", object, parents, -1, 0)
	}
	destination, err := netip.ParsePrefix(object.Destination)
	if err != nil || destination.Bits() != destination.Addr().BitLen() {
		return false, desktopDarwinCloneFailure("host-prefix", object, parents, -1, 0)
	}
	// XNU marks a host route to an interface's own address RTF_LOCAL and
	// may deliver it through loopback instead of the parent's interface.
	// Keep that entire local route as observed policy. It is not exempted as
	// a disposable cache: its exact key remains in the frozen cohort and any
	// notification still invalidates the session. No parent or interface
	// authority is inferred from the LOCAL bit.
	if object.Flags&0x200000 != 0 {
		return false, nil
	}
	best, count := -1, 0
	// Gateway and protocol semantics survive cloning. XNU RTM_RESOLVE derives
	// interface scope from the original parent rather than copying that bit.
	// The cache-only HOST/WASCLONED/LLINFO and parent CLONING/PRCLONING/STATIC
	// flags are not equivalent. A PROTO3 idle-cache change requires the private
	// original DUMP2 reference/expiry/parent observation; ordinary notification
	// rows and decoded receipts cannot synthesize that proof.
	for _, parent := range parents {
		if parent.Flags&wasCloned != 0 || parent.Validate("darwin") != nil || parent.Family != object.Family || parent.Index != object.Index ||
			parent.Gateway != object.Gateway || !desktopDarwinCloneProtocolMatches(object, parent) || parent.Flags&(0x8|0x10|0x20|0x1000|0x8000000) != 0 ||
			parent.Flags&(0x100|0x10000) == 0 || !desktopDarwinCloneScopeMatches(object, parent, destination.Addr()) {
			continue
		}
		prefix, err := netip.ParsePrefix(parent.Destination)
		if err != nil || !prefix.Contains(destination.Addr()) {
			continue
		}
		if prefix.Bits() > best {
			best, count = prefix.Bits(), 1
		} else if prefix.Bits() == best {
			count++
		}
	}
	if count != 1 {
		return false, desktopDarwinCloneFailure("unique-parent", object, parents, best, count)
	}
	return true, nil
}

// XNU route.c RTM_RESOLVE sets IFSCOPE for ordinary IPv4/IPv6 clones using
// the parent's existing scope or its original interface. IPv4 link-local
// clones instead clear IFSCOPE and acquire NOIFREF. Proxy parents are refused
// by the caller, and the original interface index must still match exactly.
// This compares the derived bits without rewriting any observed route bytes.
func desktopDarwinCloneScopeMatches(object, parent DesktopNetworkObject, destination netip.Addr) bool {
	const ifscope, noifref = uint32(0x1000000), uint32(0x2000)
	expected := parent.Flags&(ifscope|noifref) | ifscope
	if destination.Is4() && destination.IsLinkLocalUnicast() {
		expected = noifref
	}
	return object.Flags&(ifscope|noifref) == expected
}

// Failure-only, bounded numeric readback. In particular, neither private
// addresses/gateways nor arbitrary native/decoder errors enter this text.
// Unsupported cache states keep their original failure; diagnostics do not
// retry a snapshot, add a parent or authorize a routing mutation.
func desktopDarwinCloneFailure(stage string, object DesktopNetworkObject, parents []DesktopNetworkObject, best, matches int) error {
	const copied = uint32(0x2 | 0x4000 | 0x8000 | 0x40000)
	destination, _ := netip.ParsePrefix(object.Destination)
	rows := make([]string, 0, 8)
	candidates := 0
	for _, parent := range parents[:min(len(parents), 32768)] {
		prefix, err := netip.ParsePrefix(parent.Destination)
		if err != nil || parent.Validate("darwin") != nil || parent.Flags&0x20000 != 0 || parent.Family != object.Family ||
			!destination.IsValid() || !prefix.Contains(destination.Addr()) {
			continue
		}
		candidates++
		if len(rows) == cap(rows) {
			continue
		}
		rows = append(rows, fmt.Sprintf("{index=%d prefix=%d flags=%#x same_index=%t gateway_equal=%t copied_equal=%t proto3_equal=%t scope_equal=%t cloning=%t policy_safe=%t}",
			parent.Index, prefix.Bits(), parent.Flags, parent.Index == object.Index, parent.Gateway == object.Gateway,
			parent.Flags&copied == object.Flags&copied, parent.Flags&0x40000 == object.Flags&0x40000,
			desktopDarwinCloneScopeMatches(object, parent, destination.Addr()), parent.Flags&(0x100|0x10000) != 0,
			parent.Flags&(0x8|0x10|0x20|0x1000|0x8000000) == 0))
	}
	native := ""
	if observed := object.darwinCache; observed != nil {
		native = fmt.Sprintf(" dump2=[bound=%t refs=%d expiry_positive=%t up=%t ifref=%t parent_flags=%#x]", observed.binds(object), observed.references,
			observed.expires > 0, observed.rawFlags&0x1 != 0, observed.rawFlags&0x4000000 != 0, observed.parentFlags)
	}
	return fmt.Errorf("Darwin cloned route has no unique exact captured parent (reason=%s family=%d index=%d flags=%#x prefix=%d ipv4_link_local=%t mtu=%d priority=%d parents=%d best=%d matches=%d candidates=%d shown=%d inventory_truncated=%t rows=[%s]%s)",
		stage, object.Family, object.Index, object.Flags, destination.Bits(), destination.Addr().Is4() && destination.Addr().IsLinkLocalUnicast(), object.MTU, object.Priority, len(parents), best, matches,
		candidates, len(rows), len(parents) > 32768, strings.Join(rows, ","), native)
}
