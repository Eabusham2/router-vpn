package desktopnetwork

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
}

func (o DesktopNetworkObject) Key() string {
	raw, _ := json.Marshal(o)
	return string(raw)
}

func (o DesktopNetworkObject) Validate(target string) error {
	bad := errors.New("desktop network object lost its complete native identity")
	if o.Kind != "route" && o.Kind != "rule" || o.Family != 4 && o.Family != 6 {
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
		if object.Validate(r.TargetOS) != nil || key <= previous ||
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

// DesktopDarwinDerivedRoute recognizes a kernel-generated host cache only by
// an exact already captured parent route. RTF_WASCLONED by itself is not a
// permission to ignore a route. Redirects, static entries, differing gateways,
// and multiple equally specific parents remain unclassified.
func DesktopDarwinDerivedRoute(object DesktopNetworkObject, parents []DesktopNetworkObject) (bool, error) {
	const host, wasCloned, forbidden = uint32(0x4), uint32(0x20000), uint32(0x8 | 0x10 | 0x20 | 0x800 | 0x1000 | 0x8000000)
	if object.Flags&wasCloned == 0 {
		return false, nil
	}
	bad := errors.New("Darwin cloned route has no unique exact captured parent")
	if object.Validate("darwin") != nil || object.Flags&host == 0 || object.Flags&forbidden != 0 {
		return false, bad
	}
	destination, err := netip.ParsePrefix(object.Destination)
	if err != nil || destination.Bits() != destination.Addr().BitLen() {
		return false, bad
	}
	best, count := -1, 0
	// Scope and gateway semantics survive cloning. The cache-only HOST,
	// WASCLONED and LLINFO flags and parent CLONING/PRCLONING/STATIC do not.
	const copied = uint32(0x2 | 0x4000 | 0x8000 | 0x40000 | 0x1000000)
	for _, parent := range parents {
		if parent.Flags&wasCloned != 0 || parent.Validate("darwin") != nil || parent.Family != object.Family || parent.Index != object.Index ||
			parent.Gateway != object.Gateway || parent.Flags&copied != object.Flags&copied || parent.Flags&(0x8|0x10|0x20|0x1000) != 0 {
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
		return false, bad
	}
	return true, nil
}
