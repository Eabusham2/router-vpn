package desktopnetwork

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

// DesktopNetworkRetirementReceipt describes the original native constructor's
// completed retirement, including partial startup. It is evidence, never a
// capability to find, adopt or delete an object. The containing authenticated
// child/session and original process join must be checked independently.
type DesktopNetworkRetirementReceipt struct {
	Schema      int                    `json:"schema"`
	TargetOS    string                 `json:"target_os"`
	Created     bool                   `json:"created"`
	Unindexed   bool                   `json:"unindexed,omitempty"`
	Incarnation string                 `json:"incarnation"`
	Name        string                 `json:"name"`
	Index       uint32                 `json:"index"`
	Addresses   []string               `json:"addresses,omitempty"`
	Objects     []DesktopNetworkObject `json:"objects"`
}

func (r DesktopNetworkRetirementReceipt) Validate() error {
	bad := errors.New("native retirement receipt lost its original bounded constructor")
	if r.Schema != 1 || r.TargetOS != "linux" || len(r.Addresses) > 32 || len(r.Objects) > 256 || r.Objects == nil {
		return bad
	}
	if !r.Created {
		if r.Unindexed || r.Incarnation != "" || r.Name != "" || r.Index != 0 || len(r.Objects) != 0 || len(r.Addresses) != 0 {
			return bad
		}
		return nil
	}
	nonce, err := hex.DecodeString(r.Incarnation)
	if err != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != r.Incarnation || bytes.Equal(nonce, make([]byte, 16)) ||
		r.Name == "" || len(r.Name) > 15 || strings.IndexFunc(r.Name, func(c rune) bool { return c <= 0x20 || c == 0x7f || c == '/' }) >= 0 ||
		r.Unindexed && (r.Index != 0 || len(r.Objects) != 0 || len(r.Addresses) != 0) || !r.Unindexed && r.Index == 0 {
		return bad
	}
	previous := ""
	for _, address := range r.Addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil || prefix.String() != address || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || address <= previous {
			return bad
		}
		previous = address
	}
	previous = ""
	for _, object := range r.Objects {
		key := object.Key()
		if object.Validate("linux") != nil || key <= previous || object.Family != 4 && object.Family != 6 ||
			object.Kind == "route" && object.Index != r.Index || object.Kind == "rule" && object.Index != 0 || object.LUID != 0 {
			return bad
		}
		previous = key
	}
	return nil
}

func CanonicalDesktopNetworkRetirementReceipt(r DesktopNetworkRetirementReceipt) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	body, err := json.Marshal(r)
	if err != nil || len(body) > DesktopNetworkReceiptLimit {
		return "", errors.New("native retirement receipt exceeds its original bound")
	}
	return string(body), nil
}

func ParseDesktopNetworkRetirementReceipt(raw string) (DesktopNetworkRetirementReceipt, error) {
	var r DesktopNetworkRetirementReceipt
	if len(raw) == 0 || len(raw) > DesktopNetworkReceiptLimit || json.Unmarshal([]byte(raw), &r) != nil {
		return r, errors.New("native retirement receipt is unavailable or malformed")
	}
	canonical, err := CanonicalDesktopNetworkRetirementReceipt(r)
	if err != nil || canonical != raw {
		return DesktopNetworkRetirementReceipt{}, errors.New("native retirement receipt is not canonical and complete")
	}
	return r, nil
}
