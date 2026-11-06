package mobilemultihop

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"router-vpn/internal/nativecomposite"
)

// ValidateCapturedSSService verifies configured authority without resolving or
// admitting a physical transport. Hostnames remain owned by the later resolver.
func ValidateCapturedSSService(profile, node string) error {
	if !proofID.MatchString(node) || len(profile) > 8<<20 {
		return errors.New("configured SS service requires a captured node")
	}
	assets, err := nodeProfileAssets(profile)
	if err != nil {
		return err
	}
	defer func() {
		for _, data := range assets {
			clear(data)
		}
	}()
	if len(assets) != 2 || len(assets["sing-box.json"]) == 0 || len(assets[nativecomposite.SSServiceAsset]) == 0 {
		return errors.New("configured SS service requires exactly its original source and declaration")
	}
	return nativecomposite.ValidateSSServiceCompanion(assets["sing-box.json"], assets[nativecomposite.SSServiceAsset], node)
}

// ValidateResolvedSSSource permits only the address projection produced by the
// owned Xray resolver. Authentication and every other original field survive.
func ValidateResolvedSSSource(original, resolved string) error {
	bad := errors.New("resolved AES projection differs from its original captured source")
	var before, after map[string]any
	if exactJSON([]byte(original), &before, 4<<20) != nil || exactJSON([]byte(resolved), &after, 4<<20) != nil {
		return bad
	}
	find := func(graph map[string]any) map[string]any {
		rows, ok := graph["outbounds"].([]any)
		if !ok {
			return nil
		}
		var found map[string]any
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return nil
			}
			if row["type"] == "shadowsocks" {
				if found != nil {
					return nil
				}
				found = row
			}
		}
		return found
	}
	a, b := find(before), find(after)
	if a == nil || b == nil {
		return bad
	}
	old, ok := a["server"].(string)
	if !ok || old == "" {
		return bad
	}
	next, ok := b["server"].(string)
	if !ok {
		return bad
	}
	address, err := netip.ParseAddr(next)
	if err != nil || address.Zone() != "" || address.Is4In6() || !address.IsGlobalUnicast() || address.IsLoopback() {
		return bad
	}
	if previous, e := netip.ParseAddr(old); e == nil && previous != address {
		return bad
	}
	b["server"] = old
	left, e1 := json.Marshal(before)
	right, e2 := json.Marshal(after)
	if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
		return bad
	}
	return nil
}
