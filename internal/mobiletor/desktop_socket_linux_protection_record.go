package mobiletor

import "errors"

const desktopLinuxNFTTable = "router_vpn_killswitch"
const desktopLinuxNodeTablePrefix = "router_vpn_node_"

func desktopLinuxNodeTable(capture DesktopSocketCapture) string {
	return desktopLinuxNodeTablePrefix + capture.SessionID
}

func desktopLinuxTableValid(capture DesktopSocketCapture, table string) bool {
	return capture.valid() && (table == "" || table == desktopLinuxNodeTable(capture))
}

// DesktopLinuxProtectionRecord identifies a baseline observed through its
// retained native source. It is not a policy constructor, an authorization to
// replace rules, or proof that a later journal write held a kernel snapshot.
// In particular, the kernel chain binds SessionID and SourceSHA256; NetworkID
// and Owner are bound by the actual retained source, not by the chain comment.
type DesktopLinuxProtectionRecord struct {
	Capture      DesktopSocketCapture     `json:"capture"`
	Owner        DesktopSocketKernelOwner `json:"owner"`
	UID          uint32                   `json:"uid"`
	PermitPrefix string                   `json:"permit_prefix"`
	// Empty preserves the original fixed Tor/global table canonical record.
	// Node tables are derived from the exact session, never arbitrary names.
	TableName      string `json:"table_name,omitempty"`
	TableHandle    uint64 `json:"table_handle"`
	ChainHandle    uint64 `json:"chain_handle"`
	BaselineSHA256 string `json:"baseline_sha256"`
}

func (r DesktopLinuxProtectionRecord) Validate() error {
	// Keep handles within the exact integer range of the nft JSON decoder.
	// Refuse a larger handle rather than identifying two objects as one.
	const maximumExactJSONInteger = uint64(1<<53 - 1)
	if !desktopLinuxTableValid(r.Capture, r.TableName) || !r.Owner.valid() || r.Owner.Kind != "unix-isolated-uid" || r.UID == 0 ||
		len(r.PermitPrefix) != 25 || r.PermitPrefix[:5] != "rvpn_" || !desktopSocketHex(r.PermitPrefix[5:], 20) ||
		r.TableHandle == 0 || r.TableHandle > maximumExactJSONInteger || r.ChainHandle == 0 || r.ChainHandle > maximumExactJSONInteger ||
		!desktopSocketHex(r.BaselineSHA256, 64) {
		return errors.New("Linux protection record lacks its exact native source and baseline identity")
	}
	return nil
}
