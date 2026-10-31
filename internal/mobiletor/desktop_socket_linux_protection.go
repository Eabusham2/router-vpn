//go:build linux

package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"time"
)

// ObservePreparedProtection reads the actual closed baseline and empty native
// permit inventory before this source has admitted any socket work. The read
// is serialized with the guardian request stream. It does not hold a kernel
// transaction after returning and cannot authorize a later replacement owner.
func (p *DesktopLinuxSocketPolicy) ObservePreparedProtection(ctx context.Context, capture DesktopSocketCapture) (DesktopLinuxProtectionRecord, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || capture != p.capture {
		return DesktopLinuxProtectionRecord{}, net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || !p.Current(capture, p.owner) || p.socketActivity || p.closeAcknowledged.Load() {
		return DesktopLinuxProtectionRecord{}, errors.New("Linux prepared protection requires its unused live native source")
	}
	if err := p.options.validate(); err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	record, err := p.protectionRecord()
	if err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	if err = p.readProtection(ctx, true); err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	if ctx.Err() != nil || !p.Current(capture, p.owner) || p.socketActivity || p.options.validate() != nil {
		return DesktopLinuxProtectionRecord{}, errors.New("Linux prepared protection lost its captured source during readback")
	}
	return record, nil
}

// ObserveRetiredProtection is available only after Close has acknowledged the
// guardian/monitor join and complete owned-permit cleanup. It independently
// verifies that the original closed baseline still exists. Unknown cleanup,
// a missing baseline, or a replacement is never a successful retained result.
// The returned record is a point-in-time readback through this exact owner;
// callers must retain native authority for later admission/journal operations.
func (p *DesktopLinuxSocketPolicy) ObserveRetiredProtection(ctx context.Context, capture DesktopSocketCapture) (DesktopLinuxProtectionRecord, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || capture != p.capture {
		return DesktopLinuxProtectionRecord{}, net.ErrClosed
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || !p.closeAcknowledged.Load() || !p.closing.Load() || !desktopLinuxJoined(p.joined) || !desktopLinuxJoined(p.monitorDone) {
		return DesktopLinuxProtectionRecord{}, errors.New("Linux retired protection requires the acknowledged native source join")
	}
	record, err := p.protectionRecord()
	if err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	if err = p.readProtection(ctx, false); err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	if ctx.Err() != nil {
		return DesktopLinuxProtectionRecord{}, ctx.Err()
	}
	return record, nil
}

func desktopLinuxJoined(joined <-chan struct{}) bool {
	select {
	case <-joined:
		return true
	default:
		return false
	}
}

func (p *DesktopLinuxSocketPolicy) protectionRecord() (DesktopLinuxProtectionRecord, error) {
	n := p.nft
	if n == nil || n.Capture != p.capture || n.UID != p.uid || p.command == nil || p.command.Process == nil ||
		uint32(p.command.Process.Pid) != p.owner.ProcessID || len(n.Rules) != 4 || len(n.Sets) != 4 ||
		len(n.Baseline) < 4 || len(n.Baseline) > 6 {
		return DesktopLinuxProtectionRecord{}, errors.New("Linux protection has no complete captured native inventory")
	}
	// Validate the captured baseline itself as well as today's kernel rows.
	// A serialized/malformed helper result cannot supply arbitrary exemptions.
	baselineRows := make([]map[string]any, 0, len(n.Baseline))
	for handle, expressions := range n.Baseline {
		if handle == 0 || handle > 1<<53-1 {
			return DesktopLinuxProtectionRecord{}, errors.New("Linux baseline handle is not an exact JSON integer")
		}
		baselineRows = append(baselineRows, map[string]any{"rule": map[string]any{
			"family": "inet", "table": desktopLinuxNFTTable, "chain": "output", "handle": float64(handle), "expr": expressions,
		}})
	}
	captured := &desktopLinuxNFT{Baseline: make(map[uint64]any)}
	if err := captured.captureBaseline(baselineRows, p.options); err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	for _, kind := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		if n.Rules[kind] == 0 || n.Rules[kind] > 1<<53-1 || n.Sets[kind] == 0 || n.Sets[kind] > 1<<53-1 {
			return DesktopLinuxProtectionRecord{}, errors.New("Linux protection lost an exact owned rule or set handle")
		}
	}
	encoded, err := json.Marshal(n.Baseline)
	if err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	digest := sha256.Sum256(encoded)
	record := DesktopLinuxProtectionRecord{Capture: p.capture, Owner: p.owner, UID: p.uid, PermitPrefix: n.Prefix,
		TableHandle: n.TableHandle, ChainHandle: n.ChainHandle, BaselineSHA256: hex.EncodeToString(digest[:])}
	if err = record.Validate(); err != nil {
		return DesktopLinuxProtectionRecord{}, err
	}
	return record, nil
}

func (p *DesktopLinuxSocketPolicy) readProtection(parent context.Context, prepared bool) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	rows, err := desktopLinuxNFTRead(ctx)
	if err != nil {
		return err
	}
	if err = desktopLinuxProtectionRows(p.nft, rows, prepared); err != nil {
		return err
	}
	return ctx.Err()
}

func desktopLinuxProtectionKeys(value map[string]any, allowed ...string) bool {
	for key := range value {
		found := false
		for _, candidate := range allowed {
			if key == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func desktopLinuxProtectionEmpty(value map[string]any, key string) bool {
	content, exists := value[key]
	if !exists {
		return true
	}
	items, ok := content.([]any)
	return ok && len(items) == 0
}

// Unlike an ordinary active-permit readback, a closed observation accepts only
// this complete namespace. Extra objects, dormant tables and nonempty tuple
// sets cannot be mistaken for a prepared/retired deny baseline. No mutation is
// performed here, including when a newer owner has replaced the table.
func desktopLinuxProtectionRows(n *desktopLinuxNFT, rows []map[string]any, prepared bool) error {
	if err := n.verifyRows(rows, prepared); err != nil {
		return err
	}
	tables, chains, metadata, rules, sets := 0, 0, 0, 0, 0
	baseline := make(map[uint64]bool)
	for _, row := range rows {
		if len(row) != 1 {
			return errors.New("Linux closed protection received an ambiguous native object")
		}
		for kind, raw := range row {
			value, ok := raw.(map[string]any)
			if !ok || value == nil {
				return errors.New("Linux closed protection received a malformed native object")
			}
			switch kind {
			case "metainfo":
				metadata++
				if metadata > 1 {
					return errors.New("Linux closed protection received duplicate native metadata")
				}
			case "table":
				tables++
				if !desktopLinuxProtectionKeys(value, "family", "name", "handle", "flags") || value["family"] != "inet" ||
					value["name"] != desktopLinuxNFTTable || desktopLinuxNumber(value["handle"]) != n.TableHandle ||
					!desktopLinuxProtectionEmpty(value, "flags") {
					return errors.New("Linux closed protection table was replaced or is not active")
				}
			case "chain":
				chains++
				if !desktopLinuxProtectionKeys(value, "family", "table", "name", "handle", "type", "hook", "prio", "policy", "comment") ||
					value["family"] != "inet" || value["table"] != desktopLinuxNFTTable || value["name"] != "output" ||
					desktopLinuxNumber(value["handle"]) != n.ChainHandle || value["type"] != "filter" || value["hook"] != "output" ||
					value["prio"] != float64(-310) || value["policy"] != "drop" ||
					value["comment"] != "routervpn-owned-baseline:"+n.Capture.SessionID+":"+n.Capture.SourceSHA256 {
					return errors.New("Linux closed protection chain lost its exact captured baseline")
				}
			case "rule":
				if !desktopLinuxProtectionKeys(value, "family", "table", "chain", "handle", "expr", "comment") ||
					value["family"] != "inet" || value["table"] != desktopLinuxNFTTable || value["chain"] != "output" {
					return errors.New("Linux closed protection contains an unrelated rule")
				}
				handle := desktopLinuxNumber(value["handle"])
				if expected, found := n.Baseline[handle]; found {
					if baseline[handle] || !reflect.DeepEqual(value["expr"], expected) || value["comment"] != nil && value["comment"] != "" {
						return errors.New("Linux closed protection baseline gained or changed an exemption")
					}
					baseline[handle] = true
					continue
				}
				owned := false
				for _, transport := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
					if prepared && handle == n.Rules[transport] && value["comment"] == n.comment(transport) && reflect.DeepEqual(value["expr"], n.ruleExpressions(transport)) {
						owned = true
					}
				}
				if !owned {
					return errors.New("Linux closed protection contains a foreign or unretired permit rule")
				}
				rules++
			case "set":
				owned := false
				for _, transport := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
					if prepared && value["name"] == n.Prefix+"_"+transport && desktopLinuxNumber(value["handle"]) == n.Sets[transport] {
						owned = true
					}
				}
				if !owned || !desktopLinuxProtectionKeys(value, "family", "table", "name", "handle", "type", "flags", "timeout", "size", "policy", "elem") ||
					!desktopLinuxProtectionEmpty(value, "elem") || value["policy"] != nil && value["policy"] != "performance" && value["policy"] != "memory" {
					return errors.New("Linux closed protection contains a foreign, malformed or active tuple set")
				}
				sets++
			default:
				return errors.New("Linux closed protection contains an unexpected native object")
			}
		}
	}
	wantPermits := 0
	if prepared {
		wantPermits = 4
	}
	if tables != 1 || chains != 1 || len(baseline) != len(n.Baseline) || rules != wantPermits || sets != wantPermits {
		return errors.New("Linux closed protection has a missing or duplicate captured object")
	}
	return nil
}
