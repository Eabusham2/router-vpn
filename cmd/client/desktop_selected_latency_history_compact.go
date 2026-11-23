package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// Long selected paths share their full original descriptor on disk. The public
// API still carries the original capture and complete receipt. Generation is
// restored from each receipt and checked against that row's original capture
// digest, so reconnecting does not duplicate or relabel the inventory.
type desktopSelectedLatencyCompactHistory struct {
	Schema   int                                    `json:"schema"`
	Captures []desktopSelectedLatencyCompactCapture `json:"captures"`
	Records  []desktopSelectedLatencyCompactRecord  `json:"records"`
}

type desktopSelectedLatencyCompactCapture struct {
	SHA256  string `json:"sha256"`
	Capture string `json:"selected_capture"`
}

type desktopSelectedLatencyCompactRecord struct {
	CaptureSHA256         string                           `json:"capture_sha256"`
	OriginalCaptureSHA256 string                           `json:"original_capture_sha256"`
	Receipt               hopmeasure.OrderedLatencyReceipt `json:"receipt"`
}

func desktopSelectedDescriptorSHA(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func encodeDesktopSelectedLatencyHistory(history desktopSelectedLatencyHistory) ([]byte, error) {
	compact := desktopSelectedLatencyCompactHistory{Schema: 2, Captures: []desktopSelectedLatencyCompactCapture{}, Records: []desktopSelectedLatencyCompactRecord{}}
	seen := map[string]bool{}
	extended := false
	for _, row := range history.Records {
		if err := validateDesktopSelectedLatencyReceipt(row.Capture, row.Receipt, time.Now()); err != nil {
			return nil, err
		}
		capture, nodes, err := decodeDesktopSelectedLatencyCapture(row.Capture)
		if err != nil {
			return nil, err
		}
		extended = extended || len(nodes) > mobilemultihop.NodeChainMaximumNodes
		capture.GenerationSHA256 = strings.Repeat("0", 64)
		raw, err := json.Marshal(capture)
		if err != nil {
			return nil, err
		}
		digest := desktopSelectedDescriptorSHA(string(raw))
		if !seen[digest] {
			compact.Captures = append(compact.Captures, desktopSelectedLatencyCompactCapture{SHA256: digest, Capture: string(raw)})
			seen[digest] = true
		}
		compact.Records = append(compact.Records, desktopSelectedLatencyCompactRecord{
			CaptureSHA256: digest, OriginalCaptureSHA256: desktopSelectedDescriptorSHA(row.Capture), Receipt: row.Receipt})
	}
	if extended {
		return json.Marshal(compact)
	}
	return json.Marshal(history)
}

func expandDesktopSelectedLatencyCompactHistory(raw []byte) (desktopSelectedLatencyHistory, error) {
	history := desktopSelectedLatencyHistory{Schema: 1, Records: []desktopSelectedLatencyHistoryRecord{}}
	var compact desktopSelectedLatencyCompactHistory
	bad := errors.New("selected history lost its complete original descriptor table")
	if decodePrivateControlJSONBounded(raw, &compact, desktopOrderedHistoryLimit) != nil || compact.Schema != 2 ||
		len(compact.Captures) == 0 || len(compact.Captures) > desktopOrderedHistoryEntries || len(compact.Records) == 0 || len(compact.Records) > desktopOrderedHistoryEntries {
		return history, bad
	}
	captures := map[string]desktopSelectedLatencyCapture{}
	extended := false
	for _, row := range compact.Captures {
		capture, nodes, err := decodeDesktopSelectedLatencyCapture(row.Capture)
		if err != nil || !desktopOrderedDigest.MatchString(row.SHA256) || desktopSelectedDescriptorSHA(row.Capture) != row.SHA256 ||
			capture.GenerationSHA256 != strings.Repeat("0", 64) {
			return history, bad
		}
		if _, duplicate := captures[row.SHA256]; duplicate {
			return history, bad
		}
		captures[row.SHA256] = capture
		extended = extended || len(nodes) > mobilemultihop.NodeChainMaximumNodes
	}
	if !extended {
		return history, bad
	}
	used := map[string]bool{}
	for _, row := range compact.Records {
		capture, ok := captures[row.CaptureSHA256]
		if !ok || !desktopOrderedDigest.MatchString(row.Receipt.GenerationSHA256) || !desktopOrderedDigest.MatchString(row.OriginalCaptureSHA256) {
			return history, bad
		}
		capture.GenerationSHA256 = row.Receipt.GenerationSHA256
		encoded, err := json.Marshal(capture)
		if err != nil || desktopSelectedDescriptorSHA(string(encoded)) != row.OriginalCaptureSHA256 {
			return history, bad
		}
		history.Records = append(history.Records, desktopSelectedLatencyHistoryRecord{Capture: string(encoded), Receipt: row.Receipt})
		used[row.CaptureSHA256] = true
	}
	if len(used) != len(captures) {
		return history, bad
	}
	return history, nil
}
