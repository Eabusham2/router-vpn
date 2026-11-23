package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// This is durable data/size coverage, not transport qualification. Native
// timing and byte transfers are independently exercised by the encrypted gate.
func TestDesktopSelectedHistoryFullCapacityRoundtrip(t *testing.T) {
	const count = 96
	selected := desktopSelectedLatencyCapture{Schema: 1, SourceSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64),
		GenerationSHA256: strings.Repeat("c", 64), Execution: "server", Nodes: []desktopSelectedLatencyNode{},
		MultipleImported: &desktopSelectedLatencyMultipleImported{Schema: 6, OriginalSourceSHA256: strings.Repeat("d", 64), Public: []desktopSelectedLatencyPublic{}}}
	for position := 0; position < count; position++ {
		kind := "public-path"
		if position == 0 || position == count-1 {
			kind = "private-node"
		}
		role, _, _, _, _ := desktopSelectedLatencyMeaningFamily(position, count, kind, "server", true)
		selected.Nodes = append(selected.Nodes, desktopSelectedLatencyNode{NodeID: fmt.Sprintf("original-position-%d", position), Position: position, Role: role, Kind: kind})
		if kind == "public-path" {
			selected.MultipleImported.Public = append(selected.MultipleImported.Public, desktopSelectedLatencyPublic{
				Position: position, Tag: fmt.Sprintf("routervpn-chain-server-%d-%s", position, selected.SourceSHA256[:16]), SourceSHA256: fmt.Sprintf("%064x", position+1)})
		}
	}
	raw, _ := json.Marshal(selected)
	_, nodes, err := decodeDesktopSelectedLatencyCapture(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	capture := desktopOrderedLatencyCapture{SessionID: "session-1-1", ProfileID: nodes[count-1].NodeID, ProfileToken: strings.Repeat("e", 64),
		SourceSHA256: selected.SourceSHA256, ConfigSHA256: selected.ConfigSHA256, GenerationSHA256: selected.GenerationSHA256, SelectedCaptureJSON: string(raw), ExtendedOriginalNodes: count}
	a := &app{}
	a.cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	for _, node := range nodes {
		receipt := desktopSelectedLatencyReceiptFixture(capture, node)
		if err := saveDesktopOrderedCapturedHistory(a, capture, receipt, func() error { return nil }); err != nil {
			t.Fatal("position", node.Position, err)
		}
	}
	body, err := os.ReadFile(desktopSelectedLatencyHistoryPath(a))
	if err != nil || len(body) > desktopOrderedHistoryLimit {
		t.Fatal("full inventory exceeded existing private bound", err, len(body))
	}
	var compact desktopSelectedLatencyCompactHistory
	if json.Unmarshal(body, &compact) != nil || compact.Schema != 2 || len(compact.Captures) != 1 || len(compact.Records) != count {
		t.Fatal("inventory was repeated or truncated")
	}
	reopened, err := readDesktopSelectedLatencyHistory(a)
	if err != nil || len(reopened.Records) != count {
		t.Fatal("complete durable history lost positions", err)
	}
	for position, row := range reopened.Records {
		want := desktopSelectedLatencyReceiptFixture(capture, nodes[position])
		want.MeasuredAt = row.Receipt.MeasuredAt
		if row.Capture != string(raw) || !reflect.DeepEqual(row.Receipt, want) {
			t.Fatal("descriptor or exact fifty-sample statistics changed", position)
		}
	}
	for _, fault := range []string{"digest", "duplicate", "missing", "unreferenced", "generation", "foreign-generation", "original-capture", "missing-original-capture", "foreign-record"} {
		var changed desktopSelectedLatencyCompactHistory
		_ = json.Unmarshal(body, &changed)
		switch fault {
		case "digest":
			changed.Captures[0].SHA256 = strings.Repeat("f", 64)
		case "duplicate":
			changed.Captures = append(changed.Captures, changed.Captures[0])
		case "missing":
			changed.Captures = nil
		case "unreferenced":
			changed.Records = nil
		case "generation":
			changed.Records[0].Receipt.GenerationSHA256 = ""
		case "foreign-generation":
			changed.Records[0].Receipt.GenerationSHA256 = strings.Repeat("f", 64)
		case "original-capture":
			changed.Records[0].OriginalCaptureSHA256 = strings.Repeat("f", 64)
		case "missing-original-capture":
			changed.Records[0].OriginalCaptureSHA256 = ""
		case "foreign-record":
			changed.Records[count-1].CaptureSHA256 = strings.Repeat("f", 64)
		}
		encoded, _ := json.Marshal(changed)
		if _, err := decodeDesktopSelectedLatencyHistory(encoded); err == nil {
			t.Fatal("accepted compact history substitution", fault)
		}
	}
	// Reconnection changes every actual generation without repeating the
	// original descriptor. Each reconstructed capture keeps its own digest.
	var generations desktopSelectedLatencyHistory
	for position, row := range reopened.Records {
		copy := selected
		copy.GenerationSHA256 = fmt.Sprintf("%064x", position+1)
		raw, _ := json.Marshal(copy)
		row.Capture = string(raw)
		row.Receipt.GenerationSHA256 = copy.GenerationSHA256
		generations.Records = append(generations.Records, row)
	}
	generations.Schema = 1
	encoded, err := encodeDesktopSelectedLatencyHistory(generations)
	if err != nil || len(encoded) > desktopOrderedHistoryLimit {
		t.Fatal("distinct-generation history exceeds existing bound", err, len(encoded))
	}
	var shared desktopSelectedLatencyCompactHistory
	if json.Unmarshal(encoded, &shared) != nil || len(shared.Captures) != 1 || len(shared.Records) != count {
		t.Fatal("reconnection repeated or lost original descriptor")
	}
	restored, err := decodeDesktopSelectedLatencyHistory(encoded)
	if err != nil || !reflect.DeepEqual(restored, generations) {
		t.Fatal("reconnection changed exact original generation", err)
	}
	shared.Records[0].Receipt.GenerationSHA256 = shared.Records[count-1].Receipt.GenerationSHA256
	donor, _ := json.Marshal(shared)
	if _, err := decodeDesktopSelectedLatencyHistory(donor); err == nil {
		t.Fatal("accepted donor generation from a different valid original capture")
	}
}
