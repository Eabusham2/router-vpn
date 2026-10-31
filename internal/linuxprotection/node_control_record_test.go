package linuxprotection

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/linuxprocess"
	"router-vpn/internal/mobiletor"
)

func nodeControlRecords(t *testing.T) (NodeSelection, mobiletor.DesktopLinuxNodeCreationRecord, NodePreparedRecord, NodeRetirementRecord) {
	t.Helper()
	state := scopedCandidate("always")
	native := state.Target.Native
	selection := NodeSelection{SessionID: native.Capture.SessionID, SourceSHA256: native.Capture.SourceSHA256,
		ConfigSHA256: state.Target.ConfigSHA256, Policy: "always", HomeLAN: true}
	observation := func(record ProcessRecord, procParent int) linuxprocess.Observation {
		return linuxprocess.Observation{BootID: record.BootID, ProcessID: record.ProcessID, ProcProcessID: record.ProcProcessID,
			ProcParentID: procParent, StartTicks: record.StartTicks, Image: linuxprocess.Object(record.Image),
			NetworkNamespace: linuxprocess.Object(record.NetworkNamespace), PIDNamespace: linuxprocess.Object(record.PIDNamespace)}
	}
	guardian := mobiletor.DesktopLinuxGuardianRecord{Engine: observation(*state.Engine, testParent().ProcProcessID),
		Guardian: observation(state.Target.Guardian, state.Engine.ProcProcessID)}
	created := mobiletor.DesktopLinuxNodeCreationRecord{Capture: native.Capture, HomeLAN: selection.HomeLAN,
		TableName: native.TableName, TableHandle: native.TableHandle, ChainHandle: native.ChainHandle, BaselineSHA256: native.BaselineSHA256}
	prepared := NodePreparedRecord{Protection: native, Guardian: guardian, Policy: selection.Policy}
	retired := NodeRetirementRecord{Source: &mobiletor.DesktopLinuxSourceJoinRecord{Capture: native.Capture,
		ProcessID: native.Owner.ProcessID, Original: &guardian}, Prepared: &prepared}
	if selection.Validate() != nil || created.Validate() != nil || prepared.Validate() != nil || retired.Validate() != nil {
		t.Fatal("fixture must retain actual native record relationships")
	}
	return selection, created, prepared, retired
}

func TestLinuxNodeControlSelectionBindsPolicyBeforeMutation(t *testing.T) {
	selection, _, _, _ := nodeControlRecords(t)
	command, err := selection.CaptureSHA256()
	want, wantErr := NodeCommandCaptureSHA256(selection.SessionID, selection.SourceSHA256, selection.ConfigSHA256)
	if err != nil || wantErr != nil || command != want {
		t.Fatal("control selection changed the established command bootstrap digest", err, wantErr)
	}
	original, err := selection.ControlSHA256()
	if err != nil || original == command {
		t.Fatal("control selection lacks its separate selected-policy identity", err)
	}
	for label, mutate := range map[string]func(*NodeSelection){
		"session": func(s *NodeSelection) { s.SessionID = strings.Repeat("e", 32) },
		"source":  func(s *NodeSelection) { s.SourceSHA256 = strings.Repeat("e", 64) },
		"config":  func(s *NodeSelection) { s.ConfigSHA256 = strings.Repeat("e", 64) },
		"policy":  func(s *NodeSelection) { s.Policy = "on-connect" },
		"lan":     func(s *NodeSelection) { s.HomeLAN = false },
	} {
		t.Run(label, func(t *testing.T) {
			changed := selection
			mutate(&changed)
			digest, err := changed.ControlSHA256()
			if err != nil || digest == original {
				t.Fatal("changed captured selection reused its original control identity", err)
			}
		})
	}
	for _, mutate := range []func(*NodeSelection){
		func(s *NodeSelection) { s.SessionID = "" },
		func(s *NodeSelection) { s.SourceSHA256 = strings.Repeat("A", 64) },
		func(s *NodeSelection) { s.ConfigSHA256 = strings.Repeat("0", 63) },
		func(s *NodeSelection) { s.Policy = "off" },
	} {
		changed := selection
		mutate(&changed)
		if _, err := changed.ControlSHA256(); err == nil {
			t.Fatal("malformed capture created a control identity")
		}
	}
}

func TestLinuxNodeControlCanonicalPhasesAndEarlyRetirement(t *testing.T) {
	selection, created, prepared, retired := nodeControlRecords(t)
	digest, _ := selection.ControlSHA256()
	admission, err := NodePreparedSHA256(selection, prepared)
	if err != nil {
		t.Fatal(err)
	}
	retirement, err := NodeRetirementSHA256(selection, retired)
	if err != nil || admission == retirement {
		t.Fatal("retirement reused an admission receipt", err)
	}
	messages := []NodeControlMessage{
		{Sequence: 1, Action: "baseline", Network: created.Capture.NetworkID},
		{Sequence: 2, Action: "created", Created: &created},
		{Sequence: 3, Action: "prepared", Prepared: &prepared},
		{Sequence: 4, Action: "admitted", ReceiptSHA256: admission},
		{Sequence: 5, Action: "retired", Retired: &retired},
		{Sequence: 6, Action: "closed", ReceiptSHA256: retirement},
		{Sequence: 2, Action: "refused", Refusal: "baseline"},
		{Sequence: 4, Action: "refused", Refusal: "admission"},
		{Sequence: 1, Action: "retired", Retired: &NodeRetirementRecord{}},
		{Sequence: 3, Action: "retired", Retired: &NodeRetirementRecord{}},
		{Sequence: 2, Action: "closed", ReceiptSHA256: retirement},
		{Sequence: 4, Action: "closed", ReceiptSHA256: retirement},
	}
	for _, original := range messages {
		original.Schema, original.Kind, original.SelectionSHA256 = NodeControlSchema, NodeControlKind, digest
		body, err := CanonicalNodeControlMessage(original)
		if err != nil {
			t.Fatal(original.Action, err)
		}
		parsed, err := ParseNodeControlMessage(body)
		if err != nil || !reflect.DeepEqual(original, parsed) {
			t.Fatal("canonical phase changed its captured comparison record", original.Action, err)
		}
		for _, mutate := range []func(*NodeControlMessage){
			func(m *NodeControlMessage) { m.Sequence = 0 },
			func(m *NodeControlMessage) { m.Sequence = 7 },
			func(m *NodeControlMessage) { m.Sequence ^= 1 },
			func(m *NodeControlMessage) { m.Kind += "-replacement" },
			func(m *NodeControlMessage) { m.Schema++ },
			func(m *NodeControlMessage) { m.SelectionSHA256 = strings.Repeat("A", 64) },
		} {
			changed := original.Clone()
			mutate(&changed)
			if _, err := CanonicalNodeControlMessage(changed); err == nil {
				t.Fatal("invalid phase or captured envelope was accepted", original.Action)
			}
		}
	}
}

func TestLinuxNodeControlRejectsAmbiguousAndUnboundedWire(t *testing.T) {
	selection, created, _, _ := nodeControlRecords(t)
	digest, _ := selection.ControlSHA256()
	message := NodeControlMessage{Schema: 1, Kind: NodeControlKind, Sequence: 1, SelectionSHA256: digest, Action: "baseline", Network: created.Capture.NetworkID}
	body, err := CanonicalNodeControlMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	for label, bad := range map[string][]byte{
		"empty":               nil,
		"oversize":            bytes.Repeat([]byte(" "), NodeControlMessageLimit+1),
		"leading-space":       append([]byte(" "), body...),
		"trailing-space":      append(bytes.Clone(body), '\n'),
		"second-object":       append(bytes.Clone(body), body...),
		"unknown-field":       bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"future":true`), 1),
		"duplicate-field":     bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1),
		"missing-kind":        bytes.Replace(body, []byte(`"kind":"`+NodeControlKind+`",`), nil, 1),
		"fractional-sequence": bytes.Replace(body, []byte(`"sequence":1`), []byte(`"sequence":1.0`), 1),
		"null-unused-payload": bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"created":null`), 1),
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := ParseNodeControlMessage(bad); err == nil {
				t.Fatal("ambiguous or unbounded control input was accepted")
			}
		})
	}
	for _, mutate := range []func(*NodeControlMessage){
		func(m *NodeControlMessage) { m.Created = &created },
		func(m *NodeControlMessage) { m.Network = "" },
		func(m *NodeControlMessage) { m.Action = "adopt" },
		func(m *NodeControlMessage) { m.Network = strings.Repeat("g", 32) },
		func(m *NodeControlMessage) { m.Network, m.Refusal = "", "baseline" },
	} {
		changed := message.Clone()
		mutate(&changed)
		if _, err := CanonicalNodeControlMessage(changed); err == nil {
			t.Fatal("control phase accepted a missing, extra or unrelated payload")
		}
	}
}

func TestLinuxNodeControlRetirementPreservesPartialOriginalSource(t *testing.T) {
	selection, _, prepared, retired := nodeControlRecords(t)
	partial := retired.Clone()
	partial.Prepared, partial.Source.Original = nil, nil
	for _, record := range []NodeRetirementRecord{{}, partial, retired} {
		if _, err := NodeRetirementSHA256(selection, record); err != nil {
			t.Fatal("valid original no-source, partial or complete teardown required invented ownership", err)
		}
	}
	for _, mutate := range []func(*NodeRetirementRecord){
		func(r *NodeRetirementRecord) { r.Source = nil },
		func(r *NodeRetirementRecord) { r.Source.Original = nil },
		func(r *NodeRetirementRecord) { r.Source.ProcessID++ },
		func(r *NodeRetirementRecord) { r.Source.Capture.NetworkID = strings.Repeat("e", 32) },
		func(r *NodeRetirementRecord) { r.Source.Original.Guardian.StartTicks++ },
		func(r *NodeRetirementRecord) { r.Prepared.Protection.TableName = "" },
		func(r *NodeRetirementRecord) { r.Prepared.Guardian.Guardian.Image.UID = 1000 },
		func(r *NodeRetirementRecord) { r.Prepared.Policy = "on-connect" },
	} {
		changed := retired.Clone()
		mutate(&changed)
		if _, err := NodeRetirementSHA256(selection, changed); err == nil {
			t.Fatal("retirement changed or erased the captured prepared source")
		}
	}
	changed := selection
	changed.SourceSHA256 = strings.Repeat("e", 64)
	if _, err := NodeRetirementSHA256(changed, retired); err == nil {
		t.Fatal("old joined source moved to a replacement selection")
	}
	if _, err := NodePreparedSHA256(changed, prepared); err == nil {
		t.Fatal("old prepared source moved to a replacement selection")
	}
	originalHash, _ := NodeRetirementSHA256(selection, retired)
	packet := NodeControlMessage{Retired: &retired, Prepared: &prepared}
	copy := packet.Clone()
	copy.Retired.Source.Original.Guardian.StartTicks++
	copy.Retired.Prepared.Policy = "on-connect"
	copy.Prepared.Protection.TableHandle++
	stillHash, err := NodeRetirementSHA256(selection, retired)
	if err != nil || stillHash != originalHash || prepared.Protection.TableHandle != retired.Prepared.Protection.TableHandle {
		t.Fatal("caller comparison copy mutated the retained source record", err)
	}
}
