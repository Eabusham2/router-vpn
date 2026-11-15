package macosprocess

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func nodeTransferSelection() Selection {
	selection := testSelection()
	selection.Family = NodeFamily
	return selection
}

func TestNodeTransferCanonicalCaptureVector(t *testing.T) {
	selection := nodeTransferSelection()
	before := selection
	// Fixed independent encoding/digest vector, including the domain separator.
	// This is a public identity record, not a substitute for a native Capture.
	const canonical = "{\"session\":\"11111111111111111111111111111111\",\"source\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"config\":\"3333333333333333333333333333333333333333333333333333333333333333\",\"caller_uid\":501,\"workspace_device\":42,\"workspace_inode\":73,\"engine_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"controller_sha256\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"catalog_sha256\":\"6666666666666666666666666666666666666666666666666666666666666666\",\"inputs_sha256\":\"9999999999999999999999999999999999999999999999999999999999999999\",\"family\":\"paired-node-v1\"}"
	const expected = "7889ecb5652d114f8bed1cc04422f63f6c68d65f742dc13d63eed72f4c509f4e"
	raw, err := json.Marshal(selection)
	if err != nil || string(raw) != canonical {
		t.Fatal("paired-node transfer wire identity changed without a reviewed vector", err)
	}
	digest, err := NodeTransferSHA256(selection)
	if err != nil || digest != expected || selection != before {
		t.Fatal("paired-node transfer did not retain its exact canonical capture", digest, err)
	}
	again, err := NodeTransferSHA256(selection)
	if err != nil || again != digest {
		t.Fatal("unchanged original capture produced another transfer identity", err)
	}
}

func TestNodeTransferBindsEveryOriginalSelectionField(t *testing.T) {
	original := nodeTransferSelection()
	before, err := NodeTransferSHA256(original)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Selection){
		"Session":          func(s *Selection) { s.Session = strings.Repeat("a", 32) },
		"Source":           func(s *Selection) { s.Source = strings.Repeat("a", 64) },
		"Config":           func(s *Selection) { s.Config = strings.Repeat("a", 64) },
		"CallerUID":        func(s *Selection) { s.CallerUID = 502 },
		"WorkspaceDevice":  func(s *Selection) { s.WorkspaceDevice++ },
		"WorkspaceInode":   func(s *Selection) { s.WorkspaceInode++ },
		"EngineSHA256":     func(s *Selection) { s.EngineSHA256 = strings.Repeat("a", 64) },
		"ControllerSHA256": func(s *Selection) { s.ControllerSHA256 = strings.Repeat("a", 64) },
		"CatalogSHA256":    func(s *Selection) { s.CatalogSHA256 = strings.Repeat("a", 64) },
		"InputsSHA256":     func(s *Selection) { s.InputsSHA256 = strings.Repeat("a", 64) },
		"Family":           func(s *Selection) { s.Family = ExternalFamily },
	}
	shape := reflect.TypeOf(original)
	if shape.NumField() != len(mutations) {
		t.Fatal("an original selection field lacks a transfer-binding mutation")
	}
	for index := 0; index < shape.NumField(); index++ {
		if mutations[shape.Field(index).Name] == nil {
			t.Fatal("uncovered original selection field", shape.Field(index).Name)
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if changed == original {
				t.Fatal("transfer identity negative control did not change its input")
			}
			digest, err := NodeTransferSHA256(changed)
			if name == "Family" {
				if err == nil || digest != "" {
					t.Fatal("an external capture acquired paired-node readiness authority")
				}
				return
			}
			if !changed.valid() || err != nil || !longDigest.MatchString(digest) || digest == before {
				t.Fatal("changed original field reused the previous transfer identity", err)
			}
		})
	}
}

func TestNodeTransferRefusesIncompleteAndUnknownCapture(t *testing.T) {
	mutations := map[string]func(*Selection){
		"zero":               func(s *Selection) { *s = Selection{} },
		"missing-session":    func(s *Selection) { s.Session = "" },
		"uppercase-session":  func(s *Selection) { s.Session = strings.Repeat("A", 32) },
		"short-source":       func(s *Selection) { s.Source = strings.Repeat("2", 63) },
		"malformed-config":   func(s *Selection) { s.Config = "not-a-config-digest" },
		"missing-engine":     func(s *Selection) { s.EngineSHA256 = "" },
		"missing-controller": func(s *Selection) { s.ControllerSHA256 = "" },
		"missing-catalog":    func(s *Selection) { s.CatalogSHA256 = "" },
		"missing-inputs":     func(s *Selection) { s.InputsSHA256 = "" },
		"root-caller":        func(s *Selection) { s.CallerUID = 0 },
		"invalid-caller":     func(s *Selection) { s.CallerUID = ^uint32(0) },
		"missing-workspace":  func(s *Selection) { s.WorkspaceInode = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			selection := nodeTransferSelection()
			mutate(&selection)
			digest, err := NodeTransferSHA256(selection)
			if err == nil || digest != "" {
				t.Fatal("incomplete original capture produced a readiness digest")
			}
		})
	}
	for _, family := range []Family{
		ExternalFamily, NodeChainFamily, NodeChainSOCKSFamily, NodeChainCONNECTFamily, NodeChainExecutionFamily, CandidatePrefixFamily, "external", "node-chain", "ordered-node-chain-v2",
		"Ordered-node-chain-v1", " paired-node-v1", "paired-node-v1 ",
		"paired-node-v1\n", "paired-node-v1\x00",
	} {
		t.Run("family/"+string(family), func(t *testing.T) {
			selection := nodeTransferSelection()
			selection.Family = family
			digest, err := NodeTransferSHA256(selection)
			if err == nil || digest != "" {
				t.Fatal("unrecognized concrete family gained an paired-node transfer digest")
			}
		})
	}
}
