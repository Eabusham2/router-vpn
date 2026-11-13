package macosprocess

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func candidatePrefixTransferSelection() Selection {
	selection := testSelection()
	selection.Family = CandidatePrefixFamily
	return selection
}

func TestCandidatePrefixTransferCanonicalCaptureAndManifest(t *testing.T) {
	selection := candidatePrefixTransferSelection()
	before := selection
	// Independent Python hashlib vector over the exact public JSON identity.
	const expected = "c09c48d9be8b88830e026a05ffda09f1b4cfe097dca2d9698ac8325fe3594ea9"
	digest, err := CandidatePrefixTransferSHA256(selection)
	if err != nil || digest != expected || selection != before {
		t.Fatal("prefix transfer did not retain its distinct canonical capture", digest, err)
	}
	if ordinary, err := NodeChainTransferSHA256(selection); err == nil || ordinary != "" {
		t.Fatal("private prefix capture acquired ordinary ordered transfer authority")
	}
	scope := Scope{Family: CandidatePrefixFamily}
	want := []scopeInput{{"node-candidate-prefix-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}
	manifest, err := scope.inputManifest()
	if err != nil || !reflect.DeepEqual(manifest, want) {
		t.Fatal("prefix inherited another source manifest", manifest, err)
	}
	manifest[0].name, manifest[0].limit = "node-chain-source.json", 1
	again, err := scope.inputManifest()
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("a caller changed the original prefix input manifest")
	}
}

func TestCandidatePrefixTransferBindsEveryOriginalSelectionField(t *testing.T) {
	original := candidatePrefixTransferSelection()
	before, err := CandidatePrefixTransferSHA256(original)
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
		"Family":           func(s *Selection) { s.Family = NodeChainFamily },
	}
	shape := reflect.TypeOf(original)
	if shape.NumField() != len(mutations) {
		t.Fatal("an original prefix selection field lacks a transfer-binding mutation")
	}
	for index := 0; index < shape.NumField(); index++ {
		if mutations[shape.Field(index).Name] == nil {
			t.Fatal("uncovered prefix transfer field", shape.Field(index).Name)
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if changed == original {
				t.Fatal("prefix transfer negative control did not change its input")
			}
			digest, err := CandidatePrefixTransferSHA256(changed)
			if name == "Family" {
				if err == nil || digest != "" {
					t.Fatal("ordinary chain capture acquired private prefix readiness authority")
				}
				return
			}
			if !changed.valid() || err != nil || !longDigest.MatchString(digest) || digest == before {
				t.Fatal("changed original prefix field reused the previous transfer identity", err)
			}
		})
	}
	for _, family := range []Family{ExternalFamily, NodeChainFamily, "node-candidate-prefix", "node-candidate-prefix-v2", "Node-candidate-prefix-v1", " node-candidate-prefix-v1", "node-candidate-prefix-v1 ", "node-candidate-prefix-v1\x00"} {
		selection := original
		selection.Family = family
		if digest, err := CandidatePrefixTransferSHA256(selection); err == nil || digest != "" {
			t.Fatal("another concrete family acquired prefix transfer authority", family)
		}
	}
	for _, field := range []string{"Session", "Source", "Config", "CallerUID", "WorkspaceInode", "EngineSHA256", "ControllerSHA256", "CatalogSHA256", "InputsSHA256"} {
		selection := original
		value := reflect.ValueOf(&selection).Elem().FieldByName(field)
		value.Set(reflect.Zero(value.Type()))
		if digest, err := CandidatePrefixTransferSHA256(selection); err == nil || digest != "" {
			t.Fatal("incomplete original prefix capture gained a transfer identity", field)
		}
	}
}

func TestCandidatePrefixWireContractAndCrossFamilyRefusal(t *testing.T) {
	selection := candidatePrefixTransferSelection()
	value := frame{selection, 2, 0, "offer", strings.Repeat("8", 64)}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFrame(raw)
	if err != nil || decoded != value {
		t.Fatal("private prefix frame failed its original identity roundtrip", err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil || len(fields) != 15 || string(fields["family"]) != `"node-candidate-prefix-v1"` || string(fields["schema"]) != "2" {
		t.Fatal("prefix frame lacks its explicit 15-field schema-2 identity", err)
	}
	for name, body := range map[string]string{
		"legacy-schema":    strings.Replace(string(raw), `"schema":2`, `"schema":1`, 1),
		"missing-family":   strings.Replace(string(raw), `"family":"node-candidate-prefix-v1",`, "", 1),
		"empty-family":     strings.Replace(string(raw), `"node-candidate-prefix-v1"`, `""`, 1),
		"null-family":      strings.Replace(string(raw), `"node-candidate-prefix-v1"`, `null`, 1),
		"unknown-family":   strings.Replace(string(raw), `"node-candidate-prefix-v1"`, `"node-candidate-prefix-v2"`, 1),
		"case-alias":       strings.Replace(string(raw), `"family":`, `"Family":`, 1),
		"duplicate-family": strings.Replace(string(raw), `"family":`, `"family":"node-candidate-prefix-v1","family":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if body == string(raw) {
				t.Fatal("prefix wire negative control did not change its input")
			}
			if _, err := decodeFrame([]byte(body)); err == nil {
				t.Fatal("noncanonical prefix wire identity was accepted")
			}
		})
	}
	for _, parentFamily := range []Family{ExternalFamily, NodeChainFamily, CandidatePrefixFamily} {
		for _, childFamily := range []Family{ExternalFamily, NodeChainFamily, CandidatePrefixFamily} {
			if parentFamily == childFamily {
				continue
			}
			t.Run(string(parentFamily)+"/"+string(childFamily), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				parent, child, _, _ := protocolPair()
				defer parent.channel.Close()
				defer child.channel.Close()
				parent.selection.Family, child.selection.Family = parentFamily, childFamily
				parent.nonce = strings.Repeat("8", 64)
				if err := parent.send(ctx, "offer", 0); err != nil {
					t.Fatal(err)
				}
				if err := child.receive(ctx, "offer", 0, true); err == nil {
					t.Fatal("another concrete family completed private prefix admission")
				}
			})
		}
	}
}

func TestCandidatePrefixProtocolRequiresJoinedOriginalCleanup(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "retained-failure"}[failCleanup], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			parent, child, left, right := protocolPair()
			defer parent.channel.Close()
			defer child.channel.Close()
			parent.selection.Family, child.selection.Family = CandidatePrefixFamily, CandidatePrefixFamily
			var cleaned, stopped, finished atomic.Bool
			right.mutate = func(raw json.RawMessage) json.RawMessage {
				var value frame
				_ = json.Unmarshal(raw, &value)
				if value.Stage == "stopped" {
					stopped.Store(true)
				}
				return raw
			}
			left.sentFinish = func() { finished.Store(true) }
			sentinel := errors.New("original prefix native grants remain retained")
			done := make(chan error, 1)
			go func() {
				err := handshakeChild(ctx, child)
				if err == nil {
					err = child.waitStop(ctx, func(context.Context) error {
						if failCleanup {
							return sentinel
						}
						cleaned.Store(true)
						return nil
					})
				}
				done <- err
			}()
			if err := handshakeParent(ctx, parent); err != nil {
				t.Fatal(err)
			}
			if cleaned.Load() || stopped.Load() || finished.Load() {
				t.Fatal("prefix cleanup preceded its original stop")
			}
			if failCleanup {
				if err := parent.send(ctx, "stop", 4); err != nil {
					t.Fatal(err)
				}
				if err := <-done; !errors.Is(err, sentinel) || cleaned.Load() || stopped.Load() || finished.Load() {
					t.Fatal("failed original prefix cleanup released native authority", err)
				}
			} else {
				if err := parent.stop(ctx); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil || !cleaned.Load() || !stopped.Load() || !finished.Load() {
					t.Fatal("prefix cleanup did not complete before release", err)
				}
			}
		})
	}
}
