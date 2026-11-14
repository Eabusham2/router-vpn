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

func nodeChainSOCKSTransferSelection() Selection {
	selection := testSelection()
	selection.Family = NodeChainSOCKSFamily
	return selection
}

func TestNodeChainSOCKSTransferCanonicalCaptureAndManifest(t *testing.T) {
	selection := nodeChainSOCKSTransferSelection()
	before := selection
	// Independent Python hashlib vector over the exact public JSON identity.
	const expected = "eb05f4580bdfbf8fa6cb8ef033cf69f09a125ca0e4cb555fb81695151db8b49f"
	digest, err := NodeChainSOCKSTransferSHA256(selection)
	if err != nil || digest != expected || selection != before {
		t.Fatal("SOCKS transfer did not retain its distinct canonical capture", digest, err)
	}
	if ordinary, err := NodeChainTransferSHA256(selection); err == nil || ordinary != "" {
		t.Fatal("typed SOCKS capture acquired ordinary ordered transfer authority")
	}
	scope := Scope{Family: NodeChainSOCKSFamily}
	want := []scopeInput{{"node-chain-socks-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}
	manifest, err := scope.inputManifest()
	if err != nil || !reflect.DeepEqual(manifest, want) {
		t.Fatal("SOCKS inherited another source manifest", manifest, err)
	}
	manifest[0].name, manifest[0].limit = "node-chain-source.json", 1
	again, err := scope.inputManifest()
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("a caller changed the original SOCKS input manifest")
	}
}

func TestNodeChainSOCKSTransferBindsEveryOriginalSelectionField(t *testing.T) {
	original := nodeChainSOCKSTransferSelection()
	before, err := NodeChainSOCKSTransferSHA256(original)
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
		t.Fatal("an original SOCKS selection field lacks a transfer-binding mutation")
	}
	for index := 0; index < shape.NumField(); index++ {
		if mutations[shape.Field(index).Name] == nil {
			t.Fatal("uncovered SOCKS transfer field", shape.Field(index).Name)
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if changed == original {
				t.Fatal("SOCKS transfer negative control did not change its input")
			}
			digest, err := NodeChainSOCKSTransferSHA256(changed)
			if name == "Family" {
				if err == nil || digest != "" {
					t.Fatal("ordinary chain capture acquired typed SOCKS readiness authority")
				}
				return
			}
			if !changed.valid() || err != nil || !longDigest.MatchString(digest) || digest == before {
				t.Fatal("changed original SOCKS field reused the previous transfer identity", err)
			}
		})
	}
	for _, family := range []Family{ExternalFamily, NodeChainFamily, CandidatePrefixFamily, "ordered-node-chain-socks", "ordered-node-chain-socks-v2", "Ordered-node-chain-socks-v1", " ordered-node-chain-socks-v1", "ordered-node-chain-socks-v1 ", "ordered-node-chain-socks-v1\x00"} {
		selection := original
		selection.Family = family
		if digest, err := NodeChainSOCKSTransferSHA256(selection); err == nil || digest != "" {
			t.Fatal("another concrete family acquired SOCKS transfer authority", family)
		}
	}
	for _, field := range []string{"Session", "Source", "Config", "CallerUID", "WorkspaceInode", "EngineSHA256", "ControllerSHA256", "CatalogSHA256", "InputsSHA256"} {
		selection := original
		value := reflect.ValueOf(&selection).Elem().FieldByName(field)
		value.Set(reflect.Zero(value.Type()))
		if digest, err := NodeChainSOCKSTransferSHA256(selection); err == nil || digest != "" {
			t.Fatal("incomplete original SOCKS capture gained a transfer identity", field)
		}
	}
}

func TestNodeChainSOCKSWireContractAndCrossFamilyRefusal(t *testing.T) {
	selection := nodeChainSOCKSTransferSelection()
	value := frame{selection, 2, 0, "offer", strings.Repeat("8", 64)}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFrame(raw)
	if err != nil || decoded != value {
		t.Fatal("typed SOCKS frame failed its original identity roundtrip", err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil || len(fields) != 15 || string(fields["family"]) != `"ordered-node-chain-socks-v1"` || string(fields["schema"]) != "2" {
		t.Fatal("SOCKS frame lacks its explicit 15-field schema-2 identity", err)
	}
	for name, body := range map[string]string{
		"legacy-schema":    strings.Replace(string(raw), `"schema":2`, `"schema":1`, 1),
		"missing-family":   strings.Replace(string(raw), `"family":"ordered-node-chain-socks-v1",`, "", 1),
		"empty-family":     strings.Replace(string(raw), `"ordered-node-chain-socks-v1"`, `""`, 1),
		"null-family":      strings.Replace(string(raw), `"ordered-node-chain-socks-v1"`, `null`, 1),
		"unknown-family":   strings.Replace(string(raw), `"ordered-node-chain-socks-v1"`, `"ordered-node-chain-socks-v2"`, 1),
		"case-alias":       strings.Replace(string(raw), `"family":`, `"Family":`, 1),
		"duplicate-family": strings.Replace(string(raw), `"family":`, `"family":"ordered-node-chain-socks-v1","family":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if body == string(raw) {
				t.Fatal("SOCKS wire negative control did not change its input")
			}
			if _, err := decodeFrame([]byte(body)); err == nil {
				t.Fatal("noncanonical SOCKS wire identity was accepted")
			}
		})
	}
	for _, parentFamily := range []Family{ExternalFamily, NodeChainFamily, CandidatePrefixFamily, NodeChainSOCKSFamily} {
		for _, childFamily := range []Family{ExternalFamily, NodeChainFamily, CandidatePrefixFamily, NodeChainSOCKSFamily} {
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
					t.Fatal("another concrete family completed typed SOCKS admission")
				}
			})
		}
	}
}

func TestNodeChainSOCKSProtocolRequiresJoinedOriginalCleanup(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "retained-failure"}[failCleanup], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			parent, child, left, right := protocolPair()
			defer parent.channel.Close()
			defer child.channel.Close()
			parent.selection.Family, child.selection.Family = NodeChainSOCKSFamily, NodeChainSOCKSFamily
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
			sentinel := errors.New("original SOCKS native grants remain retained")
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
				t.Fatal("SOCKS cleanup preceded its original stop")
			}
			if failCleanup {
				if err := parent.send(ctx, "stop", 4); err != nil {
					t.Fatal(err)
				}
				if err := <-done; !errors.Is(err, sentinel) || cleaned.Load() || stopped.Load() || finished.Load() {
					t.Fatal("failed original SOCKS cleanup released native authority", err)
				}
			} else {
				if err := parent.stop(ctx); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil || !cleaned.Load() || !stopped.Load() || !finished.Load() {
					t.Fatal("SOCKS cleanup did not complete before release", err)
				}
			}
		})
	}
}
