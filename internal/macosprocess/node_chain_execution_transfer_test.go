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

func nodeChainExecutionTransferSelection() Selection {
	selection := testSelection()
	selection.Family = NodeChainExecutionFamily
	return selection
}

func TestNodeChainExecutionTransferCanonicalCaptureAndManifest(t *testing.T) {
	selection := nodeChainExecutionTransferSelection()
	before := selection
	// Independent Python hashlib vector over the exact public JSON identity.
	const expected = "74af369224eaec4687ba620fc332995d04e66120fcc741f417e0c70196c6dd81"
	digest, err := NodeChainExecutionTransferSHA256(selection)
	if err != nil || digest != expected || selection != before {
		t.Fatal("execution transfer did not retain its distinct canonical capture", digest, err)
	}
	if ordinary, err := NodeChainTransferSHA256(selection); err == nil || ordinary != "" {
		t.Fatal("ordered execution capture acquired ordinary ordered transfer authority")
	}
	if socks, err := NodeChainSOCKSTransferSHA256(selection); err == nil || socks != "" {
		t.Fatal("ordered execution capture acquired SOCKS transfer authority")
	}
	if candidate, err := CandidatePrefixTransferSHA256(selection); err == nil || candidate != "" {
		t.Fatal("ordered execution capture acquired candidate-prefix transfer authority")
	}
	if connect, err := NodeChainCONNECTTransferSHA256(selection); err == nil || connect != "" {
		t.Fatal("execution capture acquired typed CONNECT transfer authority")
	}
	scope := Scope{Family: NodeChainExecutionFamily}
	want := []scopeInput{{"node-chain-execution-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}
	manifest, err := scope.inputManifest()
	if err != nil || !reflect.DeepEqual(manifest, want) {
		t.Fatal("execution inherited another source manifest", manifest, err)
	}
	manifest[0].name, manifest[0].limit = "node-chain-source.json", 1
	again, err := scope.inputManifest()
	if err != nil || !reflect.DeepEqual(again, want) {
		t.Fatal("a caller changed the original execution input manifest")
	}
}

func TestNodeChainExecutionTransferBindsEveryOriginalSelectionField(t *testing.T) {
	original := nodeChainExecutionTransferSelection()
	before, err := NodeChainExecutionTransferSHA256(original)
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
		t.Fatal("an original execution selection field lacks a transfer-binding mutation")
	}
	for index := 0; index < shape.NumField(); index++ {
		if mutations[shape.Field(index).Name] == nil {
			t.Fatal("uncovered execution transfer field", shape.Field(index).Name)
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if changed == original {
				t.Fatal("execution transfer negative control did not change its input")
			}
			digest, err := NodeChainExecutionTransferSHA256(changed)
			if name == "Family" {
				if err == nil || digest != "" {
					t.Fatal("ordinary chain capture acquired ordered execution readiness authority")
				}
				return
			}
			if !changed.valid() || err != nil || !longDigest.MatchString(digest) || digest == before {
				t.Fatal("changed original execution field reused the previous transfer identity", err)
			}
		})
	}
	for _, family := range []Family{ExternalFamily, NodeChainFamily, NodeChainSOCKSFamily, NodeChainCONNECTFamily, CandidatePrefixFamily, "ordered-node-chain-execution", "ordered-node-chain-execution-v2", "Ordered-node-chain-execution-v1", " ordered-node-chain-execution-v1", "ordered-node-chain-execution-v1 ", "ordered-node-chain-execution-v1\x00"} {
		selection := original
		selection.Family = family
		if digest, err := NodeChainExecutionTransferSHA256(selection); err == nil || digest != "" {
			t.Fatal("another concrete family acquired execution transfer authority", family)
		}
	}
	for _, field := range []string{"Session", "Source", "Config", "CallerUID", "WorkspaceInode", "EngineSHA256", "ControllerSHA256", "CatalogSHA256", "InputsSHA256"} {
		selection := original
		value := reflect.ValueOf(&selection).Elem().FieldByName(field)
		value.Set(reflect.Zero(value.Type()))
		if digest, err := NodeChainExecutionTransferSHA256(selection); err == nil || digest != "" {
			t.Fatal("incomplete original execution capture gained a transfer identity", field)
		}
	}
}

func TestNodeChainExecutionWireContractAndCrossFamilyRefusal(t *testing.T) {
	selection := nodeChainExecutionTransferSelection()
	value := frame{selection, 2, 0, "offer", strings.Repeat("8", 64)}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFrame(raw)
	if err != nil || decoded != value {
		t.Fatal("ordered execution frame failed its original identity roundtrip", err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil || len(fields) != 15 || string(fields["family"]) != `"ordered-node-chain-execution-v1"` || string(fields["schema"]) != "2" {
		t.Fatal("Execution frame lacks its explicit 15-field schema-2 identity", err)
	}
	for name, body := range map[string]string{
		"legacy-schema":    strings.Replace(string(raw), `"schema":2`, `"schema":1`, 1),
		"missing-family":   strings.Replace(string(raw), `"family":"ordered-node-chain-execution-v1",`, "", 1),
		"empty-family":     strings.Replace(string(raw), `"ordered-node-chain-execution-v1"`, `""`, 1),
		"null-family":      strings.Replace(string(raw), `"ordered-node-chain-execution-v1"`, `null`, 1),
		"unknown-family":   strings.Replace(string(raw), `"ordered-node-chain-execution-v1"`, `"ordered-node-chain-execution-v2"`, 1),
		"case-alias":       strings.Replace(string(raw), `"family":`, `"Family":`, 1),
		"duplicate-family": strings.Replace(string(raw), `"family":`, `"family":"ordered-node-chain-execution-v1","family":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if body == string(raw) {
				t.Fatal("Execution wire negative control did not change its input")
			}
			if _, err := decodeFrame([]byte(body)); err == nil {
				t.Fatal("noncanonical Execution wire identity was accepted")
			}
		})
	}
	for _, parentFamily := range []Family{ExternalFamily, NodeChainFamily, CandidatePrefixFamily, NodeChainSOCKSFamily, NodeChainCONNECTFamily, NodeChainExecutionFamily} {
		for _, childFamily := range []Family{ExternalFamily, NodeChainFamily, CandidatePrefixFamily, NodeChainSOCKSFamily, NodeChainCONNECTFamily, NodeChainExecutionFamily} {
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
					t.Fatal("another concrete family completed ordered execution admission")
				}
			})
		}
	}
}

func TestNodeChainExecutionProtocolRequiresJoinedOriginalCleanup(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "retained-failure"}[failCleanup], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			parent, child, left, right := protocolPair()
			defer parent.channel.Close()
			defer child.channel.Close()
			parent.selection.Family, child.selection.Family = NodeChainExecutionFamily, NodeChainExecutionFamily
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
			sentinel := errors.New("original execution native grants remain retained")
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
				t.Fatal("Execution cleanup preceded its original stop")
			}
			if failCleanup {
				if err := parent.send(ctx, "stop", 4); err != nil {
					t.Fatal(err)
				}
				if err := <-done; !errors.Is(err, sentinel) || cleaned.Load() || stopped.Load() || finished.Load() {
					t.Fatal("failed original execution cleanup released native authority", err)
				}
			} else {
				if err := parent.stop(ctx); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil || !cleaned.Load() || !stopped.Load() || !finished.Load() {
					t.Fatal("Execution cleanup did not complete before release", err)
				}
			}
		})
	}
}

func TestNodeChainExecutionStopCannotAcknowledgePendingOrCancelledCleanup(t *testing.T) {
	for _, cancelCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending-then-joined", true: "cancelled-retained"}[cancelCleanup], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			childCtx, cancelChild := context.WithCancel(ctx)
			defer cancelChild()
			parent, child, _, right := protocolPair()
			defer parent.channel.Close()
			defer child.channel.Close()
			parent.selection.Family, child.selection.Family = NodeChainExecutionFamily, NodeChainExecutionFamily
			entered, release := make(chan struct{}), make(chan struct{})
			var stopped atomic.Bool
			right.mutate = func(raw json.RawMessage) json.RawMessage {
				var value frame
				_ = json.Unmarshal(raw, &value)
				if value.Stage == "stopped" {
					stopped.Store(true)
				}
				return raw
			}
			done := make(chan error, 1)
			go func() {
				err := handshakeChild(childCtx, child)
				if err == nil {
					err = child.waitStop(childCtx, func(call context.Context) error {
						close(entered)
						select {
						case <-call.Done():
							return call.Err()
						case <-release:
							return call.Err()
						}
					})
				}
				done <- err
			}()
			if err := handshakeParent(ctx, parent); err != nil {
				t.Fatal(err)
			}
			if err := parent.send(ctx, "stop", 4); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("execution cleanup did not enter", ctx.Err())
			}
			if stopped.Load() {
				t.Fatal("pending original execution cleanup acknowledged retirement")
			}
			if cancelCleanup {
				cancelChild()
			} else {
				close(release)
				if err := parent.receive(ctx, "stopped", 5, false); err != nil {
					t.Fatal(err)
				}
				if err := parent.send(ctx, "finish", 6); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if cancelCleanup && (!errors.Is(err, context.Canceled) || stopped.Load()) {
					t.Fatal("cancelled execution cleanup acknowledged retirement", err)
				}
				if !cancelCleanup && (err != nil || !stopped.Load()) {
					t.Fatal("joined execution cleanup failed its original stop exchange", err)
				}
			case <-ctx.Done():
				t.Fatal("execution cleanup process did not join", ctx.Err())
			}
		})
	}
}
