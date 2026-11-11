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

func TestNativeChildScopeExactInputManifest(t *testing.T) {
	for _, test := range []struct {
		name   string
		family Family
		want   []scopeInput
	}{
		{"legacy-external", ExternalFamily, []scopeInput{{"source.json", 16 << 20}, {"capture.json", 16 << 20}, {"sing-box.json", 16 << 20}}},
		{"ordered-node-chain", NodeChainFamily, []scopeInput{{"node-chain-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := Scope{Family: test.family}
			manifest, err := scope.inputManifest()
			if err != nil || !reflect.DeepEqual(manifest, test.want) {
				t.Fatalf("wrong original input manifest: %v, %v", manifest, err)
			}
			manifest[0].name, manifest[0].limit = "foreign.json", 1
			again, err := scope.inputManifest()
			if err != nil || !reflect.DeepEqual(again, test.want) {
				t.Fatal("another caller changed the retained input manifest")
			}
		})
	}
	for _, family := range []Family{"node-chain", "external", "ordered-node-chain-v2", " ordered-node-chain-v1", "ordered-node-chain-v1 "} {
		if manifest, err := (Scope{Family: family}).inputManifest(); err == nil || manifest != nil {
			t.Fatalf("unsupported family %q acquired input authority", family)
		}
	}
}

func TestNativeChildFamilyWireContract(t *testing.T) {
	for _, family := range []Family{ExternalFamily, NodeChainFamily} {
		t.Run(string(family), func(t *testing.T) {
			selection := testSelection()
			selection.Family = family
			value := frame{selection, family.protocolSchema(), 0, "offer", strings.Repeat("8", 64)}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeFrame(raw)
			if err != nil || decoded != value {
				t.Fatalf("original family frame did not round-trip: %v", err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if family == ExternalFamily {
				if len(fields) != 14 || fields["family"] != nil || string(fields["schema"]) != "1" {
					t.Fatal("legacy external frame changed its exact 14-field schema-1 contract")
				}
			} else if len(fields) != 15 || string(fields["family"]) != `"ordered-node-chain-v1"` || string(fields["schema"]) != "2" {
				t.Fatal("ordered child lacks its explicit separate protocol identity")
			}
		})
	}
	base := testSelection()
	base.Family = NodeChainFamily
	raw, _ := json.Marshal(frame{base, 2, 0, "offer", strings.Repeat("8", 64)})
	for name, body := range map[string]string{
		"legacy-schema":       strings.Replace(string(raw), `"schema":2`, `"schema":1`, 1),
		"missing-family":      strings.Replace(string(raw), `"family":"ordered-node-chain-v1",`, "", 1),
		"empty-family":        strings.Replace(string(raw), `"ordered-node-chain-v1"`, `""`, 1),
		"null-family":         strings.Replace(string(raw), `"ordered-node-chain-v1"`, `null`, 1),
		"unknown-family":      strings.Replace(string(raw), `"ordered-node-chain-v1"`, `"ordered-node-chain-v2"`, 1),
		"case-alias":          strings.Replace(string(raw), `"family":`, `"Family":`, 1),
		"case-schema-alias":   strings.Replace(string(raw), `"schema":`, `"Schema":`, 1),
		"duplicate-family":    strings.Replace(string(raw), `"family":`, `"family":"ordered-node-chain-v1","family":`, 1),
		"external-with-field": strings.Replace(strings.Replace(string(raw), `"ordered-node-chain-v1"`, `""`, 1), `"schema":2`, `"schema":1`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeFrame([]byte(body)); err == nil {
				t.Fatal("cross-family or noncanonical wire identity was accepted")
			}
		})
	}
}

func TestNativeChildOrderedProtocolJoinsOriginalCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	parent, child, left, _ := protocolPair()
	defer parent.channel.Close()
	defer child.channel.Close()
	parent.selection.Family, child.selection.Family = NodeChainFamily, NodeChainFamily
	var cleaned, finished atomic.Bool
	left.sentFinish = func() { finished.Store(true) }
	done := make(chan error, 1)
	go func() {
		err := handshakeChild(ctx, child)
		if err == nil {
			err = child.waitStop(ctx, func(context.Context) error {
				cleaned.Store(true)
				return nil
			})
		}
		done <- err
	}()
	if err := handshakeParent(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if cleaned.Load() || finished.Load() {
		t.Fatal("ordered native cleanup preceded its exact stop command")
	}
	if err := parent.stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || !cleaned.Load() || !finished.Load() {
		t.Fatalf("ordered cleanup did not complete before release: %v", err)
	}
}

func TestNativeChildProtocolRejectsDifferentConcreteFamily(t *testing.T) {
	for _, parentFamily := range []Family{ExternalFamily, NodeChainFamily} {
		t.Run(string(parentFamily), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			parent, child, _, _ := protocolPair()
			defer parent.channel.Close()
			defer child.channel.Close()
			parent.selection.Family = parentFamily
			parent.nonce = strings.Repeat("8", 64)
			if parentFamily == ExternalFamily {
				child.selection.Family = NodeChainFamily
			}
			if err := parent.send(ctx, "offer", 0); err != nil {
				t.Fatal(err)
			}
			if err := child.receive(ctx, "offer", 0, true); err == nil {
				t.Fatal("another concrete native child family completed original admission")
			}
		})
	}
}

func TestNativeChildOrderedCleanupFailureRetainsAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	parent, child, left, right := protocolPair()
	defer parent.channel.Close()
	defer child.channel.Close()
	parent.selection.Family, child.selection.Family = NodeChainFamily, NodeChainFamily
	var stopped, finished atomic.Bool
	right.mutate = func(raw json.RawMessage) json.RawMessage {
		var value frame
		_ = json.Unmarshal(raw, &value)
		if value.Stage == "stopped" {
			stopped.Store(true)
		}
		return raw
	}
	left.sentFinish = func() { finished.Store(true) }
	sentinel := errors.New("original ordered native grants remain retained")
	done := make(chan error, 1)
	go func() {
		err := handshakeChild(ctx, child)
		if err == nil {
			err = child.waitStop(ctx, func(context.Context) error { return sentinel })
		}
		done <- err
	}()
	if err := handshakeParent(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if err := parent.send(ctx, "stop", 4); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, sentinel) || stopped.Load() || finished.Load() {
		t.Fatalf("failed original cleanup released ordered authority: %v", err)
	}
}
