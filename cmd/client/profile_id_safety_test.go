package main

import "testing"

func TestProfileIDRejectsTraversalAndEncodedForms(t *testing.T) {
	valid := []string{"a", "node_2", "A-b_9", string(make([]byte, 0))}
	_ = valid
	if !validProfileID("node_2") {
		t.Fatal("valid id rejected")
	}
	if !validProfileID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("64-char id rejected")
	}
	bad := []string{"", ".", "..", "../x", `a\\b`, "a/b", "%2e%2e", "%2fetc", "%5c..", "%252e%252e", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, id := range bad {
		if validProfileID(id) {
			t.Fatalf("unsafe profile id accepted: %q", id)
		}
	}
}
