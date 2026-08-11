package main

import "testing"

func TestAllRuntimeCandidate(t *testing.T) {
	tests := []struct {
		in      string
		wantID  string
		wantBase string
	}{
		{"max-tls-wg", "max-tls-wg", "wg"},
		{"max-quic-wg\n", "max-quic-wg", "wg"},
		{"max-tls-awg", "max-tls-awg", "awg"},
		{" max-quic-awg ", "max-quic-awg", "awg"},
	}
	for _, tt := range tests {
		got, err := allRuntimeCandidate(tt.in)
		if err != nil {
			t.Fatalf("allRuntimeCandidate(%q): %v", tt.in, err)
		}
		if got.RuntimeID != tt.wantID || got.Base != tt.wantBase {
			t.Fatalf("allRuntimeCandidate(%q) = %#v, want runtime=%q base=%q", tt.in, got, tt.wantID, tt.wantBase)
		}
	}
	if _, err := allRuntimeCandidate("all"); err == nil {
		t.Fatal("expected unknown ALL branch to fail")
	}
}
