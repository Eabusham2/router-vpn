package main

import (
	"encoding/json"
	"testing"
)

func TestConnectionProfileRefRequestNormalizesValidID(t *testing.T) {
	var request connectionProfileRefRequest
	if err := json.Unmarshal([]byte(`{"id":"  saved-one  "}`), &request); err != nil {
		t.Fatalf("valid connection profile reference rejected: %v", err)
	}
	if request.ID != "saved-one" {
		t.Fatalf("connection profile id was not normalized: %q", request.ID)
	}
}

func TestConnectionProfileRefRequestRejectsUnknownAndInvalidInput(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown-field": `{"id":"saved-one","extra":true}`,
		"missing-id": `{}`,
		"bad-id": `{"id":"../escape"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request connectionProfileRefRequest
			if err := json.Unmarshal([]byte(raw), &request); err == nil {
				t.Fatalf("invalid connection profile reference %s was accepted", name)
			}
		})
	}
}
