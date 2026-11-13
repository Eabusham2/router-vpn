//go:build !linux && !windows

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrderedCandidatePrefixUnsupportedPlatformKeepsAdmissionClosed(t *testing.T) {
	a := &app{}
	if view, err := captureOrderedCandidatePreparedViewScope(context.Background(), a, 0, orderedCandidateSavedPrefixScope, func(ctx context.Context) (string, error) { return "physical", ctx.Err() }); err == nil || view != nil {
		t.Fatal("unsupported platform granted a prefix source view")
	}
	response := orderedCandidateHTTP(t, a, "/api/multihop/saved-candidates", map[string]any{"scope": orderedCandidateSavedPrefixScope, "request_id": strings.Repeat("a", 32), "view_token": strings.Repeat("b", 64), "prefix_position": 0, "candidate_ids": []string{"candidate"}, "samples": 50})
	if response.Code != 409 || a.candidatePreparation != nil || a.cmd != nil || a.state.Connected {
		t.Fatal("unsupported prefix public POST acquired native authority", response.Code)
	}
	mux := http.NewServeMux()
	registerOrderedCandidatePreparedRoutes(mux, a)
	result := httptest.NewRecorder()
	mux.ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/api/multihop/saved-candidates/catalog?prefix_position=0&scope=saved-prefix-local", nil))
	if result.Code != 409 {
		t.Fatal("unsupported prefix public catalog bypassed native gate", result.Code)
	}
}
