package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
	"net/http"
	"net/http/httptest"
)

func TestProveExpectedPublicExitMatchesExpectedIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.7\n"))
	}))
	defer server.Close()

	if err := proveExpectedPublicExit(context.Background(), server.Client(), []string{server.URL}, "203.0.113.7", "test exit", time.Second); err != nil {
		t.Fatalf("expected proof success, got %v", err)
	}
}

func TestProveExpectedPublicExitCancellationInterruptsRequest(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- proveExpectedPublicExit(ctx, server.Client(), []string{server.URL}, "203.0.113.7", "test exit", 10*time.Second)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("proof request did not start")
	}
	cancel()

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "proof cancelled") {
			t.Fatalf("expected cancellation error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled proof did not return promptly")
	}
}

func TestProveExpectedPublicExitRejectsInvalidExpectedIPWithoutRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte("203.0.113.7"))
	}))
	defer server.Close()

	err := proveExpectedPublicExit(context.Background(), server.Client(), []string{server.URL}, "not-an-ip", "test exit", time.Second)
	if err == nil || !strings.Contains(err.Error(), "expected public exit IP is invalid") {
		t.Fatalf("expected invalid-IP error, got %v", err)
	}
	if called {
		t.Fatal("invalid expected IP unexpectedly triggered a network request")
	}
}
