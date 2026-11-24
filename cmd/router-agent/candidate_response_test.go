package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/hopmeasure"
)

const (
	candidateFixtureToken    = "candidate-fixture-token"
	candidateFixtureNonce    = "00112233445566778899aabbccddeeff"
	candidateFixtureRequest  = "48987b0a57659a65f404f58feb216fc5412db8867b45c78c0318265cbd32a7c4"
	candidateFixtureResponse = "9250f8de6ccf3714aad0a7e772859c8e659ea0eaafc2c91b9dfc7ee54f86ccc6"
)

func candidateResponseFixture(t *testing.T) (*server, *http.ServeMux) {
	t.Helper()
	s := benchmarkTestServer(t)
	s.cfg.Token, s.cfg.NodeID = candidateFixtureToken, strings.Repeat("a", 64)
	mux := http.NewServeMux()
	registerBenchmarkRoutes(mux, s)
	return s, mux
}

func candidateResponseRequest() *http.Request {
	return benchmarkRequest(http.MethodGet, "http://router.invalid"+hopmeasure.CandidateChallengePath+"?nonce="+candidateFixtureNonce, nil, candidateFixtureRequest)
}

func TestCandidateResponseUsesOriginalNodeNonceAndSeparateProof(t *testing.T) {
	s, mux := candidateResponseFixture(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, candidateResponseRequest())
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("original challenge failed: status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	var reply map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply) != 3 || reply["node_id"] != s.cfg.NodeID || reply["nonce"] != candidateFixtureNonce || reply["response"] != candidateFixtureResponse {
		t.Fatalf("response lost its original identity or proof: %#v", reply)
	}
	if w.Body.Len() > 512 || strings.Contains(w.Body.String(), candidateFixtureToken) || strings.Contains(w.Body.String(), candidateFixtureRequest) {
		t.Fatal("response exposed the key, echoed request authority, or exceeded its bounded form")
	}
	if hopmeasure.CandidateChallengeMAC(candidateFixtureToken, s.cfg.NodeID, candidateFixtureNonce, false) != candidateFixtureRequest ||
		hopmeasure.CandidateChallengeMAC(candidateFixtureToken, s.cfg.NodeID, candidateFixtureNonce, true) != candidateFixtureResponse {
		t.Fatal("candidate request/response domains changed their independent known vectors")
	}
}

func TestCandidateResponseRequiresOriginalTunnelPeer(t *testing.T) {
	for _, address := range []string{"203.0.113.40:3434", "127.0.0.1:3434", "[2001:db8::40]:3434", "10.77.0.2", "invalid:3434", ""} {
		t.Run(address, func(t *testing.T) {
			_, mux := candidateResponseFixture(t)
			r := candidateResponseRequest()
			r.RemoteAddr = address
			r.Header.Set("X-Forwarded-For", "10.77.0.2")
			r.Header.Set("X-Real-IP", "10.77.0.2")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), candidateFixtureResponse) {
				t.Fatal("non-tunnel origin acquired a private response", w.Code, w.Body.String())
			}
		})
	}
	s, mux := candidateResponseFixture(t)
	_, peer, err := net.ParseCIDR("fd77::/64")
	if err != nil {
		t.Fatal(err)
	}
	s.nets = append(s.nets, peer)
	r := candidateResponseRequest()
	r.RemoteAddr = "[fd77::2]:3434"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatal("original IPv6 tunnel peer lost challenge access", w.Code)
	}
}

func TestCandidateResponseRejectsChangedChallengeAuthority(t *testing.T) {
	cases := map[string]func(*server, *http.Request){
		"missing-authorization":              func(_ *server, r *http.Request) { r.Header.Del("Authorization") },
		"original-bearer-is-not-a-challenge": func(_ *server, r *http.Request) { r.Header.Set("Authorization", "Bearer "+candidateFixtureToken) },
		"response-cannot-authorize-request":  func(_ *server, r *http.Request) { r.Header.Set("Authorization", "Bearer "+candidateFixtureResponse) },
		"changed-nonce":                      func(_ *server, r *http.Request) { r.URL.RawQuery = "nonce=" + strings.Repeat("b", 32) },
		"changed-node":                       func(s *server, _ *http.Request) { s.cfg.NodeID = strings.Repeat("b", 64) },
		"changed-key":                        func(s *server, _ *http.Request) { s.cfg.Token += "-changed" },
		"empty-key": func(s *server, r *http.Request) {
			s.cfg.Token = ""
			r.Header.Set("Authorization", "Bearer "+hopmeasure.CandidateChallengeMAC("", s.cfg.NodeID, candidateFixtureNonce, false))
		},
		"invalid-node": func(s *server, r *http.Request) {
			s.cfg.NodeID = "unqualified-node"
			r.Header.Set("Authorization", "Bearer "+hopmeasure.CandidateChallengeMAC(s.cfg.Token, s.cfg.NodeID, candidateFixtureNonce, false))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, mux := candidateResponseFixture(t)
			r := candidateResponseRequest()
			mutate(s, r)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"response"`) {
				t.Fatal("foreign authority acquired candidate proof", w.Code, w.Body.String())
			}
		})
	}
}

func TestCandidateResponseRequiresCanonicalBoundedGet(t *testing.T) {
	for _, query := range []string{"", "nonce=", "nonce=abc", "nonce=" + strings.Repeat("a", 33), "nonce=" + strings.ToUpper(candidateFixtureNonce), "nonce=" + strings.Repeat("z", 32), "nonce=" + candidateFixtureNonce + "&nonce=" + candidateFixtureNonce, "nonce=" + candidateFixtureNonce + "&extra=1", "nonce=%30" + candidateFixtureNonce[1:], "nonce=" + strings.Repeat("a", 65536)} {
		_, mux := candidateResponseFixture(t)
		r := candidateResponseRequest()
		r.URL.RawQuery = query
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), `"response"`) {
			t.Fatalf("noncanonical nonce acquired proof: query size=%d status=%d", len(query), w.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		_, mux := candidateResponseFixture(t)
		r := candidateResponseRequest()
		r.Method = method
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed || strings.Contains(w.Body.String(), `"response"`) {
			t.Fatal("non-GET request acquired proof", method, w.Code)
		}
	}
}
