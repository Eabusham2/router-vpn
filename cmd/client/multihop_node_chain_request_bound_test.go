package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

// Exercise the shipping HTTP handlers with the exact payload shape sent by
// the desktop editors. An empty private catalog must reject the original
// revisions after decoding, before any runtime, network, or device access.
func TestExtendedOrderedRequestHTTPBounds(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	directory := filepath.Join(root, "runtime", "native")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if !nativeNodeChainPlatformSupported() {
		t.Skip("ordered desktop controller unavailable on this host")
	}
	makeBody := func(count int) []byte {
		t.Helper()
		nodes := make([]common.MultihopNodeSelection, count)
		tokens := make(map[string]string, count)
		for i := range nodes {
			id := fmt.Sprintf("%02d-%s", i, strings.Repeat("n", 61))
			nodes[i] = common.MultihopNodeSelection{ID: id, Mode: "shadowsocks"}
			tokens[id] = strings.Repeat("a", 64)
		}
		nodes[0].Mode = "wg"
		raw, err := json.Marshal(map[string]any{
			"nodes": nodes, "execution": "local", "expected_selected_node_id": nodes[len(nodes)-1].ID,
			"expected_profile_tokens": tokens,
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	complete := makeBody(common.MultihopPhysicalTraversalDepth)
	if len(complete) <= 16<<10 || len(complete) >= 32<<10 {
		t.Fatalf("unexpected size for maximum-length original IDs and revisions: %d", len(complete))
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, state: state{Mode: "off", Phase: "off"}}
	mux := http.NewServeMux()
	registerDesktopMultihopRoutes(mux, a)
	registerOrderedCandidatePreparedRoutes(mux, a)
	type route struct {
		name, path                   string
		handler                      http.Handler
		sourceCode                   int
		sourceMessage, decodeMessage string
	}
	routes := []route{
		{"native connect", "/api/multihop/connect", mux, http.StatusConflict, errDesktopProfileSelectionChanged.Error(), "bad json"},
		{"draft catalog", "/api/multihop/draft-candidates/catalog?scope=saved-prefix-local&prefix_position=0", mux,
			http.StatusConflict, errDesktopProfileSelectionChanged.Error(), "an exact editor draft"},
	}
	if runtime.GOOS == "linux" {
		routes = append(routes, route{"legacy connect", "/api/multihop/connect", http.HandlerFunc(a.multihopConnect),
			http.StatusBadRequest, "ordered nodes require the protected native controller", "bad json"})
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			check := func(raw []byte, status int, message string) {
				t.Helper()
				rec := httptest.NewRecorder()
				route.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, route.path, bytes.NewReader(raw)))
				if rec.Code != status || !strings.Contains(rec.Body.String(), message) {
					t.Fatalf("got %d %q; want %d containing %q", rec.Code, rec.Body.String(), status, message)
				}
			}
			check(complete, route.sourceCode, route.sourceMessage)
			check(makeBody(common.MultihopPhysicalTraversalDepth+1), http.StatusBadRequest, route.decodeMessage)
			// A valid object with additional whitespace is still over budget.
			check(append(bytes.Clone(complete), bytes.Repeat([]byte(" "), (32<<10)+1-len(complete))...), http.StatusBadRequest, route.decodeMessage)
		})
	}
}
