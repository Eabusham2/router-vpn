package mobilemultihop

import (
	"reflect"
	"testing"
)

func TestExternalPredecessorCapturedDNSQueryOptions(t *testing.T) {
	original := map[string]any{"server": "original-dns", "strategy": "ipv4_only", "timeout": "3s", "disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": float64(42), "client_subnet": "192.0.2.0/24"}
	captured, err := predecessorResolverSelection(original)
	if err != nil || !reflect.DeepEqual(captured, original) {
		t.Fatal("valid captured query changed", err)
	}
	node := map[string]any{"domain_resolver": original}
	if err := predecessorRelabelResolver(node, map[string]string{"original-dns": "owned-dns"}); err != nil {
		t.Fatal(err)
	}
	rewritten := node["domain_resolver"].(map[string]any)
	want := predecessorCopy(original)
	want["server"] = "owned-dns"
	if !reflect.DeepEqual(rewritten, want) || original["server"] != "original-dns" {
		t.Fatal("retagging changed options or original owner")
	}
	for _, fault := range []string{"timeout", "cache", "optimistic", "ttl", "subnet", "unknown", "server"} {
		t.Run(fault, func(t *testing.T) {
			q := predecessorCopy(original)
			switch fault {
			case "timeout":
				q["timeout"] = "2m"
			case "cache":
				q["disable_cache"] = "true"
			case "optimistic":
				q["disable_optimistic_cache"] = float64(1)
			case "ttl":
				q["rewrite_ttl"] = float64(-1)
			case "subnet":
				q["client_subnet"] = "192.0.2.1/24"
			case "unknown":
				q["foreign"] = true
			case "server":
				q["server"] = true
			}
			if _, err := predecessorResolverSelection(q); err == nil {
				t.Fatal("invalid query accepted")
			}
		})
	}
}
