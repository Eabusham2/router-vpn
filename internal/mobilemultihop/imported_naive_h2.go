package mobilemultihop

import (
	"errors"
	"net/netip"
	"reflect"
	"strconv"

	"router-vpn/internal/multihoprelay"
)

// Naive H2 carries application datagrams over its authenticated stream. Its
// separately captured transport resolver belongs to the lower entry/layer;
// application UoT does not grant datagrams to that lower transport.
func importedNaiveH2DNS(graph, final map[string]any, lowerUDP bool) error {
	return importedNaiveDNS(graph, final, "naive-h2", lowerUDP)
}

// The mode is validated before reading either resolver tree. H3 requires an
// independently admitted UDP predecessor; Naive's inner UoT does not provide it.
func importedNaiveDNS(graph, final map[string]any, mode string, lowerUDP bool) error {
	bad := errors.New("imported Naive requires its exact original transport and complete captured DNS bootstrap tree")
	if mode != "naive-h2" && mode != "naive-h3" || mode == "naive-h3" && !lowerUDP {
		return bad
	}
	transport := predecessorCopy(final)
	delete(transport, "domain_resolver")
	detour := predecessorText(final, "detour")
	if detour == "" {
		if _, exists := final["detour"]; exists {
			return bad
		}
		if err := multihoprelay.ValidateNaiveTransport(transport, mode); err != nil {
			return err
		}
	} else {
		if detour != NativeStartLayerTag {
			return bad
		}
		if err := multihoprelay.ValidateNaiveRoutedTransport(transport, mode); err != nil {
			return err
		}
	}
	dns, ok := graph["dns"].(map[string]any)
	if !ok || dns["final"] != ExternalDNSTag {
		return bad
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) != 2 && len(servers) != 4 {
		return bad
	}
	count := len(servers) / 2
	application := predecessorCopy(dns)
	application["servers"] = append([]any(nil), servers[:count]...)
	// Preserve the existing primary/explicit-bootstrap validator unchanged.
	// Application DNS has Naive's own native UoT-v2 authority, including UDP.
	if err := importedCONNECTDNS(map[string]any{"dns": application}, true); err != nil {
		return err
	}
	// The strict Naive validator above requires the original literal endpoint
	// and self-contained TLS identity. Cronet's exact literal/SNI mapping
	// establishes H2 without consulting the lower resolver, including the
	// remote literal service inside the separately validated AES/XOR layer.
	// Keep that complete resolver attached to its original layer: it remains
	// an owned, unusable fallback, not lower UDP authority through CONNECT.
	// Only a single literal UDP application resolver qualifies; hostname DNS
	// and DoH3 retain their existing capability gate.
	literalH2UDP := mode == "naive-h2" && count == 1 &&
		predecessorText(servers[0].(map[string]any), "type") == "udp"
	if literalH2UDP && detour != "" {
		var layer map[string]any
		outbounds, _ := graph["outbounds"].([]any)
		for _, raw := range outbounds {
			value, _ := raw.(map[string]any)
			if predecessorText(value, "tag") != detour {
				continue
			}
			if layer != nil {
				return bad
			}
			layer = value
		}
		// A hostname on the outer AES peer would still require a working
		// lower resolver. The inner literal/SNI mapping cannot provide it.
		literalH2UDP = importedNaiveLiteralStartLayer(layer)
	}
	names := map[string]string{ExternalDNSTag: "routervpn-predecessor-bootstrap-0"}
	if count == 2 {
		names["external-dns-bootstrap"] = "routervpn-predecessor-bootstrap-1"
	}
	expectedQuery := map[string]any{"server": names[ExternalDNSTag]}
	if strategy, exists := dns["strategy"]; exists {
		expectedQuery["strategy"] = strategy
	}
	query, ok := final["domain_resolver"].(map[string]any)
	if !ok || !reflect.DeepEqual(query, expectedQuery) || externalDNSQuery(query, names[ExternalDNSTag]) != nil {
		return bad
	}
	bootstrap := map[string]map[string]any{}
	for _, raw := range servers[count:] {
		server, ok := raw.(map[string]any)
		name := predecessorText(server, "tag")
		if !ok || name == "" || bootstrap[name] != nil {
			return bad
		}
		bootstrap[name] = server
	}
	for index, raw := range servers[:count] {
		original, ok := raw.(map[string]any)
		if !ok {
			return bad
		}
		name := "routervpn-predecessor-bootstrap-" + strconv.Itoa(index)
		if names[predecessorText(original, "tag")] != name {
			return bad
		}
		expected := predecessorCopy(original)
		expected["tag"] = name
		delete(expected, "detour")
		if detour != "" {
			expected["detour"] = detour
		}
		if selection, exists := expected["domain_resolver"]; exists {
			query, err := predecessorResolverSelection(selection)
			if err != nil || names[predecessorText(query, "server")] == "" {
				return bad
			}
			query["server"] = names[predecessorText(query, "server")]
			expected["domain_resolver"] = query
		}
		if !reflect.DeepEqual(bootstrap[name], expected) {
			return bad
		}
		// Equality above preserves the exact selected endpoint, transport,
		// TLS identity, port/path and query options. Only capability is checked
		// here; no selected resolver is rewritten for a TCP-only entry.
		if !lowerUDP && !literalH2UDP && (expected["type"] == "udp" || expected["type"] == "h3") {
			return errors.New("Naive H2 over CONNECT requires an explicitly captured TCP-compatible DNS bootstrap; the selected UDP or DoH3 policy cannot traverse that entry")
		}
	}
	return nil
}

func importedNaiveLiteralStartLayer(layer map[string]any) bool {
	if layer == nil || layer["type"] != "shadowsocks" && layer["type"] != "routervpn-aes-xor" || layer["method"] != NativeStartLayerMethod {
		return false
	}
	ip, err := netip.ParseAddr(predecessorText(layer, "server"))
	return err == nil && ip.Zone() == "" && !ip.Is4In6()
}

// Called only after the complete original Naive bootstrap tree has passed the
// validation above. Existing final/layer resolver edges remain unchanged.
func attachImportedNaiveBootstrap(graph map[string]any) {
	servers := graph["dns"].(map[string]any)["servers"].([]any)
	for _, raw := range servers[len(servers)/2:] {
		server := raw.(map[string]any)
		if server["detour"] == nil {
			server["detour"] = "entry-wg"
		}
	}
}
