package mobilemultihop

import (
	"errors"
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
		if !lowerUDP && (expected["type"] == "udp" || expected["type"] == "h3") {
			return errors.New("Naive H2 over CONNECT requires an explicitly captured TCP-compatible DNS bootstrap; the selected UDP or DoH3 policy cannot traverse that entry")
		}
	}
	return nil
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
