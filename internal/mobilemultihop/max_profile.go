package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"router-vpn/internal/applexray"
	"router-vpn/internal/multihoprelay"
)

const MAXShadowsocksTag = "routervpn-max-ss"
const MAXOuterTag = "routervpn-max-outer"
const MAXStartLayerTag = "routervpn-max-start-layer"

// MAXMode denotes a complete generated chain, not the older raw "max" Xray
// dual-transport mode. Each complete chain retains a mandatory PQ-keyed base.
func MAXMode(mode string) bool {
	switch mode {
	case "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg":
		return true
	}
	return false
}

type maxPolicy struct {
	NodeID     string `json:"node_id"`
	NodeKind   string `json:"node_kind"`
	RouterAPI  string `json:"router_api"`
	Endpoint   string `json:"endpoint"`
	StartLayer string `json:"start_layer,omitempty"`
}

func capturedMAXPolicy(raw string) (maxPolicy, string, error) {
	var policy maxPolicy
	bad := errors.New("MAX requires the exact selected Router VPN node and private service")
	if exactJSON([]byte(raw), &policy, 16384) != nil || !proofID.MatchString(policy.NodeID) || policy.NodeKind != "router-vpn" || !wireGuardServerIP(policy.Endpoint) {
		return policy, "", bad
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil {
		return policy, "", bad
	}
	if value, present := fields["start_layer"]; present && (len(value) < 2 || value[0] != '"') {
		return policy, "", bad
	}
	// Reject unknown fields as well as duplicate keys; policy is a frozen launch
	// record, never a bag of defaults that can silently replace a selected node.
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil {
		return policy, "", bad
	}
	api, err := url.Parse(policy.RouterAPI)
	if err != nil || api == nil || (api.Scheme != "http" && api.Scheme != "https") || api.User != nil || api.RawQuery != "" || api.Fragment != "" || api.RawPath != "" || (api.Path != "" && api.Path != "/") {
		return policy, "", bad
	}
	ip, err := netip.ParseAddr(api.Hostname())
	if err != nil || !ip.IsPrivate() || ip.Is4In6() || !wireGuardServerIP(ip.String()) {
		return policy, "", bad
	}
	if api.Port() != "" {
		if _, err = wireGuardNumber(api.Port(), 1, 65535); err != nil {
			return policy, "", bad
		}
	}
	if policy.StartLayer != "" && policy.StartLayer != "off" && !multihoprelay.ValidLayerMode(policy.StartLayer) {
		return policy, "", errors.New("MAX Start Layer must use authenticated AES; no unknown or XOR-only downgrade")
	}
	return policy, ip.String(), nil
}

// CompileMAXProfile composes the complete saved MAX chain inside the existing
// native core: mandatory PQ-keyed WG/AWG -> SS2022 -> PQ XHTTP/REALITY/FinalMask
// or Hysteria2. Desktop loopback relays are compiled away, never opened on the
// phone. The independent PQ exchange uses the same authenticated outer chain
// before the base peer starts, avoiding a circular or weaker bootstrap tunnel.
// The output is private configuration, not telemetry; no file or socket opens.
func CompileMAXProfile(mode, encodedFiles, metadata string) (string, error) {
	bad := errors.New("invalid or incomplete captured MAX chain")
	if !MAXMode(mode) {
		return "", bad
	}
	policy, service, err := capturedMAXPolicy(metadata)
	if err != nil {
		return "", err
	}
	var encoded map[string]string
	if exactJSON([]byte(encodedFiles), &encoded, 16<<20) != nil {
		return "", bad
	}
	baseMode, baseFile, compatibility := "wg-pq", "wg.conf", "wg-socks.conf"
	if strings.HasSuffix(mode, "-awg") {
		baseMode, baseFile, compatibility = "awg2-pq", "awg.conf", "awg-socks.conf"
	}
	required := map[string]bool{baseFile: true, "middle-sing-box.json": true, "chain.env": true,
		"rosenpass.env": true, "rosenpass.toml": true, "rosenpass-client-secret": true, "rosenpass-client-public": true, "rosenpass-server-public": true}
	tls := strings.HasPrefix(mode, "max-tls-")
	if tls {
		required["outer-xray.json"] = true
	} else {
		required["cert.pem"] = true
	}
	if len(encoded) < len(required) || len(encoded) > len(required)+2 {
		return "", bad
	}
	files := map[string][]byte{}
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	total := 0
	for name, text := range encoded {
		if !required[name] && name != compatibility && name != "stack.json" {
			return "", errors.New("MAX profile contains an unowned helper or asset")
		}
		raw, e := base64.StdEncoding.Strict().DecodeString(text)
		if e != nil || len(raw) == 0 || len(raw) > 4<<20 || base64.StdEncoding.EncodeToString(raw) != text {
			return "", bad
		}
		total += len(raw)
		if total > 12<<20 {
			return "", bad
		}
		files[name] = raw
	}
	for name := range required {
		if len(files[name]) == 0 {
			return "", bad
		}
	}
	env, err := parseMAXEnvironment(string(files["chain.env"]), tls)
	if err != nil {
		return "", err
	}
	relayPort, err := wireGuardNumber(env["LOCAL_RELAY_PORT"], 1, 65535)
	if err != nil {
		return "", bad
	}
	var middle map[string]any
	if exactJSON(files["middle-sing-box.json"], &middle, 4<<20) != nil || !maxFields(middle, "log", "inbounds", "outbounds", "route") {
		return "", bad
	}
	if log, ok := middle["log"]; ok {
		v, ok := log.(map[string]any)
		if !ok || len(v) != 1 || v["level"] != "warn" {
			return "", bad
		}
	}
	inbound, err := maxOne(middle["inbounds"])
	if err != nil || !maxFields(inbound, "type", "tag", "listen", "listen_port", "network", "override_address", "override_port") || len(inbound) != 7 || inbound["type"] != "direct" || inbound["tag"] != "base-relay" || inbound["listen"] != "127.0.0.1" || inbound["listen_port"] != float64(relayPort) || inbound["network"] != "udp" || inbound["override_address"] != "127.0.0.1" {
		return "", bad
	}
	basePort, ok := exactStartPort(inbound["override_port"])
	if !ok {
		return "", bad
	}
	route, ok := middle["route"].(map[string]any)
	if !ok || len(route) != 1 || route["final"] != "ss-hop" {
		return "", bad
	}
	outs, ok := middle["outbounds"].([]any)
	if !ok || len(outs) != 2 {
		return "", bad
	}
	var outer, ss map[string]any
	for _, value := range outs {
		out, ok := value.(map[string]any)
		if !ok {
			return "", bad
		}
		switch out["tag"] {
		case "outer":
			if outer != nil {
				return "", bad
			}
			outer = out
		case "ss-hop":
			if ss != nil {
				return "", bad
			}
			ss = out
		default:
			return "", bad
		}
	}
	if outer == nil || ss == nil || ss["type"] != "shadowsocks" || ss["server"] != "127.0.0.1" || ss["detour"] != "outer" || ss["method"] != NativeStartLayerMethod {
		return "", bad
	}
	// Only the generated same-node remote loopback is replaced. Every key, cipher
	// and port stays byte-identical; arbitrary routing and plugin options fail.
	delete(ss, "detour")
	ss["server"] = service
	if err = validateProxyEntry(ss, "shadowsocks"); err != nil {
		return "", err
	}
	if err = validateMAXAESKey(ss); err != nil {
		return "", err
	}
	ss["tag"], ss["detour"] = MAXShadowsocksTag, MAXOuterTag
	if tls {
		if len(outer) != 5 || outer["type"] != "socks" || outer["tag"] != "outer" || outer["server"] != "127.0.0.1" || outer["version"] != "5" {
			return "", bad
		}
		plan, e := applexray.Prepare("reality-xhttp", files["outer-xray.json"])
		if e != nil || !maxTLSLayers(files["outer-xray.json"]) || plan.ServerHost != policy.Endpoint || outer["server_port"] != float64(plan.ListenerPort) {
			return "", errors.New("MAX TLS outer protocol does not belong to the selected node")
		}
		profile, _ := json.Marshal(map[string]string{"xray.json": encoded["outer-xray.json"]})
		value, e := CompileProxyEntry(string(profile), "reality-xhttp")
		if e != nil {
			return "", e
		}
		// Unmarshal reuses non-nil maps: discard the old SOCKS wrapper so its
		// server/version fields cannot leak into the native Xray outbound.
		outer = nil
		if json.Unmarshal([]byte(value), &outer) != nil {
			return "", bad
		}
	} else {
		if outer["type"] != "hysteria2" || outer["server"] != policy.Endpoint {
			return "", bad
		}
		trust, ok := outer["tls"].(map[string]any)
		if !ok || trust["certificate_path"] != "cert.pem" || trust["certificate"] != nil || !validEntryCertificate(files["cert.pem"]) {
			return "", errors.New("MAX QUIC must retain its captured native TLS certificate")
		}
		delete(trust, "certificate_path")
		trust["certificate"] = []any{string(files["cert.pem"])}
		if err = validateProxyEntry(outer, "hysteria2"); err != nil {
			return "", err
		}
	}
	outer["tag"] = MAXOuterTag
	raw, err := maxBaseEndpoint(string(files[baseFile]), relayPort, service, basePort)
	if err != nil {
		return "", err
	}
	if err := maxPQSource(files, baseMode); err != nil {
		return "", err
	}
	pqFiles := map[string]string{baseFile: base64.StdEncoding.EncodeToString([]byte(raw))}
	for _, name := range []string{"rosenpass.env", "rosenpass.toml", "rosenpass-client-secret", "rosenpass-client-public", "rosenpass-server-public"} {
		pqFiles[name] = encoded[name]
	}
	pqRaw, _ := json.Marshal(pqFiles)
	graph, err := CompilePQProfile(baseMode, string(pqRaw), policy.NodeID)
	if err != nil {
		return "", err
	}
	var root map[string]any
	if json.Unmarshal([]byte(graph), &root) != nil {
		return "", bad
	}
	endpoint := root["endpoints"].([]any)[0].(map[string]any)
	endpoint["detour"] = MAXShadowsocksTag
	root["outbounds"] = []any{ss, outer}
	if policy.StartLayer != "" && policy.StartLayer != "off" {
		// Add the requested outermost AES transport. The existing SS middle
		// layer stays present and keeps its credentials and position in MAX.
		// The generated middle and outer Start Layer share this paired node's
		// SS2022 service; no plaintext local helper or second VPN is introduced.
		aes := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": policy.Endpoint,
			"server_port": ss["server_port"], "method": ss["method"], "password": ss["password"]}
		outerMode := "hysteria2"
		if tls {
			outerMode = "reality-xhttp"
		}
		// The relay wrapper expects the exact explicit service port. Preserve
		// URL semantics when an imported private API uses HTTP(S)'s default.
		api, _ := url.Parse(policy.RouterAPI)
		if api.Port() == "" {
			port := "80"
			if api.Scheme == "https" {
				port = "443"
			}
			api.Host = net.JoinHostPort(service, port)
		}
		inner, added, wrapErr := multihoprelay.WrapStartLayer(outer, outerMode,
			&multihoprelay.StartLayer{Mode: policy.StartLayer, API: api.String(), Transport: aes}, MAXStartLayerTag, "")
		if wrapErr != nil {
			return "", wrapErr
		}
		root["outbounds"] = []any{ss, inner, added}
	}
	result, err := json.Marshal(root)
	if err != nil || len(result) > 4<<20 {
		return "", bad
	}
	return string(result), nil
}

func parseMAXEnvironment(text string, tls bool) (map[string]string, error) {
	bad := errors.New("MAX chain metadata must retain every owned layer and mandatory PQ")
	if len(text) == 0 || len(text) > 16384 || !utf8.ValidString(text) {
		return nil, bad
	}
	result := map[string]string{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || result[key] != "" || value == "" {
			return nil, bad
		}
		switch key {
		case "CHAIN_READY", "PQ_BASE", "OUTER_ENGINE", "CHAIN_LAYERS", "LOCAL_RELAY_PORT":
		default:
			return nil, bad
		}
		result[key] = value
	}
	layers, engine := "rosenpass-pq>base>shadowsocks2022>hysteria2-quic", "sing-box"
	if tls {
		layers, engine = "rosenpass-pq>base>shadowsocks2022>xray-vless-pq-reality-xhttp-finalmask", "xray"
	}
	if len(result) != 5 || result["CHAIN_READY"] != "1" || result["PQ_BASE"] != "1" || result["OUTER_ENGINE"] != engine || result["CHAIN_LAYERS"] != layers {
		return nil, bad
	}
	if _, err := wireGuardNumber(result["LOCAL_RELAY_PORT"], 1, 65535); err != nil {
		return nil, bad
	}
	return result, nil
}
func maxFields(value map[string]any, fields ...string) bool {
	if value == nil {
		return false
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	for f := range value {
		if !allowed[f] {
			return false
		}
	}
	return true
}
func maxOne(value any) (map[string]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) != 1 {
		return nil, errors.New("MAX requires one owned service")
	}
	item, ok := list[0].(map[string]any)
	if !ok {
		return nil, errors.New("invalid MAX service")
	}
	return item, nil
}
func maxBaseEndpoint(raw string, localPort int, host string, remotePort int) (string, error) {
	bad := errors.New("MAX base must use exactly its generated local relay")
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.ValidString(raw) {
		return "", bad
	}
	lines := strings.Split(raw, "\n")
	count := 0
	for i, line := range lines {
		clean := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		key, value, ok := strings.Cut(clean, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "Endpoint") {
			continue
		}
		address, port, err := net.SplitHostPort(strings.TrimSpace(value))
		if err != nil || address != "127.0.0.1" || port != strconv.Itoa(localPort) {
			return "", bad
		}
		lines[i] = "Endpoint=" + net.JoinHostPort(host, strconv.Itoa(remotePort))
		count++
	}
	if count != 1 {
		return "", bad
	}
	return strings.Join(lines, "\n"), nil
}
func validateMAXAESKey(ss map[string]any) error {
	key, ok := ss["password"].(string)
	bad := errors.New("MAX requires captured SS2022 AES-256 keys")
	if !ok || key == "" || ss["method"] != NativeStartLayerMethod {
		return bad
	}
	for _, part := range strings.Split(key, ":") {
		raw, e := base64.StdEncoding.Strict().DecodeString(part)
		if e != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != part {
			return bad
		}
	}
	return nil
}

// Ordinary native XHTTP can intentionally omit some camouflage. A complete
// MAX-TLS label cannot: all of its declared layers remain independently needed.
func maxTLSLayers(raw []byte) bool {
	var root map[string]any
	if exactJSON(raw, &root, 4<<20) != nil {
		return false
	}
	out, err := maxOne(root["outbounds"])
	if err != nil {
		return false
	}
	stream, ok := out["streamSettings"].(map[string]any)
	if !ok {
		return false
	}
	reality, ok := stream["realitySettings"].(map[string]any)
	if !ok || reality["fingerprint"] != "chrome" {
		return false
	}
	mask, ok := stream["finalmask"].(map[string]any)
	if !ok {
		return false
	}
	tcp, ok := mask["tcp"].([]any)
	return ok && len(tcp) > 0
}

func maxPQSource(files map[string][]byte, mode string) error {
	bad := errors.New("MAX PQ handshake source is not the captured generated base")
	env, err := parsePQEnvironment(string(files["rosenpass.env"]))
	if err != nil {
		return err
	}
	port, err := wireGuardNumber(env["ROSENPASS_PORT"], 1, 65535)
	if err != nil {
		return bad
	}
	document := string(files["rosenpass.toml"])
	if err = validatePQDocument(document, port); err != nil {
		return err
	}
	host := "10.77.0.1"
	if mode == "awg2-pq" {
		host = "10.78.0.1"
	}
	count := 0
	for _, line := range strings.Split(document, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(key) != "endpoint" {
			continue
		}
		value = strings.TrimSpace(value)
		if value != strconv.Quote(net.JoinHostPort(host, strconv.Itoa(port))) {
			return bad
		}
		count++
	}
	if count != 1 {
		return bad
	}
	return nil
}
