package mobilemultihop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"router-vpn/internal/applexray"
)

// MAXProfileCapture is an immutable, fully checked selection. It retains the
// original private source bytes; it is not a runnable native configuration.
// A new lookup owner is required for each launch and cannot resolve application
// destinations, private inner services, certificate names, or DNS providers.
type MAXProfileCapture struct {
	mode, files, metadata, endpoint, sourceSHA256 string
}

// MAXResolvedProfile contains only launch copies. Saved assets and selected
// node identity remain in MAXProfileCapture. All runtime addresses have passed
// CompileMAXProfile again, including the physical outermost Start Layer.
type MAXResolvedProfile struct {
	config, files, metadata, endpoint, sourceSHA256 string
}

func CaptureMAXProfile(mode, files, metadata string) (*MAXProfileCapture, error) {
	if _, err := compileMAXProfile(mode, files, metadata, true); err != nil {
		return nil, err
	}
	policy, _, err := capturedMAXPolicyForSelection(metadata, true)
	if err != nil {
		return nil, err
	}
	// Encoding the strings preserves every byte and length boundary. Reordered
	// or changed saved metadata/assets are a different capture, even when their
	// decoded JSON might happen to produce the same graph.
	source, err := json.Marshal([]string{"routervpn-max-capture-v1", mode, files, metadata})
	if err != nil {
		return nil, errors.New("MAX source capture could not be bound")
	}
	digest := sha256.Sum256(source)
	clear(source)
	return &MAXProfileCapture{mode: mode, files: files, metadata: metadata, endpoint: policy.Endpoint, sourceSHA256: hex.EncodeToString(digest[:])}, nil
}

func (c *MAXProfileCapture) Endpoint() string {
	if c == nil {
		return ""
	}
	return c.endpoint
}

func (c *MAXProfileCapture) SourceSHA256() string {
	if c == nil {
		return ""
	}
	return c.sourceSHA256
}

func (c *MAXProfileCapture) RequiresResolution() bool {
	return c != nil && applexray.ValidNodeHostname(c.endpoint)
}

// Resolve performs at most one explicitly supplied lookup after complete
// validation. It runs synchronously so cancellation never abandons an owned
// lookup goroutine; the caller must drain its resolver before returning. A
// canceled/expired owner never receives launch material, even after a late DNS
// answer. There is deliberately no system or global-default resolver here.
func (c *MAXProfileCapture) Resolve(ctx context.Context, lookup applexray.Lookup) (*MAXResolvedProfile, error) {
	if c == nil || c.sourceSHA256 == "" || ctx == nil {
		return nil, errors.New("MAX resolution requires a captured selection and owner")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpoint := c.endpoint
	if c.RequiresResolution() {
		if lookup == nil {
			return nil, errors.New("MAX node hostname requires its captured pre-tunnel resolver")
		}
		answers, err := lookup(ctx, c.endpoint)
		if expired := ctx.Err(); expired != nil {
			return nil, expired
		}
		if err != nil || len(answers) == 0 || len(answers) > 32 {
			return nil, errors.New("MAX node hostname resolution failed")
		}
		var chosen netip.Addr
		for _, candidate := range answers {
			if !wireGuardServerIP(candidate.String()) {
				continue
			}
			if !chosen.IsValid() || candidate.Is4() {
				chosen = candidate
				if chosen.Is4() {
					break
				}
			}
		}
		if !chosen.IsValid() {
			return nil, errors.New("MAX node hostname has no allowed literal endpoint")
		}
		endpoint = chosen.String()
	}
	files, metadata, err := c.launchInputs(endpoint)
	if err != nil {
		return nil, err
	}
	config, err := CompileMAXProfile(c.mode, files, metadata)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &MAXResolvedProfile{config: config, files: files, metadata: metadata, endpoint: endpoint, sourceSHA256: c.sourceSHA256}, nil
}

func (c *MAXProfileCapture) launchInputs(endpoint string) (string, string, error) {
	if endpoint == c.endpoint {
		return c.files, c.metadata, nil
	}
	bad := errors.New("MAX launch copy lost its captured outer endpoint")
	if !c.RequiresResolution() || !wireGuardServerIP(endpoint) {
		return "", "", bad
	}
	var files map[string]string
	if exactJSON([]byte(c.files), &files, 16<<20) != nil {
		return "", "", bad
	}
	name := "middle-sing-box.json"
	if strings.HasPrefix(c.mode, "max-tls-") {
		name = "outer-xray.json"
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(files[name])
	if err != nil {
		return "", "", bad
	}
	defer clear(raw)
	// Object retains exact JSON numbers and rejects duplicate keys. Every
	// authentication, camouflage, TLS-name and private-layer field is copied.
	root, err := applexray.Object(raw)
	if err != nil {
		return "", "", bad
	}
	changed := 0
	for _, value := range root["outbounds"].([]any) {
		out := value.(map[string]any)
		if strings.HasPrefix(c.mode, "max-tls-") {
			remote := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			if remote["address"] != c.endpoint {
				return "", "", bad
			}
			remote["address"] = endpoint
			changed++
		} else if out["tag"] == "outer" {
			if out["server"] != c.endpoint || out["type"] != "hysteria2" {
				return "", "", bad
			}
			if err = captureMAXTLSName(out["tls"].(map[string]any), c.endpoint); err != nil {
				return "", "", err
			}
			out["server"] = endpoint
			changed++
		}
	}
	if changed != 1 {
		return "", "", bad
	}
	resolved, err := json.Marshal(root)
	if err != nil {
		return "", "", bad
	}
	defer clear(resolved)
	files[name] = base64.StdEncoding.EncodeToString(resolved)
	encoded, err := json.Marshal(files)
	if err != nil {
		return "", "", bad
	}
	defer clear(encoded)
	var policy map[string]any
	if exactJSON([]byte(c.metadata), &policy, 16384) != nil || policy["endpoint"] != c.endpoint {
		return "", "", bad
	}
	policy["endpoint"] = endpoint
	meta, err := json.Marshal(policy)
	if err != nil {
		return "", "", bad
	}
	return string(encoded), string(meta), nil
}

// Hysteria2 otherwise derives its verified TLS name from server. Make that
// captured hostname explicit before changing server to the owned DNS answer;
// an explicit saved certificate identity is always retained byte-for-byte.
func captureMAXTLSName(trust map[string]any, hostname string) error {
	if value, present := trust["server_name"]; present {
		name, ok := value.(string)
		if !ok {
			return errors.New("MAX QUIC lost its captured TLS identity")
		}
		if name != "" {
			return nil
		}
	}
	trust["server_name"] = hostname
	return nil
}

// Getters return immutable private launch strings. Hosts must keep the source
// digest and lookup owner bound to the pending session until adoption.
func (r *MAXResolvedProfile) Config() string       { return r.config }
func (r *MAXResolvedProfile) Files() string        { return r.files }
func (r *MAXResolvedProfile) Metadata() string     { return r.metadata }
func (r *MAXResolvedProfile) Endpoint() string     { return r.endpoint }
func (r *MAXResolvedProfile) SourceSHA256() string { return r.sourceSHA256 }
