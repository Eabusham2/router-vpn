package windowsapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

const portablePrivateLimit = 4 << 20

// portableConfiguration changes only the launcher's four owned location fields.
// In particular, pairing credentials, selected policy and unknown newer fields
// survive relocation. The catalog is immutable package source; an old writable
// modes.windows.json never becomes command authority for the elevated child.
func portableConfiguration(existing, defaults []byte, packageRoot, dataRoot string) ([]byte, error) {
	body := existing
	if body == nil {
		body = defaults
	}
	fields, err := portableJSONObject(body)
	if err != nil {
		return nil, fmt.Errorf("Portable client configuration is invalid; refusing a reset: %w", err)
	}
	set := func(name string, value any) {
		fields[name], _ = json.Marshal(value)
	}
	for name, value := range map[string]any{"listen": "127.0.0.1:8788", "health_url": "http://10.77.0.1:8787/health", "auto_test_seconds": 8} {
		if _, exists := fields[name]; !exists {
			set(name, value)
		}
	}
	var listen string
	if json.Unmarshal(fields["listen"], &listen) != nil || listen != "" && listen != "127.0.0.1:8788" {
		return nil, errors.New("Portable requires its captured fixed loopback listener")
	}
	for name, path := range map[string]string{
		"modes_file":    filepath.Join(packageRoot, "modes.json"),
		"scripts_dir":   filepath.Join(packageRoot, "modes"),
		"state_file":    filepath.Join(dataRoot, "state.json"),
		"profiles_file": filepath.Join(dataRoot, "routers.json"),
	} {
		if supplied, exists := fields[name]; exists {
			var previous string
			if json.Unmarshal(supplied, &previous) != nil {
				return nil, fmt.Errorf("Portable %s is not a saved location", name)
			}
		}
		set(name, path)
	}
	result, err := json.MarshalIndent(fields, "", "  ")
	if err != nil || len(result)+1 > portablePrivateLimit {
		return nil, errors.Join(err, errors.New("Portable client configuration exceeds its bound"))
	}
	return append(result, '\n'), nil
}

func portableJSONObject(body []byte) (map[string]json.RawMessage, error) {
	if len(body) == 0 || len(body) > portablePrivateLimit {
		return nil, errors.New("Portable input is empty or unbounded")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("Portable input requires an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		name, err := decoder.Token()
		key, ok := name.(string)
		if err != nil || !ok || len(fields) >= 4096 {
			return nil, errors.New("Portable object is malformed or unbounded")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("Portable object repeats a field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	end, err := decoder.Token()
	var extra any
	if err != nil || end != json.Delim('}') || decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("Portable object has incomplete or trailing content")
	}
	return fields, nil
}

type portableAccessGrant struct {
	principal string
	allow     bool
	flags     byte
	mask      uint32
}

func portableTrustedPrincipal(principal, desktop string) bool {
	return principal != "" && desktop != "" && (principal == desktop || principal == "S-1-5-18" || principal == "S-1-5-32-544")
}

func validatePortablePackageGrants(owner, desktop string, grants []portableAccessGrant) error {
	if !portableTrustedPrincipal(owner, desktop) || len(grants) == 0 || len(grants) > 1024 {
		return errors.New("Portable package default has no captured owner")
	}
	for _, grant := range grants {
		if grant.principal == "" || grant.flags&^byte(0x1f) != 0 ||
			grant.allow && grant.flags&0x08 == 0 && grant.mask&^uint32(0xa01200a9) != 0 && !portableTrustedPrincipal(grant.principal, desktop) {
			return errors.New("Portable package default has an untrusted writer")
		}
	}
	return nil
}

// Denials do not excuse a foreign allow, and inheritance-only foreign grants
// are rejected too: new private children must remain inside the same boundary.
func validatePortablePrivateGrants(owner, desktop string, grants []portableAccessGrant) error {
	if !portableTrustedPrincipal(owner, desktop) || len(grants) == 0 || len(grants) > 1024 {
		return errors.New("Portable private state has no captured owner and bounded access grants")
	}
	effective := false
	for _, grant := range grants {
		if grant.flags&^byte(0x1f) != 0 || grant.principal == "" {
			return errors.New("Portable private state has unsupported access flags")
		}
		if grant.allow && grant.mask != 0 {
			if !portableTrustedPrincipal(grant.principal, desktop) {
				return errors.New("Portable private state grants access outside its original desktop owner")
			}
			if grant.flags&0x08 == 0 {
				effective = true
			}
		}
	}
	if !effective {
		return errors.New("Portable private state has no effective owner grant")
	}
	return nil
}
