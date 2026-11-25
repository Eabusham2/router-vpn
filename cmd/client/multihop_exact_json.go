package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"router-vpn/internal/multihoprelay"
	"unicode/utf8"
)

// decodeRelayControlJSON rejects ambiguous duplicate members before decoding a
// bounded exact response. No response material is copied into an error message.
func decodeRelayControlJSON(data []byte, out any) error {
	return decodeRelayControlJSONBounded(data, out, multihoprelay.MaxControlResponseBytes)
}

func decodeRelayControlJSONBounded(data []byte, out any, limit int) error {
	if limit != multihoprelay.MaxControlResponseBytes && limit != multihoprelay.MaxCapabilitiesBytes {
		return errors.New("relay control response must be bounded unambiguous JSON")
	}
	return decodePrivateControlJSONBounded(data, out, limit)
}

// Internal private files have their own explicit bounds. The relay entry point
// above still accepts only its original proof and capability limits.
func decodePrivateControlJSONBounded(data []byte, out any, limit int) error {
	if limit <= 0 || limit > 1<<20 {
		return errors.New("relay control response must be bounded unambiguous JSON")
	}
	return decodeExactJSONObjectBounded(data, out, limit)
}

// Private Router profile files use their separate 4 MiB limit. Reuse the same
// duplicate-member, depth and exact typed-decoding checks without increasing
// any network control-message limit.
func decodeExactJSONObjectBounded(data []byte, out any, limit int) error {
	bad := errors.New("relay control response must be bounded unambiguous JSON")
	if limit <= 0 || limit > maxPrivateStoreBytes || len(data) == 0 || len(data) > limit || !utf8.Valid(data) {
		return bad
	}
	scan := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return bad
		}
		token, err := scan.Token()
		if err != nil {
			return bad
		}
		delim, compound := token.(json.Delim)
		if !compound {
			if depth == 0 {
				return bad
			}
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for scan.More() {
				key, err := scan.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return bad
				}
				seen[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := scan.Token()
			if err != nil || end != json.Delim('}') {
				return bad
			}
		case '[':
			if depth == 0 {
				return bad
			}
			for scan.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := scan.Token()
			if err != nil || end != json.Delim(']') {
				return bad
			}
		default:
			return bad
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := scan.Token(); err != io.EOF {
		return bad
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return bad
	}
	return nil
}
