package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// decodeRelayControlJSON rejects ambiguous duplicate members before decoding a
// bounded exact response. No response material is copied into an error message.
func decodeRelayControlJSON(data []byte, out any) error {
	bad := errors.New("relay control response must be bounded unambiguous JSON")
	if len(data) == 0 || len(data) > 8192 || !utf8.Valid(data) {
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
