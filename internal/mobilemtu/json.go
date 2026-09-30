// Package mobilemtu selects an MTU using the retained OS VPN interface. It owns
// no ambient network dialer, private listener, firewall change or public test.
package mobilemtu

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

func strictJSON(raw string, out any, limit int) error {
	invalid := errors.New("expected bounded unambiguous MTU JSON")
	if raw == "" || len(raw) > limit || !utf8.ValidString(raw) {
		return invalid
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 40 {
			return invalid
		}
		token, err := d.Token()
		if err != nil {
			return invalid
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[key] {
					return invalid
				}
				seen[key] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim('}') {
				return invalid
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim(']') {
				return invalid
			}
		default:
			return invalid
		}
		return nil
	}
	if walk(0) != nil {
		return invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid
	}
	d = json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return invalid
	}
	return nil
}
func stringField(p map[string]any, key, fallback string) (string, error) {
	value, present := p[key]
	if !present {
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", errors.New("invalid typed MTU profile setting")
	}
	return strings.TrimSpace(text), nil
}
func boolField(p map[string]any, key string) (bool, error) {
	value, present := p[key]
	if !present {
		return false, nil
	}
	b, ok := value.(bool)
	if !ok {
		return false, errors.New("invalid typed MTU boolean")
	}
	return b, nil
}
func intField(p map[string]any, key string, fallback int) (int, error) {
	value, present := p[key]
	if !present {
		return fallback, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, errors.New("invalid typed MTU number")
	}
	n, err := number.Int64()
	if err != nil || n < 0 || n > 65535 {
		return 0, errors.New("MTU integer outside bounded range")
	}
	return int(n), nil
}
