package applexray

import (
	"errors"
	"regexp"
)

var nativeTag = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// SingleTransportMode excludes Split/MAX: their independent TCP and UDP legs
// cannot be replaced with one generic outbound under the same label.
func SingleTransportMode(mode string) bool {
	return mode == "reality-vision" || mode == "reality-pq-vision" || mode == "reality-xhttp"
}

// ValidateSingleTransport checks a frozen native node with no extra physical
// dial policy or helper assets. Callers add only their explicitly owned detour
// after this validation. Prepare prohibits file paths, listeners and DNS escape.
func ValidateSingleTransport(value map[string]any, mode string) error {
	bad := errors.New("native Xray transport lost its exact protocol or ownership")
	if !SingleTransportMode(mode) || len(value) != 4 || value["type"] != Type || value["mode"] != mode {
		return bad
	}
	tag, ok := value["tag"].(string)
	if !ok || !nativeTag.MatchString(tag) {
		return bad
	}
	raw, ok := value["config_json"].(string)
	if !ok {
		return bad
	}
	if _, e := Prepare(mode, []byte(raw)); e != nil {
		return bad
	}
	return nil
}
