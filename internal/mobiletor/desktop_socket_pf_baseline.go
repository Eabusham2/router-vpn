package mobiletor

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const DesktopDarwinPFBaselineLimit = 4096

// These records describe an exact fixed-namespace transition. Parsing a
// record does not grant PF authority: the native utility independently checks
// privilege, its installed image/lock and the current kernel namespace/rules.
type DesktopDarwinPFBaselineProof struct {
	Present     bool   `json:"present"`
	RulesSHA256 string `json:"rules_sha256"`
}

type DesktopDarwinPFBaselineRequest struct {
	Schema        int                            `json:"schema"`
	Action        string                         `json:"action"`
	HomeLANAccess bool                           `json:"home_lan_access"`
	SessionID     string                         `json:"session_id"`
	SourceSHA256  string                         `json:"source_sha256"`
	Expected      []DesktopDarwinPFBaselineProof `json:"expected"`
}

type DesktopDarwinPFBaselineResult struct {
	Schema        int                          `json:"schema"`
	RequestSHA256 string                       `json:"request_sha256"`
	Previous      DesktopDarwinPFBaselineProof `json:"previous"`
	Target        DesktopDarwinPFBaselineProof `json:"target"`
	Applied       bool                         `json:"applied"`
}

func desktopPFHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, value := range []byte(value) {
		if value < '0' || value > '9' && value < 'a' || value > 'f' {
			return false
		}
	}
	return true
}

func (p DesktopDarwinPFBaselineProof) valid() bool {
	return p.Present && desktopPFHex(p.RulesSHA256, 64) || !p.Present && p.RulesSHA256 == ""
}

func (r DesktopDarwinPFBaselineRequest) validate() error {
	if r.Schema != 1 || (r.Action != "replace" && r.Action != "clear") || len(r.Expected) < 1 || len(r.Expected) > 2 {
		return errors.New("Darwin PF baseline request lost its bounded transition")
	}
	if (r.SessionID != "" || r.SourceSHA256 != "") && (!desktopPFHex(r.SessionID, 32) || !desktopPFHex(r.SourceSHA256, 64)) {
		return errors.New("Darwin PF baseline request lost its complete captured source")
	}
	if r.Action == "clear" && (r.HomeLANAccess || r.SessionID != "" || r.SourceSHA256 != "") {
		return errors.New("Darwin PF baseline removal cannot borrow a connection policy")
	}
	for index, proof := range r.Expected {
		if !proof.valid() || index != 0 && proof == r.Expected[0] {
			return errors.New("Darwin PF baseline request has an invalid or duplicate prior proof")
		}
	}
	return nil
}

func EncodeDesktopDarwinPFBaselineRequest(request DesktopDarwinPFBaselineRequest) ([]byte, error) {
	if err := request.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

func ParseDesktopDarwinPFBaselineRequest(raw []byte) (DesktopDarwinPFBaselineRequest, error) {
	var request DesktopDarwinPFBaselineRequest
	if len(raw) == 0 || len(raw) > DesktopDarwinPFBaselineLimit {
		return request, errors.New("Darwin PF baseline request exceeds its private input bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return DesktopDarwinPFBaselineRequest{}, errors.New("Darwin PF baseline request is not a complete record")
	}
	canonical, err := EncodeDesktopDarwinPFBaselineRequest(request)
	if err != nil || !bytes.Equal(canonical, raw) {
		return DesktopDarwinPFBaselineRequest{}, errors.Join(err, errors.New("Darwin PF baseline request has missing, duplicate, null or noncanonical fields"))
	}
	return request, nil
}

func (r DesktopDarwinPFBaselineRequest) accepts(proof DesktopDarwinPFBaselineProof) bool {
	if r.validate() != nil || !proof.valid() {
		return false
	}
	for _, expected := range r.Expected {
		if expected == proof {
			return true
		}
	}
	return false
}

func desktopPFDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func desktopPFLabel(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "rvpn:" + base64.RawURLEncoding.EncodeToString(digest[:])
}

// Both the guardian and the fixed baseline utility compile this policy. The
// scope parameter is private native-fixture input; no public record contains
// an anchor, address, interface, rules text or replacement command.
func desktopPFOwnedBaseline(session, source string, lan bool, scope string) string {
	active := session != ""
	if !active {
		session = "inactive"
	}
	allowed := desktopPFLabel("allowed\x00" + session + "\x00" + source)
	reset := desktopPFLabel("unproven\x00" + session + "\x00" + source)
	label := desktopPFLabel("baseline\x00" + session + "\x00" + source)
	if scope != "" {
		lines := []string{fmt.Sprintf("pass out %s tag \"%s\" no state", scope, reset)}
		if active {
			lines = append(lines, fmt.Sprintf("anchor \"p%s\" out", session))
		}
		lines = append(lines, fmt.Sprintf("block drop out quick %s ! tagged \"%s\" label \"%s\"", scope, allowed, label))
		return strings.Join(lines, "\n") + "\n"
	}
	lines := []string{fmt.Sprintf("pass out all tag \"%s\" no state", reset)}
	if active {
		lines = append(lines, fmt.Sprintf("anchor \"p%s\" out", session))
	}
	lines = append(lines,
		fmt.Sprintf("pass out on lo0 all tag \"%s\" no state", allowed),
		fmt.Sprintf("pass out inet proto udp from any port 68 to 255.255.255.255 port 67 tag \"%s\" no state", allowed),
		fmt.Sprintf("pass out inet6 proto udp from any port 546 to any port 547 tag \"%s\" no state", allowed),
		fmt.Sprintf("pass out inet6 proto icmp6 from { ::, fe80::/10 } to { fe80::/10, ff00::/8 } tag \"%s\" no state", allowed))
	if lan {
		lines = append(lines,
			fmt.Sprintf("pass out inet to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } tag \"%s\" no state", allowed),
			fmt.Sprintf("pass out inet to 224.0.0.0/4 tag \"%s\" no state", allowed),
			fmt.Sprintf("pass out inet6 to { fc00::/7, fe80::/10 } tag \"%s\" no state", allowed),
			fmt.Sprintf("pass out inet6 to ff00::/8 tag \"%s\" no state", allowed))
	}
	lines = append(lines, fmt.Sprintf("block drop out quick all ! tagged \"%s\" label \"%s\"", allowed, label))
	return strings.Join(lines, "\n") + "\n"
}
