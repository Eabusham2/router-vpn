package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"
)

// DesktopStartupAdmission carries only the accepted host operation's budget.
// It never grants process, source, socket, policy or native-reader authority.
// Each child must compare it with its independently captured original graph.
type DesktopStartupAdmission struct {
	Schema       int    `json:"schema"`
	Kind         string `json:"kind"`
	Session      string `json:"session"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	DeadlineNS   int64  `json:"deadline_ns"`
}

const DesktopStartupAdmissionEnvironment = "HOMEVPN_NATIVE_STARTUP"

func NewDesktopStartupAdmission(kind, session, source, config string, deadline time.Time) (DesktopStartupAdmission, error) {
	value := DesktopStartupAdmission{1, kind, session, source, config, deadline.UnixNano()}
	if err := value.validate(); err != nil {
		return DesktopStartupAdmission{}, err
	}
	return value, nil
}
func (a DesktopStartupAdmission) validate() error {
	if a.Schema != 1 || (a.Kind != "external" && a.Kind != "tor") || !desktopExternalSessionID.MatchString(a.Session) || !proofID.MatchString(a.SourceSHA256) || !proofID.MatchString(a.ConfigSHA256) || a.DeadlineNS <= 0 {
		return errors.New("native startup has no exact original admission")
	}
	return nil
}
func (a DesktopStartupAdmission) Canonical() (string, error) {
	if err := a.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(a)
	return string(raw), err
}
func ParseDesktopStartupAdmission(raw, kind, session, source, config string) (DesktopStartupAdmission, error) {
	var value DesktopStartupAdmission
	if len(raw) == 0 || len(raw) > 1024 || json.Unmarshal([]byte(raw), &value) != nil {
		return value, errors.New("native startup admission is missing or malformed")
	}
	canonical, err := value.Canonical()
	if err != nil || !bytes.Equal([]byte(raw), []byte(canonical)) || value.Kind != kind || value.Session != session || value.SourceSHA256 != source || value.ConfigSHA256 != config {
		return DesktopStartupAdmission{}, errors.New("native startup admission differs from its captured graph")
	}
	return value, nil
}

// Context preserves the transported absolute deadline and any shorter local
// caller deadline. It must be kept separate from the connection lifetime.
func (a DesktopStartupAdmission) Context(parent context.Context) (context.Context, context.CancelFunc, error) {
	if err := a.validate(); err != nil {
		return nil, nil, err
	}
	if parent == nil {
		return nil, nil, errors.New("native startup has no original local caller")
	}
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(parent, time.Unix(0, a.DeadlineNS))
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, nil, err
	}
	return ctx, cancel, nil
}
