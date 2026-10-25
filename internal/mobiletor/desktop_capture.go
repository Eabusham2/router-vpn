package mobiletor

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

// DesktopBridgeCapture contains private launch parameters, not proof of a
// running engine. IsolationSecret must remain in the owned private workspace.
type DesktopBridgeCapture struct {
	Schema          int    `json:"schema"`
	SessionID       string `json:"session_id"`
	IsolationSecret string `json:"isolation_secret"`
	TargetOS        string `json:"target_os"`
	TorBinary       string `json:"tor_binary"`
}

type DesktopBridgeInputDigests struct {
	SourceSHA256   string `json:"source_sha256"`
	ProfileSHA256  string `json:"profile_sha256"`
	CaptureSHA256  string `json:"capture_sha256"`
	TorrcSHA256    string `json:"torrc_sha256"`
	DefaultsSHA256 string `json:"defaults_sha256"`
	ConfigSHA256   string `json:"config_sha256"`
}

// DesktopBridgeInputs is immutable and opens no file, listener or process.
// Both the controller and native child reconstruct these exact bytes. The
// native host must additionally verify OS, executable provenance, raw digests
// and private directory identity before spawning its standalone Tor child.
type DesktopBridgeInputs struct {
	capture DesktopBridgeCapture
	policy  *DesktopBridgePolicy
	json    string
	torrc   string
	dir     string
	digests DesktopBridgeInputDigests
}

func (i *DesktopBridgeInputs) Capture() DesktopBridgeCapture      { return i.capture }
func (i *DesktopBridgeInputs) Policy() *DesktopBridgePolicy       { return i.policy }
func (i *DesktopBridgeInputs) JSON() string                       { return i.json }
func (i *DesktopBridgeInputs) Torrc() string                      { return i.torrc }
func (i *DesktopBridgeInputs) Defaults() string                   { return "\n" }
func (i *DesktopBridgeInputs) RuntimeDir() string                 { return i.dir }
func (i *DesktopBridgeInputs) Digests() DesktopBridgeInputDigests { return i.digests }

func NewDesktopBridgeCapture(profile, sessionID, isolationSecret, targetOS, torBinary, runtimeDir string) (*DesktopBridgeInputs, error) {
	capture := DesktopBridgeCapture{Schema: 1, SessionID: sessionID, IsolationSecret: isolationSecret, TargetOS: targetOS, TorBinary: torBinary}
	raw, err := json.Marshal(capture)
	if err != nil {
		return nil, err
	}
	return DecodeDesktopBridgeCapture(profile, string(raw), runtimeDir)
}

func DecodeDesktopBridgeCapture(profile, rawCapture, runtimeDir string) (*DesktopBridgeInputs, error) {
	object, err := profileObject(rawCapture, 16<<10)
	if err != nil {
		return nil, errors.New("desktop Tor launch requires one exact bounded capture")
	}
	required := []string{"schema", "session_id", "isolation_secret", "target_os", "tor_binary"}
	if len(object) != len(required) {
		return nil, errors.New("desktop Tor capture contains missing or unowned fields")
	}
	for _, name := range required {
		if value, found := object[name]; !found || value == nil {
			return nil, errors.New("desktop Tor capture is incomplete")
		}
	}
	var capture DesktopBridgeCapture
	if json.Unmarshal([]byte(rawCapture), &capture) != nil || capture.Schema != 1 || !desktopHex(capture.SessionID, 16) || !desktopHex(capture.IsolationSecret, 32) {
		return nil, errors.New("desktop Tor capture has an invalid schema or session identity")
	}
	if err := desktopCapturePath(capture.TorBinary, false); err != nil {
		return nil, err
	}
	if err := desktopCapturePath(runtimeDir, true); err != nil {
		return nil, err
	}
	if capture.TorBinary == runtimeDir {
		return nil, errors.New("desktop Tor executable cannot be its runtime directory")
	}
	policy, err := NewDesktopBridgePolicy(profile, capture.SessionID, capture.IsolationSecret, capture.TargetOS)
	if err != nil {
		return nil, err
	}
	// This file contains no Bridge, PT executable, SOCKS listener or active
	// networking. The authenticated native control owner installs those only
	// after its Box, physical observer and Go PT listeners are ready.
	torrc := strings.Join([]string{
		"ClientOnly 1", "AvoidDiskWrites 1", "SafeLogging 1", "RunAsDaemon 0",
		"DisableNetwork 1", "__ReloadTorrcOnSIGHUP 0", "SocksPort 0", "UseBridges 0",
		"DNSPort 0", "TransPort 0", "HTTPTunnelPort 0", "MetricsPort 0", "ORPort 0", "DirPort 0",
		"ControlPort 127.0.0.1:auto", "CookieAuthentication 1", "CookieAuthFileGroupReadable 0", "DataDirectoryGroupReadable 0",
		"DataDirectory " + torQuote(filepath.Join(runtimeDir, "tor-data")),
		"CookieAuthFile " + torQuote(filepath.Join(runtimeDir, "tor-control.cookie")),
		"ControlPortWriteToFile " + torQuote(filepath.Join(runtimeDir, "tor-control.port")),
		// The native process owns bounded child diagnostics. A persistent log is
		// neither a bootstrap proof nor an unbounded private workspace payload.
		"Log notice stdout",
	}, "\n") + "\n"
	input := &DesktopBridgeInputs{capture: capture, policy: policy, json: rawCapture, torrc: torrc, dir: runtimeDir}
	input.digests = DesktopBridgeInputDigests{
		SourceSHA256: policy.SourceSHA256(), ProfileSHA256: desktopDigest([]byte(profile)), CaptureSHA256: desktopDigest([]byte(rawCapture)),
		TorrcSHA256: desktopDigest([]byte(torrc)), DefaultsSHA256: desktopDigest([]byte(input.Defaults())), ConfigSHA256: policy.Metadata().ConfigSHA256,
	}
	return input, nil
}

func desktopCapturePath(value string, directory bool) error {
	if value == "" || len(value) > 4096 || strings.TrimSpace(value) != value || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return errors.New("desktop Tor paths require exact canonical absolute captured locations")
	}
	if directory && filepath.Dir(value) == value {
		return errors.New("desktop Tor runtime cannot own a filesystem root")
	}
	return nil
}
