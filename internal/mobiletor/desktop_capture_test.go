package mobiletor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDesktopBridgeCaptureReconstructsExactDisabledInputs(t *testing.T) {
	for _, target := range []string{"linux", "darwin", "windows"} {
		t.Run(target, func(t *testing.T) {
			profile := torHostEncode(t, desktopProfile())
			root := t.TempDir()
			directory, executable := filepath.Join(root, "private Tor session"), filepath.Join(root, "runtime", "tor")
			input, err := NewDesktopBridgeCapture(profile, desktopSession, desktopIsolation, target, executable, directory)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeDesktopBridgeCapture(profile, input.JSON(), directory)
			if err != nil || !reflect.DeepEqual(input, decoded) {
				t.Fatal("native reconstruction changed captured inputs", err)
			}
			fields := input.Capture()
			fields.SessionID, fields.TorBinary = "changed", "changed"
			if input.Capture().SessionID != desktopSession || input.Capture().TorBinary != executable {
				t.Fatal("capture getter changed its owner")
			}
			digests := input.Digests()
			if digests.ProfileSHA256 != desktopDigest([]byte(profile)) || digests.CaptureSHA256 != desktopDigest([]byte(input.JSON())) || digests.TorrcSHA256 != desktopDigest([]byte(input.Torrc())) || digests.DefaultsSHA256 != desktopDigest([]byte("\n")) || digests.ConfigSHA256 != desktopDigest([]byte(input.Policy().Config())) || digests.SourceSHA256 != input.Policy().SourceSHA256() {
				t.Fatal("input bytes do not match their captured digests")
			}
			lines := map[string]string{}
			for _, line := range strings.Split(strings.TrimSuffix(input.Torrc(), "\n"), "\n") {
				name, value, ok := strings.Cut(line, " ")
				if !ok || lines[name] != "" {
					t.Fatal("ambiguous startup directive")
				}
				lines[name] = value
			}
			for name, expected := range map[string]string{"DisableNetwork": "1", "__ReloadTorrcOnSIGHUP": "0", "SocksPort": "0", "UseBridges": "0", "RunAsDaemon": "0", "ControlPort": "127.0.0.1:auto", "CookieAuthentication": "1", "CookieAuthFileGroupReadable": "0", "DataDirectoryGroupReadable": "0", "DNSPort": "0", "TransPort": "0", "HTTPTunnelPort": "0", "MetricsPort": "0", "ORPort": "0", "DirPort": "0"} {
				if lines[name] != expected {
					t.Fatal("Tor acquired unowned startup policy", name, lines[name])
				}
			}
			for name, child := range map[string]string{"DataDirectory": "tor-data", "CookieAuthFile": "tor-control.cookie", "ControlPortWriteToFile": "tor-control.port"} {
				if lines[name] != torQuote(filepath.Join(directory, child)) {
					t.Fatal("startup path escaped the captured workspace", name)
				}
			}
			if lines["Bridge"] != "" || lines["ClientTransportPlugin"] != "" || strings.Contains(input.Torrc(), desktopIsolation) || input.Defaults() != "\n" {
				t.Fatal("Tor startup contains live transport, credentials or inherited defaults")
			}
			if lines["Log"] != "notice stdout" || strings.Contains(input.Torrc(), "tor.log") {
				t.Fatal("Tor startup acquired an unbounded persistent diagnostic file")
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("pure capture compiler created a private workspace", err)
			}
		})
	}
}

func TestDesktopBridgeCaptureRejectsAmbiguousOrUnownedInputs(t *testing.T) {
	profile := torHostEncode(t, desktopProfile())
	root := t.TempDir()
	base, err := NewDesktopBridgeCapture(profile, desktopSession, desktopIsolation, "linux", filepath.Join(root, "tor"), filepath.Join(root, "session"))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		base.JSON() + `{}`, `[]`, `null`, strings.Replace(base.JSON(), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(base.JSON(), `"schema":1`, `"schema":1,"cookie":"another-owner"`, 1),
		strings.Replace(base.JSON(), `"schema":1`, `"schema":null`, 1), strings.Replace(base.JSON(), `"schema":1`, `"schema":1.5`, 1),
		strings.Replace(base.JSON(), `"schema":1`, `"schema":2`, 1), strings.Replace(base.JSON(), desktopSession, "wrong-session", 1),
		strings.Replace(base.JSON(), desktopIsolation, "", 1), strings.Replace(base.JSON(), `"target_os":"linux"`, `"target_os":true`, 1),
		strings.Replace(base.JSON(), `"target_os":"linux"`, `"target_os":"unknown"`, 1), strings.Repeat(" ", 16<<10) + base.JSON(),
	} {
		if _, err := DecodeDesktopBridgeCapture(profile, source, base.RuntimeDir()); err == nil {
			t.Fatal("unsafe capture accepted")
		}
	}
	for _, path := range []string{"", "tor", "../tor", root + string(filepath.Separator) + ".." + string(filepath.Separator) + "tor", root + "\nBridge injected", " " + root, root + "\x00", root + "\x7f"} {
		if _, err := NewDesktopBridgeCapture(profile, desktopSession, desktopIsolation, "linux", path, base.RuntimeDir()); err == nil {
			t.Fatal("unsafe executable path accepted")
		}
		if _, err := NewDesktopBridgeCapture(profile, desktopSession, desktopIsolation, "linux", base.Capture().TorBinary, path); err == nil {
			t.Fatal("unsafe workspace path accepted")
		}
	}
	if _, err := DecodeDesktopBridgeCapture(profile, base.JSON(), filepath.VolumeName(root)+string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root accepted as private runtime")
	}
}

func TestDesktopBridgeCaptureDigestsBindRawBytesAndWorkspace(t *testing.T) {
	profile := torHostEncode(t, desktopProfile())
	root := t.TempDir()
	first, err := NewDesktopBridgeCapture(profile, desktopSession, desktopIsolation, "linux", filepath.Join(root, "tor"), filepath.Join(root, "first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecodeDesktopBridgeCapture(profile, first.JSON(), filepath.Join(root, "second"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digests().TorrcSHA256 == second.Digests().TorrcSHA256 {
		t.Fatal("workspace change retained startup authority")
	}
	var captured any
	_ = json.Unmarshal([]byte(first.JSON()), &captured)
	indented, _ := json.MarshalIndent(captured, "", "  ")
	third, err := DecodeDesktopBridgeCapture(profile, string(indented), first.RuntimeDir())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digests().CaptureSHA256 == third.Digests().CaptureSHA256 || first.Policy().Config() != third.Policy().Config() {
		t.Fatal("raw capture identity was replaced by normalized JSON")
	}
	fourth, err := DecodeDesktopBridgeCapture(profile+"\n", first.JSON(), first.RuntimeDir())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digests().ProfileSHA256 == fourth.Digests().ProfileSHA256 || first.Policy().SourceSHA256() == fourth.Policy().SourceSHA256() {
		t.Fatal("raw profile identity was replaced by normalized JSON")
	}
}
