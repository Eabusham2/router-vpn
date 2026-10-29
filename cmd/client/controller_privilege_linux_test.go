//go:build linux

package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func testLinuxOwnedHandshake() []byte {
	return []byte(`{"schema":1,"access_token":"` + testLocalControllerAccess + `","owner_token":"` + testControllerOwner + `"}` + "\n")
}

func TestLinuxOwnedHandshakeRequiresExactPrivateSingleFrame(t *testing.T) {
	valid := string(testLinuxOwnedHandshake())
	access, owner, err := decodeLinuxOwnedHandshake([]byte(valid))
	if err != nil || access != testLocalControllerAccess || owner != testControllerOwner {
		t.Fatal("exact private launch frame rejected", err)
	}
	cases := map[string]string{
		"empty": "", "array": "[]\n", "null": "null\n", "no-newline": strings.TrimSuffix(valid, "\n"),
		"second-line": valid + valid, "second-empty-line": valid + "\n", "trailing-json": strings.TrimSuffix(valid, "\n") + "{}\n",
		"duplicate-schema": strings.TrimSuffix(valid, "}\n") + `,"schema":1}` + "\n",
		"duplicate-secret": strings.TrimSuffix(valid, "}\n") + `,"access_token":"` + testLocalControllerAccess + `"}` + "\n",
		"unknown":          strings.TrimSuffix(valid, "}\n") + `,"role":"root"}` + "\n",
		"case-alias":       strings.Replace(valid, `"schema"`, `"Schema"`, 1),
		"missing":          strings.Replace(valid, `"schema":1,`, "", 1),
		"schema-null":      strings.Replace(valid, `"schema":1`, `"schema":null`, 1),
		"schema-string":    strings.Replace(valid, `"schema":1`, `"schema":"1"`, 1),
		"version":          strings.Replace(valid, `"schema":1`, `"schema":2`, 1),
		"uppercase-access": strings.Replace(valid, testLocalControllerAccess, strings.ToUpper(testLocalControllerAccess), 1),
		"short-access":     strings.Replace(valid, testLocalControllerAccess, testLocalControllerAccess[1:], 1),
		"invalid-access":   strings.Replace(valid, testLocalControllerAccess, strings.Repeat("g", 64), 1),
		"empty-owner":      strings.Replace(valid, testControllerOwner+`"}`, `"}`, 1),
		"uppercase-owner":  strings.Replace(valid, testControllerOwner+`"}`, strings.ToUpper(testControllerOwner)+`"}`, 1),
		"short-owner":      strings.Replace(valid, testControllerOwner+`"}`, testControllerOwner[1:]+`"}`, 1),
		"oversized":        strings.Repeat(" ", 385) + valid,
		"invalid-utf8":     string([]byte{0xff}) + valid,
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			access, owner, err := decodeLinuxOwnedHandshake([]byte(frame))
			if err == nil || access != "" || owner != "" || strings.Contains(err.Error(), testLocalControllerAccess) || strings.Contains(err.Error(), testControllerOwner) {
				t.Fatal("malformed frame retained or disclosed authority", err)
			}
		})
	}
}

func TestLinuxOwnedConfigurationPinsAllExecutableAndPrivatePaths(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		paths := []string{"modes.json", "modes", "routers.json", "state.json"}
		if absolute {
			for index := range paths {
				paths[index] = filepath.Join(linuxOwnedControllerRoot, paths[index])
			}
		}
		config := common.ClientConfig{Listen: linuxOwnedControllerAddress, ModesFile: paths[0], ScriptsDir: paths[1], ProfilesFile: paths[2], StateFile: paths[3]}
		if err := validateLinuxOwnedConfiguration(config); err != nil {
			t.Fatal("exact installed configuration rejected", err)
		}
	}
	if err := validateLinuxOwnedConfiguration(common.ClientConfig{}); err != nil {
		t.Fatal("fixed defaults rejected", err)
	}
	for _, field := range []string{"listen", "modes_file", "scripts_dir", "profiles_file", "state_file"} {
		for _, escape := range []string{"/tmp/attacker", "../attacker", "/opt/router-vpn-client-old/state.json", "bad\x00path", "localhost:8788", "0.0.0.0:8788", "127.0.0.1:8789"} {
			var config common.ClientConfig
			raw, _ := json.Marshal(map[string]string{field: escape})
			json.Unmarshal(raw, &config)
			if err := validateLinuxOwnedConfiguration(config); err == nil {
				t.Fatalf("captured %s accepted %q", field, escape)
			}
		}
	}
}

type linuxOwnedTestInfo struct {
	mode fs.FileMode
	stat *syscall.Stat_t
}

func (i linuxOwnedTestInfo) Name() string       { return "owned" }
func (i linuxOwnedTestInfo) Size() int64        { return 1 }
func (i linuxOwnedTestInfo) Mode() fs.FileMode  { return i.mode }
func (i linuxOwnedTestInfo) ModTime() time.Time { return time.Time{} }
func (i linuxOwnedTestInfo) IsDir() bool        { return i.mode.IsDir() }
func (i linuxOwnedTestInfo) Sys() any           { return i.stat }

func TestLinuxOwnedMetadataRejectsWritableForeignAndLinkedCode(t *testing.T) {
	for _, mode := range []fs.FileMode{0600, 0644, 0755, os.ModeDir | 0755} {
		if !linuxOwnedInfo(linuxOwnedTestInfo{mode, &syscall.Stat_t{Uid: 0, Gid: 0, Nlink: 1}}) {
			t.Fatal("safe installed metadata rejected", mode)
		}
	}
	for _, mode := range []fs.FileMode{0620, 0602, 0666, os.ModeDir | 0777, os.ModeSymlink | 0777, os.ModeNamedPipe | 0600, os.ModeSocket | 0600, os.ModeDevice | 0600, os.ModeSetuid | 0755, os.ModeSetgid | 0755} {
		if linuxOwnedInfo(linuxOwnedTestInfo{mode, &syscall.Stat_t{Uid: 0, Gid: 0, Nlink: 1}}) {
			t.Fatal("unsafe installed metadata accepted", mode)
		}
	}
	for _, stat := range []*syscall.Stat_t{{Uid: 65534, Nlink: 1}, {Gid: 65534, Nlink: 1}, {Nlink: 0}, {Nlink: 2}} {
		if linuxOwnedInfo(linuxOwnedTestInfo{0600, stat}) {
			t.Fatal("foreign or aliased installed file accepted", *stat)
		}
	}
}

func TestLinuxOwnedBootstrapDoesNotConsumeOrdinaryUtilityArguments(t *testing.T) {
	for _, arguments := range [][]string{nil, {"--verify-native-runtime"}, {"--mtu-owner-stop", "captured"}} {
		owned, err := prepareLinuxOwnedController(arguments)
		if owned != nil || err != nil {
			t.Fatal("ordinary utility acquired privileged startup", arguments, err)
		}
	}
	for _, arguments := range [][]string{{linuxOwnedControllerArgument, "--config=/tmp/attacker"}, {"unexpected", linuxOwnedControllerArgument}, {linuxOwnedControllerArgument, linuxOwnedControllerArgument}} {
		owned, err := prepareLinuxOwnedController(arguments)
		if owned != nil || err == nil {
			t.Fatal("privileged startup accepted extra arguments", arguments)
		}
	}
}

func TestLinuxOwnedStartupRejectsAnUnretainedOwner(t *testing.T) {
	if err := validateLinuxOwnedStartup(testLocalControllerOwner()); err == nil {
		t.Fatal("HTTP identity without retained input and both locks became a privileged startup")
	}
}
