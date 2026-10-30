package windowsapp

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsPortableConfigurationPreservesAndRelocates(t *testing.T) {
	original := []byte("{\"listen\":\"127.0.0.1:8788\",\"health_url\":\"https://router.home.arpa/health\",\"auto_test_seconds\":19,\"modes_file\":\"old/modes.windows.json\",\"scripts_dir\":\"old/modes\",\"state_file\":\"old/state.json\",\"profiles_file\":\"old/routers.json\",\"api_token\":\"fixture-secret\",\"new_setting\":{\"count\":9007199254740993,\"selected\":\"custom\",\"ipv6\":\"on\"}}")
	captured := append([]byte(nil), original...)
	packageRoot, dataRoot := filepath.Join(t.TempDir(), "App", "RouterVPN"), filepath.Join(t.TempDir(), "Data")
	body, err := portableConfiguration(original, []byte("{\"api_token\":\"wrong-default\"}"), packageRoot, dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := portableJSONObject(original)
	after, _ := portableJSONObject(body)
	for _, name := range []string{"listen", "health_url", "auto_test_seconds", "api_token", "new_setting"} {
		var left, right bytes.Buffer
		_ = json.Compact(&left, before[name])
		_ = json.Compact(&right, after[name])
		if !bytes.Equal(left.Bytes(), right.Bytes()) {
			t.Fatalf("Portable relocation replaced saved field %s", name)
		}
	}
	for name, expected := range map[string]string{
		"modes_file": filepath.Join(packageRoot, "modes.json"), "scripts_dir": filepath.Join(packageRoot, "modes"),
		"state_file": filepath.Join(dataRoot, "state.json"), "profiles_file": filepath.Join(dataRoot, "routers.json"),
	} {
		var actual string
		if json.Unmarshal(after[name], &actual) != nil || actual != expected {
			t.Fatalf("Portable %s did not follow the captured relocated layout", name)
		}
	}
	if !bytes.Equal(original, captured) || bytes.Contains(body, []byte("modes.windows.json")) {
		t.Fatal("Portable relocation mutated its captured input or retained writable command authority")
	}
	repeated, err := portableConfiguration(body, nil, packageRoot, dataRoot)
	if err != nil || !bytes.Equal(body, repeated) {
		t.Fatal("Portable repeated preparation rewrote an unchanged config", err)
	}
}

func TestWindowsPortableConfigurationFreshDefaultsAndInvalidPreservation(t *testing.T) {
	body, err := portableConfiguration(nil, []byte("{\"new_setting\":{\"keep\":true}}"), "package", "data")
	if err != nil {
		t.Fatal(err)
	}
	fields, err := portableJSONObject(body)
	if err != nil || string(fields["listen"]) != "\"127.0.0.1:8788\"" || string(fields["health_url"]) != "\"http://10.77.0.1:8787/health\"" ||
		string(fields["auto_test_seconds"]) != "8" || fields["new_setting"] == nil {
		t.Fatal("fresh Portable defaults lost the private proof or packaged preferences", err)
	}
	for _, invalid := range []string{
		"", "null", "[]", "{", "{} {}", "{\"listen\":1}", "{\"listen\":\"0.0.0.0:8788\"}",
		"{\"listen\":\"127.0.0.1:8788\",\"listen\":\"0.0.0.0:8788\"}", "{\"modes_file\":[]}",
		"{\"unknown\":1,\"unknown\":2}", strings.Repeat(" ", portablePrivateLimit+1),
	} {
		if _, err := portableConfiguration([]byte(invalid), []byte("{}"), "package", "data"); err == nil {
			t.Fatal("invalid existing Portable data was silently replaced by defaults")
		}
	}
}

func TestWindowsPortablePrivateAccessPolicy(t *testing.T) {
	user, foreign := "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	trusted := []portableAccessGrant{{user, true, 3, 0x1f01ff}, {"S-1-5-18", true, 3, 0x1f01ff}, {"S-1-5-32-544", true, 3, 0x1f01ff}}
	for _, owner := range []string{user, "S-1-5-18", "S-1-5-32-544"} {
		if err := validatePortablePrivateGrants(owner, user, trusted); err != nil {
			t.Fatal("captured private owner rejected", err)
		}
	}
	for _, owner := range []string{"", foreign, "S-1-1-0"} {
		if err := validatePortablePrivateGrants(owner, user, trusted); err == nil {
			t.Fatal("foreign Portable owner admitted")
		}
	}
	for _, extra := range []portableAccessGrant{
		{foreign, true, 0, 1}, {"S-1-1-0", true, 0, 0x80000000},
		{foreign, true, 0x08, 0x10000000}, {user, true, 0x80, 1}, {"", true, 0, 1},
	} {
		grants := append(append([]portableAccessGrant{}, trusted...), portableAccessGrant{foreign, false, 0, 0x10000000}, extra)
		if err := validatePortablePrivateGrants(user, user, grants); err == nil {
			t.Fatal("Portable private policy accepted an unrelated read/write/inherited grant")
		}
	}
	for _, grants := range [][]portableAccessGrant{nil, {{user, false, 0, 0x10000000}}, {{user, true, 8, 0x10000000}}} {
		if err := validatePortablePrivateGrants(user, user, grants); err == nil {
			t.Fatal("Portable private policy accepted no effective grant")
		}
	}
	readable := append(append([]portableAccessGrant{}, trusted...), portableAccessGrant{foreign, true, 0, 0xa01200a9})
	if err := validatePortablePackageGrants(user, user, readable); err != nil {
		t.Fatal("readable immutable package input rejected", err)
	}
	readable[len(readable)-1].mask |= 2
	if err := validatePortablePackageGrants(user, user, readable); err == nil {
		t.Fatal("ordinary foreign writer acquired Portable package authority")
	}
}
