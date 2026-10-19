#!/usr/bin/env python3
"""Exercise the shipping host-parser shell with command doubles, not a VPN."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/test_ios_multihop_pinned.sh"
PIN = "1ac1a339cb1223e9c70eae14c44411c75033c02d"

# Executed in place of Apple/Git/Go tools. The REAL shipping shell is under test;
# native CI separately runs the real compiler and exact-pinned Libbox parser.
SHIM = r'''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
def record(event):
    with open(os.environ["HOST_TEST_EVENTS"], "a") as log:
        log.write(json.dumps(event) + "\n")
def host():
    assert os.environ.get("SDKROOT") == os.environ["HOST_TEST_SDK"]
    for key in ("IPHONEOS_DEPLOYMENT_TARGET", "TVOS_DEPLOYMENT_TARGET", "WATCHOS_DEPLOYMENT_TARGET", "XROS_DEPLOYMENT_TARGET"):
        assert key not in os.environ, key
if name == "uname":
    print("Darwin")
elif name == "git":
    assert args[-2:] == ["rev-parse", "HEAD"]
    print("bad-pin" if os.environ.get("HOST_TEST_FAIL") == "pin" else os.environ["HOST_TEST_PIN"])
elif name == "xcrun":
    assert args[:2] == ["--sdk", "macosx"]
    if args[2:] == ["--show-sdk-path"]:
        if os.environ.get("HOST_TEST_FAIL") == "sdk":
            sys.exit(2)
        print(os.environ["HOST_TEST_SDK"])
    else:
        assert args[2:] in (["--find", "clang"], ["--find", "clang++"])
        if os.environ.get("HOST_TEST_FAIL") == args[3]:
            sys.exit(2)
        print(os.environ["HOST_TEST_CXX" if args[3] == "clang++" else "HOST_TEST_CC"])
elif name == "python3":
    host()
    assert args[1] == "--fixture-dir"
    directory = pathlib.Path(args[2]); directory.mkdir()
    if args[0].endswith("test_ios_xray_exits.py"):
        count = 86 if os.environ.get("HOST_TEST_FAIL") == "short-matrix" else 87
        for index in range(count):
            case = directory / ("case-" + str(index)); case.mkdir()
            for filename in ("sing-box.json", "planned.json"):
                (case / filename).write_text("{}")
        record({"event":"native-fixtures", "work":str(directory.parent)})
    else:
        assert args[0].endswith("test_ios_multihop_graph.py")
        for filename in ("shadowsocks.json", "hysteria2.json", "shadowsocks-ipv4-only.json", "wireguard.json", "wireguard-ipv4-only.json"):
            (directory / filename).write_text("{}")
        record({"event":"fixtures", "work":str(directory.parent)})
elif name == "go":
    host()
    if args == ["env", "GOHOSTARCH"]:
        print(os.environ["HOST_TEST_ARCH"])
    else:
        assert args[0] == "build" and "./cmd/sing-box" in args
        assert os.environ["GOOS"] == "darwin"
        assert os.environ["GOARCH"] == os.environ["HOST_TEST_ARCH"]
        assert os.environ["CGO_ENABLED"] == "1", "Naive's native Cronet parser requires cgo"
        assert os.environ["CC"] == os.environ["HOST_TEST_CC"], "host parser inherited the iOS C compiler"
        assert os.environ["CXX"] == os.environ["HOST_TEST_CXX"], "host parser inherited the iOS C++ compiler"
        for key in ("CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS"):
            assert key not in os.environ, "host parser inherited target flags: " + key
        assert os.environ["GOTOOLCHAIN"] == "go1.26.3"
        assert {"with_wireguard", "with_quic", "with_gvisor", "with_naive_outbound"}.issubset(args[args.index("-tags") + 1].split(",")), "host parser lost a shipping protocol"
        record({"event":"build"})
        if os.environ.get("HOST_TEST_FAIL") == "build":
            sys.exit(3)
        output = pathlib.Path(args[args.index("-o") + 1])
        output.write_text("""#!/bin/sh
set -eu
[ "$SDKROOT" = "$HOST_TEST_SDK" ]
[ "${IPHONEOS_DEPLOYMENT_TARGET+x}" != x ]
[ "${TVOS_DEPLOYMENT_TARGET+x}" != x ]
[ "${WATCHOS_DEPLOYMENT_TARGET+x}" != x ]
[ "${XROS_DEPLOYMENT_TARGET+x}" != x ]
[ "$1" = check ] && [ "$2" = -c ] && [ -f "$3" ]
fixture=${3##*/}
parent=${3%/*}
group=${parent##*/}
printf '{"event":"check","fixture":"%s","group":"%s"}\n' "$fixture" "$group" >> "$HOST_TEST_EVENTS"
[ "$HOST_TEST_FAIL" != check ] || exit 4
case "$group" in case-*) [ "$HOST_TEST_FAIL" != native-check ] || exit 4;; esac
""")
        output.chmod(0o755)
elif name == "sing-box":
    host()
    assert args[:2] == ["check", "-c"], "a validation gate must never start a tunnel"
    assert pathlib.Path(args[2]).is_file()
    record({"event":"check", "fixture":pathlib.Path(args[2]).name, "group":pathlib.Path(args[2]).parent.name})
    if os.environ.get("HOST_TEST_FAIL") == "check" or (os.environ.get("HOST_TEST_FAIL") == "native-check" and pathlib.Path(args[2]).parent.name.startswith("case-")):
        sys.exit(4)
else:
    raise AssertionError(name)
'''


class HostEnvironmentTest(unittest.TestCase):
    def run_gate(self, failure="", missing_sdk=False, drop_naive=False,
                 disable_cgo=False, leak_cgo_flags=False, host_arch="arm64"):
        with tempfile.TemporaryDirectory(prefix="routervpn-host-sdk-") as tmp:
            root = Path(tmp)
            (root / "deploy").mkdir()
            (root / "ios/RouterVPN/.deps/sing-box-apple").mkdir(parents=True)
            script = root / "deploy/test_ios_multihop_pinned.sh"
            shutil.copyfile(SCRIPT, script)
            if drop_naive:
                script.write_text(script.read_text().replace(",with_naive_outbound", ""))
            if disable_cgo:
                script.write_text(script.read_text().replace("export CGO_ENABLED=1", "export CGO_ENABLED=0"))
            if leak_cgo_flags:
                script.write_text(script.read_text().replace("unset CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS", ":"))
            sdk = root / "MacOSX.sdk"
            if not missing_sdk:
                sdk.mkdir()
            tools = root / "bin"; tools.mkdir()
            for name in ("uname", "git", "xcrun", "python3", "go"):
                path = tools / name
                path.write_text("#!" + sys.executable + "\n" + SHIM)
                path.chmod(0o755)
            events_file = root / "events.jsonl"
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                       SDKROOT="/invalid/iPhoneOS.sdk", IPHONEOS_DEPLOYMENT_TARGET="17.0",
                       TVOS_DEPLOYMENT_TARGET="17.0", WATCHOS_DEPLOYMENT_TARGET="10.0",
                       XROS_DEPLOYMENT_TARGET="1.0", HOST_TEST_SDK=str(sdk),
                       GOOS="ios", GOARCH="386", CGO_ENABLED="0",
                       CC="/invalid/iPhoneOS/clang", CXX="/invalid/iPhoneOS/clang++",
                       CGO_CFLAGS="-target arm64-apple-ios17.0", CGO_CPPFLAGS="-isysroot /invalid/iPhoneOS.sdk",
                       CGO_CXXFLAGS="-target arm64-apple-ios17.0", CGO_LDFLAGS="-isysroot /invalid/iPhoneOS.sdk",
                       HOST_TEST_CC=str(tools / "host-clang"), HOST_TEST_CXX=str(tools / "host-clang++"),
                       HOST_TEST_ARCH=host_arch,
                       HOST_TEST_EVENTS=str(events_file), HOST_TEST_PIN=PIN, HOST_TEST_FAIL=failure)
            completed = subprocess.run(["bash", str(script)], env=env, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            events = [json.loads(line) for line in events_file.read_text().splitlines()] if events_file.exists() else []
            for event in events:
                if "work" in event:
                    self.assertFalse(Path(event["work"]).exists(), "temporary fixtures/binary were not removed")
            self.assertEqual(env["SDKROOT"], "/invalid/iPhoneOS.sdk", "enclosing IPA SDK was changed")
            self.assertEqual(env["CGO_ENABLED"], "0", "enclosing IPA cgo setting was changed")
            self.assertEqual(env["CGO_CFLAGS"], "-target arm64-apple-ios17.0", "enclosing IPA compiler flags were changed")
            return completed, events

    def test_xcode_iphone_sdk_is_not_used_for_host_executables(self):
        result, events = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([event["event"] for event in events], ["fixtures", "native-fixtures", "build"] + ["check"] * 179)
        self.assertEqual({event["fixture"] for event in events if event["event"] == "check"},
                         {"shadowsocks.json", "hysteria2.json", "shadowsocks-ipv4-only.json", "wireguard.json", "wireguard-ipv4-only.json", "sing-box.json", "planned.json"})

    def test_intel_host_uses_its_own_architecture(self):
        result, events = self.run_gate(host_arch="amd64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(event["event"] == "check" for event in events), 179)

    def test_naive_cgo_cannot_be_disabled(self):
        result, events = self.run_gate(disable_cgo=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Naive's native Cronet parser requires cgo", result.stderr)
        self.assertFalse(any(event["event"] == "check" for event in events))

    def test_ios_cgo_flags_cannot_leak_into_host_parser(self):
        result, events = self.run_gate(leak_cgo_flags=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host parser inherited target flags", result.stderr)
        self.assertFalse(any(event["event"] == "check" for event in events))

    def test_naive_build_tag_cannot_be_removed(self):
        result, events = self.run_gate(drop_naive=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host parser lost a shipping protocol", result.stderr)
        self.assertFalse(any(event["event"] == "check" for event in events))

    def test_wrong_pin_stops_before_build(self):
        result, events = self.run_gate("pin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])

    def test_sdk_lookup_failure_stops_before_build(self):
        result, events = self.run_gate("sdk")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])

    def test_missing_sdk_directory_stops_before_build(self):
        result, events = self.run_gate(missing_sdk=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(events, [])

    def test_host_compiler_lookup_failure_stops_before_build(self):
        for compiler in ("clang", "clang++"):
            with self.subTest(compiler=compiler):
                result, events = self.run_gate(compiler)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([event["event"] for event in events], ["fixtures", "native-fixtures"])

    def test_compile_failure_is_not_a_pass(self):
        result, events = self.run_gate("build")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event["event"] for event in events], ["fixtures", "native-fixtures", "build"])

    def test_parser_failure_is_not_a_pass(self):
        result, events = self.run_gate("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event["event"] for event in events], ["fixtures", "native-fixtures", "build", "check"])

    def test_native_exit_parser_failure_is_not_a_pass(self):
        result, events = self.run_gate("native-check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event["event"] for event in events], ["fixtures", "native-fixtures", "build"] + ["check"] * 6)
        self.assertTrue(events[-1]["group"].startswith("case-"))

    def test_incomplete_native_matrix_is_not_a_pass(self):
        result, events = self.run_gate("short-matrix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Incomplete Apple native exit graph matrix", result.stdout + result.stderr)
        self.assertEqual(sum(event["event"] == "check" for event in events), 177)


if __name__ == "__main__":
    unittest.main()
