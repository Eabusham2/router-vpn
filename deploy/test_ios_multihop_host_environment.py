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
    assert args == ["--sdk", "macosx", "--show-sdk-path"]
    if os.environ.get("HOST_TEST_FAIL") == "sdk":
        sys.exit(2)
    print(os.environ["HOST_TEST_SDK"])
elif name == "python3":
    host()
    assert args[0].endswith("test_ios_multihop_graph.py")
    assert args[1] == "--fixture-dir"
    directory = pathlib.Path(args[2]); directory.mkdir()
    for filename in ("shadowsocks.json", "hysteria2.json", "shadowsocks-ipv4-only.json"):
        (directory / filename).write_text("{}")
    record({"event":"fixtures", "work":str(directory.parent)})
elif name == "go":
    host()
    if args == ["env", "GOHOSTARCH"]:
        print("arm64")
    else:
        assert args[0] == "build" and "./cmd/sing-box" in args
        assert os.environ["GOOS"] == "darwin"
        assert os.environ["GOARCH"] == "arm64"
        assert os.environ["CGO_ENABLED"] == "0"
        assert os.environ["GOTOOLCHAIN"] == "go1.26.3"
        record({"event":"build"})
        if os.environ.get("HOST_TEST_FAIL") == "build":
            sys.exit(3)
        output = pathlib.Path(args[args.index("-o") + 1])
        output.write_text(pathlib.Path(sys.argv[0]).read_text())
        output.chmod(0o755)
elif name == "sing-box":
    host()
    assert args[:2] == ["check", "-c"], "a validation gate must never start a tunnel"
    assert pathlib.Path(args[2]).is_file()
    record({"event":"check", "fixture":pathlib.Path(args[2]).name})
    if os.environ.get("HOST_TEST_FAIL") == "check":
        sys.exit(4)
else:
    raise AssertionError(name)
'''


class HostEnvironmentTest(unittest.TestCase):
    def run_gate(self, failure="", missing_sdk=False):
        with tempfile.TemporaryDirectory(prefix="routervpn-host-sdk-") as tmp:
            root = Path(tmp)
            (root / "deploy").mkdir()
            (root / "ios/RouterVPN/.deps/sing-box-apple").mkdir(parents=True)
            script = root / "deploy/test_ios_multihop_pinned.sh"
            shutil.copyfile(SCRIPT, script)
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
                       HOST_TEST_EVENTS=str(events_file), HOST_TEST_PIN=PIN, HOST_TEST_FAIL=failure)
            completed = subprocess.run(["bash", str(script)], env=env, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            events = [json.loads(line) for line in events_file.read_text().splitlines()] if events_file.exists() else []
            for event in events:
                if "work" in event:
                    self.assertFalse(Path(event["work"]).exists(), "temporary fixtures/binary were not removed")
            self.assertEqual(env["SDKROOT"], "/invalid/iPhoneOS.sdk", "enclosing IPA SDK was changed")
            return completed, events

    def test_xcode_iphone_sdk_is_not_used_for_host_executables(self):
        result, events = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([event["event"] for event in events], ["fixtures", "build", "check", "check", "check"])
        self.assertEqual({event["fixture"] for event in events if event["event"] == "check"},
                         {"shadowsocks.json", "hysteria2.json", "shadowsocks-ipv4-only.json"})

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

    def test_compile_failure_is_not_a_pass(self):
        result, events = self.run_gate("build")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event["event"] for event in events], ["fixtures", "build"])

    def test_parser_failure_is_not_a_pass(self):
        result, events = self.run_gate("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([event["event"] for event in events], ["fixtures", "build", "check"])


if __name__ == "__main__":
    unittest.main()
