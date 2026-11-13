#!/usr/bin/env python3
"""Check the shipping Apple Tor preprocessing target before cold native builds.

The ordinary tests execute the actual packaging environment preparation without
building dependencies. --native also invokes the selected Xcode C preprocessor
for all three shipping slices, then pairs an explicit foreign compiler default
with intact and omitted CPP target flags. Host defaults cannot make an omission
control accidentally valid for the same architecture and SDK.
"""
from pathlib import Path
import argparse
import importlib.util
import inspect
import os
import platform
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_package(source):
    path = Path(source) / "deploy/build-mobile-tor-package.py"
    spec = importlib.util.spec_from_file_location("original_apple_tor_package", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Prepared(Exception):
    pass


def capture_environment(package, target, work, native=False):
    captured = {}
    original_env = package.base_env
    original_run = package.run

    def base(directory):
        environment = original_env(directory)
        captured["environment"] = environment
        return environment

    def run(command, **kwargs):
        if command[:1] != ["xcrun"]:
            raise AssertionError("Dependency build started before environment capture")
        if native:
            return original_run(command, **kwargs)
        if command[-1] == "--show-sdk-path":
            return "/Selected Xcode/" + target["sdk"] + ".sdk\n"
        return "/Selected Xcode/bin/" + command[-1] + "\n"

    # Stop after the real platform branch, before any archive is read or built.
    with patch.object(package.platform, "system", return_value="Darwin"), \
         patch.object(package, "base_env", side_effect=base), \
         patch.object(package, "run", side_effect=run), \
         patch.object(package, "extract", side_effect=Prepared):
        try:
            package.compile_dependencies(target, work, dict.fromkeys(package.lock()["sources"]),
                                         package.lock(), 2)
        except Prepared:
            pass
        else:
            raise AssertionError("Original package preparation did not reach its source boundary")
    environment = captured["environment"]
    flags = shlex.split(environment["CPPFLAGS"])
    expected = target["arch"] + "-apple-ios" + package.lock()["ios_minimum"]
    if target["sdk"] == "iphonesimulator":
        expected += "-simulator"
    for name in ("CFLAGS", "CPPFLAGS", "LDFLAGS"):
        observed = shlex.split(environment[name])
        if (observed.count("-target") != 1 or observed[observed.index("-target")+1] != expected or
                observed.count("-isysroot") != 1 or observed[observed.index("-isysroot")+1] != environment["SDKROOT"] or
                observed.count("-fapplication-extension") != 1):
            raise AssertionError("Original Apple target/SDK missing from " + name)
    if flags.count("-DROUTERVPN_TOR_EMBEDDED=1") != 1:
        raise AssertionError("Original embedded policy was replaced")
    return environment


def targets(package):
    return [dict(name=name, platform="ios", sdk=sdk, arch=arch, openssl=openssl)
            for name, sdk, arch, openssl in package.APPLE]


def without_cpp_target(environment):
    changed = dict(environment)
    flags = shlex.split(changed["CPPFLAGS"])
    for option in ("-target", "-isysroot"):
        index = flags.index(option)
        del flags[index:index+2]
    flags.remove("-fapplication-extension")
    changed["CPPFLAGS"] = shlex.join(flags)
    return changed


def probe_text(target):
    arch = "__aarch64__" if target["arch"] == "arm64" else "__x86_64__"
    simulator = 1 if target["sdk"] == "iphonesimulator" else 0
    return (
        "#include <stdio.h>\n#include <sys/queue.h>\n#include <TargetConditionals.h>\n"
        "#if !defined(" + arch + ")\n#error ROUTERVPN_WRONG_ARCHITECTURE\n#endif\n"
        "#if !TARGET_OS_IPHONE\n#error ROUTERVPN_WRONG_APPLE_PLATFORM\n#endif\n"
        "#if TARGET_OS_SIMULATOR != " + str(simulator) + "\n#error ROUTERVPN_WRONG_APPLE_VARIANT\n#endif\n"
        "#if __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ != 170000\n#error ROUTERVPN_WRONG_DEPLOYMENT_TARGET\n#endif\n"
        "#ifndef TAILQ_FOREACH\n#error ROUTERVPN_MISSING_SYSTEM_QUEUE_HEADER\n#endif\n"
        "ROUTERVPN_ORIGINAL_APPLE_PREPROCESSOR\n"
    )


def preprocess(environment, source, default_target=None):
    # The ordinary call is the Autoconf CPP invocation, without CFLAGS.
    # Paired controls set the same explicit foreign compiler default before the
    # actual CPPFLAGS; only their original target flags differ between runs.
    defaults = []
    if default_target is not None:
        if default_target not in ("arm64-apple-macos13.0", "x86_64-apple-macos13.0"):
            raise ValueError("Uncaptured Apple preprocessor default")
        defaults = ["-target", default_target]
    command = [environment["CC"], "-E", *defaults, *shlex.split(environment["CPPFLAGS"]), str(source)]
    return subprocess.run(command, env=environment, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=30)


def require_omitted_target_failure(result):
    witnesses = (
        b"error: ROUTERVPN_WRONG_ARCHITECTURE",
        b"error: ROUTERVPN_WRONG_APPLE_PLATFORM",
        b"error: ROUTERVPN_WRONG_APPLE_VARIANT",
        b"error: ROUTERVPN_WRONG_DEPLOYMENT_TARGET",
        b"fatal error: 'stdio.h' file not found",
        b"fatal error: 'sys/queue.h' file not found",
        b"fatal error: 'TargetConditionals.h' file not found",
    )
    if result.returncode != 1 or not any(witness in result.stdout for witness in witnesses):
        diagnostics = result.stdout.decode("utf-8", "replace")
        error_lines = [line[:1000] for line in diagnostics.splitlines()
                       if "error:" in line or "warning:" in line][:20]
        raise RuntimeError("Missing Apple CPP target did not produce its intended target/header rejection; "
                           "exit=" + str(result.returncode) + "; diagnostics=" + repr(error_lines) +
                           "; output_tail=" + diagnostics[-3000:])


def native_checks(package):
    if platform.system() != "Darwin":
        raise ValueError("Actual Apple preprocessing requires the Xcode host")
    with tempfile.TemporaryDirectory(prefix="routervpn-apple-tor-cpp-") as directory:
        work = Path(directory)
        for target in targets(package):
            environment = capture_environment(package, target, work, native=True)
            source = work / (target["name"] + ".c")
            source.write_text(probe_text(target))
            result = preprocess(environment, source)
            if result.returncode or b"ROUTERVPN_ORIGINAL_APPLE_PREPROCESSOR" not in result.stdout:
                raise RuntimeError("Original Apple preprocessing failed " + target["name"] + ":\n" +
                                   result.stdout.decode("utf-8", "replace")[-5000:])
            # Xcode may infer the same iOS slice from SDKROOT and the host
            # architecture even after CPPFLAGS are removed. Use a paired,
            # explicit foreign default so omission must be causally observable.
            foreign = ("x86_64" if target["arch"] == "arm64" else "arm64") + "-apple-macos13.0"
            controlled = preprocess(environment, source, default_target=foreign)
            if controlled.returncode or b"ROUTERVPN_ORIGINAL_APPLE_PREPROCESSOR" not in controlled.stdout:
                raise RuntimeError("Original CPP target failed to override the captured compiler default " +
                                   target["name"] + ":\n" + controlled.stdout.decode("utf-8", "replace")[-5000:])
            broken = preprocess(without_cpp_target(environment), source, default_target=foreign)
            require_omitted_target_failure(broken)
            print("PASS original Apple Tor preprocessor: " + target["name"], flush=True)
            print("PASS original CPP target over foreign default: " + target["name"], flush=True)
            print("Rejected missing Apple CPP target under same foreign default: " + target["name"], flush=True)
    print("Apple Tor preprocessing: 3 actual Xcode slices, 3 paired default overrides and 3 rejected target omissions", flush=True)


def self_test(package):
    class Contracts(unittest.TestCase):
        def test_actual_shipping_target_environment(self):
            with tempfile.TemporaryDirectory() as directory:
                for target in targets(package):
                    with self.subTest(target=target["name"]):
                        env = capture_environment(package, target, Path(directory))
                        self.assertEqual(env["IPHONEOS_DEPLOYMENT_TARGET"], "17.0")
                        self.assertEqual(env["CC"], "/Selected Xcode/bin/clang")
                        self.assertIn("-DROUTERVPN_TOR_EMBEDDED=1", env["CPPFLAGS"])

        def test_original_missing_preprocessor_target_is_detected(self):
            original = package.compile_dependencies
            text = inspect.getsource(original)
            guard = "        env['CPPFLAGS'] += ' ' + flags\n"
            self.assertEqual(text.count(guard), 1)
            exec(compile(text.replace(guard, "", 1), "<original-cpp-omission>", "exec"), package.__dict__)
            try:
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaisesRegex(AssertionError, "missing from CPPFLAGS"):
                        capture_environment(package, targets(package)[0], Path(directory))
            finally:
                package.compile_dependencies = original

        def test_parent_compiler_and_sdk_cannot_replace_original_target(self):
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,
                    {"CPP": "/foreign/cpp", "CPPFLAGS": "-isysroot /foreign", "SDKROOT": "/foreign",
                     "CFLAGS": "-target foreign", "CGO_CFLAGS": "foreign"}):
                env = capture_environment(package, targets(package)[0], Path(directory))
                self.assertNotIn("CPP", env)
                self.assertNotIn("CGO_CFLAGS", env)
                self.assertNotIn("foreign", env["CPPFLAGS"])
                self.assertNotIn("foreign", env["CFLAGS"])

        def test_omission_control_keeps_compiler_linker_and_embedded_policy(self):
            with tempfile.TemporaryDirectory() as directory:
                env = capture_environment(package, targets(package)[0], Path(directory))
                broken = without_cpp_target(env)
                self.assertEqual({k:v for k,v in broken.items() if k!="CPPFLAGS"},
                                 {k:v for k,v in env.items() if k!="CPPFLAGS"})
                self.assertNotIn("-target", shlex.split(broken["CPPFLAGS"]))
                self.assertIn("-DROUTERVPN_TOR_EMBEDDED=1", broken["CPPFLAGS"])

        def test_paired_native_control_changes_only_original_cpp_flags(self):
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "original.c"
                for target in targets(package):
                    environment = capture_environment(package, target, Path(directory))
                    foreign = ("x86_64" if target["arch"] == "arm64" else "arm64") + "-apple-macos13.0"
                    with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"ok")) as run:
                        preprocess(environment, source)
                        ordinary = run.call_args
                        preprocess(environment, source, foreign)
                        intact = run.call_args
                        preprocess(without_cpp_target(environment), source, foreign)
                        omitted = run.call_args
                    self.assertEqual(ordinary.args[0], [environment["CC"], "-E", *shlex.split(environment["CPPFLAGS"]), str(source)])
                    self.assertEqual(intact.args[0][:4], [environment["CC"], "-E", "-target", foreign])
                    self.assertEqual(omitted.args[0][:4], intact.args[0][:4])
                    self.assertEqual(intact.args[0][4:], ordinary.args[0][2:])
                    self.assertEqual(omitted.args[0][4:], [*shlex.split(without_cpp_target(environment)["CPPFLAGS"]), str(source)])
                    self.assertEqual({k:v for k,v in intact.kwargs["env"].items() if k != "CPPFLAGS"},
                                     {k:v for k,v in omitted.kwargs["env"].items() if k != "CPPFLAGS"})
                    self.assertEqual(intact.kwargs["timeout"], 30)
                    self.assertEqual(omitted.kwargs["timeout"], 30)
                with patch.object(subprocess, "run") as run, self.assertRaises(ValueError):
                    preprocess(environment, source, "foreign arbitrary target")
                run.assert_not_called()

        def test_native_control_requires_expected_failure_not_a_crash(self):
            witness = b"error: ROUTERVPN_WRONG_APPLE_VARIANT"
            require_omitted_target_failure(subprocess.CompletedProcess([], 1, witness))
            require_omitted_target_failure(subprocess.CompletedProcess([], 1, b"fatal error: 'stdio.h' file not found"))
            for status, output in ((0, witness), (-11, witness), (139, witness), (124, witness),
                                   (1, b"clang: unexpected unrelated compiler failure")):
                with self.subTest(status=status), self.assertRaises(RuntimeError):
                    require_omitted_target_failure(subprocess.CompletedProcess([], status, output))
            with self.assertRaisesRegex(RuntimeError, "exit=1; diagnostics=.*unrelated compiler failure"):
                require_omitted_target_failure(subprocess.CompletedProcess(
                    [], 1, b"error: unrelated compiler failure\n" + b"large header output\n" * 500))

        def test_native_probe_requires_each_architecture_variant_and_sdk(self):
            for target in targets(package):
                text = probe_text(target)
                for witness in ("WRONG_ARCHITECTURE", "WRONG_APPLE_PLATFORM", "WRONG_APPLE_VARIANT",
                                "WRONG_DEPLOYMENT_TARGET", "MISSING_SYSTEM_QUEUE_HEADER"):
                    self.assertIn(witness, text)
            self.assertNotEqual(probe_text(targets(package)[0]), probe_text(targets(package)[1]))
            self.assertNotEqual(probe_text(targets(package)[1]), probe_text(targets(package)[2]))
    return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contracts)).wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--native", action="store_true")
    args = parser.parse_args()
    package = load_package(args.source)
    if not self_test(package):
        return 1
    if args.native:
        native_checks(package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
