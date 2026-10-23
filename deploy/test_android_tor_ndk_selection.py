#!/usr/bin/env python3
"""Execute the shipping Gradle Tor finalizer with conflicting NDK environments.

This is a required dependency of prepareSingBoxLibbox. Its isolated plain Gradle
project uses the actual registered task/finalizer without loading Android or
building native code. Only native payload inspection is doubled; the shipping
Python CLI and ndk_tools revision/compiler validation execute unchanged.
"""
from pathlib import Path
import argparse
import json
import os
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / 'mobile/torpack/sources.json').read_text())['android_ndk']
GRADLE = None

# Exact task from 94ecb55d04470e86ea3f75e32d479d56ad0b92c3, whose APK
# assembled successfully but whose finalizer inherited the runner's wrong NDK.
ORIGINAL_TASK = '''tasks.register('verifyDebugNativeTor', Exec) {
    dependsOn 'packageDebug'
    workingDir rootProject.projectDir
    commandLine 'python3', '../deploy/verify-mobile-tor-link.py', '--native-package',
        nativeTorPackage.absolutePath, '--android-apk', file("$buildDir/outputs/apk/debug/app-debug.apk").absolutePath
}
'''


def task_block(source, marker):
    """Keep the registered shipping block verbatim, including nested actions."""
    if source.count(marker) != 1:
        raise ValueError('Expected one shipping Gradle task: ' + marker)
    start = source.index(marker)
    end = source.index('\n}\n', start) + 3
    return source[start:end]


def verifier_boundary():
    # Execute the actual argparse/dispatch block with only android() replaced.
    # The callback still invokes real ndk_tools, so omitting --ndk or accepting
    # a stale revision/compiler cannot become a passing fixture.
    return '''from pathlib import Path
import ast, importlib.util, json, os
source = Path(%r)
spec = importlib.util.spec_from_file_location('tor_link_boundary', source)
link = importlib.util.module_from_spec(spec)
spec.loader.exec_module(link)
def inspect_payload(native_package, archive, apk, ndk=None):
    selected, tools = link.PACKAGE.ndk_tools(ndk)
    Path(os.environ['ROUTERVPN_NDK_CALL']).write_text(json.dumps(dict(
        explicit=str(ndk) if ndk else None, selected=str(selected),
        tools=str(tools), native_package=str(native_package),
        archive=str(archive), apk=apk)))
link.android = inspect_payload
tree = ast.parse(source.read_text())
entry = [node for node in tree.body if isinstance(node, ast.If)
         and ast.unparse(node.test) == "__name__ == '__main__'"]
if len(entry) != 1:
    raise ValueError('Shipping Tor verifier CLI entry changed')
exec(compile(ast.Module(body=entry[0].body, type_ignores=[]), str(source), 'exec'), link.__dict__)
''' % str(ROOT / 'deploy/verify-mobile-tor-link.py')


class GradleNdkSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='routervpn-gradle-ndk-')
        cls.root = Path(cls.temporary.name).resolve()
        # Never acquire locks or change caches belonging to an outer APK build.
        cls.gradle_home = cls.root / 'isolated-gradle-user-home'

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def make_ndk(self, root, revision=PIN):
        root.mkdir(parents=True)
        (root / 'source.properties').write_text('Pkg.Revision = ' + revision + '\n')
        host = 'darwin-x86_64' if platform.system() == 'Darwin' else 'linux-x86_64'
        compiler = root / 'toolchains/llvm/prebuilt' / host / 'bin/clang'
        compiler.parent.mkdir(parents=True)
        compiler.write_text('Fixture compiler presence; no native code is built.\n')
        return compiler

    def run_gradle(self, mutation=None, fallback=False, original=False):
        case = Path(tempfile.mkdtemp(prefix='case with spaces-', dir=self.root))
        project = case / 'android'
        app = project / 'app'
        app.mkdir(parents=True)
        (project / 'settings.gradle').write_text("rootProject.name = 'ndk-boundary'\ninclude ':app'\n")
        (project / 'gradle.properties').write_text(
            'org.gradle.daemon=false\norg.gradle.parallel=false\n'
            'org.gradle.jvmargs=-Xmx256m -XX:MaxMetaspaceSize=256m\n')
        lock = case / 'mobile/torpack/sources.json'
        lock.parent.mkdir(parents=True)
        lock.write_bytes((ROOT / 'mobile/torpack/sources.json').read_bytes())
        boundary = case / 'deploy/verify-mobile-tor-link.py'
        boundary.parent.mkdir()
        boundary.write_text(verifier_boundary())

        source = (ROOT / 'android/app/build.gradle').read_text()
        task = ORIGINAL_TASK if original else task_block(source, "tasks.register('verifyDebugNativeTor', Exec) {")
        finalizer = task_block(source[source.index(task_block(source, "tasks.register('verifyDebugNativeTor', Exec) {")):],
                               "tasks.matching { it.name == 'assembleDebug' }.configureEach {")
        (app / 'build.gradle').write_text(
            "def nativeTorPackage = file('libs/tor-native')\n"
            "tasks.register('packageDebug')\n"
            "tasks.register('assembleDebug') { dependsOn 'packageDebug' }\n" + task + '\n' + finalizer)

        sdk = case / 'selected sdk with spaces'
        pinned = sdk / 'ndk' / PIN
        compiler = self.make_ndk(pinned)
        foreign_sdk = case / 'other sdk'
        self.make_ndk(foreign_sdk / 'ndk' / PIN, '27.2.12479018')
        foreign_home = case / 'foreign ambient ndk'
        foreign_root = case / 'other ambient ndk'
        self.make_ndk(foreign_home, '27.2.12479018')
        self.make_ndk(foreign_root, '29.0.13113456')
        if mutation == 'missing-properties':
            (pinned / 'source.properties').unlink()
        elif mutation == 'wrong-revision':
            (pinned / 'source.properties').write_text('Pkg.Revision = 27.2.12479018\n')
        elif mutation == 'missing-compiler':
            compiler.unlink()

        record = case / 'verifier.json'
        env = dict(os.environ)
        for key in ('GRADLE_OPTS', 'JAVA_OPTS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS',
                    'GRADLE_RO_DEP_CACHE'):
            env.pop(key, None)
        env.update(GRADLE_USER_HOME=str(self.gradle_home), ANDROID_HOME='' if fallback else str(sdk),
                   ANDROID_SDK_ROOT=str(sdk if fallback else foreign_sdk),
                   ANDROID_NDK_HOME=str(foreign_home), ANDROID_NDK_ROOT=str(foreign_root),
                   ROUTERVPN_NDK_CALL=str(record))
        if mutation == 'missing-sdk':
            env.update(ANDROID_HOME='', ANDROID_SDK_ROOT='')
        result = subprocess.run([str(GRADLE), '--offline', '--no-daemon', '--no-watch-fs',
                                 '--console=plain', '--max-workers=1', ':app:assembleDebug'],
                                cwd=project, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding='utf-8', timeout=90)
        captured = json.loads(record.read_text()) if record.is_file() else None
        return result, captured, pinned, app

    def assert_selection(self, fallback):
        result, record, pinned, app = self.run_gradle(fallback=fallback)
        self.assertEqual(result.returncode, 0, result.stdout[-8000:])
        self.assertIn(':app:verifyDebugNativeTor', result.stdout)
        self.assertIsNotNone(record, 'assembleDebug did not execute its shipping finalizer')
        self.assertEqual(record['explicit'], str(pinned))
        self.assertEqual(record['selected'], str(pinned.resolve()))
        self.assertEqual(record['native_package'], str(app / 'libs/tor-native'))
        self.assertEqual(record['archive'], str(app / 'build/outputs/apk/debug/app-debug.apk'))
        self.assertIs(record['apk'], True)

    def test_android_home_wins_conflicting_sdk_and_ndk_defaults(self):
        self.assert_selection(False)

    def test_android_sdk_root_fallback_preserves_paths_with_spaces(self):
        self.assert_selection(True)

    def assert_rejected(self, mutation, message):
        result, record, _, _ = self.run_gradle(mutation=mutation)
        self.assertNotEqual(result.returncode, 0, 'Invalid pinned NDK was accepted')
        self.assertIsNone(record)
        self.assertIn(message, result.stdout[-12000:])

    def test_missing_sdk_cannot_use_ambient_ndk(self):
        self.assert_rejected('missing-sdk', 'Android SDK is missing from ANDROID_HOME/ANDROID_SDK_ROOT')

    def test_missing_pinned_revision_cannot_use_ambient_ndk(self):
        self.assert_rejected('missing-properties', 'source.properties')

    def test_mismatched_pinned_revision_still_fails(self):
        self.assert_rejected('wrong-revision', 'Native Tor Android NDK revision differs from the pinned mobile runtime')

    def test_missing_pinned_compiler_still_fails(self):
        self.assert_rejected('missing-compiler', 'Pinned Android NDK compiler is missing')

    def test_exact_original_task_reproduces_the_ci_failure(self):
        result, record, _, _ = self.run_gradle(original=True)
        self.assertNotEqual(result.returncode, 0, 'Original ambient NDK regression was not reproduced')
        self.assertIsNone(record)
        self.assertIn('Native Tor Android NDK revision differs from the pinned mobile runtime', result.stdout[-12000:])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gradle', default=shutil.which('gradle'))
    arguments = parser.parse_args()
    if not arguments.gradle or not Path(arguments.gradle).is_file():
        parser.error('A real Gradle executable is required; this boundary must not be skipped')
    GRADLE = Path(arguments.gradle).resolve()
    unittest.main(argv=[__file__], verbosity=2)
