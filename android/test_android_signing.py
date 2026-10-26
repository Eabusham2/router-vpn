#!/usr/bin/env python3
"""Execute shipping key/version policy; optionally build and inspect real APKs."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/buildSrc/src/main/java/com/eabusham/routervpn/build/AndroidBuildPolicy.java'


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'android' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


VERIFY, BUILD = module('verify-delivery'), module('build-delivery')
GRADLE, SDK = None, None
HARNESS = r'''
import com.eabusham.routervpn.build.AndroidBuildPolicy;
import java.io.File;
public final class PolicyHarness {
 public static void main(String[] args) {
  try {
   var p=AndroidBuildPolicy.resolve(new File(args[0]),System.getenv());
   System.out.println(p.sourceSha+"|"+p.versionCode+"|"+p.versionName+"|"+p.production+"|"+p.certificateSHA256);
  } catch(IllegalArgumentException invalid) { System.err.println(invalid.getMessage());System.exit(2); }
 }
}
'''


def run(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True, check=True, **kwargs)


class SigningPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='routervpn-android-signing-tests-')
        cls.work = Path(cls.temporary.name)
        cls.environment = {key: value for key, value in os.environ.items()
                           if not key.startswith('ROUTERVPN_ANDROID_') and key not in ('GITHUB_SHA', 'ROUTER_VPN_SOURCE_SHA')}
        cls.classes = cls.work / 'classes'
        cls.classes.mkdir()
        harness = cls.work / 'PolicyHarness.java'
        harness.write_text(HARNESS)
        run(['javac', '--release', '17', '-d', str(cls.classes), str(JAVA), str(harness)])
        cls.store = cls.work / 'disposable.p12'
        cls.secret = 'disposable-fixture-password-ONLY'
        # This key lives only in the temporary fixture and is never uploaded or
        # accepted as production release evidence.
        run(['keytool', '-genkeypair', '-alias', 'fixture', '-keyalg', 'RSA', '-keysize', '2048',
             '-validity', '2', '-dname', 'CN=Disposable Router VPN signing fixture', '-storetype', 'PKCS12',
             '-keystore', str(cls.store), '-storepass:env', 'FIXTURE_PASSWORD', '-keypass:env', 'FIXTURE_PASSWORD',
             '-noprompt'], env=dict(cls.environment, FIXTURE_PASSWORD=cls.secret))
        certificate = subprocess.check_output(['keytool', '-exportcert', '-alias', 'fixture', '-keystore', str(cls.store),
                                              '-storepass:env', 'FIXTURE_PASSWORD'], env=dict(cls.environment, FIXTURE_PASSWORD=cls.secret))
        cls.fingerprint = hashlib.sha256(certificate).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(dir=self.work)
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name) / 'source'
        self.repo.mkdir()
        run(['git', 'init', '-q', str(self.repo)])
        run(['git', '-C', str(self.repo), 'config', 'user.email', 'fixture@example.invalid'])
        run(['git', '-C', str(self.repo), 'config', 'user.name', 'Disposable fixture'])
        (self.repo / 'source.txt').write_text('first source\n')
        run(['git', '-C', str(self.repo), 'add', 'source.txt'])
        run(['git', '-C', str(self.repo), 'commit', '-qm', 'first'])
        self.sha = run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD']).stdout.strip()
        self.env = dict(self.environment, GITHUB_SHA=self.sha)

    def signed(self):
        return dict(self.env, ROUTERVPN_ANDROID_KEYSTORE=str(self.store),
                    ROUTERVPN_ANDROID_STORE_PASSWORD=self.secret, ROUTERVPN_ANDROID_KEY_ALIAS='fixture',
                    ROUTERVPN_ANDROID_KEY_PASSWORD=self.secret, ROUTERVPN_ANDROID_CERT_SHA256=self.fingerprint,
                    ROUTERVPN_ANDROID_REQUIRE_PRODUCTION='true')

    def policy(self, environment=None, source=None, accepted=True):
        result = subprocess.run(['java', '-cp', str(self.classes), 'PolicyHarness', str(source or self.repo)],
                                env=environment or self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0 if accepted else 2, result.stdout + result.stderr)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        if accepted:
            return result.stdout.strip().split('|')
        self.assertIn('Android build policy:', result.stderr)
        return result.stderr

    def test_real_private_key_and_explicit_certificate_pin(self):
        result = self.policy(self.signed())
        self.assertEqual(result, [self.sha, '2', '0.1.2-' + self.sha[:12], 'true', self.fingerprint])
        normalized = self.signed()
        normalized['ROUTERVPN_ANDROID_CERT_SHA256'] = ':'.join(self.fingerprint[i:i + 2].upper() for i in range(0, 64, 2))
        self.assertEqual(self.policy(normalized), result)
        for name, value in [('STORE_PASSWORD', 'wrong'), ('KEY_PASSWORD', 'wrong'), ('KEY_ALIAS', 'missing'),
                            ('CERT_SHA256', 'f' * 64), ('KEYSTORE', str(self.work / 'missing.p12'))]:
            with self.subTest(name=name):
                env = self.signed(); env['ROUTERVPN_ANDROID_' + name] = value
                self.policy(env, accepted=False)

    def test_absent_partial_and_required_configuration(self):
        self.assertEqual(self.policy()[3], 'false')
        for name in ['KEYSTORE', 'STORE_PASSWORD', 'KEY_PASSWORD', 'KEY_ALIAS', 'CERT_SHA256']:
            env = self.signed(); env.pop('ROUTERVPN_ANDROID_' + name)
            self.policy(env, accepted=False)
        self.policy(dict(self.env, ROUTERVPN_ANDROID_REQUIRE_PRODUCTION='true'), accepted=False)
        self.policy(dict(self.env, ROUTERVPN_ANDROID_REQUIRE_PRODUCTION='yes'), accepted=False)
        self.policy(dict(self.env, ROUTERVPN_ANDROID_KEYSTORE_BASE64='a2V5'), accepted=False)

    def test_versions_are_stable_and_increase_for_actual_descendants(self):
        self.assertEqual(self.policy(), self.policy())
        previous = self.policy()[1]
        for index in range(3):
            (self.repo / 'source.txt').write_text('next source ' + str(index))
            run(['git', '-C', str(self.repo), 'commit', '-qam', 'next'])
            self.env['GITHUB_SHA'] = run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD']).stdout.strip()
            current = self.policy()[1]
            self.assertGreater(int(current), int(previous)); previous = current
        wrong = dict(self.env, ROUTERVPN_ANDROID_VERSION_SHA=self.env['GITHUB_SHA'], ROUTERVPN_ANDROID_VERSION_CODE='2')
        self.policy(wrong, accepted=False)
        self.policy(dict(self.env, GITHUB_SHA=self.sha), accepted=False)
        (self.repo / 'source.txt').write_text('uncommitted source')
        self.policy(accepted=False)

    def test_shallow_and_archive_versions_fail_closed(self):
        shallow = Path(self.scratch.name) / 'shallow'
        run(['git', 'clone', '-q', '--depth', '1', self.repo.as_uri(), str(shallow)])
        self.policy(source=shallow, accepted=False)
        archive = Path(self.scratch.name) / 'archive'; archive.mkdir()
        self.policy(source=archive, accepted=False)
        for code in ['', '1', '0', '-1', '2.0', '2100000001', '999999999999999999999999']:
            self.policy(dict(self.env, ROUTERVPN_ANDROID_VERSION_SHA=self.sha, ROUTERVPN_ANDROID_VERSION_CODE=code), source=archive, accepted=False)
        captured = dict(self.env, ROUTERVPN_ANDROID_VERSION_SHA=self.sha, ROUTERVPN_ANDROID_VERSION_CODE='2')
        self.assertEqual(self.policy(captured, source=archive), self.policy())
        self.policy(dict(captured, ROUTERVPN_ANDROID_VERSION_SHA='f' * 40), source=archive, accepted=False)

    def test_archive_manifest_and_owned_key_cleanup(self):
        manifest = Path(self.scratch.name) / 'snapshot.json'
        data = dict(schema_version=1, repository='Eabusham2/router-vpn', artifact_family='exact-source-snapshot', source_sha=self.sha, android_version_code=2)
        manifest.write_text(json.dumps(data))
        env = dict(self.env); BUILD.archive_version(env, manifest, self.sha)
        self.assertEqual(env['ROUTERVPN_ANDROID_VERSION_CODE'], '2')
        with self.assertRaises(ValueError): BUILD.archive_version(dict(self.env), manifest, 'f' * 40)
        unrelated_runner = dict(self.env, GITHUB_SHA='f' * 40)
        BUILD.archive_version(unrelated_runner, manifest, self.sha)
        self.assertEqual(unrelated_runner['GITHUB_SHA'], self.sha)
        self.assertEqual(unrelated_runner['ROUTER_VPN_SOURCE_SHA'], self.sha)
        for change in [dict(source_sha='f' * 40), dict(android_version_code=True), dict(android_version_code=1), dict(android_version_code=None)]:
            manifest.write_text(json.dumps(dict(data, **change)))
            with self.assertRaises(ValueError): BUILD.archive_version(dict(self.env), manifest, self.sha)
        runner = Path(self.scratch.name) / 'runner'; runner.mkdir()
        fake_gradle = Path(self.scratch.name) / 'gradle'
        fake_gradle.write_text('#!/usr/bin/env python3\nimport os,pathlib,sys\np=pathlib.Path(os.environ["ROUTERVPN_ANDROID_KEYSTORE"])\nassert p.is_file() and p.stat().st_mode & 0o777 == 0o600\nassert "ROUTERVPN_ANDROID_KEYSTORE_BASE64" not in os.environ\nsys.exit(7)\n')
        fake_gradle.chmod(0o700)
        self.assertEqual(BUILD.build(self.repo, str(fake_gradle), dict(self.env, RUNNER_TEMP=str(runner), ROUTERVPN_ANDROID_KEYSTORE_BASE64=base64.b64encode(self.store.read_bytes()).decode())), 7)
        self.assertEqual(list(runner.iterdir()), [])

    def test_actual_package_receipt_rejects_mismatched_bytes_and_config(self):
        metadata = dict(schema_version=1, source_sha=self.sha, application_id='com.eabusham.routervpn',
                        version_code=2, version_name='0.1.2-' + self.sha[:12], variant='release',
                        signing='production-signed', certificate_sha256=self.fingerprint)
        badging = f"package: name='com.eabusham.routervpn' versionCode='2' versionName='{metadata['version_name']}'\n"
        signer = 'Signer #1 certificate SHA-256 digest: ' + self.fingerprint + '\n'
        result = VERIFY.verified_receipt(metadata, badging, signer, True, 'release', 2, self.fingerprint, False)
        self.assertEqual(result['signing'], 'production-signed')
        for kwargs in [dict(signature_ok=False), dict(signing_output=signer + signer), dict(certificate='f' * 64),
                       dict(code=3), dict(variant='debug'), dict(badging=badging + 'application-debuggable\n'),
                       dict(badging=badging.replace("versionCode='2'", "versionCode='1'"))]:
            arguments = dict(metadata=metadata, badging=badging, signing_output=signer, signature_ok=True,
                             variant='release', code=2, certificate=self.fingerprint, allow_unsigned=False)
            arguments.update(kwargs)
            with self.assertRaises(ValueError): VERIFY.verified_receipt(**arguments)

    def test_apk_capture_and_publication_reject_replacement(self):
        spec = importlib.util.spec_from_file_location('android_receipt_fixture', ROOT / 'deploy/android_delivery_test_fixture.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        apk = Path(self.scratch.name) / 'app-debug.apk'
        fixture.write_android_fixture(apk, self.sha)
        original = apk.read_bytes()
        sdk = Path(self.scratch.name) / 'sdk'; tools = sdk / 'build-tools/36.0.0'; tools.mkdir(parents=True)
        for name in ('aapt', 'apksigner'): (tools / name).write_text('boundary marker')
        def inspect(command, **kwargs):
            captured = Path(command[-1])
            self.assertNotEqual(captured, apk)
            self.assertEqual(captured.read_bytes(), original)
            if command[0].endswith('/aapt'):
                apk.write_bytes(b'replacement after capture')
                output = f"package: name='com.eabusham.routervpn' versionCode='42' versionName='0.1.42-{self.sha[:12]}'\napplication-debuggable\n"
            else:
                output = 'Signer #1 certificate SHA-256 digest: ' + 'c' * 64 + '\n'
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr='')
        # Tool responses are boundary doubles here. The separately required
        # Gradle fixture performs real APK signing/apksigner verification.
        with patch.object(VERIFY.subprocess, 'run', side_effect=inspect):
            receipt = VERIFY.verify(apk, sdk, self.sha, 'debug', 42)
        self.assertEqual(receipt['apk_sha256'], hashlib.sha256(original).hexdigest())
        with self.assertRaisesRegex(ValueError, 'changed after signature'):
            VERIFY.stage(apk, Path(self.scratch.name) / 'output', receipt)
        apk.write_bytes(original)
        VERIFY.stage(apk, Path(self.scratch.name) / 'output', receipt)
        delivered = Path(self.scratch.name) / 'output/app-debug.apk'
        self.assertEqual(delivered.read_bytes(), original)
        self.assertEqual(VERIFY.load_receipt(delivered, self.sha), receipt)
        delivered.write_bytes(b'changed after adoption')
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            VERIFY.load_receipt(delivered, self.sha)
        link = Path(self.scratch.name) / 'redirected.apk'; link.symlink_to(apk)
        with self.assertRaisesRegex(RuntimeError, 'redirected'):
            VERIFY.verify(link, sdk, self.sha, 'debug', 42)

    @unittest.skipUnless(GRADLE and SDK, 'real APK fixture requires explicit Gradle and Android SDK')
    def test_real_gradle_signed_debug_unsigned_apks(self):
        android = self.repo / 'android'; android.mkdir()
        shutil.copytree(ROOT / 'android/buildSrc', android / 'buildSrc', ignore=shutil.ignore_patterns('build', '.gradle'))
        shutil.copy2(ROOT / 'android/release-build.gradle', android / 'release-build.gradle')
        shutil.copy2(ROOT / 'android/settings.gradle', android / 'settings.gradle')
        shutil.copy2(ROOT / 'android/build.gradle', android / 'build.gradle')
        app = android / 'app'; app.mkdir()
        main = app / 'src/main'; main.mkdir(parents=True)
        (main / 'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:label="Disposable signing fixture"/></manifest>')
        assets = main / 'assets'; assets.mkdir(); shutil.copy2(ROOT / 'LICENSE', assets / 'LICENSE')
        shipping = (ROOT / 'android/app/build.gradle').read_text()
        stage = shipping[shipping.index('def generatedDeliveryAssets ='):shipping.index('def awgAar =')]
        (app / 'build.gradle').write_text("""plugins { id 'com.android.application' }
android { namespace 'com.eabusham.routervpn'; compileSdk 36
 defaultConfig { applicationId 'com.eabusham.routervpn'; minSdk 24; targetSdk 36 }
}
apply from: rootProject.file('release-build.gradle')
""" + stage + """
def generatedSource = file("$buildDir/generated/fixture-source")
android.sourceSets.main.assets.srcDir generatedSource
tasks.register('stageFixtureSource') {
 doLast {
  generatedSource.mkdirs()
  new File(generatedSource, 'ROUTER-VPN-SOURCE.json').text = groovy.json.JsonOutput.toJson([
   schema_version:1, repository:'Eabusham2/router-vpn', artifact_family:'android-apk', source_sha:routerVpnAndroidPolicy.sourceSha])
 }
}
tasks.named('preBuild').configure { dependsOn 'stageFixtureSource' }
""")
        env = dict(self.signed(), ANDROID_HOME=str(SDK), ANDROID_SDK_ROOT=str(SDK))
        result = subprocess.run([GRADLE, '-p', str(android), '--no-daemon', '--max-workers=2', ':app:assembleRelease', ':app:assembleDebug'],
                                env=env, text=True, capture_output=True, timeout=480)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = app / 'build/outputs/apk/release/app-release.apk'
        debug = app / 'build/outputs/apk/debug/app-debug.apk'
        receipt = VERIFY.verify(release, SDK, self.sha, 'release', 2, self.fingerprint)
        self.assertEqual(receipt['signing'], 'production-signed')
        with self.assertRaises(ValueError): VERIFY.verify(release, SDK, self.sha, 'release', 2, 'f' * 64)
        self.assertEqual(VERIFY.verify(debug, SDK, self.sha, 'debug', 2)['signing'], 'debug-signed')
        damaged = Path(self.scratch.name) / 'tampered.apk'; shutil.copy2(release, damaged)
        with zipfile.ZipFile(damaged, 'a') as archive: archive.writestr('assets/foreign.txt', 'changed after signing')
        with self.assertRaises(ValueError): VERIFY.verify(damaged, SDK, self.sha, 'release', 2, self.fingerprint)
        result = subprocess.run([GRADLE, '-p', str(android), '--no-daemon', '--max-workers=2', ':app:assembleRelease'],
                                env=dict(self.env, ANDROID_HOME=str(SDK), ANDROID_SDK_ROOT=str(SDK)), text=True, capture_output=True, timeout=480)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        unsigned = app / 'build/outputs/apk/release/app-release-unsigned.apk'
        receipt = VERIFY.verify(unsigned, SDK, self.sha, 'release', 2, allow_unsigned=True)
        self.assertEqual(receipt['signing'], 'unsigned')
        with self.assertRaises(ValueError): VERIFY.stage(unsigned, Path(self.scratch.name) / 'delivery', receipt)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--gradle')
    parser.add_argument('--sdk', type=Path)
    args, remaining = parser.parse_known_args()
    GRADLE, SDK = args.gradle, args.sdk
    # unittest decorators are evaluated before CLI parsing.
    test = SigningPolicy.test_real_gradle_signed_debug_unsigned_apks
    test.__unittest_skip__ = not (GRADLE and SDK)
    unittest.main(argv=[__file__] + remaining)
