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

    def delivery_task(self, variant, fallback=False, failure=None):
        """Execute the exact shipping Exec task, CLI and owned staging path.

        Only Android assembly/native verification and SDK inspection are test
        boundaries here; real APK signing retains its separate required test.
        The real Java policy selects the variant and checks the disposable key.
        """
        case = Path(tempfile.mkdtemp(prefix='delivery with spaces-', dir=self.scratch.name))
        project, app = case / 'android', case / 'android/app'
        app.mkdir(parents=True)
        (project / 'settings.gradle').write_text("rootProject.name = 'delivery-boundary'\ninclude ':app'\n")
        (project / 'gradle.properties').write_text(
            'org.gradle.daemon=false\norg.gradle.parallel=false\n'
            'org.gradle.jvmargs=-Xmx256m -XX:MaxMetaspaceSize=256m\n')
        shipping = (ROOT / 'android/app/build.gradle').read_text()
        marker = 'def deliveryVariant = routerVpnAndroidPolicy.deliveryVariant()'
        self.assertEqual(shipping.count(marker), 1)
        start = shipping.index(marker)
        task = shipping[start:shipping.index('\n}\n', start) + 3]
        if failure == 'original-interpolation':
            fixed = '$buildDir/outputs/apk/${deliveryVariant}/app-${deliveryVariant}.apk'
            self.assertEqual(task.count(fixed), 1)
            task = task.replace(fixed, '$buildDir/outputs/apk/$deliveryVariant/app-$deliveryVariant.apk')
        (app / 'build.gradle').write_text('''buildscript {
 dependencies { classpath files(System.getenv('ROUTERVPN_POLICY_CLASSES')) }
}
import com.eabusham.routervpn.build.AndroidBuildPolicy
def routerVpnAndroidPolicy = AndroidBuildPolicy.resolve(new File(System.getenv('ROUTERVPN_POLICY_SOURCE')), System.getenv())
// Boundary tasks only: the separate real APK fixture owns assembly/signatures.
['assembleDebug','assembleRelease','verifyDebugProjectLicense','verifyReleasePackage','verifyDebugNativeTor','verifyReleaseNativeTor'].each { name ->
 tasks.register(name) { doLast { new File(System.getenv('ROUTERVPN_DELIVERY_DEPENDENCIES')).append(name + '\\n') } }
}
''' + task)
        (project / 'verify-delivery.py').write_text(
            'import runpy\nrunpy.run_path(' + repr(str(ROOT / 'android/verify-delivery.py')) + ",run_name='__main__')\n")
        sdk = case / 'selected sdk with spaces'
        tools = sdk / 'build-tools/36.0.0'; tools.mkdir(parents=True)
        tool_boundary = '''#!/usr/bin/env python3
import hashlib,json,os,pathlib,sys,zipfile
name=pathlib.Path(__file__).name
assert sys.argv[1:-1] == (['dump','badging'] if name=='aapt' else ['verify','--verbose','--print-certs'])
apk=pathlib.Path(sys.argv[-1]);assert apk.name=='captured.apk'
with zipfile.ZipFile(apk) as archive: metadata=json.loads(archive.read('assets/ROUTER-VPN-ANDROID.json'))
with open(os.environ['ROUTERVPN_DELIVERY_TOOLS'],'a') as output: output.write(json.dumps(dict(tool=name,sha256=hashlib.sha256(apk.read_bytes()).hexdigest()))+'\\n')
if name=='aapt':
 print("package: name='com.eabusham.routervpn' versionCode='%s' versionName='%s'" % (metadata['version_code'],metadata['version_name']))
 if metadata['variant']=='debug': print('application-debuggable')
else: print('Signer #1 certificate SHA-256 digest: '+os.environ['ROUTERVPN_FIXTURE_CERTIFICATE'])
'''
        for name in ('aapt', 'apksigner'):
            tool = tools / name; tool.write_text(tool_boundary); tool.chmod(0o700)
        apk = app / 'build/outputs/apk' / variant / ('app-' + variant + '.apk')
        apk.parent.mkdir(parents=True)
        metadata = dict(schema_version=1, source_sha=self.sha, application_id='com.eabusham.routervpn',
                        version_code=2, version_name='0.1.2-' + self.sha[:12], variant=variant,
                        signing='production-signed' if variant == 'release' else 'debug-signed',
                        certificate_sha256=self.fingerprint if variant == 'release' else '')
        with zipfile.ZipFile(apk, 'w') as archive:
            archive.writestr('classes.dex', b'Disposable delivery routing fixture, not a signed APK')
            archive.writestr('assets/LICENSE', (ROOT / 'LICENSE').read_bytes())
            archive.writestr('assets/ROUTER-VPN-SOURCE.json', json.dumps(dict(schema_version=1,
                             repository='Eabusham2/router-vpn', artifact_family='android-apk', source_sha=self.sha)))
            archive.writestr('assets/ROUTER-VPN-ANDROID.json', json.dumps(metadata))
        dependencies, tool_calls = case / 'dependencies.txt', case / 'tools.jsonl'
        env = dict(self.signed() if variant == 'release' else self.env)
        for key in ('GRADLE_OPTS', 'JAVA_OPTS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'GRADLE_RO_DEP_CACHE'):
            env.pop(key, None)
        env.update(GRADLE_USER_HOME=str(self.work / 'delivery-gradle-home'),
                   ROUTERVPN_POLICY_CLASSES=str(self.classes), ROUTERVPN_POLICY_SOURCE=str(self.repo),
                   ROUTERVPN_DELIVERY_DEPENDENCIES=str(dependencies), ROUTERVPN_DELIVERY_TOOLS=str(tool_calls),
                   ROUTERVPN_FIXTURE_CERTIFICATE=self.fingerprint,
                   ANDROID_HOME='' if fallback else str(sdk),
                   ANDROID_SDK_ROOT=str(sdk if fallback else case / 'wrong ambient sdk'))
        if failure == 'missing-sdk':
            env.update(ANDROID_HOME='', ANDROID_SDK_ROOT='')
        result = subprocess.run([GRADLE, '--offline', '--no-daemon', '--no-watch-fs', '--console=plain',
                                 '--max-workers=1', ':app:assembleDelivery'], cwd=project, env=env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        self.assertNotIn(self.secret, result.stdout)
        expected = {'assemble' + variant.capitalize(), 'verifyReleasePackage' if variant == 'release' else 'verifyDebugProjectLicense',
                    'verify' + variant.capitalize() + 'NativeTor'}
        self.assertTrue(dependencies.is_file(), result.stdout[-8000:])
        self.assertEqual(set(dependencies.read_text().splitlines()), expected)
        output = app / 'build/outputs/routervpn/app-debug.apk'
        if failure:
            self.assertNotEqual(result.returncode, 0, result.stdout[-8000:])
            self.assertFalse(tool_calls.exists(), 'failed delivery reached APK inspection')
            self.assertFalse(output.exists(), 'failed delivery published a package')
            self.assertIn('No such property: apk' if failure == 'original-interpolation' else 'Android SDK is required', result.stdout)
        else:
            self.assertEqual(result.returncode, 0, result.stdout[-8000:])
            self.assertEqual(output.read_bytes(), apk.read_bytes())
            receipt = VERIFY.load_receipt(output, self.sha)
            self.assertEqual((receipt['variant'], receipt['version_code'], receipt['signing'], receipt['certificate_sha256']),
                             (variant, 2, metadata['signing'], self.fingerprint))
            calls = [json.loads(line) for line in tool_calls.read_text().splitlines()]
            self.assertEqual([call['tool'] for call in calls], ['aapt', 'apksigner'])
            self.assertEqual({call['sha256'] for call in calls}, {hashlib.sha256(apk.read_bytes()).hexdigest()})

    def test_shipping_gradle_delivery_task_and_cli(self):
        if not GRADLE:
            self.skipTest('shipping delivery task fixture requires explicit Gradle')
        for variant, fallback in [('debug', False), ('release', False), ('release', True)]:
            with self.subTest(variant=variant, fallback=fallback):
                self.delivery_task(variant, fallback=fallback)
        for failure in ('missing-sdk', 'original-interpolation'):
            with self.subTest(failure=failure):
                self.delivery_task('release', failure=failure)

    def test_real_gradle_signed_debug_unsigned_apks(self):
        if not (GRADLE and SDK):
            self.skipTest('real APK fixture requires explicit Gradle and Android SDK')
        android = self.repo / 'android'; android.mkdir()
        source = ROOT / 'android/buildSrc'
        # Only skip generated output at the buildSrc root. The shipping Java
        # policy itself lives in com/eabusham/routervpn/build and must be copied.
        shutil.copytree(source, android / 'buildSrc', ignore=lambda directory, names:
                        [name for name in names if name == '.gradle' or (name == 'build' and Path(directory) == source)])
        self.assertTrue((android / 'buildSrc/src/main/java/com/eabusham/routervpn/build/AndroidBuildPolicy.java').is_file())
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
    unittest.main(argv=[__file__] + remaining)
