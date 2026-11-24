"""Verify exact shallow selection and optional Actions credentials with a local Git fixture."""
import base64
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import fetch_mobile_pinned_git as dependency


class MobilePinnedGit(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.url = "https://github.com/SagerNet/sing-box.git"
        self.header = "AUTHORIZATION: basic " + base64.b64encode(b"test-only:value").decode()
        self.upstream = self.root / "upstream"
        self.owner = self.root / "owner"
        self.destination = self.root / "vendor"
        workspace = dict(GITHUB_ACTIONS="true", GITHUB_SERVER_URL="https://github.com", GITHUB_WORKSPACE=str(self.owner),
                         GITHUB_REPOSITORY="example/router", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.root/"git.config"))
        clean = patch.dict(os.environ, workspace)
        clean.start()
        self.addCleanup(clean.stop)
        for repo in (self.owner,self.upstream):
            subprocess.run(["git","init","-q",str(repo)],check=True)
        self.git(self.owner,"remote","add","origin","https://github.com/example/router")
        self.git(self.owner,"config","http.https://github.com/.extraheader",self.header)
        for content in ("pinned", "newer default"):
            (self.upstream/"asset").write_text(content)
            self.git(self.upstream,"add","asset")
            self.git(self.upstream,"-c","user.name=fixture","-c","user.email=test@example.invalid","commit","-qm",content)
            if content == "pinned":
                self.commit = self.git(self.upstream,"rev-parse","HEAD")
        self.git(self.upstream,"tag","unrelated")
        self.git(self.owner,"config","--global",f"url.{self.upstream.as_uri()}.insteadOf",self.url)

    @staticmethod
    def git(root,*args):
        return subprocess.check_output(["git","-C",str(root),*args],text=True).strip()

    def test_mobile_builders_call_the_pinned_fetch_for_each_original(self):
        root=Path(__file__).resolve().parents[1]
        apple=(root/"ios/RouterVPN/prepare-libbox.sh").read_text()
        android=(root/"android/build-sing-box-libbox.sh").read_text()
        for source in (apple,android):
            self.assertIn("COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d",source)
            self.assertIn('fetch_mobile_pinned_git.py" https://github.com/SagerNet/sing-box.git "$COMMIT" "$VENDOR"',source)
            self.assertNotIn("git clone",source)
        self.assertIn("XRAY_COMMIT=50231eaff98ccc31b5cbd247a721c16e97fe5ec1",apple)
        self.assertIn('fetch_mobile_pinned_git.py" https://github.com/XTLS/Xray-core.git "$XRAY_COMMIT" "$XRAY_VENDOR"',apple)
        self.assertIn('fetch_mobile_pinned_git.py" https://github.com/XTLS/Xray-core.git 50231eaff98ccc31b5cbd247a721c16e97fe5ec1 "$XRAY_CORE_VENDOR"',android)
        self.assertIn("LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998",android)
        self.assertIn('fetch_mobile_pinned_git.py" https://github.com/XTLS/libXray.git "$LIBXRAY_COMMIT" "$XRAY_VENDOR"',android)
        self.assertIn("inputs.file rootProject.file('../deploy/fetch_mobile_pinned_git.py')",(root/"android/app/build.gradle").read_text())

    def test_exact_old_commit_and_scoped_transient_header(self):
        real_run = subprocess.run
        calls = []
        def observed(argv, **kwargs):
            if "fetch" in argv:
                self.assertEqual(argv[-5:],["fetch","--no-tags","--depth=1","origin",self.commit])
                self.assertIn("--config-env=http."+self.url+".extraHeader=ROUTERVPN_PIN_FETCH_HEADER",argv)
                self.assertEqual(kwargs["env"]["ROUTERVPN_PIN_FETCH_HEADER"],self.header)
                self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"],"0")
                calls.append("fetch")
            else:
                self.assertNotIn("ROUTERVPN_PIN_FETCH_HEADER",kwargs.get("env",{}))
            self.assertFalse(any(self.header in arg for arg in argv))
            return real_run(argv, **kwargs)
        output=io.StringIO()
        with patch.object(subprocess,"run",observed),redirect_stdout(output):
            dependency.fetch(self.url,self.commit,self.destination)
        self.assertEqual(calls,["fetch"])
        self.assertNotIn(self.header,output.getvalue())
        self.assertEqual((self.destination/"asset").read_text(),"pinned")
        self.assertEqual(self.git(self.destination,"rev-parse","HEAD"),self.commit)
        self.assertEqual(self.git(self.destination,"rev-parse","--is-shallow-repository"),"true")
        self.assertEqual(self.git(self.destination,"tag","--list"),"")
        config=(self.destination/".git/config").read_text()
        self.assertIn(self.url,config)
        self.assertNotIn("extraheader",config.lower())
        self.assertNotIn(self.header,config)

    def test_retry_budget_and_no_partial_publication(self):
        with patch.object(dependency.time,"sleep") as delay, self.assertRaises(RuntimeError), redirect_stdout(io.StringIO()):
            dependency.fetch(self.url,"0"*40,self.destination)
        self.assertEqual([c.args for c in delay.call_args_list],[(3,),(6,)])
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob("mobile-pinned-source-*")),[])

    def test_retry_starts_a_fresh_checkout_with_the_same_commit(self):
        real_run = subprocess.run
        attempted = []
        def intermittent(argv, **kwargs):
            if "fetch" in argv:
                attempted.append((argv[2],argv[-1]))
                if len(attempted) == 1:
                    return subprocess.CompletedProcess(argv,1)
            return real_run(argv,**kwargs)
        with patch.object(subprocess,"run",intermittent), patch.object(dependency.time,"sleep") as delay, redirect_stdout(io.StringIO()):
            dependency.fetch(self.url,self.commit,self.destination)
        self.assertEqual([sha for _,sha in attempted],[self.commit,self.commit])
        self.assertNotEqual(attempted[0][0],attempted[1][0])
        delay.assert_called_once_with(3)
        self.assertEqual(self.git(self.destination,"rev-parse","HEAD"),self.commit)

    def test_foreign_checkout_or_provider_has_no_checkout_credential(self):
        self.git(self.owner,"remote","set-url","origin","https://github.com/other/private")
        self.assertIsNone(dependency.github_checkout_header())
        with patch.object(subprocess,"run",side_effect=AssertionError("unexpected Git call")):
            for url,pin in [(self.url+"/redirect",self.commit),(self.url,"main")]:
                with self.assertRaises(ValueError):
                    dependency.fetch(url,pin,self.destination)
        with patch.dict(os.environ,{"GITHUB_ACTIONS":"false"}):
            self.assertIsNone(dependency.github_checkout_header())


if __name__ == "__main__":
    unittest.main()
