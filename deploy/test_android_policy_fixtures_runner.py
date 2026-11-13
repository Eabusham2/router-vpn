#!/usr/bin/env python3
"""Refusal tests for the fixed Android policy fixture source gate; no SDK/compiler."""
from pathlib import Path
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("android_policy_fixed_gate", ROOT/"deploy/validate-android-policy-fixtures.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def transcript(phase):
    return ("\n".join([t["example"] for t in phase["terminals"]]+phase["controls"])+"\n").encode()


class FixedPolicyFixtures(unittest.TestCase):
    def test_exact_four_original_commands_counts_and_no_sdk_claim(self):
        self.assertEqual(G.SUITE, "android-policy-fixtures")
        self.assertEqual([p["args"] for p in G.PHASES], [
            ["android/test_android_tor_form.py"],
            ["android/test_android_external_policy.py"],
            ["android/test_android_external_entries.py"],
            ["android/test_android_imported_router.py", "--phase", "shadowsocks"]])
        self.assertEqual(G.OUTER_SECONDS, 1200)
        self.assertEqual([len(p["controls"]) for p in G.PHASES], [2,0,0,6])
        self.assertEqual([len(p["terminals"]) for p in G.PHASES], [3,1,1,1])
        for phase in G.PHASES:
            accepted=G.verdict(transcript(phase),0,False,True,phase)
            self.assertTrue(accepted["accepted"])
            self.assertEqual(accepted["controls"],phase["controls"])
        self.assertEqual(G.verdict(transcript(G.PHASES[2]),0,False,True,G.PHASES[2])["positive_counts"][0][:5],
                         [456,912,144,171,342])

    def test_failed_timeout_and_unjoined_children_never_pass(self):
        for phase in G.PHASES:
            for code,timed_out,joined in ((1,False,True),(-9,False,True),(0,True,True),(0,False,False)):
                with self.subTest(phase=phase["name"],code=code,timed_out=timed_out,joined=joined):
                    with self.assertRaises(ValueError):
                        G.verdict(transcript(phase),code,timed_out,joined,phase)

    def test_every_original_terminal_is_required_once(self):
        for phase in G.PHASES:
            raw=transcript(phase)
            for terminal in phase["terminals"]:
                line=(terminal["example"]+"\n").encode()
                for invalid in (raw.replace(line,b""),raw+line):
                    with self.subTest(phase=phase["name"],terminal=terminal["example"]):
                        with self.assertRaises(ValueError):G.verdict(invalid,0,False,True,phase)

    def test_fixed_graph_inventory_selected_phase_and_positive_counts_cannot_change(self):
        entries=G.PHASES[2];raw=transcript(entries)
        for count in ("456","912","144","171","342"):
            with self.assertRaises(ValueError):G.verdict(raw.replace(count.encode(),b"1",1),0,False,True,entries)
        phase=G.PHASES[3]
        with self.assertRaises(ValueError):G.verdict(transcript(phase).replace(b"; shadowsocks,",b"; hysteria2,"),0,False,True,phase)
        for phase in G.PHASES:
            with self.assertRaises(ValueError):G.verdict(transcript(phase).replace(b"100 checks",b"0 checks").replace(b"100 executable",b"0 executable"),0,False,True,phase)

    def test_compiled_controls_missing_duplicate_foreign_or_reordered_refuse(self):
        for phase in G.PHASES:
            raw=transcript(phase)
            for control in phase["controls"]:
                line=(control+"\n").encode()
                for invalid in (raw.replace(line,b""),raw+line):
                    with self.assertRaises(ValueError):G.verdict(invalid,0,False,True,phase)
            with self.assertRaises(ValueError):
                G.verdict(raw+b"Android foreign causal rejected: unrelated\n",0,False,True,phase)
            if phase["controls"]:
                lines=raw.decode().splitlines()
                first=lines.index(phase["controls"][0]);last=lines.index(phase["controls"][-1])
                lines[first],lines[last]=lines[last],lines[first]
                with self.assertRaises(ValueError):G.verdict(("\n".join(lines)+"\n").encode(),0,False,True,phase)

    def test_unrelated_runtime_failure_or_invalid_utf8_refuses(self):
        for phase in G.PHASES:
            for line in ("Traceback (most recent call last):","Exception in thread main","panic: foreign","fatal error: deadlock","WARNING: DATA RACE","FAIL native"):
                with self.assertRaises(ValueError):G.verdict(transcript(phase)+(line+"\n").encode(),0,False,True,phase)
            with self.assertRaises(UnicodeDecodeError):G.verdict(transcript(phase)+b"\xff",0,False,True,phase)

    def fixture(self, root):
        def repo(name):
            path=root/name;path.mkdir()
            def git(*args):
                return subprocess.check_output(["git","-C",str(path),*args],stderr=subprocess.STDOUT,timeout=10)
            git("init","-q");git("config","user.name","Policy validator fixture");git("config","user.email","fixture@example.invalid")
            (path/".gitignore").write_text("ignored-output\n")
            for relative in G.CANDIDATE_PATHS:
                file=path/relative;file.parent.mkdir(exist_ok=True);file.write_text("# actual tracked fixture identity\n")
            git("add",".");git("commit","-qm","Original exact fixture")
            return path,git("rev-parse","HEAD").decode().strip(),git("rev-parse","HEAD^{tree}").decode().strip()
        candidate,sha,tree=repo("candidate");trusted,validator,validator_tree=repo("trusted")
        evidence=root/"evidence";evidence.mkdir();output=evidence/"tests"
        record=dict(schema=1,suite=G.SUITE,source_sha=sha,source_tree=tree,
                    validator_sha=validator,validator_tree=validator_tree,base_sha=validator,base_tree=validator_tree,
                    validation_scope="read-only-source-candidate",changes=[{"path":p} for p in G.CANDIDATE_PATHS])
        (evidence/"selection.json").write_text(json.dumps(record))
        return candidate,trusted,sha,output,record

    def test_actual_git_selection_preserves_source_validator_and_fixed_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate,trusted,sha,output,record=self.fixture(Path(directory))
            with patch.object(G,"ROOT",trusted):
                self.assertEqual(G.selection(candidate,sha,output)[0],record)
                for key,value in (("suite","android-sdk"),("source_sha","0"*40),("validator_tree","0"*40),
                                  ("changes",record["changes"][:-1]),("changes",record["changes"]+[record["changes"][0]])):
                    invalid=copy.deepcopy(record);invalid[key]=value
                    (output.parent/"selection.json").write_text(json.dumps(invalid))
                    with self.assertRaises(ValueError):G.selection(candidate,sha,output)
                (output.parent/"selection.json").write_text(json.dumps(record))
                (trusted/"android/test_android_tor_form.py").write_text("# changed trusted source\n")
                with self.assertRaises(ValueError):G.selection(candidate,sha,output)

    def test_actual_complete_source_snapshot_rejects_changed_deleted_and_ignored_files(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate,_,_,_,_=self.fixture(Path(directory));before=G.CORE.snapshot(candidate)
            self.assertEqual(G.require_pristine(candidate,before),before)
            file=candidate/G.CANDIDATE_PATHS[0];original=file.read_bytes()
            file.write_bytes(original+b"# changed\n")
            with self.assertRaises(ValueError):G.require_pristine(candidate,before)
            file.write_bytes(original);file.unlink()
            with self.assertRaises((ValueError,FileNotFoundError)):G.require_pristine(candidate,before)
            file.write_bytes(original)
            (candidate/"ignored-output").write_text("actual ignored generated output")
            with self.assertRaises(ValueError):G.require_pristine(candidate,before)

    def test_original_executor_observes_actual_child_exit_timeout_and_join(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            for label,body,bound in (("pass","print('actual original child')",3),
                                     ("failure","raise SystemExit(17)",3),
                                     ("timeout","import time;time.sleep(30)",0.1)):
                result=G.CORE.execute([sys.executable,"-c",body],path,dict(os.environ),path/(label+".log"),bound)
                if label=="pass":self.assertEqual(result,(0,False,True))
                else:
                    self.assertTrue(result[2])
                    self.assertEqual(result[1],label=="timeout")
                    self.assertNotEqual(result[0],0)
                    with self.assertRaises(ValueError):G.verdict(transcript(G.PHASES[0]),*result,G.PHASES[0])

    def test_fixture_closure_is_checked_after_each_original_phase(self):
        source=(ROOT/"deploy/validate-android-policy-fixtures.py").read_text()
        self.assertIn('record.update(verdict(raw,code,timed_out,joined,phase));save()\n            require_pristine(source,before)',source)
        self.assertIn('source-after.json',source)
        self.assertIn('sdk_accepted=False,native_tunnel_accepted=False',source)
        self.assertIn('GOFLAGS="-p=2 -mod=readonly"',source)
        self.assertIn('go version go1.26.3 linux/amd64',source)
        self.assertIn('javac 17.',source)


def run_tests():
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FixedPolicyFixtures))
    if not result.wasSuccessful():raise SystemExit(1)


if __name__=="__main__":run_tests()
