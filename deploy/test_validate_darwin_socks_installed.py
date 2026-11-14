#!/usr/bin/env python3
"""Exercise installed receipt, exact invocation and independent clone boundaries."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location("installed_trusted",Path(__file__).with_name("validate-darwin-socks-installed.py"))
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)
# Use the shipping typed wrapper: changing module constants does not change
# the original parser's already-bound keyword defaults.
T=V.module("installed_typed_parser",V.ROOT/"deploy/test_macos_socks_node_chain_host.py")

def joined_receipt(case):
    if case not in (*V.ORIGINAL,*V.TYPED):
        raise ValueError("Unknown original or typed fixture case")
    return 'actual sealed Darwin ordered host verified '+case+': original native transaction and intended proof boundary, complete captured identities, stopped acknowledgment, PF and utun retirement, controller join'

def completed(case):
    gate=T if case in V.TYPED else V.BASE
    lines=["=== RUN   "+gate.TEST,"=== RUN   "+gate.TEST+"/"+case]
    if case in V.BASE.MTU_CASES:lines.append("    desktop_node_chain_darwin_native_test.go:2: "+V.BASE.MTU_RECEIPT)
    if case in gate.MEASUREMENT_CASES:lines.append("    desktop_node_chain_darwin_native_test.go:3: "+V.BASE.MEASUREMENT_RECEIPT)
    lines+=["    desktop_node_chain_darwin_native_test.go:4: "+joined_receipt(case),
            "--- PASS: "+gate.TEST+" (0.2s)","    --- PASS: "+gate.TEST+"/"+case+" (0.1s)","PASS",""]
    return "\n".join(lines)

def envelope(root):
    (root/"original.go").write_text("original")
    gate=SimpleNamespace(ROOT=root,SOURCES=("original.go",),check_verdict=T.check_verdict)
    metadata={"source_sha":"1"*40,"source_tree":"2"*40}
    value=dict(schema=1,gate="installed-darwin-ordered-socks-host",scope="installed-controller-typed-socks-and-original-preservation",
               target="darwin/amd64",public_darwin_admission="closed",native=True,
               repository={"repository":"Eabusham2/router-vpn","commit":metadata["source_sha"],"tree":metadata["source_tree"]},
               source_sha256="3"*64,bundle_sha256="4"*64,sealed_bundle_sha256="5"*64,
               cases=list(V.TYPED),original_cases=list(V.ORIGINAL),completed=list((*V.ORIGINAL,*V.TYPED)),
               authority_cases=list(V.BASE.AUTHORITY_CASES),hysteria_authority_cases=list(V.BASE.HYSTERIA_AUTHORITY_CASES),
               typed_authority_cases=list(V.AUTHORITY_CASES),
               images={"controller":"6"*64,"peer":"7"*64},sources={"application":{"original.go":V.sha(root/"original.go")}})
    for key in ("authority_output_sha256","hysteria_authority_output_sha256","typed_authority_output_sha256","output_sha256"):
        value[key]="8"*64
    for key,cases,witness in (("hysteria_source_control",V.BASE.HYSTERIA_AUTHORITY_CASES,V.BASE.HYSTERIA_CONTROL_WITNESS),
                              ("typed_source_control",V.AUTHORITY_CASES,V.SOURCE_CONTROL)):
        value[key]={"cases":list(cases),"witness":witness,"image_sha256":"9"*64,"output_sha256":"a"*64}
    return value,metadata,[completed(case) for case in (*V.ORIGINAL,*V.TYPED)],gate

def checked(value,metadata,outputs,gate):
    V.require_receipt(value,"darwin/amd64",metadata,"3"*64,"4"*64,"5"*64,outputs,gate)

def command(case):
    root=V.TEST if case in V.TYPED else V.BASE.TEST
    return ["sudo","-n","--","/original/controller.test","-test.run=^"+root+"$/^"+case+"$",
            "-test.v","-test.count=1","-test.timeout=240s"]

class InstalledBoundary(unittest.TestCase):
    def test_exact_original37_and_typed8_actual_parser_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            args=envelope(Path(directory));checked(*args)
            self.assertEqual((len(V.ORIGINAL),len(V.TYPED)),(37,8))

    def test_each_original_case_must_prove_its_own_join_measurement_and_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            value,metadata,outputs,gate=envelope(Path(directory))
            for index,case in enumerate((*V.ORIGINAL,*V.TYPED)):
                original=outputs[index]
                parser=T if case in V.TYPED else V.BASE
                faults=[original.replace(joined_receipt(case),"foreign joined receipt"),
                        original.replace("--- PASS:","--- SKIP:",1),
                        original.replace("--- PASS:","--- FAIL:",1),original+"PASS\n",
                        "WARNING: DATA RACE\n"+original,original+"unfinished\n"]
                if case in parser.MEASUREMENT_CASES:
                    faults.append(original.replace(V.BASE.MEASUREMENT_RECEIPT,"missing original measured traffic"))
                for raw in faults:
                    changed=list(outputs);changed[index]=raw
                    with self.subTest(case=case),self.assertRaises(ValueError):checked(value,metadata,changed,gate)

    def test_receipt_rejects_foreign_source_bundle_controls_inventory_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            value,metadata,outputs,gate=envelope(Path(directory))
            for fault in ("source","target","bundle","signed","policy","native","schema","scope","admission","images",
                          "cases","originals","completed","authority","control-witness","control-cases","hash","source-file"):
                changed=copy.deepcopy(value)
                if fault=="source":changed["repository"]["commit"]="f"*40
                elif fault=="target":changed["target"]="darwin/arm64"
                elif fault=="bundle":changed["bundle_sha256"]="f"*64
                elif fault=="signed":changed["sealed_bundle_sha256"]="f"*64
                elif fault=="policy":changed["source_sha256"]="f"*64
                elif fault=="native":changed["native"]=1
                elif fault=="schema":changed["schema"]=True
                elif fault=="scope":changed["scope"]="compiled-only"
                elif fault=="admission":changed["public_darwin_admission"]="open"
                elif fault=="images":changed["images"]["replacement"]="f"*64
                elif fault=="cases":changed["cases"].pop()
                elif fault=="originals":changed["original_cases"].pop()
                elif fault=="completed":changed["completed"].reverse()
                elif fault=="authority":changed["typed_authority_cases"].pop()
                elif fault=="control-witness":changed["typed_source_control"]["witness"]="foreign"
                elif fault=="control-cases":changed["typed_source_control"]["cases"].pop()
                elif fault=="hash":changed["output_sha256"]=""
                else:changed["sources"]["application"]["original.go"]="f"*64
                with self.subTest(fault=fault),self.assertRaises(ValueError):checked(changed,metadata,outputs,gate)
            for changed in (outputs[:-1],outputs+[outputs[-1]],list(reversed(outputs))):
                with self.assertRaises(ValueError):checked(value,metadata,changed,gate)

    def test_all_original_commands_forward_unchanged_and_logs_bind_original_signed_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=root/"sealed-bundle";bundle.mkdir();(bundle/"NATIVE-RUNTIME.json").write_text("sealed")
            calls=[]
            def run(cmd,**kw):
                calls.append((cmd,kw));return completed((*V.ORIGINAL,*V.TYPED)[len(calls)-1])
            def reuse(path,*a,**kw):return "original-reuse"
            gate=SimpleNamespace(CONTROLLER=SimpleNamespace(reported_run=run),BUILD=SimpleNamespace(reuse=reuse))
            outputs=[];observations={}
            with V.capture_cases(gate,root,outputs,observations):
                self.assertEqual(gate.BUILD.reuse(bundle),"original-reuse")
                for case in (*V.ORIGINAL,*V.TYPED):
                    cmd=command(case);self.assertEqual(gate.CONTROLLER.reported_run(cmd,timeout=270,sudo="/usr/bin/sudo"),completed(case))
                    self.assertIs(calls[-1][0],cmd);self.assertEqual(calls[-1][1],{"timeout":270,"sudo":"/usr/bin/sudo"})
            self.assertEqual(len(outputs),45);self.assertEqual(len(list(root.glob("*.log"))),45)
            self.assertEqual(observations["signed_bundle"],V.sha(bundle/"NATIVE-RUNTIME.json"))
            self.assertIs(gate.CONTROLLER.reported_run,run);self.assertIs(gate.BUILD.reuse,reuse)

    def test_changed_case_bound_or_failed_original_child_never_becomes_native_acceptance(self):
        for fault in ("case","inner","outer","failure","exception"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);outputs=[];observations={};calls=[]
                def run(cmd,**kw):
                    calls.append(cmd)
                    if fault=="failure":raise subprocess.CalledProcessError(1,cmd,output=b"original native assertion failed\n")
                    if fault=="exception":raise RuntimeError("original group join unknown")
                    return completed(V.ORIGINAL[0])
                reuse=lambda *a,**k:None
                gate=SimpleNamespace(CONTROLLER=SimpleNamespace(reported_run=run),BUILD=SimpleNamespace(reuse=reuse))
                cmd=command(V.ORIGINAL[0]);bound=270
                if fault=="case":cmd=command(V.ORIGINAL[1])
                if fault=="inner":cmd[-1]="-test.timeout=241s"
                if fault=="outer":bound=271
                with self.assertRaises((ValueError,RuntimeError,subprocess.CalledProcessError)):
                    with V.capture_cases(gate,root,outputs,observations):gate.CONTROLLER.reported_run(cmd,timeout=bound)
                self.assertEqual(outputs,[]);self.assertIs(gate.CONTROLLER.reported_run,run)
                self.assertEqual(bool(calls),fault in ("failure","exception"))
                if calls:self.assertEqual(len(list(root.glob("*failure.log"))),1)

    def test_matching_native_host_and_toolchain_cannot_be_forged(self):
        for system,machine,wanted in (("Darwin","x86_64","darwin/amd64"),("Darwin","arm64","darwin/arm64"),("Linux","x86_64",None),("Darwin","foreign",None)):
            with patch.object(V.platform,"system",return_value=system),patch.object(V.platform,"machine",return_value=machine):
                if wanted:self.assertEqual(V.native_target(),wanted)
                else:
                    with self.assertRaises(ValueError):V.native_target()
        env=V.native_environment({"PATH":"/original","GITHUB_ENV":"/foreign","GITHUB_PATH":"/foreign"},"darwin/arm64")
        self.assertNotIn("GITHUB_ENV",env);self.assertNotIn("GITHUB_PATH",env);self.assertEqual(env["GOARCH"],"arm64")
        with self.assertRaises(ValueError):V.native_environment({"HOMEVPN_MTU_BENCH_FAKE":"1"},"darwin/amd64")
        with self.assertRaises(ValueError):V.native_environment({"GOARCH":"amd64"},"darwin/arm64")
        suffix="aarch64_apple_darwin"
        values={key:"/captured/compiler" for key in ("LIBCLANG_PATH","CC","CXX","AR","CC_"+suffix,"CXX_"+suffix,"AR_"+suffix,"CARGO_TARGET_"+suffix.upper()+"_LINKER")}
        values["RUSTUP_TOOLCHAIN"]=V.BASE.BUILD.PQ.RUST
        value={"target":"darwin/arm64","rust_target":"aarch64-apple-darwin","environment":values,"prepend_path":["/captured/bin"]}
        V.apply_toolchain(json.dumps(value),"darwin/arm64",env)
        for change in ("target","key","newline","relative"):
            broken=copy.deepcopy(value)
            if change=="target":broken["target"]="linux/arm64"
            elif change=="key":broken["environment"]["GITHUB_TOKEN"]="foreign"
            elif change=="newline":broken["environment"]["CC"]="/captured\nforeign"
            else:broken["prepend_path"]=["relative"]
            with self.subTest(change=change),self.assertRaises(ValueError):V.apply_toolchain(json.dumps(broken),"darwin/arm64",{})

    def test_actual_git_clone_keeps_generated_files_outside_pristine_selection_and_retains_unknown_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"candidate";source.mkdir();output=root/"evidence"/"tests";output.parent.mkdir()
            def git(*args):return subprocess.check_output(["git","-C",str(source),*args],stderr=subprocess.STDOUT).decode().strip()
            git("init","-b","main");git("config","user.email","fixture@example.invalid");git("config","user.name","fixture")
            (source/".gitignore").write_text("dist/\n");(source/"original.txt").write_text("original")
            git("add",".");git("commit","-m","original");sha=git("rev-parse","HEAD")
            expected=V.CORE.snapshot(source);version=V.SDK.full_history_version(source)
            workspace=V.SDK.OwnedBuildCheckout(source,output,sha,expected,version,parent=root)
            def run(name,cmd,bound,cwd):
                self.assertIn(bound,(120,60));subprocess.run(cmd,cwd=cwd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=bound)
            workspace.prepare(run)
            (workspace.path/"dist").mkdir();(workspace.path/"dist"/"native").write_text("generated")
            workspace.verify();self.assertFalse((source/"dist").exists())
            self.assertFalse(workspace.cleanup(False)["removed"]);self.assertTrue(workspace.path.exists())
            self.assertTrue(workspace.cleanup(True)["removed"]);self.assertFalse(workspace.root.exists())

    def test_unknown_build_or_replaced_workspace_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);owned=root/"owned";owned.mkdir();old=owned.stat()
            owner=object.__new__(V.SDK.OwnedBuildCheckout);owner.root=owned;owner.identity=(old.st_dev,old.st_ino)
            moved=root/"original";owned.rename(moved);owned.mkdir();(owned/"foreign").write_text("retain")
            with self.assertRaises(ValueError):owner.cleanup(True)
            self.assertEqual((owned/"foreign").read_text(),"retain");self.assertTrue(moved.exists())


    def test_composed_success_failure_and_unknown_native_join_retire_only_proven_owned_clone(self):
        for fault in (None,"build-failure","native-join","foreign-receipt"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);source=root/"candidate";source.mkdir();output=root/"evidence"/"tests";output.parent.mkdir()
                def git(*args):return subprocess.check_output(["git","-C",str(source),*args],stderr=subprocess.STDOUT).decode().strip()
                git("init","-b","main");git("config","user.email","fixture@example.invalid");git("config","user.name","fixture")
                (source/"original.go").write_text("original");git("add",".");git("commit","-m","original")
                sha=git("rev-parse","HEAD");tree=git("rev-parse","HEAD^{tree}")
                metadata={"source_sha":sha,"source_tree":tree}
                gate=SimpleNamespace(BASE=V.BASE,CASES=V.TYPED,TEST=V.TEST,AUTHORITY_CASES=V.AUTHORITY_CASES,SOURCES=("original.go",))
                state={}
                def reuse(bundle,*a,**kw):return {"actual-readback":V.sha(Path(bundle)/"NATIVE-RUNTIME.json")}
                gate.BUILD=SimpleNamespace(digest=lambda:"3"*64,reuse=reuse)
                def native(cmd,**kw):
                    text=completed((*V.ORIGINAL,*V.TYPED)[state.setdefault("calls",0)]);state["calls"]+=1
                    if fault=="native-join":raise RuntimeError("original native child join unknown")
                    return text
                gate.CONTROLLER=SimpleNamespace(reported_run=native);gate.check_verdict=T.check_verdict
                def execute(bundle,**kw):
                    gate.ROOT=state["work"]
                    sealed=state["work"].parent/"sealed-bundle";sealed.mkdir();(sealed/"NATIVE-RUNTIME.json").write_text("signed")
                    gate.BUILD.reuse(sealed)
                    value,_,_,_=envelope(gate.ROOT);value["repository"].update(commit=sha,tree=tree)
                    value["bundle_sha256"]=V.sha(Path(bundle)/"NATIVE-RUNTIME.json")
                    value["sealed_bundle_sha256"]=V.sha(sealed/"NATIVE-RUNTIME.json")
                    for case in (*V.ORIGINAL,*V.TYPED):gate.CONTROLLER.reported_run(command(case),timeout=270,sudo=None)
                    if fault=="foreign-receipt":value["bundle_sha256"]="f"*64
                    Path(kw["receipt_file"]).write_text(json.dumps(value));return value
                gate.execute=execute
                suffix="x86_64_apple_darwin"
                fields={key:"/captured/compiler" for key in ("LIBCLANG_PATH","CC","CXX","AR","CC_"+suffix,"CXX_"+suffix,"AR_"+suffix,"CARGO_TARGET_"+suffix.upper()+"_LINKER")}
                fields["RUSTUP_TOOLCHAIN"]=V.BASE.BUILD.PQ.RUST
                toolchain=json.dumps({"target":"darwin/amd64","rust_target":"x86_64-apple-darwin","environment":fields,"prepend_path":["/captured/bin"]})
                def owned_execute(cmd,cwd,env,log,bound):
                    state["work"]=Path(cwd) if Path(cwd).name=="checkout" else state.get("work")
                    if cmd[0]=="git":
                        result=subprocess.run(cmd,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=bound)
                        Path(log).write_bytes(result.stdout);return result.returncode,False,True
                    if cmd[-1]=="version":text="go version go1.26.3 darwin/amd64\n"
                    elif "setup-desktop-native-toolchain.py" in cmd[1]:text=toolchain
                    elif "build-native-runtime.py" in cmd[1]:
                        bundle=Path(cmd[-1]);bundle.mkdir();(bundle/"NATIVE-RUNTIME.json").write_text("bundle");text="original bundle phase\n"
                        if fault=="build-failure":Path(log).write_text(text);return 1,False,True
                    else:text="original finite phase\n"
                    Path(log).write_text(text);return 0,False,True
                original_module=V.module
                def load(name,path):
                    if str(path).endswith("test_macos_socks_node_chain_host.py"):return gate
                    return original_module(name,path)
                with patch.object(V,"native_target",return_value="darwin/amd64"),patch.object(V,"selection",return_value=(metadata,b"selection")), \
                     patch.object(V.CORE,"execute",side_effect=owned_execute),patch.object(V,"module",side_effect=load), \
                     patch.object(V.shutil,"which",return_value="/captured/go"),patch.dict(os.environ,{"RUNNER_TEMP":str(root)}):
                    if fault:
                        with self.assertRaises((ValueError,RuntimeError)):V.validate(source,sha,output)
                    else:self.assertTrue(V.validate(source,sha,output)["accepted"])
                result=json.loads((output/"manifest.json").read_text())
                self.assertIs(result["accepted"],fault is None);self.assertIs(result["workspace_cleanup"]["removed"],fault is None)
                self.assertEqual((source/"original.go").read_text(),"original");self.assertIs(gate.BUILD.reuse,reuse)
                if fault:self.assertTrue(Path(result["workspace_cleanup"]["retained_path"]).exists())

    def test_fixed_workflow_has_both_architectures_exact_history_and_before_pf_checkpoint(self):
        text=(V.ROOT/".github/workflows/focused-source-validation.yml").read_text()
        job=re.split(r"\n  [a-z][a-z0-9-]*:\n",text.split("  darwin-socks-installed:\n",1)[1],maxsplit=1)[0]
        required=("    if: inputs.suite == 'darwin-socks-installed'","    timeout-minutes: 360",
                  "          - arch: amd64\n            runner: macos-15-intel",
                  "          - arch: arm64\n            runner: macos-15",
                  "          fetch-depth: '0'","          fetch-depth: 1",
                  "        run: brew install cmake ninja pkg-config openssl@3 autoconf automake libtool",
                  "python3 validator/deploy/validate-darwin-socks-installed.py",
                  '"original_cases":37, "typed_cases":8,','"native_accepted":False',
                  "python3 candidate/deploy/test_macos_node_chain_host_runner.py",
                  "python3 candidate/deploy/test_macos_socks_node_chain_host_runner.py")
        def check(value):
            if any(value.count(x)!=1 for x in required) or value.count("persist-credentials: false")!=2:
                raise ValueError("fixed installed architecture/source gate changed")
            if value.index("Focused-darwin-socks-installed-scheduled-")>value.index("brew install") or value.index("brew install")>value.index("validate-darwin-socks-installed.py --source"):
                raise ValueError("native preparation preceded the completed scheduled checkpoint")
            if value.count("if: "+chr(36)+"{{ !cancelled() }}")!=2:raise ValueError("original failure identity/artifacts lost")
        check(job)
        for anchor in required:
            with self.subTest(anchor=anchor),self.assertRaises(ValueError):check(job.replace(anchor,"missing",1))
        self.assertIn("inputs.suite != 'darwin-socks-child' && inputs.suite != 'darwin-socks-installed'",text)
        self.assertIn("  darwin-socks-child:",text)

    def test_allowlist_is_exact129_and_public_activation_remains_separate(self):
        paths=V.IDENTITY.ALLOWLISTS["darwin-socks-installed"]
        expected=(V.IDENTITY.ALLOWLISTS["desktop-socks-parent"]|V.IDENTITY.ALLOWLISTS["darwin-socks-child"]|{
            "cmd/client/desktop_node_chain_darwin_native_test.go","cmd/client/desktop_node_chain_darwin_peer_native_test.go",
            "cmd/client/desktop_node_chain_socks_darwin_native_test.go","deploy/test_macos_node_chain_host.py",
            "deploy/test_macos_node_chain_host_runner.py","deploy/test_macos_socks_node_chain_host.py",
            "deploy/test_macos_socks_node_chain_host_runner.py","client/macos/RouterVPNConnectionProfiles.swift",
            "deploy/test_desktop_connection_profile_modes.py"})
        self.assertEqual(paths,expected);self.assertEqual(len(paths),129)
        self.assertNotIn(".github/workflows/focused-source-validation.yml",paths)
        self.assertNotIn("deploy/validate-darwin-socks-installed.py",paths)
        source=(V.ROOT/"deploy/validate-darwin-socks-installed.py").read_text()
        self.assertIn("swift_editor_accepted=False",source)
        self.assertIn("generated_fifty_and_mtu_rollback_accepted=False",source)
        self.assertIn('public_darwin_admission="closed"',source)

if __name__=="__main__":
    unittest.main(verbosity=2)
