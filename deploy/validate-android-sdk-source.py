#!/usr/bin/env python3
"""Build the original Android SDK/APK from an exact source candidate.

This executes the existing complete Android delivery graph, including native
dependencies, generated gomobile bindings, Java compilation and package
verification. It cannot establish VPN permission, kernel or device traffic.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "deploy/test_focused_multihop_clocks.py"
spec = importlib.util.spec_from_file_location("android_sdk_original_executor", CORE_PATH)
CORE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CORE
spec.loader.exec_module(CORE)
sys.dont_write_bytecode = True
SUITE = "android-sdk"
BUILD_SECONDS = 7200
READBACK_SECONDS = 1200
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
ABIS = {"armeabi-v7a": (1, 40), "arm64-v8a": (2, 183), "x86": (1, 3), "x86_64": (2, 62)}
PACKAGE = "io.nekohasekai.libbox."
PLAN_SIGNATURES = (
    "java.lang.String source() throws java.lang.Exception;",
    "java.lang.String config() throws java.lang.Exception;",
    "java.lang.String sourceSHA256();",
    "java.lang.String configSHA256();",
    "java.lang.String metadata();",
    PACKAGE+"CommandServer newCommandServer("+PACKAGE+"CommandServerHandler, "+PACKAGE+"PlatformInterface) throws java.lang.Exception;",
    "void bindNative("+PACKAGE+"CommandServer) throws java.lang.Exception;",
    "void run("+PACKAGE+"CommandServer) throws java.lang.Exception;",
    "boolean healthy();",
    "java.lang.String progressJSON();",
    "void networkChanged();",
    "void close() throws java.lang.Exception;",
    "boolean nativeClosed();",
    "boolean retainsServerCleanup("+PACKAGE+"CommandServer);",
    "java.lang.String mtuProfile();",
)
STATIC_SIGNATURES = (
    PACKAGE+"RouterNodeChainSOCKS newRouterNodeChainSOCKS(java.lang.String) throws java.lang.Exception;",
    "java.lang.String routerNodeChainImportedSOCKSMemberInput(java.lang.String, java.lang.String) throws java.lang.Exception;",
    PACKAGE+"RouterHopMeasurement routerNodeChainSOCKSNewHopMeasurement("+PACKAGE+"RouterNodeChainSOCKS, "+PACKAGE+"CommandServer) throws java.lang.Exception;",
    PACKAGE+"RouterMTU routerNodeChainSOCKSNewMTU("+PACKAGE+"RouterNodeChainSOCKS, "+PACKAGE+"CommandServer, "+PACKAGE+"RouterMTUPlatform) throws java.lang.Exception;",
)
PRODUCTION_INPUTS = ("KEYSTORE_BASE64", "KEYSTORE", "STORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD", "CERT_SHA256", "REQUIRE_PRODUCTION", "VERSION_CODE", "VERSION_SHA")

def sha_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()

def regular(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0:
        raise ValueError("Original SDK artifact is absent or redirected: "+path.name)
    return path

def child_environment(original, sha):
    if not HEX40.fullmatch(sha):
        raise ValueError("Exact source identity required")
    env=dict(original)
    # The shipping AWG Makefile owns an older bootstrap Go and lets its
    # pinned module select the required patch-level toolchain. A focused
    # compiler fixture override must not leak into that original SDK build.
    env.pop("GOTOOLCHAIN",None)
    for suffix in PRODUCTION_INPUTS:
        env.pop("ROUTERVPN_ANDROID_"+suffix,None)
    env.update(GITHUB_SHA=sha,ROUTER_VPN_SOURCE_SHA=sha,GITHUB_REPOSITORY="Eabusham2/router-vpn",
               ROUTERVPN_ANDROID_REQUIRE_PRODUCTION="false",PYTHONDONTWRITEBYTECODE="1",
               CGO_ENABLED="1",GOWORK="off",GOFLAGS="")
    return env

def require_signatures(raw, signatures, owner):
    text=raw.decode("utf-8","strict")
    if re.search(r"(?mi)^(error:|exception|panic:|fatal error:|warning: data race)",text):
        raise ValueError("Generated API inspection failed")
    lines=[line.strip() for line in text.splitlines()]
    if sum(line.startswith("public ") and ("class "+PACKAGE+owner+" ") in line for line in lines)!=1:
        raise ValueError("Original generated API class changed")
    for signature in signatures:
        method=signature.split("(",1)[0].rsplit(" ",1)[-1]
        candidates=[line for line in lines if re.search(r"\b"+re.escape(method)+r"\(",line)]
        if len(candidates)!=1 or not candidates[0].endswith(" "+signature):
            raise ValueError("Generated typed SDK method mismatch: "+method)
    return {"class":PACKAGE+owner,"required_signatures":list(signatures),"javap_sha256":hashlib.sha256(raw).hexdigest()}

def zip_index(archive):
    entries=archive.infolist()
    names=[x.filename for x in entries]
    if len(names)!=len(set(names)):
        raise ValueError("Native archive repeats a member")
    for entry in entries:
        parts=Path(entry.filename).parts
        if not parts or entry.filename.startswith(("/", "\\")) or "\\" in entry.filename or ".." in parts or ((entry.external_attr>>16)&0o170000)==0o120000:
            raise ValueError("Native archive contains a redirected member")
    return set(names)

def elf_member(archive, name, abi):
    info=archive.getinfo(name)
    if info.is_dir() or info.file_size<64:
        raise ValueError("Native library is empty")
    with archive.open(info) as stream:
        header=stream.read(64)
        expected_class,machine=ABIS[abi]
        if header[:4]!=b"\x7fELF" or header[4]!=expected_class or header[5]!=1 or struct.unpack_from("<H",header,18)[0]!=machine:
            raise ValueError("Native library has the wrong Android ABI")
        digest=hashlib.sha256(header)
        while block:=stream.read(1024*1024):digest.update(block)
    return {"path":name,"bytes":info.file_size,"sha256":digest.hexdigest(),"abi":abi}

def archive_shape(aar,apk):
    records=[]
    with zipfile.ZipFile(regular(aar)) as library,zipfile.ZipFile(regular(apk)) as app:
        a=zip_index(library);p=zip_index(app)
        if "classes.jar" not in a or not any(re.fullmatch(r"classes[0-9]*\.dex",n) for n in p):
            raise ValueError("Generated SDK classes or compiled APK DEX are missing")
        if any(n.endswith("/libgojni.so") for n in a|p):
            raise ValueError("A second generic gomobile native runtime is packaged")
        classes=library.read("classes.jar")
        with zipfile.ZipFile(io.BytesIO(classes)) as jar:
            c=zip_index(jar)
            for name in ("go/Seq.class","io/nekohasekai/libbox/Libbox.class","io/nekohasekai/libbox/RouterNodeChainSOCKS.class"):
                if name not in c:raise ValueError("Required generated class is absent: "+name)
        for abi in ABIS:
            records.append(elf_member(library,"jni/"+abi+"/libbox.so",abi))
            for native in ("libbox.so","libroutervpn_tor.so","libroutervpn_rosenpass_jni.so","libwg-go.so","libawg-go.so"):
                records.append(elf_member(app,"lib/"+abi+"/"+native,abi))
        for name in ("assets/LICENSE","assets/ROUTER-VPN-SOURCE.json","assets/ROUTER-VPN-ANDROID.json"):
            if name not in p or not app.getinfo(name).file_size:
                raise ValueError("APK source, license or delivery receipt is missing")
    return records,classes

def require_debug_receipt(receipt,sha,version,apk):
    if not isinstance(receipt,dict) or receipt.get("schema_version")!=1 or receipt.get("source_sha")!=sha or receipt.get("application_id")!="com.eabusham.routervpn":
        raise ValueError("Actual Android delivery source differs")
    if receipt.get("version_code")!=version or receipt.get("version_name")!=f"0.1.{version}-{sha[:12]}":
        raise ValueError("Actual Android full-history version differs")
    if receipt.get("variant")!="debug" or receipt.get("signing")!="debug-signed" or receipt.get("apk_signature_verified") is not True:
        raise ValueError("SDK fixture requires the original verified debug package")
    if not HEX64.fullmatch(str(receipt.get("certificate_sha256",""))) or receipt.get("compatibility_asset")!="app-debug.apk":
        raise ValueError("Actual Android signer/delivery receipt is absent")
    if receipt.get("apk_sha256")!=sha_file(apk) or receipt.get("apk_size")!=Path(apk).stat().st_size:
        raise ValueError("Actual APK bytes changed after signature verification")

def full_history_version(source):
    if CORE.git(source,"rev-parse","--is-shallow-repository").strip()!=b"false":
        raise ValueError("Original Android version policy requires complete Git history")
    version=int(CORE.git(source,"rev-list","--count","HEAD"))+1
    if not 2<=version<=2100000000:raise ValueError("Original Android version is out of bounds")
    return version

def selection(source,sha,output):
    if not HEX40.fullmatch(sha):raise ValueError("Exact source SHA required")
    path=output.parent/"selection.json"
    if path.is_symlink() or not path.is_file():raise ValueError("Original trusted SDK selection is missing")
    raw=path.read_bytes();record=json.loads(raw)
    if record.get("schema")!=1 or record.get("suite")!=SUITE or record.get("source_sha")!=sha or record.get("validation_scope")!="read-only-source-candidate":
        raise ValueError("SDK suite or selected source changed")
    for key in ("validator_sha","validator_tree","base_sha","base_tree","source_sha","source_tree"):
        if not isinstance(record.get(key),str) or not HEX40.fullmatch(record[key]):raise ValueError("SDK selection lost Git identity")
    for root,commit,tree in ((source,sha,record["source_tree"]),(ROOT,record["validator_sha"],record["validator_tree"])):
        if CORE.git(root,"rev-parse","HEAD").decode().strip()!=commit or CORE.git(root,"rev-parse","HEAD^{tree}").decode().strip()!=tree or CORE.git(root,"status","--porcelain","--untracked-files=all"):
            raise ValueError("Original SDK source checkout changed")
    full_history_version(source)
    return record,raw

def validate(source,sha,output,gradle,sdk):
    source=Path(source).resolve(strict=True);output=Path(output).absolute();sdk=Path(sdk).resolve(strict=True)
    if output.exists() or output.is_symlink() or output==source or source in output.parents:
        raise ValueError("SDK output must be fresh and outside candidate")
    selected,selection_bytes=selection(source,sha,output)
    before=CORE.snapshot(source)
    if platform.system()!="Linux" or platform.machine()!="x86_64":raise ValueError("SDK gate requires Ubuntu amd64")
    for tool in (gradle,"go","java","javac","javap","jar","rustup","cmake","ninja","clang","make","autoconf","automake","libtoolize","pkg-config","perl","patch","git","unzip"):
        if not shutil.which(tool):raise ValueError("Original Android build dependency is missing: "+tool)
    for name in ("cmdline-tools/latest/bin/sdkmanager","build-tools/36.0.0/aapt","build-tools/36.0.0/apksigner","platforms/android-36/android.jar"):
        regular(sdk/name)
    env=child_environment(os.environ,sha);env.update(ANDROID_HOME=str(sdk),ANDROID_SDK_ROOT=str(sdk))
    go=subprocess.check_output(["go","version"],text=True,env=env,timeout=15).strip()
    java=subprocess.check_output(["javac","-version"],stderr=subprocess.STDOUT,text=True,env=env,timeout=15).strip()
    if go!="go version go1.26.3 linux/amd64" or not java.startswith("javac 17."):
        raise ValueError("Original pinned Go or Java changed")
    version=full_history_version(source)
    output.mkdir(mode=0o700);(output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    receipt=dict(schema=1,suite=SUITE,selection=selected,status="running",go_version=go,javac_version=java,
        source_file_count=len(before),source_closure_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        expected_version_code=version,signing="debug-signed",production_signing=False,device_accepted=False,
        native_traffic_accepted=False,source_file_mutation_allowed=False,phases=[],
        trusted_executor_sha256=sha_file(CORE_PATH),scope="actual-generated-Android-AAR-and-shipping-Java-Gradle-APK")
    def save():(output/"progress.json").write_text(json.dumps(receipt,indent=2)+"\n")
    def run(name,command,bound):
        log=output/(name+".log");start=time.monotonic()
        code,timed_out,joined=CORE.execute(command,source,env,log,bound)
        receipt["phases"].append(dict(name=name,command=command,seconds=time.monotonic()-start,outer_seconds=bound,
            exit=code,timed_out=timed_out,process_group_joined=joined,log_sha256=sha_file(log)));save()
        if code!=0 or timed_out or not joined:raise ValueError("Original SDK phase failed or did not join: "+name)
        return log.read_bytes()
    save()
    try:
        gradle_version=run("gradle-version",[gradle,"--version"],60).decode("utf-8","strict")
        if len(re.findall(r"^Gradle 9\.5\.0$",gradle_version,re.M))!=1:raise ValueError("Original Gradle9.5.0 is required")
        run("original-debug-delivery",[sys.executable,str(source/"android/build-delivery.py"),"--root",str(source/"android"),"--gradle",gradle],BUILD_SECONDS)
        aar=regular(source/"android/app/libs/libbox.aar")
        apk=regular(source/"android/app/build/outputs/routervpn/app-debug.apk")
        built_aar=sha_file(aar);built_apk=sha_file(apk)
        run("canonical-aar-readback",["bash",str(source/"android/build-sing-box-libbox.sh")],READBACK_SECONDS)
        if sha_file(aar)!=built_aar or sha_file(apk)!=built_apk:raise ValueError("Readback rebuilt or replaced the assembled native package")
        if (source/"android/app/libs/libxray.aar").exists():raise ValueError("Standalone second Go runtime remains")
        libraries,classes=archive_shape(aar,apk)
        classes_path=output/"captured-classes.jar";classes_path.write_bytes(classes);classes_sha=sha_file(classes_path)
        plan=run("generated-socks-api",["javap","-classpath",str(classes_path),PACKAGE+"RouterNodeChainSOCKS"],60)
        api=run("generated-libbox-api",["javap","-classpath",str(classes_path),PACKAGE+"Libbox"],60)
        receipt["generated_api"]=[require_signatures(plan,PLAN_SIGNATURES,"RouterNodeChainSOCKS"),require_signatures(api,STATIC_SIGNATURES,"Libbox")]
        if sha_file(classes_path)!=classes_sha:raise ValueError("Captured generated classes changed")
        raw=run("original-package-signature",[sys.executable,str(ROOT/"android/verify-delivery.py"),"--apk",str(apk),"--sdk",str(sdk),"--sha",sha,"--variant","debug","--version-code",str(version)],180)
        delivered=json.loads(raw)
        require_debug_receipt(delivered,sha,version,apk)
        original=json.loads(regular(apk.parent/"android-delivery.json").read_bytes())
        if delivered!=original:raise ValueError("Original assembled delivery receipt changed")
        receipt["delivery"]=delivered;receipt["native_libraries"]=libraries
        receipt["artifacts"]=[]
        for path in (aar,apk,apk.parent/"android-delivery.json",source/"android/app/libs/libbox.commit",source/"android/app/libs/libbox.openvpn.sha256",source/"android/app/libs/amneziawg-tunnel.commit",source/"android/app/libs/rosenpass-native/source.json"):
            path=regular(path);receipt["artifacts"].append(dict(path=str(path.relative_to(source)),bytes=path.stat().st_size,sha256=sha_file(path)))
        artifacts=output/"artifacts";artifacts.mkdir(mode=0o700)
        for original_path,name in ((aar,"libbox.aar"),(apk,"app-debug.apk"),(apk.parent/"android-delivery.json","android-delivery.json")):
            captured=artifacts/name;shutil.copyfile(original_path,captured)
            if sha_file(captured)!=sha_file(original_path):raise ValueError("Owned SDK artifact copy changed")
        if CORE.snapshot(source)!=before or CORE.git(source,"status","--porcelain","--untracked-files=all"):
            raise ValueError("Candidate source changed during the original SDK build")
        if (output.parent/"selection.json").read_bytes()!=selection_bytes or selection(source,sha,output)[0]!=selected:
            raise ValueError("Original trusted SDK selection changed")
        if sha_file(aar)!=built_aar or sha_file(apk)!=built_apk:raise ValueError("Assembled SDK/APK identity changed")
        receipt.update(status="passed",generated_sdk_accepted=True,shipping_java_compiled=True,apk_verified=True)
        (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    except BaseException as error:
        receipt.update(status="failed",error=str(error));raise
    finally:save()
    return receipt

def self_test():
    def transcript(owner,signatures):
        return ("Compiled from \""+owner+".java\"\npublic final class "+PACKAGE+owner+" implements go.Seq$Proxy {\n"+"\n".join("  public "+s for s in signatures)+"\n}\n").encode()
    def elf(abi):
        cls,machine=ABIS[abi];data=bytearray(64);data[:6]=b"\x7fELF"+bytes([cls,1]);struct.pack_into("<H",data,18,machine);return bytes(data)
    def fixture(root):
        jar=io.BytesIO()
        with zipfile.ZipFile(jar,"w") as z:
            for name in ("go/Seq.class","io/nekohasekai/libbox/Libbox.class","io/nekohasekai/libbox/RouterNodeChainSOCKS.class"):z.writestr(name,b"fixture class")
        aar=root/"libbox.aar";apk=root/"app.apk"
        with zipfile.ZipFile(aar,"w") as z:
            z.writestr("classes.jar",jar.getvalue())
            for abi in ABIS:z.writestr("jni/"+abi+"/libbox.so",elf(abi))
        with zipfile.ZipFile(apk,"w") as z:
            z.writestr("classes.dex",b"fixture dex")
            for name in ("assets/LICENSE","assets/ROUTER-VPN-SOURCE.json","assets/ROUTER-VPN-ANDROID.json"):z.writestr(name,b"fixture only")
            for abi in ABIS:
                for name in ("libbox.so","libroutervpn_tor.so","libroutervpn_rosenpass_jni.so","libwg-go.so","libawg-go.so"):z.writestr("lib/"+abi+"/"+name,elf(abi))
        return aar,apk
    class Checks(unittest.TestCase):
        def test_exact_signature_inventory(self):
            self.assertEqual(len(PLAN_SIGNATURES),15);self.assertEqual(len(STATIC_SIGNATURES),4)
            for owner,signatures in (("RouterNodeChainSOCKS",PLAN_SIGNATURES),("Libbox",STATIC_SIGNATURES)):
                raw=transcript(owner,signatures);self.assertEqual(len(require_signatures(raw,signatures,owner)["required_signatures"]),len(signatures))
        def test_every_missing_duplicate_and_changed_method_refused(self):
            for owner,signatures in (("RouterNodeChainSOCKS",PLAN_SIGNATURES),("Libbox",STATIC_SIGNATURES)):
                raw=transcript(owner,signatures)
                for signature in signatures:
                    line=("  public "+signature+"\n").encode()
                    for wrong in (raw.replace(line,b""),raw+line,raw.replace(signature.encode(),signature.replace("(","(int, ",1).encode())):
                        with self.subTest(signature=signature):
                            with self.assertRaises(ValueError):require_signatures(wrong,signatures,owner)
        def test_exact_factory_argument_order_and_mtu_owner_refused(self):
            raw=transcript("RouterNodeChainSOCKS",PLAN_SIGNATURES)
            wrong=raw.replace((PACKAGE+"CommandServerHandler, "+PACKAGE+"PlatformInterface").encode(),(PACKAGE+"PlatformInterface, "+PACKAGE+"CommandServerHandler").encode())
            with self.assertRaises(ValueError):require_signatures(wrong,PLAN_SIGNATURES,"RouterNodeChainSOCKS")
            raw=transcript("Libbox",STATIC_SIGNATURES).replace((PACKAGE+"RouterNodeChainSOCKS, "+PACKAGE+"CommandServer, "+PACKAGE+"RouterMTUPlatform").encode(),(PACKAGE+"CommandServer, "+PACKAGE+"RouterMTUPlatform").encode())
            with self.assertRaises(ValueError):require_signatures(raw,STATIC_SIGNATURES,"Libbox")
        def test_candidate_environment_never_reuses_validator_sha_or_production_key(self):
            original={"GITHUB_SHA":"b"*40,"ROUTERVPN_ANDROID_KEYSTORE":"private","ROUTERVPN_ANDROID_STORE_PASSWORD":"private","PATH":"/original","GOTOOLCHAIN":"local"}
            env=child_environment(original,"a"*40)
            self.assertEqual(env["GITHUB_SHA"],"a"*40);self.assertEqual(env["ROUTER_VPN_SOURCE_SHA"],"a"*40)
            self.assertNotIn("ROUTERVPN_ANDROID_KEYSTORE",env);self.assertNotIn("ROUTERVPN_ANDROID_STORE_PASSWORD",env)
            self.assertEqual(original["GITHUB_SHA"],"b"*40);self.assertEqual(env["PATH"],"/original")
            self.assertNotIn("GOTOOLCHAIN",env);self.assertEqual(original["GOTOOLCHAIN"],"local")
        def test_all_four_actual_archive_abi_slots_required(self):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);aar,apk=fixture(root);rows,_=archive_shape(aar,apk);self.assertEqual(len(rows),24)
                with zipfile.ZipFile(apk) as z:original={n:z.read(n) for n in z.namelist()}
                for abi in ABIS:
                    for name in ("libbox.so","libroutervpn_tor.so","libroutervpn_rosenpass_jni.so","libwg-go.so","libawg-go.so"):
                        omitted="lib/"+abi+"/"+name;bad=root/"bad.apk"
                        with zipfile.ZipFile(bad,"w") as z:
                            for p,b in original.items():
                                if p!=omitted:z.writestr(p,b)
                        with self.assertRaises((ValueError,KeyError)):archive_shape(aar,bad)
        def test_wrong_machine_duplicate_runtime_and_redirect_refused(self):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);aar,apk=fixture(root)
                with zipfile.ZipFile(apk) as z:original={n:z.read(n) for n in z.namelist()}
                for fault in ("machine","generic-runtime","redirect","duplicate"):
                    bad=root/"bad.apk"
                    with zipfile.ZipFile(bad,"w") as z:
                        for p,b in original.items():z.writestr(p,elf("x86") if fault=="machine" and p=="lib/arm64-v8a/libbox.so" else b)
                        if fault=="generic-runtime":z.writestr("lib/arm64-v8a/libgojni.so",elf("arm64-v8a"))
                        if fault=="redirect":z.writestr("../foreign",b"x")
                        if fault=="duplicate":
                            import warnings
                            with warnings.catch_warnings():
                                warnings.simplefilter("ignore");z.writestr("classes.dex",b"second")
                    with self.assertRaises(ValueError):archive_shape(aar,bad)
        def test_debug_receipt_rejects_wrong_source_signing_version_or_bytes(self):
            with tempfile.TemporaryDirectory() as directory:
                apk=Path(directory)/"fixture.apk";apk.write_bytes(b"fixture only");sha="a"*40
                good=dict(schema_version=1,source_sha=sha,application_id="com.eabusham.routervpn",version_code=7,version_name="0.1.7-"+sha[:12],variant="debug",signing="debug-signed",apk_signature_verified=True,certificate_sha256="c"*64,compatibility_asset="app-debug.apk",apk_sha256=sha_file(apk),apk_size=apk.stat().st_size)
                require_debug_receipt(good,sha,7,apk)
                for key,value in (("source_sha","b"*40),("version_code",8),("variant","release"),("signing","production-signed"),("apk_signature_verified",False),("certificate_sha256",""),("apk_sha256","0"*64)):
                    with self.subTest(key=key):
                        with self.assertRaises(ValueError):require_debug_receipt(dict(good,**{key:value}),sha,7,apk)
        def test_full_original_history_required_with_real_git_checkouts(self):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);original=root/"original";original.mkdir()
                def git(*args):return subprocess.check_output(["git",*map(str,args)],stderr=subprocess.STDOUT,timeout=10)
                git("init","-q",original);git("-C",original,"config","user.name","SDK fixture");git("-C",original,"config","user.email","sdk-fixture@example.invalid")
                for index in range(3):
                    (original/"source").write_text(str(index));git("-C",original,"add","source");git("-C",original,"commit","-qm","fixture"+str(index))
                self.assertEqual(full_history_version(original),4)
                shallow=root/"shallow";git("clone","--quiet","--depth=1",original.as_uri(),shallow)
                with self.assertRaises(ValueError):full_history_version(shallow)
        def test_original_executor_observes_owned_child(self):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);log=root/"child.log"
                self.assertEqual(CORE.execute([sys.executable,"-c","print('SDK parser self-test only')"],root,dict(os.environ),log,3),(0,False,True))
                self.assertEqual(log.read_text().strip(),"SDK parser self-test only")
    if not unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks)).wasSuccessful():raise SystemExit(1)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--suite",choices=(SUITE,),default=SUITE)
    parser.add_argument("--source",type=Path);parser.add_argument("--source-sha");parser.add_argument("--output",type=Path)
    parser.add_argument("--gradle",default="gradle");parser.add_argument("--sdk",type=Path)
    args=parser.parse_args()
    if args.self_test:self_test();return
    if not all((args.source,args.source_sha,args.output,args.sdk)):parser.error("Exact source, SHA, output and original SDK required")
    print(json.dumps(validate(args.source,args.source_sha,args.output,args.gradle,args.sdk),sort_keys=True))

if __name__=="__main__":main()
