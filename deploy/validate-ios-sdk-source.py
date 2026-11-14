#!/usr/bin/env python3
"""Build the original unsigned iOS app/PacketTunnel against generated gomobile.

The receipt covers actual generated SDK headers, Xcode compilation and original
IPA provenance. It does not authorize public SOCKS UI or claim device traffic.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "deploy/test_focused_multihop_clocks.py"
spec = importlib.util.spec_from_file_location("ios_sdk_original_executor", CORE_PATH)
CORE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CORE
spec.loader.exec_module(CORE)
sys.dont_write_bytecode = True
SUITE = "ios-sdk"
HEX40 = re.compile(r"[0-9a-f]{40}")
WG_PIN = "9d5ee60edefa95b933a738dd7cda671dd18021fc"
LIBBOX_PIN = "1.14.1+1ac1a339cb1223e9c70eae14c44411c75033c02d+go1.26.3+0.1.12+ios,iossimulator"
SDK_SECONDS = 7200
XCODE_SECONDS = 3600
READBACK_SECONDS = 1200
PLAN_DECL = "@interface LibboxRouterNodeChainSOCKS : NSObject <goSeqRefInterface> {"
PLAN_METHODS = (
    "- (NSString* _Nonnull)source:(NSError* _Nullable* _Nullable)error;",
    "- (NSString* _Nonnull)config:(NSError* _Nullable* _Nullable)error;",
    "- (NSString* _Nonnull)sourceSHA256;",
    "- (NSString* _Nonnull)configSHA256;",
    "- (NSString* _Nonnull)metadata;",
    "- (LibboxCommandServer* _Nullable)newCommandServer:(id<LibboxCommandServerHandler> _Nullable)handler platform:(id<LibboxPlatformInterface> _Nullable)platform error:(NSError* _Nullable* _Nullable)error;",
    "- (BOOL)bindNative:(LibboxCommandServer* _Nullable)server error:(NSError* _Nullable* _Nullable)error;",
    "- (BOOL)run:(LibboxCommandServer* _Nullable)server error:(NSError* _Nullable* _Nullable)error;",
    "- (BOOL)healthy;",
    "- (NSString* _Nonnull)progressJSON;",
    "- (void)networkChanged;",
    "- (BOOL)close:(NSError* _Nullable* _Nullable)error;",
    "- (BOOL)nativeClosed;",
    "- (BOOL)retainsServerCleanup:(LibboxCommandServer* _Nullable)server;",
    "- (NSString* _Nonnull)mtuProfile;",
)
C_FUNCTIONS = (
    ("LibboxNewRouterNodeChainSOCKS", "LibboxRouterNodeChainSOCKS* _Nullable", ("NSString* _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainSOCKSNewCommandServer", "LibboxCommandServer* _Nullable", ("LibboxRouterNodeChainSOCKS* _Nullable", "id<LibboxCommandServerHandler> _Nullable", "id<LibboxPlatformInterface> _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainImportedSOCKSMemberInput", "NSString* _Nonnull", ("NSString* _Nullable", "NSString* _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainSOCKSNewHopMeasurement", "LibboxRouterHopMeasurement* _Nullable", ("LibboxRouterNodeChainSOCKS* _Nullable", "LibboxCommandServer* _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainSOCKSNewMTU", "LibboxRouterMTU* _Nullable", ("LibboxRouterNodeChainSOCKS* _Nullable", "LibboxCommandServer* _Nullable", "id<LibboxRouterMTUPlatform> _Nullable", "NSError* _Nullable* _Nullable")),
)
# CONNECT has its own published API inventory. Do not inherit future SOCKS
# benchmark factories or methods through a textual transport substitution.
CONNECT_C_FUNCTIONS = (
    ("LibboxNewRouterNodeChainCONNECT", "LibboxRouterNodeChainCONNECT* _Nullable", ("NSString* _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainCONNECTNewCommandServer", "LibboxCommandServer* _Nullable", ("LibboxRouterNodeChainCONNECT* _Nullable", "id<LibboxCommandServerHandler> _Nullable", "id<LibboxPlatformInterface> _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainImportedCONNECTMemberInput", "NSString* _Nonnull", ("NSString* _Nullable", "NSString* _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainCONNECTNewHopMeasurement", "LibboxRouterHopMeasurement* _Nullable", ("LibboxRouterNodeChainCONNECT* _Nullable", "LibboxCommandServer* _Nullable", "NSError* _Nullable* _Nullable")),
    ("LibboxRouterNodeChainCONNECTNewMTU", "LibboxRouterMTU* _Nullable", ("LibboxRouterNodeChainCONNECT* _Nullable", "LibboxCommandServer* _Nullable", "id<LibboxRouterMTUPlatform> _Nullable", "NSError* _Nullable* _Nullable")),
)
C_FUNCTIONS += CONNECT_C_FUNCTIONS
SHARED_PACKET_SOURCES = (
    "App/Models.swift",
    "App/IOSNodeChainSOCKSCapture.swift",
    "App/IOSNodeChainCONNECTCapture.swift",
    "App/IOSNodeChainProviderCapture.swift",
)

def sha_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()

def regular(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size<=0:
        raise ValueError("Original iOS artifact is absent or redirected: "+path.name)
    return path

def contained(root,relative):
    root=Path(root).resolve(strict=True);relative=Path(relative)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("SDK slice escaped its original framework")
    path=root/relative
    try:resolved=path.resolve(strict=True)
    except OSError as error:raise ValueError("Original SDK slice is missing") from error
    if resolved!=root and root not in resolved.parents:
        raise ValueError("SDK slice is redirected outside its framework")
    return path

def tree_snapshot(root):
    root=Path(root).resolve(strict=True)
    if not root.is_dir():raise ValueError("Original artifact directory is missing")
    found={}
    for path in sorted(root.rglob("*")):
        name=str(path.relative_to(root))
        if path.is_symlink():
            contained(root,name)
            found[name]={"symlink":os.readlink(path)}
        elif path.is_file():
            found[name]={"bytes":path.stat().st_size,"sha256":sha_file(path)}
        elif not path.is_dir():raise ValueError("Unsupported native artifact member")
    if not found:raise ValueError("Original artifact tree is empty")
    return found

def require_headers(raw):
    text=raw.decode("utf-8","strict")
    for kind in ("SOCKS", "CONNECT"):
        owner_decl=PLAN_DECL.replace("SOCKS",kind)
        owners=re.findall(r"^"+re.escape(owner_decl)+r"\n(.*?)^@end",text,re.M|re.S)
        if len(owners)!=1:raise ValueError("Generated typed "+kind+" owner is absent or ambiguous")
        lines=[line.strip() for line in owners[0].splitlines()]
        for method in PLAN_METHODS:
            selector=method.split(")",1)[1].split(":",1)[0].rstrip(";")
            matching=[line for line in lines if re.match(r"^- \([^)]*\)"+re.escape(selector)+r"(?=:|;)",line)]
            if matching!=[method]:raise ValueError("Generated typed "+kind+" owner selector differs: "+selector)
    declarations=[]
    for name,result,arguments in C_FUNCTIONS:
        matches=re.findall(r"^FOUNDATION_EXPORT (.+?) "+re.escape(name)+r"\((.*?)\);$",text,re.M)
        if len(matches)!=1 or matches[0][0]!=result:
            raise ValueError("Generated typed C factory changed: "+name)
        # Parameter spelling is generator output; type/order and nullability
        # are the ABI. The exact original declaration is retained in receipt.
        actual=[]
        for argument in matches[0][1].split(","):
            value=argument.strip()
            if not re.fullmatch(r".+ [A-Za-z_][A-Za-z_0-9]*",value):
                raise ValueError("Generated typed factory parameter is malformed")
            actual.append(value.rsplit(" ",1)[0])
        if tuple(actual)!=arguments:raise ValueError("Generated typed C factory arguments changed: "+name)
        declarations.append("FOUNDATION_EXPORT "+matches[0][0]+" "+name+"("+matches[0][1]+");")
    return {"owners":[{"owner":PLAN_DECL.replace("SOCKS",kind),"methods":list(PLAN_METHODS)} for kind in ("SOCKS","CONNECT")],"owner":PLAN_DECL,"methods":list(PLAN_METHODS),"factories":declarations,"header_sha256":hashlib.sha256(raw).hexdigest()}

def framework_slices(root):
    root=Path(root)
    meta=plistlib.loads(regular(root/"Info.plist").read_bytes())
    libraries=meta.get("AvailableLibraries")
    if not isinstance(libraries,list) or not libraries:raise ValueError("Native SDK has no slices")
    identities=set();platforms=set();out=[]
    for item in libraries:
        if not isinstance(item,dict) or item.get("SupportedPlatform")!="ios":
            raise ValueError("Native SDK contains a foreign platform")
        identity=item.get("LibraryIdentifier");variant=item.get("SupportedPlatformVariant","")
        arches=item.get("SupportedArchitectures")
        if not isinstance(identity,str) or not identity or identity in identities or variant not in ("","simulator"):
            raise ValueError("Native SDK repeats or changes a platform slice")
        if not isinstance(arches,list) or not arches or len(arches)!=len(set(arches)) or not set(arches)<={"arm64","x86_64"} or (not variant and set(arches)!={"arm64"}):
            raise ValueError("Native SDK platform architecture changed")
        identities.add(identity);platforms.add(variant)
        location=contained(root,Path(identity)/(item.get("LibraryPath") or "Libbox.framework"))
        if not location.is_dir() or location.name!="Libbox.framework":
            raise ValueError("Original gomobile framework layout changed")
        binary=regular(contained(root,location.relative_to(root)/"Libbox"))
        header=regular(contained(root,location.relative_to(root)/"Headers/Libbox.objc.h"))
        module=regular(contained(root,location.relative_to(root)/"Modules/module.modulemap"))
        out.append({"identity":identity,"variant":variant,"architectures":sorted(arches),"binary":binary,"header":header,"module":module})
    if platforms!={"","simulator"}:raise ValueError("Original iOS and simulator slices are required")
    return out

def require_plist(path,sha,family,bundle):
    value=plistlib.loads(regular(path).read_bytes())
    expected={"RouterVPNSourceSHA":sha,"RouterVPNSourceRepository":"Eabusham2/router-vpn","RouterVPNArtifactFamily":family,"CFBundleIdentifier":bundle}
    if not isinstance(value,dict) or any(value.get(k)!=v for k,v in expected.items()):
        raise ValueError("Actual iOS package source or identity changed")
    if family=="ios-packet-tunnel":
        ext=value.get("NSExtension",{})
        if ext.get("NSExtensionPointIdentifier")!="com.apple.networkextension.packet-tunnel" or ext.get("NSExtensionPrincipalClass")!="RouterVPNPacketTunnel.PacketTunnelProvider":
            raise ValueError("Original PacketTunnel extension changed")
    elif set(value.get("UIDeviceFamily",[]))!={1,2}:
        raise ValueError("Original iPhone/iPad device families changed")
    return expected

def require_project_sources(text):
    match=re.search(r"^  RouterVPNPacketTunnel:\n(.*?)(?=^  [A-Za-z]|\Z)",text,re.M|re.S)
    if not match:raise ValueError("Original PacketTunnel target is missing")
    line=re.search(r"^    sources: \[(.*?)\]$",match[1],re.M)
    if not line:raise ValueError("Original PacketTunnel explicit source inventory changed")
    names=[v.strip() for v in line[1].split(",")]
    for name in SHARED_PACKET_SOURCES:
        if names.count(name)!=1:raise ValueError("Typed PacketTunnel shared source is not compiled: "+name)
    if names.count("PacketTunnel")!=1:raise ValueError("Original complete PacketTunnel source folder is missing")
    return names

def child_environment(original,sha):
    if not HEX40.fullmatch(sha):raise ValueError("Exact source identity required")
    env=dict(original)
    env.update(GITHUB_SHA=sha,ROUTER_VPN_SOURCE_SHA=sha,GITHUB_REPOSITORY="Eabusham2/router-vpn",
               PYTHONDONTWRITEBYTECODE="1",CGO_ENABLED="1",GOWORK="off",GOTOOLCHAIN="local",GOFLAGS="")
    return env

def selection(source,sha,output):
    if not HEX40.fullmatch(sha):raise ValueError("Exact source SHA required")
    path=output.parent/"selection.json"
    if path.is_symlink() or not path.is_file():raise ValueError("Original trusted iOS selection is missing")
    raw=path.read_bytes();record=json.loads(raw)
    if record.get("schema")!=1 or record.get("suite")!=SUITE or record.get("source_sha")!=sha or record.get("validation_scope")!="read-only-source-candidate":
        raise ValueError("iOS SDK suite or selected source changed")
    for key in ("validator_sha","validator_tree","base_sha","base_tree","source_sha","source_tree"):
        if not isinstance(record.get(key),str) or not HEX40.fullmatch(record[key]):raise ValueError("SDK selection lost Git identity")
    for root,commit,tree in ((source,sha,record["source_tree"]),(ROOT,record["validator_sha"],record["validator_tree"])):
        if CORE.git(root,"rev-parse","HEAD").decode().strip()!=commit or CORE.git(root,"rev-parse","HEAD^{tree}").decode().strip()!=tree or CORE.git(root,"status","--porcelain","--untracked-files=all"):
            raise ValueError("Original iOS SDK source checkout changed")
    return record,raw


def require_checkout(root, sha, tree, expected, *, generated=False):
    """Require exact tracked bytes/modes; only the owned build may contain outputs."""
    if (CORE.git(root,"rev-parse","HEAD").decode().strip()!=sha or
            CORE.git(root,"rev-parse","HEAD^{tree}").decode().strip()!=tree or
            CORE.snapshot(root)!=expected):
        raise ValueError("Original SDK checkout source identity changed")
    CORE.git(root,"-c","core.fileMode=true","diff","--exit-code","--")
    CORE.git(root,"diff","--cached","--exit-code","--")
    arguments=["status","--porcelain","--untracked-files=all"]
    if not generated:arguments.append("--ignored=matching")
    if CORE.git(root,*arguments):
        raise ValueError("Original SDK checkout is not clean")

class OwnedBuildCheckout:
    """One isolated, non-shared clone; never remove it while child join is uncertain."""
    def __init__(self, source, output, parent=None):
        source=Path(source).resolve(strict=True)
        forbidden=(source,Path(output).absolute().parent.resolve(strict=True))
        parent=Path(parent or os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()).resolve(strict=True)
        if any(parent==path or path in parent.parents for path in forbidden):
            raise ValueError("SDK build ownership must be outside candidate and uploaded output")
        self.root=Path(tempfile.mkdtemp(prefix="routervpn-ios-sdk-build-",dir=parent))
        state=self.root.lstat();self.identity=(state.st_dev,state.st_ino)
        self.checkout=self.root/"source";self.joined=True;self.verified=False

    def execute(self, command, cwd, env, log, bound):
        if not self.joined:raise ValueError("SDK original child has not proved its join")
        self.joined=False
        result=CORE.execute(command,cwd,env,log,bound)
        self.joined=result[2]
        return result

    def populate(self, source, sha, tree, before, run):
        require_checkout(source,sha,tree,before)
        run("source-clone",["git","clone","--no-local","--no-hardlinks","--no-checkout","--",
                           Path(source).as_uri(),str(self.checkout)],60,self.root)
        run("source-detach",["git","checkout","--detach",sha],30,self.checkout)
        gitdir=self.checkout/".git"
        if gitdir.is_symlink() or not gitdir.is_dir() or (gitdir/"objects/info/alternates").exists():
            raise ValueError("SDK build clone shares or redirects its original object database")
        require_checkout(self.checkout,sha,tree,before)
        require_checkout(source,sha,tree,before)
        self.verified=True
        return self.checkout

    def cleanup(self):
        if not self.joined:return False
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("SDK build directory ownership changed before cleanup")
        state=self.root.lstat()
        if (state.st_dev,state.st_ino)!=self.identity:
            raise ValueError("SDK build directory identity changed before cleanup")
        shutil.rmtree(self.root)
        return not self.root.exists()

def validate(source,sha,output):
    source=Path(source).resolve(strict=True);output=Path(output).absolute()
    if output.is_symlink():raise ValueError("SDK output may not be redirected")
    output=output.parent.resolve(strict=True)/output.name
    if output.exists() or output.is_symlink() or output==source or source in output.parents:
        raise ValueError("SDK output must be fresh and outside candidate")
    selected,selection_bytes=selection(source,sha,output);before=CORE.snapshot(source)
    if platform.system()!="Darwin" or platform.machine() not in ("x86_64","arm64"):
        raise ValueError("iOS SDK gate requires a native macOS host")
    for tool in ("go","swiftc","xcrun","xcodebuild","xcodegen","git","rustup","clang","make","autoconf","automake","glibtool","pkg-config","perl","patch","ditto","zip","unzip"):
        if not shutil.which(tool):raise ValueError("Original Apple build dependency is missing: "+tool)
    env=child_environment(os.environ,sha)
    architecture={"x86_64":"amd64","arm64":"arm64"}[platform.machine()]
    go=subprocess.check_output(["go","version"],text=True,env=env,timeout=15).strip()
    if go!="go version go1.26.3 darwin/"+architecture:raise ValueError("Original pinned Go1.26.3 changed")
    require_checkout(source,sha,selected["source_tree"],before)
    require_project_sources(regular(source/"ios/RouterVPN/project.yml").read_text())
    output.mkdir(mode=0o700);(output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    receipt=dict(schema=1,suite=SUITE,selection=selected,status="running",go_version=go,
        source_file_count=len(before),source_closure_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
        scope="actual-generated-Apple-SDK-and-shipping-iOS-iPadOS-app-and-PacketTunnel",signing="unsigned-resignable",
        generated_sdk_accepted=False,shipping_swift_compiled=False,packet_tunnel_build_accepted=False,
        device_accepted=False,native_traffic_accepted=False,visible_editor_device_accepted=False,
        native_mtu_device_accepted=False,source_file_mutation_allowed=False,phases=[],
        trusted_executor_sha256=sha_file(CORE_PATH),build_checkout_removed=False,
        build_checkout_source_verified=False,build_children_joined=True)
    owned=None;build_source=None;failure=None
    def save():(output/"progress.json").write_text(json.dumps(receipt,indent=2)+"\n")
    def run(name,command,bound,cwd=None):
        log=output/(name+".log");start=time.monotonic()
        executor=owned.execute if owned is not None else CORE.execute
        code,timed_out,joined=executor(command,cwd or build_source or source,env,log,bound)
        receipt["phases"].append(dict(name=name,command=command,seconds=time.monotonic()-start,outer_seconds=bound,
            exit=code,timed_out=timed_out,process_group_joined=joined,log_sha256=sha_file(log)));save()
        if code!=0 or timed_out or not joined:raise ValueError("Original Apple SDK phase failed or did not join: "+name)
        return log.read_bytes()
    save()
    try:
        owned=OwnedBuildCheckout(source,output)
        receipt["build_checkout"]=str(owned.checkout);save()
        build_source=owned.populate(source,sha,selected["source_tree"],before,run)
        receipt["build_checkout_source_verified"]=True
        receipt["build_checkout_sha"]=sha;receipt["build_checkout_tree"]=selected["source_tree"]
        (output/"build-source-before.json").write_text(json.dumps(CORE.snapshot(build_source),sort_keys=True)+"\n")
        app_root=build_source/"ios/RouterVPN";framework=app_root/".deps/Libbox.xcframework"
        receipt["xcode_version"]=run("xcode-version",["xcodebuild","-version"],30).decode("utf-8","strict").strip()
        receipt["swift_version"]=run("swift-version",["swiftc","--version"],30).decode("utf-8","strict").strip()
        if not re.search(r"Apple Swift version 6\.",receipt["swift_version"]):raise ValueError("Shipping Swift6 is required")
        run("original-provenance-order",[sys.executable,str(build_source/"deploy/test_ios_provenance_order.py"),"--native"],300)
        run("original-wireguard-kit",["sh",str(app_root/"prepare-wireguard-kit.sh")],900)
        kit=app_root/".deps/wireguard-apple"
        run("original-timer-preparation",[sys.executable,str(build_source/"deploy/test_apple_amnezia_timer_preparation.py"),"--kit",str(kit)],300)
        run("original-gomobile-sdk",["bash",str(app_root/"prepare-libbox.sh")],SDK_SECONDS)
        framework_before=tree_snapshot(framework);slices=framework_slices(framework)
        receipt["generated_api"]=[];receipt["sdk_slices"]=[]
        headers=output/"generated-headers";headers.mkdir()
        for index,item in enumerate(slices):
            info=require_headers(item["header"].read_bytes());info["slice"]=item["identity"]
            receipt["generated_api"].append(info)
            captured=headers/(item["identity"]+".objc.h");shutil.copyfile(item["header"],captured)
            actual=run("sdk-architectures-"+str(index),["xcrun","lipo","-archs",str(item["binary"])],30).decode().split()
            if sorted(actual)!=item["architectures"]:raise ValueError("SDK binary architectures differ from its manifest")
            receipt["sdk_slices"].append(dict(identity=item["identity"],variant=item["variant"],architectures=actual,binary_sha256=sha_file(item["binary"]),header_sha256=sha_file(item["header"]),module_sha256=sha_file(item["module"])))
        run("original-xcodegen",["xcodegen","generate"],120,app_root)
        derived=app_root/"build/DerivedData"
        run("original-xcode-build",["xcodebuild","-project","RouterVPN.xcodeproj","-scheme","RouterVPN","-configuration","Release","-sdk","iphoneos","-destination","generic/platform=iOS","-derivedDataPath",str(derived),"CODE_SIGNING_ALLOWED=NO","CODE_SIGNING_REQUIRED=NO","DEVELOPMENT_TEAM=","ROUTER_VPN_SOURCE_SHA="+sha,"INFOPLIST_KEY_RouterVPNSourceSHA="+sha,"build"],XCODE_SECONDS,app_root)
        app=derived/"Build/Products/Release-iphoneos/RouterVPN.app";extension=app/"PlugIns/RouterVPNPacketTunnel.appex"
        app_before=tree_snapshot(app)
        receipt["package_identity"]=[
            require_plist(app/"Info.plist",sha,"ios-app","com.eabusham.routervpn"),
            require_plist(extension/"Info.plist",sha,"ios-packet-tunnel","com.eabusham.routervpn.PacketTunnel")]
        for index,binary in enumerate((regular(app/"RouterVPN"),regular(extension/"RouterVPNPacketTunnel"),regular(derived/"Build/Products/Release-iphoneos/libwg-go.a"))):
            actual=run("shipping-architectures-"+str(index),["xcrun","lipo","-archs",str(binary)],30).decode().split()
            if actual!=["arm64"]:raise ValueError("Shipping iOS executable has wrong architecture")
        if CORE.git(kit,"rev-parse","HEAD").decode().strip()!=WG_PIN or regular(kit/"Package.swift").read_text().splitlines()[0]!="// swift-tools-version:5.5" or regular(app_root/".deps/wireguard-apple.pin").read_text().strip()!=WG_PIN:
            raise ValueError("Original Apple WireGuardKit source changed")
        run("original-timer-readback",[sys.executable,str(build_source/"deploy/prepare-apple-amnezia-timers.py"),str(kit),"--verify"],120)
        run("canonical-sdk-readback",["bash",str(app_root/"prepare-libbox.sh")],READBACK_SECONDS)
        if tree_snapshot(framework)!=framework_before or tree_snapshot(app)!=app_before:
            raise ValueError("SDK readback rebuilt or replaced the linked app/framework")
        if regular(app_root/".deps/Libbox.xcframework.pin").read_text().strip()!=LIBBOX_PIN:
            raise ValueError("Original Libbox native source pin changed")
        run("original-native-tor-link",[sys.executable,str(ROOT/"deploy/verify-mobile-tor-link.py"),"--native-package",str(app_root/".deps/tor-native"),"--apple-app",str(app)],180)
        artifacts=output/"artifacts";artifacts.mkdir()
        package=output/"package";payload=package/"Payload";payload.mkdir(parents=True)
        run("capture-unsigned-app",["ditto",str(app),str(payload/"RouterVPN.app")],180)
        if tree_snapshot(payload/"RouterVPN.app")!=app_before:raise ValueError("Captured unsigned app differs")
        ipa=artifacts/"RouterVPN-native-unsigned-resignable.ipa"
        run("package-unsigned-ipa",["zip","-qry",str(ipa),"Payload"],180,package)
        run("original-ipa-container",["unzip","-tq",str(ipa)],120)
        run("original-mobile-provenance",[sys.executable,str(ROOT/"server/scripts/mobile-artifact-provenance.py"),"--name","router-vpn-ios.ipa","--path",str(ipa),"--sha",sha,"--repo","Eabusham2/router-vpn"],120)
        receipt["artifacts"]=[]
        provenance=output/"provenance";provenance.mkdir()
        for path in (ipa,app_root/".deps/Libbox.xcframework.pin",app_root/".deps/Libbox.routervpn-openvpn.sha256",app_root/".deps/libbox-LICENSE.txt",app_root/".deps/xray-core-LICENSE.txt",app_root/".deps/native-amneziawg-LICENSE.txt",app_root/".deps/rosenpass-native/source.json"):
            path=regular(path);preserved=path
            if path!=ipa:
                preserved=provenance/path.relative_to(app_root)
                preserved.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,preserved)
                if sha_file(preserved)!=sha_file(path):raise ValueError("Captured native provenance differs")
            receipt["artifacts"].append(dict(path=str(preserved),original_path=str(path),bytes=path.stat().st_size,sha256=sha_file(path)))
        (output/"sdk-files.json").write_text(json.dumps(framework_before,sort_keys=True)+"\n")
        (output/"app-files.json").write_text(json.dumps(app_before,sort_keys=True)+"\n")
        require_checkout(build_source,sha,selected["source_tree"],before,generated=True)
        require_checkout(source,sha,selected["source_tree"],before)
        if (output.parent/"selection.json").read_bytes()!=selection_bytes or selection(source,sha,output)[0]!=selected:
            raise ValueError("Original trusted iOS SDK selection changed")
        if tree_snapshot(framework)!=framework_before or tree_snapshot(app)!=app_before:
            raise ValueError("Original compiled app/SDK identity changed")
        receipt["build_completed"]=True
    except BaseException as error:
        failure=error;receipt.update(status="failed",error=str(error))
    finally:
        try:
            require_checkout(source,sha,selected["source_tree"],before)
            if (output.parent/"selection.json").read_bytes()!=selection_bytes:
                raise ValueError("Original trusted iOS SDK selection changed")
            if owned is not None and owned.verified:
                require_checkout(owned.checkout,sha,selected["source_tree"],before,generated=True)
            receipt["source_unchanged"]=True
        except BaseException as error:
            receipt.update(status="failed",identity_error=str(error))
            if failure is None:failure=error
        try:
            if owned is not None:
                receipt["build_children_joined"]=owned.joined
                receipt["build_checkout_removed"]=owned.cleanup()
                if not receipt["build_checkout_removed"]:
                    raise ValueError("SDK build checkout retained because child join is unproved")
        except BaseException as error:
            receipt.update(status="failed",cleanup_error=str(error))
            if failure is None:failure=error
        save()
    if failure is not None:raise failure
    receipt.update(status="passed",generated_sdk_accepted=True,shipping_swift_compiled=True,packet_tunnel_build_accepted=True,ipa_verified=True)
    save()
    (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    return receipt

def self_test():
    def header():
        declarations=["FOUNDATION_EXPORT "+result+" "+name+"("+", ".join(arg+" p"+str(i) for i,arg in enumerate(args))+");" for name,result,args in C_FUNCTIONS]
        return ("".join(PLAN_DECL.replace("SOCKS",kind)+"\n"+"\n".join(PLAN_METHODS)+"\n@end\n" for kind in ("SOCKS","CONNECT"))+"\n".join(declarations)+"\n").encode()
    def framework(root):
        libs=[]
        for identity,variant,arches in (("ios-arm64","",["arm64"]),("ios-arm64_x86_64-simulator","simulator",["arm64","x86_64"])):
            location=root/identity/"Libbox.framework";(location/"Headers").mkdir(parents=True);(location/"Modules").mkdir()
            (location/"Libbox").write_bytes(b"original-binary");(location/"Headers/Libbox.objc.h").write_bytes(header());(location/"Modules/module.modulemap").write_text("framework module Libbox {}")
            entry=dict(LibraryIdentifier=identity,LibraryPath="Libbox.framework",SupportedPlatform="ios",SupportedArchitectures=arches)
            if variant:entry["SupportedPlatformVariant"]=variant
            libs.append(entry)
        (root/"Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries":libs}))
        return libs

    def git_fixture(parent):
        source=parent/"candidate";source.mkdir()
        subprocess.run(["git","init","-q",str(source)],check=True)
        for key,value in (("user.name","SDK fixture"),("user.email","fixture@example.invalid")):
            CORE.git(source,"config",key,value)
        (source/".gitignore").write_text(".deps/\nbuild/\n*.xcodeproj/\n")
        (source/"source.txt").write_text("original source\n")
        script=source/"builder.sh";script.write_text("#!/bin/sh\nexit 0\n");script.chmod(0o755)
        CORE.git(source,"add",".");CORE.git(source,"commit","-qm","original source")
        (source/"source.txt").write_text("original exact candidate\n")
        CORE.git(source,"commit","-qam","selected candidate")
        sha=CORE.git(source,"rev-parse","HEAD").decode().strip()
        tree=CORE.git(source,"rev-parse","HEAD^{tree}").decode().strip()
        output=parent/"evidence/tests";output.mkdir(parents=True)
        return source,sha,tree,CORE.snapshot(source),output

    def original_runner(owner,output):
        def run(name,command,bound,cwd):
            log=output/(name+".log")
            result=owner.execute(command,cwd,os.environ.copy(),log,bound)
            if result!=(0,False,True):raise ValueError("Owned original command failed or did not join")
            return log.read_bytes()
        return run

    class Gate(unittest.TestCase):
        def test_actual_header_parser_requires_every_original_selector_and_factory(self):
            valid=header();self.assertEqual(len(require_headers(valid)["methods"]),15)
            for method in PLAN_METHODS:
                connect=PLAN_DECL.replace("SOCKS","CONNECT")+"\n"+"\n".join(PLAN_METHODS)+"\n@end\n"
                with self.assertRaises(ValueError):require_headers(valid.replace(connect.encode(),connect.replace(method+"\n", "",1).encode()))
                with self.subTest(method=method):
                    with self.assertRaises(ValueError):require_headers(valid.replace((method+"\n").encode(),b"",1))
                    with self.assertRaises(ValueError):require_headers(valid.replace(method.encode(),(method+"\n"+method).encode(),1))
            for name,result,args in C_FUNCTIONS:
                declaration="FOUNDATION_EXPORT "+result+" "+name+"("+", ".join(a+" p"+str(i) for i,a in enumerate(args))+");"
                with self.subTest(factory=name):
                    with self.assertRaises(ValueError):require_headers(valid.replace(declaration.encode(),b"",1))
                    with self.assertRaises(ValueError):require_headers(valid+declaration.encode()+b"\n")
        def test_foreign_owner_handler_order_nullability_and_untyped_mtu_rejected(self):
            valid=header()
            for old,new in ((PLAN_DECL,PLAN_DECL.replace("SOCKS","Execution")),
                    ("id<LibboxCommandServerHandler> _Nullable)handler platform:(id<LibboxPlatformInterface>","id<LibboxPlatformInterface> _Nullable)handler platform:(id<LibboxCommandServerHandler>"),
                    ("LibboxRouterMTU* _Nullable","LibboxRouterMTU* _Nonnull"),
                    ("LibboxRouterNodeChainSOCKS* _Nullable p0, LibboxCommandServer*","LibboxRouterNodeChainExecution* _Nullable p0, LibboxCommandServer*")):
                with self.subTest(old=old):
                    with self.assertRaises(ValueError):require_headers(valid.replace(old.encode(),new.encode()))
        def test_every_platform_slice_and_architecture_is_required(self):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);libs=framework(root)
                self.assertEqual(len(framework_slices(root)),2)
                for bad in ([libs[0]],[libs[1]],libs+[libs[0]],[dict(libs[0],SupportedPlatform="macos"),libs[1]],[dict(libs[0],SupportedArchitectures=["x86_64"]),libs[1]],[dict(libs[0],LibraryIdentifier="../escape"),libs[1]]):
                    with self.subTest(bad=bad):
                        (root/"Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries":bad}))
                        with self.assertRaises((ValueError,FileNotFoundError)):framework_slices(root)
        def test_missing_binary_header_and_module_refused(self):
            for member in ("Libbox","Headers/Libbox.objc.h","Modules/module.modulemap"):
                with self.subTest(member=member),tempfile.TemporaryDirectory() as temporary:
                    root=Path(temporary);framework(root);(root/"ios-arm64/Libbox.framework"/member).unlink()
                    with self.assertRaises(ValueError):framework_slices(root)
        def test_snapshot_detects_changed_and_redirected_original_artifact(self):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)/"root";root.mkdir();p=root/"one";p.write_bytes(b"one")
                before=tree_snapshot(root);p.write_bytes(b"two");self.assertNotEqual(tree_snapshot(root),before)
                p.unlink();p.symlink_to(Path(temporary)/"outside");(Path(temporary)/"outside").write_bytes(b"outside")
                with self.assertRaises(ValueError):tree_snapshot(root)
        def test_plist_source_family_original_extension_and_ipad_are_mandatory(self):
            with tempfile.TemporaryDirectory() as temporary:
                p=Path(temporary)/"Info.plist";sha="a"*40
                for family,bundle in (("ios-app","com.eabusham.routervpn"),("ios-packet-tunnel","com.eabusham.routervpn.PacketTunnel")):
                    good=dict(RouterVPNSourceSHA=sha,RouterVPNSourceRepository="Eabusham2/router-vpn",RouterVPNArtifactFamily=family,CFBundleIdentifier=bundle,UIDeviceFamily=[1,2],NSExtension={"NSExtensionPointIdentifier":"com.apple.networkextension.packet-tunnel","NSExtensionPrincipalClass":"RouterVPNPacketTunnel.PacketTunnelProvider"})
                    p.write_bytes(plistlib.dumps(good));require_plist(p,sha,family,bundle)
                    changes={"RouterVPNSourceSHA":"b"*40,"RouterVPNSourceRepository":"foreign/repo","RouterVPNArtifactFamily":"ios-app" if family!="ios-app" else "ios-packet-tunnel","CFBundleIdentifier":"foreign"}
                    changes["UIDeviceFamily" if family=="ios-app" else "NSExtension"]=[1] if family=="ios-app" else {}
                    for key,value in changes.items():
                        with self.subTest(family=family,key=key):
                            p.write_bytes(plistlib.dumps(dict(good,**{key:value})))
                            with self.assertRaises(ValueError):require_plist(p,sha,family,bundle)
        def test_exact_packet_tunnel_dependency_closure(self):
            good="targets:\n  RouterVPNPacketTunnel:\n    sources: [PacketTunnel, "+", ".join(SHARED_PACKET_SOURCES)+"]\n"
            require_project_sources(good)
            for source in SHARED_PACKET_SOURCES:
                with self.subTest(source=source):
                    with self.assertRaises(ValueError):require_project_sources(good.replace(", "+source,""))
                    with self.assertRaises(ValueError):require_project_sources(good.replace(source,source+", "+source))
        def test_environment_preserves_selected_source_without_native_or_signing_override(self):
            source="a"*40
            actual=child_environment({"GITHUB_SHA":"b"*40,"UNCHANGED":"yes"},source)
            self.assertEqual(actual["GITHUB_SHA"],source);self.assertEqual(actual["ROUTER_VPN_SOURCE_SHA"],source);self.assertEqual(actual["UNCHANGED"],"yes")
            self.assertEqual(actual["GOFLAGS"],"");self.assertEqual(actual["GOTOOLCHAIN"],"local")
            with self.assertRaises(ValueError):child_environment({},source.upper())

        def test_independent_exact_git_clone_keeps_candidate_pristine(self):
            with tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);source,sha,tree,before,output=git_fixture(parent)
                owner=OwnedBuildCheckout(source,output,parent)
                try:
                    build=owner.populate(source,sha,tree,before,original_runner(owner,output))
                    self.assertEqual(CORE.snapshot(build),before)
                    self.assertEqual(CORE.git(build,"rev-list","--count","HEAD"),b"2\n")
                    self.assertEqual((build/"builder.sh").stat().st_mode & 0o111,0o111)
                    source_objects={(p.stat().st_dev,p.stat().st_ino) for p in (source/".git/objects").rglob("*") if p.is_file()}
                    clone_objects={(p.stat().st_dev,p.stat().st_ino) for p in (build/".git/objects").rglob("*") if p.is_file()}
                    self.assertTrue(source_objects and clone_objects)
                    self.assertFalse(source_objects & clone_objects,"build shared original Git object inodes")
                    require_checkout(source,sha,tree,before)
                finally:self.assertTrue(owner.cleanup())
                self.assertTrue((source/"source.txt").is_file())
                self.assertTrue((output/"source-clone.log").is_file())

        def test_generated_outputs_allowed_only_in_owned_clone(self):
            with tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);source,sha,tree,before,output=git_fixture(parent)
                owner=OwnedBuildCheckout(source,output,parent)
                try:
                    build=owner.populate(source,sha,tree,before,original_runner(owner,output))
                    for name in (".deps","build","RouterVPN.xcodeproj"):
                        (build/name).mkdir();(build/name/"generated").write_text("generated")
                    require_checkout(build,sha,tree,before,generated=True)
                    require_checkout(source,sha,tree,before)
                    with self.assertRaises(ValueError):require_checkout(build,sha,tree,before)
                    (source/".deps").mkdir();(source/".deps/generated").write_text("must reject")
                    with self.assertRaises(ValueError):require_checkout(source,sha,tree,before)
                    shutil.rmtree(source/".deps")
                    require_checkout(source,sha,tree,before)
                finally:self.assertTrue(owner.cleanup())

        def test_clone_rejects_tracked_bytes_mode_index_and_head_changes(self):
            for change in ("bytes","mode","index","head","symlink","untracked"):
                with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                    parent=Path(temporary);source,sha,tree,before,output=git_fixture(parent)
                    owner=OwnedBuildCheckout(source,output,parent)
                    try:
                        build=owner.populate(source,sha,tree,before,original_runner(owner,output))
                        if change=="bytes":(build/"source.txt").write_text("changed")
                        elif change=="mode":
                            CORE.git(build,"config","core.fileMode","false")
                            (build/"builder.sh").chmod(0o644)
                        elif change=="index":CORE.git(build,"update-index","--chmod=-x","builder.sh")
                        elif change=="head":CORE.git(build,"checkout","--detach","HEAD~1")
                        elif change=="symlink":
                            (build/"source.txt").unlink();(build/"source.txt").symlink_to(source/"source.txt")
                        else:(build/"unowned").write_text("unowned")
                        with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                            require_checkout(build,sha,tree,before,generated=True)
                        require_checkout(source,sha,tree,before)
                    finally:self.assertTrue(owner.cleanup())

        def test_joined_failed_build_retains_log_and_removes_only_owned_clone(self):
            with tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);source,sha,tree,before,output=git_fixture(parent)
                owner=OwnedBuildCheckout(source,output,parent)
                build=owner.populate(source,sha,tree,before,original_runner(owner,output))
                log=output/"failed-build.log"
                result=owner.execute([sys.executable,"-c","print('original failure');raise SystemExit(17)"],
                                     build,os.environ.copy(),log,10)
                self.assertEqual(result,(17,False,True))
                self.assertTrue(owner.cleanup())
                self.assertEqual(log.read_text(),"original failure\n")
                require_checkout(source,sha,tree,before)

        def test_uncertain_join_and_replaced_directory_preserve_cleanup_owner(self):
            with tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);source,sha,tree,before,output=git_fixture(parent)
                owner=OwnedBuildCheckout(source,output,parent)
                owner.populate(source,sha,tree,before,original_runner(owner,output))
                owner.joined=False
                self.assertFalse(owner.cleanup());self.assertTrue(owner.checkout.is_dir())
                with self.assertRaises(ValueError):
                    owner.execute([sys.executable,"-c","raise SystemExit(99)"],owner.checkout,os.environ.copy(),output/"never-started.log",10)
                self.assertFalse((output/"never-started.log").exists())
                # No actual child was acquired for this injected unknown-result branch.
                owner.joined=True
                original=owner.root.with_name(owner.root.name+"-original")
                owner.root.rename(original);owner.root.mkdir();(owner.root/"replacement").write_text("preserve")
                with self.assertRaises(ValueError):owner.cleanup()
                self.assertTrue((owner.root/"replacement").is_file());self.assertTrue(original.is_dir())
                shutil.rmtree(owner.root);original.rename(owner.root)
                self.assertTrue(owner.cleanup())

        def test_candidate_change_during_clone_and_inside_output_build_rejected(self):
            with tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);source,sha,tree,before,output=git_fixture(parent)
                for bad_parent in (source,output,output.parent):
                    with self.subTest(parent=bad_parent),self.assertRaises(ValueError):
                        OwnedBuildCheckout(source,output,bad_parent)
                owner=OwnedBuildCheckout(source,output,parent)
                run=original_runner(owner,output)
                def altered(name,command,bound,cwd):
                    value=run(name,command,bound,cwd)
                    if name=="source-detach":(source/"source.txt").write_text("concurrent source change")
                    return value
                try:
                    with self.assertRaises(ValueError):owner.populate(source,sha,tree,before,altered)
                    self.assertFalse(owner.verified)
                finally:self.assertTrue(owner.cleanup())

        def test_original_process_group_is_joined(self):
            with tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary);log=directory/"child.log"
                code,timed_out,joined=CORE.execute([sys.executable,"-c","print('original iOS SDK executor')"],directory,os.environ.copy(),log,10)
                self.assertEqual((code,timed_out,joined),(0,False,True));self.assertEqual(log.read_text(),"original iOS SDK executor\n")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Gate))
    return 0 if result.wasSuccessful() else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite",choices=[SUITE],default=SUITE)
    parser.add_argument("--source",type=Path);parser.add_argument("--source-sha");parser.add_argument("--output",type=Path)
    parser.add_argument("--self-test",action="store_true");args=parser.parse_args()
    if args.self_test:return self_test()
    if not args.source or not args.source_sha or not args.output:parser.error("--source, --source-sha and --output are required")
    validate(args.source,args.source_sha,args.output)
    print("Actual iOS SDK and unsigned app/PacketTunnel accepted for exact candidate source")
    return 0
if __name__=="__main__":raise SystemExit(main())
