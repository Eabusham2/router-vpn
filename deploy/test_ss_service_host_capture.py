#!/usr/bin/env python3
"""Keep actual generated SS service bytes through shipping host stores/capture.

Android OS/file publication and Apple durable-write/native JSON validation are
explicit boundary doubles reused from existing store fixtures. Production node
stores and final asset-capture methods execute unchanged. Native declaration
schema/node/key authority is covered by the real generator/core consumer suite.
"""
from pathlib import Path
import argparse, importlib.util, os, platform, shutil, subprocess, sys, tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
sys.path.insert(0,str(ROOT/'deploy'))

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def block(text,signature):
 a=text.index(signature);b=text.index('{',a);depth=1;i=b+1
 while depth:
  depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[a:i]

SWIFT_MAIN=r''' static func main() throws {
  defer { UserDefaults.standard.removePersistentDomain(forName: UserDefaults.suite) }
  let raw=try Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[1]))
  let original=try JSONDecoder().decode(ClientBundle.self,from:raw)
  let assets=original.profiles["shadowsocks"]!
  try check("real producer supplies exact two assets",Set(assets.keys)==["sing-box.json","routervpn-ss-service.json"])
  let store=IOSNodeBundleStore.shared;store.reset()
  let linked=try store.link(raw,preserving:nil,prepare:{$0})
  try check("import keeps exact private assets",linked.bundle.profiles==original.profiles)
  let id=linked.bundle.selectedRouterID
  let persisted=store.bundleData(containing:id,current:nil)!
  var restored=try JSONDecoder().decode(ClientBundle.self,from:persisted)
  try check("reload keeps private bytes",restored.profiles==original.profiles)
  restored.routerProfiles[0].name="Restored same node"
  let adopted=try store.restoreConnectionProfile([(original:persisted,updated:restored)],selectedID:id,current:nil,prepare:{$0},validate:{_,_ in})
  try check("restore preserves credentials and declaration",adopted.bundle.profiles==original.profiles)
  var profile=try JSONSerialization.jsonObject(with:JSONEncoder().encode(adopted.bundle.routerProfiles[0])) as! [String:Any]
  profile["multihop_exit_mode"]="shadowsocks"
  for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"] {
   profile["start_layer"]=layer
   let captured=try IOSMultihopStartLayer.capture(profile:profile,profiles:adopted.bundle.profiles)
   if layer=="off" {try check("Off has no invented layer",captured.source==nil)}
   else {
    let value=try JSONSerialization.jsonObject(with:Data(captured.source!.utf8)) as! [String:Any]
    try check("captured layer keeps exact original declaration",value["profile"] as? [String:String]==assets)
    var legacy=adopted.bundle.profiles;legacy["shadowsocks"]!.removeValue(forKey:"routervpn-ss-service.json")
    let retained=try IOSMultihopStartLayer.capture(profile:profile,profiles:legacy)
    let legacyCapture=try JSONSerialization.jsonObject(with:Data(retained.source!.utf8)) as! [String:Any]
    try check("historical one-asset capture remains exact",legacyCapture["profile"] as? [String:String]==legacy["shadowsocks"])
   }
   let final=try SSFinalCapture.importedRouterFinalSource(profile:profile,profiles:adopted.bundle.profiles)
   let files=try JSONSerialization.jsonObject(with:Data(final.files.utf8)) as! [String:String]
   try check("final capture preserves all exact original bytes",files==assets)
  }
  profile["start_layer"]="aes-256-gcm"
  for bad in ["unknown","empty","base64","non-json","array"] {
   var values=adopted.bundle.profiles
   if bad=="unknown" {values["shadowsocks"]!["foreign.json"]="e30="}
   else {values["shadowsocks"]!["routervpn-ss-service.json"] = bad=="empty" ? "" : bad=="base64" ? "@@" : Data((bad=="array" ? "[]" : "invalid").utf8).base64EncodedString()}
   try reject("malformed or unowned asset "+bad) {_ = try IOSMultihopStartLayer.capture(profile:profile,profiles:values)}
  }
  try check("capture left store unchanged",store.bundleData(containing:id,current:nil)==adopted.data)
  print("Apple generated SS store/capture: \(checks) exact byte and refusal checks passed")
 }'''

def apple(bundle,work,mutant=False):
 import test_ios_node_store_transactions as N
 store=(APP/'IOSNodeBundleStore.swift').read_text();model=(APP/'RouterVPNModel.swift').read_text();external=(APP/'RouterVPNModelExternal.swift').read_text()
 body=N.SWIFT.replace(block(N.SWIFT,' static func main()'),SWIFT_MAIN)
 for marker,text,start,end in [('STORE',store,'    func link(','    private func storeDirectory('),('PERSISTED_BUNDLE',model,'    var persistedNodeBundle:','    init()'),('IMPORT',model,'    func importBundle(','    func restoreIOSSpeedLabBundle('),('LATENCY_COMMIT',model,'    func commitNodeLatency(','    func importFromLAN('),('SAVE',model,'    @discardableResult\n    func saveRouter(','    private func apply('),('LEGACY_MODES',model,'    private func legacyLogicalModes(','    func modeCandidates('),('SELECT_AND_LINK',external,'    func selectNode(','    func connectSelectedExternal(')]:
  body=body.replace(' // SHIPPING_'+marker,text[text.index(start):text.index(end)])
 capture=block((ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift').read_text(),'    static func importedRouterFinalSource(')
 body+='\nenum SSFinalCapture { static func error(_ text:String)->NSError {NSError(domain:text,code:1)}\n'+capture+'\n}'
 (work/'Test.swift').write_text(body)
 layer=(APP/'IOSMultihopStartLayer.swift').read_text()
 if mutant:
  old='(assets.count == 1 || assets.count == 2)'
  assert layer.count(old)==1
  layer=layer.replace(old,'assets.count == 1')
 (work/'Layer.swift').write_text(layer)
 swift=shutil.which('swiftc');assert swift,'swiftc required'
 command=[swift,'-swift-version','6','-module-cache-path',str(work/'module-cache')]
 if platform.system()!='Darwin':
  from test_ios_physical_path import LINUX_CRYPTO
  (work/'CryptoKit.swift').write_text(LINUX_CRYPTO)
  subprocess.run(command+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-lcrypto','-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/'libCryptoKit.so')],check=True,timeout=90)
  command+=['-I',str(work),'-L',str(work),'-lCryptoKit','-Xlinker','-rpath','-Xlinker',str(work)]
 subprocess.run(command+[str(APP/'Models.swift'),str(APP/'IOSNodeLatencyStatistics.swift'),str(APP/'IOSSpeedLabOwnership.swift'),str(work/'Layer.swift'),str(work/'Test.swift'),'-o',str(work/'test')],check=True,timeout=90)
 result=subprocess.run([str(work/'test'),str(bundle)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
 if mutant:
  assert result.returncode!=0 and 'Entry Start Layer requires the exact bounded AES assets' in result.stdout,result.stdout[-3000:]
  print('Apple original one-asset guard rejected by actual generated-layer capture',flush=True)
 else:
  assert result.returncode==0,result.stdout[-5000:]
  print(result.stdout,end='',flush=True)

JAVA_MAIN=r'''package com.eabusham.routervpn;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import org.json.*;
public final class SSServiceCapture {
 static int checks;static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
 public static void main(String[] args)throws Exception{
  byte[] original=Files.readAllBytes(Path.of(args[0]));JSONObject source=new JSONObject(new String(original,StandardCharsets.UTF_8));
  JSONObject assets=source.getJSONObject("profiles").getJSONObject("shadowsocks");
  check(assets.length()==2&&assets.has("routervpn-ss-service.json")&&assets.has("sing-box.json"),"actual producer assets missing");
  var context=new android.content.Context(Path.of(args[1]).toFile());var store=new AndroidNodeStore(context);var node=store.importBundle(original);
  check(Arrays.equals(original,Files.readAllBytes(node.file.toPath())),"import changed original bundle bytes");
  var reloaded=new AndroidNodeStore(context);JSONObject updated=new JSONObject(new String(original,StandardCharsets.UTF_8));AndroidProfileSelection.selectedRouterProfile(updated).put("name","same owner policy");byte[] changed=updated.toString().getBytes(StandardCharsets.UTF_8);
  reloaded.applyProfileBundle(node.id,original,changed);check(new JSONObject(Files.readString(node.file.toPath())).getJSONObject("profiles").getJSONObject("shadowsocks").toString().equals(assets.toString()),"apply lost source");
  reloaded.restoreProfileBundle(node.id,original,changed);check(Arrays.equals(original,Files.readAllBytes(node.file.toPath())),"restore lost exact original bytes");
  JSONObject restored=new JSONObject(Files.readString(node.file.toPath()));var entry=new AndroidStandardExitStore.Entry();entry.id="independent-entry";entry.protocol="socks5";entry.server="192.0.2.88";entry.serverPort=1080;entry.expectedPublicIp="203.0.113.88";
  for(String layer:List.of("off","aes-256-gcm","aes-256-gcm+xor-whitening"))for(String mode:List.of("shadowsocks","wg")){
   AndroidProfileSelection.selectedRouterProfile(restored).put("start_layer",layer);
   var capture=AndroidImportedRouterPath.compile(entry,restored,mode,"local").input;
   JSONObject files=new JSONObject(capture.getString("exit_files"));
   if(mode.equals("shadowsocks"))check(files.toString().equals(assets.toString()),"final capture dropped original service declaration");
   if(mode.equals("wg")&&!layer.equals("off"))check(new JSONObject(capture.getString("exit_start")).toString().equals(assets.toString()),"outer capture dropped original service declaration");
   check(Arrays.equals(original,Files.readAllBytes(node.file.toPath())),"capture rewrote persisted original");
  }
  System.out.println("Android generated SS store/capture: "+checks+" exact source checks passed");
 }
}'''

def android(bundle,work):
 P=load('ss_store_fixture',ROOT/'android/test_android_connection_profiles.py')
 jar=Path(os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar'));assert jar.is_file(),'real Android JSON required'
 for name,text in P.STUBS.items():
  path=work/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
 app=work/'com/eabusham/routervpn';app.mkdir(parents=True)
 store_dependencies=load('ss_shipping_store_dependencies',ROOT/'android/android_store_fixture.py')
 store_sources=store_dependencies.sources()
 for name,text in store_sources.items():
  if name.endswith('/AndroidExternalPolicy.java'):continue
  path=work/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
 for name in ('AndroidNodeStore','AndroidProfileSelection'):
  shutil.copyfile(JAVA/(name+'.java'),app/(name+'.java'))
 boundaries='package com.eabusham.routervpn; import org.json.*;import java.util.*;import java.io.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;\n'
 boundaries+=block(P.BOUNDARIES,'final class AndroidPrivateFileStore')+block(P.BOUNDARIES,'final class AndroidVpnMutationGuard')
 boundaries+=block(P.BOUNDARIES,'final class AndroidHomeStateStore')+block(P.BOUNDARIES,'final class AndroidRuntimeRegistry')
 # Retain the shipping saved-policy validator with its complete pure closure;
 # only this fixture's explicit imported capture boundary is supplied below.
 policy=block(store_sources['com/eabusham/routervpn/AndroidExternalPolicy.java'],'final class AndroidExternalPolicy')
 boundaries+=policy[:-1]+'''static final class Captured{String source="{}",capture="{}";}static Captured captureImportedEntry(AndroidStandardExitStore.Entry e){return new Captured();}
'''+block((JAVA/'AndroidExternalPolicy.java').read_text(),'    static String protocol(')+'}\n'
 layer=(JAVA/'AndroidStartLayer.java').read_text()
 boundaries+='final class AndroidStartLayer {'+'\n'.join(line for line in layer.splitlines() if any('static final String '+name+' =' in line for name in ('OFF','AES','AES_XOR')))
 boundaries+='\n'.join(block(layer,signature) for signature in ('    static String selectedMode(','    private static JSONObject selectedRouterProfile(','    private static JSONObject requireHome(','    private static String normalize('))+'}\n'
 source=(JAVA/'AndroidImportedRouterPath.java').read_text()
 boundaries+='final class AndroidImportedRouterPath {static final class Compiled {final JSONObject input;Compiled(JSONObject input){this.input=input;}}\n'
 boundaries+='\n'.join(block(source,signature) for signature in ('    static boolean xrayFinal(', '    static boolean supports(','    static void requireEntry(','    private static boolean pairedKind(','    static Compiled compile('))+'}'
 path=app/'Boundaries.java';path.write_text(boundaries)
 (app/'SSServiceCapture.java').write_text(JAVA_MAIN)
 (work/'main.go').write_text(P.GO)
 subprocess.run(['go','build','-p=1','-o',str(work/'compiler'),str(work/'main.go')],cwd=ROOT,check=True,timeout=120)
 env=dict(os.environ,ROUTERVPN_PROFILE_COMPILER=str(work/'compiler'))
 classes=work/'classes'
 command=['javac','--release','17','-encoding','UTF-8','-cp',str(jar),'-d',str(classes),*map(str,work.rglob('*.java'))]
 run=['java','-cp',os.pathsep.join((str(classes),str(jar))),'com.eabusham.routervpn.SSServiceCapture',str(bundle)]
 for mutant in (False,True):
  if mutant:
   old='exit.getJSONObject("profiles").getJSONObject(exitMode).toString()'
   assert boundaries.count(old)==1
   path.write_text(boundaries.replace(old,'new JSONObject().put("sing-box.json", exit.getJSONObject("profiles").getJSONObject(exitMode).getString("sing-box.json")).toString()'))
  subprocess.run(command,check=True,timeout=60)
  private=work/('mutant-private' if mutant else 'private');private.mkdir()
  result=subprocess.run(run+[str(private)],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
  if mutant:
   assert result.returncode!=0 and 'final capture dropped original service declaration' in result.stdout,result.stdout
   print('Android service-drop causal rejected at actual final-source capture',flush=True)
  else:
   assert result.returncode==0,result.stdout
   print(result.stdout,end='',flush=True)


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--platform',choices=['apple','android','all'],default='all');args=parser.parse_args()
 with tempfile.TemporaryDirectory(prefix='routervpn-ss-host-',dir=ROOT) as td:
  work=Path(td);bundle=work/'bundle.json'
  subprocess.run([sys.executable,str(ROOT/'server/scripts/ss_service_consumer_fixture.py'),'--endpoint','192.0.2.44','--output',str(bundle)],check=True,timeout=45)
  if args.platform in ('all','android'):
   folder=work/'android';folder.mkdir();android(bundle,folder)
  if args.platform in ('all','apple'):
   for mutant in (False,True):
    folder=work/('original-guard' if mutant else 'current');folder.mkdir();apple(bundle,folder,mutant)
if __name__=='__main__':main()
